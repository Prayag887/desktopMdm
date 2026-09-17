//! User-mode global keyboard guard for the restriction screen.
//!
//! Installs a `WH_KEYBOARD_LL` low-level keyboard hook (a documented user-mode
//! Windows API — NOT a kernel driver). While the device is locked it blocks the
//! **entire** keyboard — every key and chord, no exceptions and nothing to
//! enumerate. The owner unlock token is entered with the app's on-screen keyboard
//! (mouse clicks), so no physical key ever needs to pass.
//!
//! The hook runs on its **own dedicated thread** with a tight message loop.
//! Windows enforces `LowLevelHooksTimeout` (~300 ms) and silently bypasses a
//! low-level hook whose thread does not service the callback in time; the eframe
//! UI thread is often busy rendering, so a hook installed there leaks keys. A
//! dedicated pump thread is always ready, so keys are blocked reliably.
//!
//! What a low-level hook CANNOT block (OS-protected secure sequences): Ctrl+Alt+
//! Del and Win+L. Task Manager is instead suppressed via the `DisableTaskMgr`
//! policy, and the power button (hardware) always shuts the device down — that is
//! the intended physical escape.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, MSG, SetWindowsHookExW, TranslateMessage,
    WH_KEYBOARD_LL,
};

/// Whether the keyboard is currently blocked. Set from the UI thread every
/// frame; read by the hook callback on the pump thread.
static LOCK_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Guards against installing the hook more than once.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Turn full keyboard blocking on or off. Called each frame with whether the
/// restriction screen is showing.
pub fn set_locked(active: bool) {
    LOCK_ACTIVE.store(active, Ordering::Relaxed);
}

/// Install the low-level keyboard hook on a dedicated pump thread. Idempotent.
pub fn install() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(|| {
        // Install on THIS thread so its message loop — not the busy UI thread —
        // services the callback within Windows' low-level-hook timeout.
        let module = match unsafe { GetModuleHandleW(None) } {
            Ok(handle) => HINSTANCE(handle.0),
            Err(_) => return,
        };
        // SAFETY: standard Win32 hook installation; `hook_proc` has the required
        // signature and lives for the whole process.
        let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), Some(module), 0) };
        // Record the outcome so a failure to block the keyboard can be diagnosed.
        let note = match &hook {
            Ok(_) => "keyboard guard: hook installed".to_string(),
            Err(error) => format!("keyboard guard: SetWindowsHookExW FAILED: {error}"),
        };
        let _ = std::fs::write(
            std::env::temp_dir().join("emi-keyboard-guard.log"),
            format!("{note}\n"),
        );
        if hook.is_err() {
            return;
        }
        // Pump messages forever so the OS keeps dispatching the hook callback on
        // this thread. GetMessageW returns 0 on WM_QUIT and -1 on error.
        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
            if result.0 <= 0 {
                break;
            }
            // SAFETY: translating/dispatching the retrieved message is always valid.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    });
}

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // While locked, eat EVERY key so no app or the OS sees any keyboard input.
    if code >= 0 && LOCK_ACTIVE.load(Ordering::Relaxed) {
        return LRESULT(1);
    }
    // SAFETY: passing the event to the next hook in the chain is always valid.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}
