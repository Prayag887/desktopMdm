//! User-mode global keyboard guard for the restriction screen.
//!
//! Installs a `WH_KEYBOARD_LL` low-level keyboard hook (a documented user-mode
//! Windows API — NOT a kernel driver). While the device is locked it blocks the
//! **entire** keyboard — every key and chord, no exceptions. The owner unlock
//! token is entered with the app's on-screen keyboard (mouse), so no physical
//! key ever needs to pass.
//!
//! The hook runs on its **own dedicated thread** whose message loop never exits,
//! so the hook is never auto-removed (a low-level hook is uninstalled if its
//! owning thread ends) and Windows never bypasses it for a slow UI thread.
//!
//! Diagnostics (in `%TEMP%`): `emi-keyboard-guard.log` records whether the hook
//! installed; `emi-keyboard-guard-fired.log` is written the first time the hook
//! actually fires while locked — if that file appears, the keyboard is being
//! blocked.
//!
//! What a low-level hook CANNOT block (OS-protected secure sequences): Ctrl+Alt+
//! Del and Win+L. Task Manager is suppressed via `DisableTaskMgr`, and the power
//! button (hardware) always shuts the device down — the intended physical escape.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

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
/// Set the first time the hook fires while locked (diagnostic only).
static FIRED: AtomicBool = AtomicBool::new(false);

/// Turn full keyboard blocking on or off. Called each frame with whether the
/// restriction screen is showing.
pub fn set_locked(active: bool) {
    LOCK_ACTIVE.store(active, Ordering::Relaxed);
}

fn log(name: &str, message: &str) {
    let _ = std::fs::write(std::env::temp_dir().join(name), format!("{message}\n"));
}

/// Install the low-level keyboard hook on a dedicated pump thread. Idempotent.
pub fn install() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(|| {
        let module = unsafe { GetModuleHandleW(None) }
            .ok()
            .map(|handle| HINSTANCE(handle.0));
        // SAFETY: standard Win32 hook installation. Try with the module handle,
        // then fall back to a NULL hmod (both are valid for a low-level hook).
        let mut hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), module, 0) };
        if hook.is_err() {
            hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), None, 0) };
        }
        match &hook {
            Ok(_) => log("emi-keyboard-guard.log", "keyboard guard: hook installed"),
            Err(error) => {
                log(
                    "emi-keyboard-guard.log",
                    &format!("keyboard guard: SetWindowsHookExW FAILED: {error}"),
                );
                return;
            }
        }
        // Pump forever. Never break, so the thread — and therefore the hook —
        // stays alive for the whole process. GetMessageW blocks while idle; the
        // OS still invokes the hook callback on this thread during the wait.
        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
            if result.0 <= 0 {
                thread::sleep(Duration::from_millis(50));
                continue;
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
        if !FIRED.swap(true, Ordering::Relaxed) {
            log("emi-keyboard-guard-fired.log", "hook fired while locked");
        }
        return LRESULT(1);
    }
    // SAFETY: passing the event to the next hook in the chain is always valid.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}
