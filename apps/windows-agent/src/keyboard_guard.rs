//! User-mode global keyboard guard for the restriction screen.
//!
//! Installs a `WH_KEYBOARD_LL` low-level keyboard hook (a documented user-mode
//! Windows API — NOT a kernel driver) that blocks the keyboard while the device
//! is locked: every modifier chord (Alt+*, Ctrl+*, Win+* including Win+Tab), the
//! Windows keys, Tab, Esc and Alt+F4, and all plain keys too — except plain
//! typing into the recovery field (so the owner unlock token can be entered).
//!
//! What a low-level hook CANNOT block (OS-protected secure sequences): Ctrl+Alt+
//! Del and Win+L. Task Manager is instead suppressed via the `DisableTaskMgr`
//! policy, and the power button (hardware) always shuts the device down — that is
//! the intended physical escape.
//!
//! The hook runs on its **own dedicated thread** with a tight message loop. This
//! matters: Windows enforces `LowLevelHooksTimeout` (~300 ms) and silently
//! bypasses a low-level hook whose thread does not service the callback in time.
//! The eframe UI thread is often busy rendering (or asleep between repaints), so
//! a hook installed there leaks keys intermittently. A dedicated pump thread is
//! always ready to run the callback, so shortcuts are blocked reliably.
//!
//! Limits (be honest): a low-level hook CANNOT intercept Ctrl+Alt+Del (the Secure
//! Attention Sequence) — only Assigned Access / Keyboard Filter policy can — and,
//! being user-mode, it stops working if the process is killed by another elevated
//! process. For a robust, Microsoft-supported guarantee combine this with
//! `Set-PaymentRestriction.ps1` (kiosk + WEKF) on Enterprise/IoT.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VIRTUAL_KEY, VK_CONTROL, VK_ESCAPE, VK_F4, VK_LWIN, VK_MENU, VK_RWIN, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, MSG,
    SetWindowsHookExW, TranslateMessage, WH_KEYBOARD_LL,
};

/// Whether the keyboard should currently be blocked. Set from the UI thread
/// every frame; read by the hook callback on the pump thread.
static LOCK_ACTIVE: AtomicBool = AtomicBool::new(false);
/// While locked, whether plain typing may pass through (recovery field focused).
/// Chords and system keys are blocked regardless.
static ALLOW_TYPING: AtomicBool = AtomicBool::new(false);
/// Guards against installing the hook more than once.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Turn keyboard blocking on or off. Called each frame with whether the
/// restriction screen is showing.
pub fn set_locked(active: bool) {
    LOCK_ACTIVE.store(active, Ordering::Relaxed);
}

/// While locked, allow plain typing (letters/digits/navigation) through so the
/// owner unlock token can be entered. Only set true when the recovery field is
/// focused; chords and system keys stay blocked either way.
pub fn set_typing_allowed(active: bool) {
    ALLOW_TYPING.store(active, Ordering::Relaxed);
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

fn key_down(vk: VIRTUAL_KEY) -> bool {
    // SAFETY: GetAsyncKeyState is safe to call with any virtual-key code; the
    // high bit of the result means the key is currently down (i16 < 0).
    (unsafe { GetAsyncKeyState(i32::from(vk.0)) }) < 0
}

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && LOCK_ACTIVE.load(Ordering::Relaxed) {
        // SAFETY: for HC_ACTION the OS guarantees lparam points to a valid
        // KBDLLHOOKSTRUCT for the duration of this call.
        let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let vk = event.vkCode;
        let alt = (event.flags.0 & LLKHF_ALTDOWN.0) != 0 || key_down(VK_MENU);
        let ctrl = key_down(VK_CONTROL);
        let win = key_down(VK_LWIN)
            || key_down(VK_RWIN)
            || vk == u32::from(VK_LWIN.0)
            || vk == u32::from(VK_RWIN.0);
        let hard_key =
            vk == u32::from(VK_TAB.0) || vk == u32::from(VK_ESCAPE.0) || vk == u32::from(VK_F4.0);
        // Block every modifier chord (Alt+*, Ctrl+*, Win+* incl Win+Tab), the
        // Windows keys, Tab, Esc and Alt+F4 outright. Block plain keys too, unless
        // the recovery field is focused so the owner token can still be typed.
        if alt || ctrl || win || hard_key || !ALLOW_TYPING.load(Ordering::Relaxed) {
            // Non-zero return eats the key so no other app or the OS sees it.
            return LRESULT(1);
        }
    }
    // SAFETY: passing the event to the next hook in the chain is always valid.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}
