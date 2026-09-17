//! User-mode global keyboard guard for the restriction screen.
//!
//! Installs a `WH_KEYBOARD_LL` low-level keyboard hook (a documented user-mode
//! Windows API — NOT a kernel driver) that swallows the common escape shortcuts
//! while the device is locked: Alt+Tab, the Windows keys, Alt+Esc, Ctrl+Esc,
//! Ctrl+Shift+Esc (Task Manager) and Alt+F4.
//!
//! Limits (be honest): a low-level hook CANNOT intercept Ctrl+Alt+Del (the Secure
//! Attention Sequence) — only Assigned Access / Keyboard Filter policy can — and,
//! being user-mode, it stops working if the process is killed by another elevated
//! process. For a robust, Microsoft-supported guarantee combine this with
//! `Set-PaymentRestriction.ps1` (kiosk + WEKF) on Enterprise/IoT.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VIRTUAL_KEY, VK_CONTROL, VK_ESCAPE, VK_F4, VK_LWIN, VK_MENU, VK_RWIN, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, SetWindowsHookExW, WH_KEYBOARD_LL,
};

/// Whether escape shortcuts should currently be swallowed. Set every frame from
/// the UI thread; read by the hook callback.
static LOCK_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Guards against installing the hook more than once.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Turn shortcut suppression on or off. Called each frame with whether the
/// restriction screen is showing.
pub fn set_locked(active: bool) {
    LOCK_ACTIVE.store(active, Ordering::Relaxed);
}

/// Install the low-level keyboard hook once, on the calling (UI) thread. The
/// thread must run a message loop — eframe/winit does — for the hook to fire.
pub fn install() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let module = match unsafe { GetModuleHandleW(None) } {
        Ok(handle) => HINSTANCE(handle.0),
        Err(_) => return,
    };
    // SAFETY: standard Win32 hook installation; `hook_proc` has the required
    // signature and lives for the whole process.
    let _ = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), Some(module), 0) };
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
        let is_win = vk == u32::from(VK_LWIN.0) || vk == u32::from(VK_RWIN.0);
        let swallow = is_win
            || (vk == u32::from(VK_TAB.0) && alt)
            || (vk == u32::from(VK_ESCAPE.0) && (alt || ctrl))
            || (vk == u32::from(VK_F4.0) && alt);
        if swallow {
            // Non-zero return eats the key so no other app or the OS sees it.
            return LRESULT(1);
        }
    }
    // SAFETY: passing the event to the next hook in the chain is always valid.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}
