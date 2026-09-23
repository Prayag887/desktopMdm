//! Single-instance guard for the lock UI.
//!
//! Install sets up several independent auto-start triggers for the same
//! `emi-device-ui.exe` (a StartUp-folder shortcut, an all-users logon
//! scheduled task, and — once payment restriction is applied — a per-user
//! shell replacement plus its own logon task). At a single logon, more than
//! one of these can fire, launching several instances of this process at
//! once. Each instance independently boots straight into the fullscreen,
//! always-on-top lock screen and re-asserts focus/topmost every ~100 ms, so
//! two or more windows fight over the foreground — seen as the blue screen
//! "appearing more than once" and flickering, mostly right after a reboot.
//!
//! A named OS mutex makes only the first instance per logon session proceed;
//! later ones exit immediately and leave the first window alone.
#![allow(unsafe_code)]

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
#[cfg(windows)]
use windows::Win32::System::Threading::CreateMutexW;
#[cfg(windows)]
use windows::core::w;

/// Returns `true` if another instance of the lock UI already holds the
/// mutex for this session, in which case the caller should exit at once
/// without touching the screen, keyboard hook, or Task Manager policy.
///
/// The winning instance's handle is deliberately left open (not closed) so
/// the mutex stays held for the rest of the process's life; Windows releases
/// it automatically on exit, which is exactly when this instance should stop
/// being "the" running one.
#[cfg(windows)]
#[must_use]
pub fn already_running() -> bool {
    // SAFETY: `w!` produces a valid null-terminated wide string literal; the
    // other arguments are simple by-value flags with no aliasing concerns.
    let handle = unsafe { CreateMutexW(None, false, w!("Local\\EmiDeviceUiSingleInstance")) };
    match handle {
        Ok(handle) => {
            // SAFETY: `handle` is a fresh, valid mutex handle from the call above.
            let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            if already {
                // Not the surviving instance: release it right away.
                let _ = unsafe { CloseHandle(handle) };
            }
            already
        }
        Err(_) => {
            // If we can't even create the mutex, fail open rather than refuse
            // to show the lock screen at all.
            false
        }
    }
}

#[cfg(not(windows))]
#[must_use]
pub fn already_running() -> bool {
    false
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn second_check_in_the_same_process_sees_the_first_as_already_running() {
        assert!(!already_running(), "first call should acquire the mutex");
        assert!(
            already_running(),
            "second call must detect the mutex is already held"
        );
    }
}
