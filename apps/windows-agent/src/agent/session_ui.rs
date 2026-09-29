//! Keeps the lock screen on the signed-in user's desktop while locked.
//!
//! The service runs as SYSTEM in session 0 and cannot show UI itself. If the
//! device is locked but the user closed (or never started) the desktop UI,
//! start `emi-device-ui.exe` in the active console session with that user's
//! own token. The UI's single-instance mutex makes a redundant launch exit.
#![allow(unsafe_code)]

use anyhow::Context;
use std::path::Path;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{HSTRING, PWSTR};

const UI_EXE: &str = "emi-device-ui.exe";

/// Start the desktop UI in the active console session unless it already runs
/// there. Returns `Ok(false)` when nobody is signed in at the console.
pub(crate) fn ensure_ui_running() -> anyhow::Result<bool> {
    // SAFETY: no arguments; returns 0xFFFFFFFF when no session is attached.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return Ok(false);
    }
    if ui_running_in_session(session) {
        return Ok(true);
    }
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer. Fails with ERROR_NO_TOKEN when
    // no user is signed in to the session (e.g. at the logon screen).
    if unsafe { WTSQueryUserToken(session, &raw mut token) }.is_err() {
        return Ok(false);
    }
    let result = launch_as_user(token);
    // SAFETY: `token` was returned by WTSQueryUserToken and is owned here.
    let _ = unsafe { CloseHandle(token) };
    result.map(|()| true)
}

fn ui_running_in_session(session: u32) -> bool {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    system.processes().values().any(|process| {
        if !process.name().eq_ignore_ascii_case(UI_EXE) {
            return false;
        }
        let mut process_session = 0;
        // SAFETY: `process_session` is a valid out-pointer.
        unsafe { ProcessIdToSessionId(process.pid().as_u32(), &raw mut process_session) }
            .is_ok_and(|()| process_session == session)
    })
}

fn launch_as_user(token: HANDLE) -> anyhow::Result<()> {
    let agent = std::env::current_exe().context("locate the agent executable")?;
    let directory = agent.parent().unwrap_or(Path::new("."));
    let ui = directory.join(UI_EXE);
    let mut environment = std::ptr::null_mut();
    // SAFETY: `environment` is a valid out-pointer; `token` is a user token.
    unsafe { CreateEnvironmentBlock(&raw mut environment, Some(token), false) }
        .context("build the user's environment")?;
    let mut desktop: Vec<u16> = "winsta0\\default\0".encode_utf16().collect();
    let startup = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX),
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: every pointer refers to a live local for the duration of the
    // call; the environment block came from CreateEnvironmentBlock.
    let launched = unsafe {
        CreateProcessAsUserW(
            Some(token),
            &HSTRING::from(ui.as_os_str()),
            None,
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            Some(environment.cast_const()),
            &HSTRING::from(directory.as_os_str()),
            &raw const startup,
            &raw mut process,
        )
    };
    // SAFETY: the block was allocated by CreateEnvironmentBlock above.
    let _ = unsafe { DestroyEnvironmentBlock(environment) };
    launched.context("start the lock screen in the user's session")?;
    // SAFETY: both handles were returned by CreateProcessAsUserW.
    unsafe {
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
    }
    Ok(())
}
