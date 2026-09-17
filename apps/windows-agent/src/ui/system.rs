//! Local system probes and small persistence helpers used by the UI.

use std::os::windows::process::CommandExt as _;
use std::{fs, path::PathBuf, process::Command};

use emi_core::DeviceHealth;
use uuid::Uuid;

/// `CREATE_NO_WINDOW` — spawn console helpers without flashing a window.
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// True when the current account is a member of the local Administrators group
/// (SID S-1-5-32-544). Authorized administrators are never restricted.
pub(crate) fn current_user_is_admin() -> bool {
    Command::new("whoami")
        .args(["/groups", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("S-1-5-32-544"))
}

/// True when this exe is the enrolled account's Winlogon shell — i.e. the
/// provisioning script made the app replace Explorer for this user. Read-only
/// registry query of the current user's own hive; no elevation required.
pub(crate) fn launched_as_user_shell() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    Command::new("reg.exe")
        .args([
            "query",
            r"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "/v",
            "Shell",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .to_lowercase()
                    .contains(&exe.to_string_lossy().to_lowercase())
        })
}

pub(crate) fn read_health() -> Option<DeviceHealth> {
    let base = std::env::var_os("PROGRAMDATA")?;
    fs::read(PathBuf::from(base).join("EmiDeviceAgent/health.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

pub(crate) fn read_device_id() -> Option<Uuid> {
    read_health().map(|health| health.device_id)
}

fn counter_path() -> Option<PathBuf> {
    std::env::var_os("PROGRAMDATA")
        .map(|base| PathBuf::from(base).join("EmiDeviceAgent/unlock-counter.txt"))
}

/// Highest unlock-token counter already accepted. Rollback protection: a token
/// must exceed this. Missing/unreadable file means "none seen yet". Backed by
/// the tested `emi_core::recovery` persistence helpers.
pub(crate) fn read_last_counter() -> u64 {
    counter_path().map_or(0, |path| emi_core::recovery::read_counter(&path))
}

pub(crate) fn write_last_counter(counter: u64) {
    if let Some(path) = counter_path() {
        let _ = emi_core::recovery::record_counter(&path, counter);
    }
}

pub(crate) fn agent_path() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    Ok(current.with_file_name("emi-device-agent.exe"))
}

pub(crate) fn service_is_running() -> bool {
    Command::new("sc.exe")
        .args(["query", "EmiDeviceAgent"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("RUNNING")
        })
}
