//! Local system probes and small persistence helpers used by the UI.

use std::os::windows::process::CommandExt as _;
use std::{fs, path::PathBuf, process::Command};

use crate::agent_api::PersistedRemoteState;
use emi_core::{BiosProvider, DeviceHealth};
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

pub(crate) fn read_remote_state() -> Option<PersistedRemoteState> {
    let base = std::env::var_os("PROGRAMDATA")?;
    fs::read(PathBuf::from(base).join("EmiDeviceAgent/remote-state.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
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

/// Enable or disable Task Manager for the current user via the documented
/// `DisableTaskMgr` policy value in the user's own HKCU hive. No elevation is
/// needed (the app runs as this user), it works on Windows Home, and Windows
/// shows "Task Manager has been disabled by your administrator" on Ctrl+Shift+Esc
/// or the taskbar menu. Best-effort: registry failures are ignored so a lock is
/// never blocked by this. Removed again on unlock.
pub(crate) fn set_task_manager_disabled(disabled: bool) {
    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System";
    let value = if disabled { "1" } else { "0" };
    let _ = Command::new("reg.exe")
        .args([
            "add",
            KEY,
            "/v",
            "DisableTaskMgr",
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

fn dell_cctk_path() -> Option<PathBuf> {
    [
        r"C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe",
        r"C:\Program Files\Dell\Command Configure\X86_64\cctk.exe",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn hp_cmsl_path() -> Option<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")?;
    ["HPCMSL", "HP.ClientManagement"]
        .into_iter()
        .map(|module| {
            PathBuf::from(&program_files)
                .join("WindowsPowerShell/Modules")
                .join(module)
        })
        .find(|path| path.exists())
}

fn asus_act_path() -> Option<PathBuf> {
    [
        r"C:\Program Files\ASUS\ASUS BIOS Config Tool\act.exe",
        r"C:\Program Files\ASUS\ACT\act.exe",
        r"C:\Program Files (x86)\ASUS\ASUS BIOS Config Tool\act.exe",
        r"C:\Program Files (x86)\ASUS\ACT\act.exe",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

/// Read-only status of the OEM firmware adapter for the detected manufacturer:
/// `(present, message)`. Cheap enough to call per frame (a file check for Dell;
/// constant answers otherwise). No firmware is touched.
pub(crate) fn bios_adapter_status(provider: BiosProvider) -> (bool, String) {
    match provider {
        BiosProvider::Dell => {
            let present = dell_cctk_path().is_some();
            let message = if present {
                "Dell Command | Configure detected"
            } else {
                "Dell Command | Configure not installed"
            };
            (present, message.to_string())
        }
        BiosProvider::Lenovo => (
            true,
            "Lenovo BIOS WMI detected as the built-in adapter".to_string(),
        ),
        BiosProvider::Hp => {
            let present = hp_cmsl_path().is_some();
            let message = if present {
                "HP Client Management Script Library detected"
            } else {
                "HP CMSL required — install to enable firmware management"
            };
            (present, message.to_string())
        }
        BiosProvider::Asus => {
            let present = asus_act_path().is_some();
            let message = if present {
                "ASUS BIOS Configuration Tool detected"
            } else {
                "ASUS ACT is required and must be obtained for this model"
            };
            (present, message.to_string())
        }
        BiosProvider::Acer => (
            false,
            "Acer does not publish a universal in-Windows password adapter".to_string(),
        ),
        BiosProvider::Unsupported => (
            false,
            "Manufacturer not supported for firmware management".to_string(),
        ),
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
