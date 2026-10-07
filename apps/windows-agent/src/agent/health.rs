//! Local health snapshot and `WinGet` bootstrap.

use super::storage::data_dir;
use anyhow::bail;
use chrono::Utc;
use emi_core::{BiosProvider, DeviceHealth};
use std::{fs, process::Command};
use sysinfo::{Disks, System};
use tracing::info;
use uuid::Uuid;

pub(crate) fn write_health_snapshot(device_id: Uuid) -> anyhow::Result<()> {
    let health = collect_health(device_id);
    let directory = data_dir()?;
    let temporary = directory.join("health.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&health)?)?;
    fs::rename(temporary, directory.join("health.json"))?;
    info!(%device_id, "local health snapshot refreshed");
    Ok(())
}

fn collect_health(device_id: Uuid) -> DeviceHealth {
    let disks = Disks::new_with_refreshed_list();
    let (manufacturer, model) = computer_system_identity();
    DeviceHealth {
        device_id,
        hostname: hostname(),
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".into()),
        bios_provider: bios_provider_from_manufacturer(&manufacturer),
        manufacturer,
        model,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        disk_free_bytes: disks.iter().map(sysinfo::Disk::available_space).sum(),
        battery_percent: battery_status(),
        secure_boot: secure_boot_status(),
        winget_available: executable_available("winget"),
        observed_at: Utc::now(),
    }
}

pub(crate) fn bootstrap() -> anyhow::Result<()> {
    if !cfg!(windows) {
        bail!("bootstrap is only supported on Windows");
    }
    if executable_available("winget") {
        info!("winget is already installed");
        return Ok(());
    }
    let status = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "& { $ProgressPreference='SilentlyContinue'; $p=Join-Path $env:TEMP 'Microsoft.DesktopAppInstaller.msixbundle'; Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile $p; Add-AppxPackage -Path $p; Remove-Item $p -Force }"]).status()?;
    if !status.success() {
        bail!("winget installation failed with {status}");
    }
    Ok(())
}

fn hostname() -> String {
    System::host_name().unwrap_or_else(|| "unknown-device".into())
}

fn executable_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn secure_boot_status() -> Option<bool> {
    #[cfg(windows)]
    {
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Confirm-SecureBootUEFI",
            ])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| v.trim().to_ascii_lowercase().parse().ok())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn battery_status() -> Option<u8> {
    #[cfg(windows)]
    {
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_Battery | Select-Object -First 1 -ExpandProperty EstimatedChargeRemaining",
            ])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse::<u8>().ok())
            .filter(|value| *value <= 100)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn computer_system_identity() -> (String, String) {
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$c=Get-CimInstance Win32_ComputerSystem; $c.Manufacturer; $c.Model",
            ])
            .output();
        if let Ok(output) = output
            && output.status.success()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
            if let Some(manufacturer) = lines.next() {
                return (
                    manufacturer.to_string(),
                    lines.next().unwrap_or("Unknown model").to_string(),
                );
            }
        }
    }
    ("Unknown manufacturer".into(), "Unknown model".into())
}

fn bios_provider_from_manufacturer(manufacturer: &str) -> BiosProvider {
    let manufacturer = manufacturer.to_ascii_lowercase();
    if manufacturer.contains("dell") {
        BiosProvider::Dell
    } else if manufacturer.contains("hewlett")
        || manufacturer == "hp"
        || manufacturer.starts_with("hp ")
    {
        BiosProvider::Hp
    } else if manufacturer.contains("lenovo") {
        BiosProvider::Lenovo
    } else if manufacturer.contains("asus") || manufacturer.contains("asustek") {
        BiosProvider::Asus
    } else if manufacturer.contains("acer") {
        BiosProvider::Acer
    } else {
        BiosProvider::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_describes_this_pc() {
        let id = Uuid::new_v4();
        let health = collect_health(id);
        assert_eq!(health.device_id, id);
        assert_eq!(health.agent_version, env!("CARGO_PKG_VERSION"));
        assert_ne!(health.hostname, "");
        assert_ne!(health.os_version, "");
        assert_ne!(health.manufacturer, "");
        assert_ne!(health.model, "");
    }

    #[test]
    fn maps_common_laptop_manufacturers_to_firmware_adapters() {
        assert_eq!(
            bios_provider_from_manufacturer("Dell Inc."),
            BiosProvider::Dell
        );
        assert_eq!(bios_provider_from_manufacturer("HP"), BiosProvider::Hp);
        assert_eq!(
            bios_provider_from_manufacturer("LENOVO"),
            BiosProvider::Lenovo
        );
        assert_eq!(
            bios_provider_from_manufacturer("ASUSTeK COMPUTER INC."),
            BiosProvider::Asus
        );
        assert_eq!(bios_provider_from_manufacturer("Acer"), BiosProvider::Acer);
        assert_eq!(
            bios_provider_from_manufacturer("Framework"),
            BiosProvider::Unsupported
        );
    }
}
