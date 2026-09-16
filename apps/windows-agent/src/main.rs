use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use emi_core::{BiosProvider, DeviceHealth};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use sysinfo::{Disks, System};
#[cfg(windows)]
use tracing::error;
use tracing::info;
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about = "Standalone Windows desktop health companion")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Initialize this PC locally; no server or account is required.
    Init,
    /// Refresh the local health snapshot.
    Run {
        #[arg(long)]
        once: bool,
    },
    /// Install `WinGet` when it is missing (Windows only).
    Bootstrap,
    /// Show this PC's local identity.
    Status,
    #[command(hide = true)]
    Service,
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESUME_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize, Deserialize)]
struct AgentConfig {
    device_id: Uuid,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        AgentCommand::Init => {
            initialize()?;
            Ok(())
        }
        AgentCommand::Run { once } => run(once),
        AgentCommand::Bootstrap => bootstrap(),
        AgentCommand::Status => {
            println!("local device {}", initialize()?.device_id);
            Ok(())
        }
        AgentCommand::Service => service_entry(),
    }
}

fn initialize() -> anyhow::Result<AgentConfig> {
    let path = data_dir()?.join("config.json");
    let config = match fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice::<AgentConfig>(&bytes).context("parse local device config")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentConfig {
            device_id: Uuid::new_v4(),
        },
        Err(error) => return Err(error).context("read local device config"),
    };
    // A legacy config's extra server/token fields are deliberately not retained.
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    fs::write(
        data_dir()?.join("ui-config.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(config)
}

fn run(once: bool) -> anyhow::Result<()> {
    let config = initialize()?;
    let mut next_health = Instant::now();
    loop {
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return Ok(());
        }
        if Instant::now() >= next_health || RESUME_REQUESTED.swap(false, Ordering::Relaxed) {
            let health = collect_health(config.device_id);
            let directory = data_dir()?;
            let temporary = directory.join("health.json.tmp");
            fs::write(&temporary, serde_json::to_vec_pretty(&health)?)?;
            fs::rename(temporary, directory.join("health.json"))?;
            info!(device_id=%config.device_id, "local health snapshot refreshed");
            if once {
                return Ok(());
            }
            next_health = Instant::now() + Duration::from_secs(300);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn collect_health(device_id: Uuid) -> DeviceHealth {
    let disks = Disks::new_with_refreshed_list();
    DeviceHealth {
        device_id,
        hostname: hostname(),
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".into()),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        disk_free_bytes: disks.iter().map(sysinfo::Disk::available_space).sum(),
        battery_percent: battery_status(),
        secure_boot: secure_boot_status(),
        winget_available: executable_available("winget"),
        bios_provider: detect_bios_provider(),
        observed_at: Utc::now(),
    }
}

fn bootstrap() -> anyhow::Result<()> {
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

#[cfg(windows)]
fn service_entry() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start("EmiDeviceAgent", ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
fn service_entry() -> anyhow::Result<()> {
    bail!("Windows service mode is only available on Windows")
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    use windows_service::{
        service::{
            PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
            ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let handler = move |control| match control {
        ServiceControl::Stop => {
            STOP_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::PowerEvent(
            PowerEventParam::ResumeAutomatic
            | PowerEventParam::ResumeSuspend
            | PowerEventParam::ResumeCritical,
        ) => {
            RESUME_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate | ServiceControl::PowerEvent(_) => {
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register("EmiDeviceAgent", handler) else {
        return;
    };
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::POWER_EVENT,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if handle.set_service_status(running).is_err() {
        return;
    }
    let exit_code = match run(false) {
        Ok(()) => 0,
        Err(error) => {
            error!(%error, "service stopped with an error");
            1
        }
    };
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });
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
fn detect_bios_provider() -> BiosProvider {
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).Manufacturer",
            ])
            .output();
        if let Ok(output) = output {
            let m = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
            if m.contains("dell") {
                return BiosProvider::Dell;
            }
            if m.contains("hewlett") || m.contains("hp") {
                return BiosProvider::Hp;
            }
            if m.contains("lenovo") {
                return BiosProvider::Lenovo;
            }
        }
    }
    BiosProvider::Unsupported
}

fn data_dir() -> anyhow::Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .context("PROGRAMDATA is unavailable")?
    } else {
        std::env::temp_dir()
    };
    let path = base.join("EmiDeviceAgent");
    fs::create_dir_all(&path)?;
    Ok(path)
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
        assert!(!health.hostname.is_empty());
        assert!(!health.os_version.is_empty());
    }
    #[test]
    fn local_config_does_not_retain_legacy_server_credentials() {
        let config: AgentConfig = serde_json::from_str(r#"{"device_id":"6fa459ea-ee8a-3ca4-894e-db77e160355e","server":"https://old.invalid","agent_token":"legacy"}"#).unwrap();
        let encoded = serde_json::to_value(config).unwrap();
        assert!(encoded.get("server").is_none());
        assert!(encoded.get("agent_token").is_none());
    }
}
