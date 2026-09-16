use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use emi_core::{BiosProvider, DeviceCommand, DeviceHealth};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};
use tracing::{error, info};
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about = "Authorized EMI device management agent")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand)]
enum AgentCommand {
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long)]
        enrollment_key: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        serial: Option<String>,
    },
    Run {
        #[arg(long)]
        once: bool,
    },
    Bootstrap,
    Status,
    #[command(hide = true)]
    Service,
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize, Deserialize)]
struct AgentConfig {
    server: String,
    device_id: Uuid,
    agent_token: String,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    enrollment_key: &'a str,
    name: &'a str,
    serial_number: &'a str,
}
#[derive(Deserialize)]
struct EnrollResponse {
    device_id: Uuid,
    agent_token: String,
}
#[derive(Deserialize)]
struct QueuedCommand {
    id: String,
    command: DeviceCommand,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        AgentCommand::Enroll {
            server,
            enrollment_key,
            name,
            serial,
        } => enroll(&server, &enrollment_key, name, serial).await,
        AgentCommand::Run { once } => run(once).await,
        AgentCommand::Bootstrap => bootstrap(),
        AgentCommand::Status => status(),
        AgentCommand::Service => service_entry(),
    }
}

async fn enroll(
    server: &str,
    key: &str,
    name: Option<String>,
    serial: Option<String>,
) -> anyhow::Result<()> {
    let name = name.unwrap_or_else(hostname);
    let serial = serial.unwrap_or_else(machine_serial);
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/enroll", server.trim_end_matches('/')))
        .json(&EnrollRequest {
            enrollment_key: key,
            name: &name,
            serial_number: &serial,
        })
        .send()
        .await?
        .error_for_status()?
        .json::<EnrollResponse>()
        .await?;
    let config = AgentConfig {
        server: server.trim_end_matches('/').into(),
        device_id: response.device_id,
        agent_token: response.agent_token,
    };
    save_config(&config)?;
    info!(device_id=%config.device_id, "device enrolled");
    Ok(())
}

async fn run(once: bool) -> anyhow::Result<()> {
    let config = load_config()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    loop {
        if let Err(error) = check_in(&client, &config).await {
            error!(%error, "check-in failed");
        }
        if once {
            return Ok(());
        }
        for _ in 0..60 {
            if STOP_REQUESTED.load(Ordering::Relaxed) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn check_in(client: &reqwest::Client, config: &AgentConfig) -> anyhow::Result<()> {
    let health = collect_health(config.device_id);
    client
        .post(format!(
            "{}/api/v1/devices/{}/health",
            config.server, config.device_id
        ))
        .bearer_auth(&config.agent_token)
        .json(&health)
        .send()
        .await?
        .error_for_status()?;
    let commands = client
        .get(format!(
            "{}/api/v1/devices/{}/commands",
            config.server, config.device_id
        ))
        .bearer_auth(&config.agent_token)
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<QueuedCommand>>()
        .await?;
    for queued in commands {
        let result = execute(&queued.command).unwrap_or_else(|error| format!("error: {error:#}"));
        client
            .post(format!(
                "{}/api/v1/devices/{}/commands/{}/complete",
                config.server, config.device_id, queued.id
            ))
            .bearer_auth(&config.agent_token)
            .json(&serde_json::json!({"result": result}))
            .send()
            .await?
            .error_for_status()?;
    }
    Ok(())
}

fn collect_health(device_id: Uuid) -> DeviceHealth {
    let mut system = System::new_all();
    system.refresh_all();
    let disks = Disks::new_with_refreshed_list();
    DeviceHealth {
        device_id,
        hostname: hostname(),
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".into()),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        disk_free_bytes: disks.iter().map(sysinfo::Disk::available_space).sum(),
        battery_percent: None,
        secure_boot: secure_boot_status(),
        winget_available: executable_available("winget"),
        bios_provider: detect_bios_provider(),
        observed_at: Utc::now(),
    }
}

fn execute(command: &DeviceCommand) -> anyhow::Result<String> {
    match command {
        DeviceCommand::ShowPaymentReminder { title, message } => show_notification(title, message),
        DeviceCommand::SetManagedLockPin { pin_hash } => {
            if pin_hash.len() < 32 {
                bail!("invalid managed PIN verifier");
            }
            fs::write(data_dir()?.join("managed-pin.verifier"), pin_hash)
                .context("store managed PIN verifier")?;
            Ok("managed lock PIN verifier updated".into())
        }
        DeviceCommand::RotateBiosPassword { .. } => bail!(
            "BIOS secret envelope execution requires a configured OEM adapter; no secret was applied"
        ),
        DeviceCommand::ClearManagedRestrictions => {
            let path = data_dir()?.join("managed-pin.verifier");
            if path.exists() {
                fs::remove_file(path)?;
            }
            Ok("managed restrictions cleared".into())
        }
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

fn status() -> anyhow::Result<()> {
    let config = load_config()?;
    println!("enrolled device {} -> {}", config.device_id, config.server);
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
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let handler = move |control| match control {
        ServiceControl::Stop => {
            STOP_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register("EmiDeviceAgent", handler) else {
        return;
    };
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if handle.set_service_status(running).is_err() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let exit_code = match runtime
        .and_then(|runtime| runtime.block_on(run(false)).map_err(std::io::Error::other))
    {
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

#[allow(clippy::unnecessary_wraps)] // Windows path can fail; non-Windows test path cannot.
fn show_notification(title: &str, message: &str) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let text = format!("{}: {}", sanitize_message(title), sanitize_message(message));
        let status = Command::new("msg.exe")
            .args(["*", "/TIME:120", &text])
            .status()?;
        if !status.success() {
            bail!("notification command failed");
        }
        Ok("notification displayed".into())
    }
    #[cfg(not(windows))]
    {
        let _ = (title, message);
        Ok("notification skipped on non-Windows host".into())
    }
}

#[cfg(windows)]
fn sanitize_message(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect()
}

fn hostname() -> String {
    System::host_name().unwrap_or_else(|| "unknown-device".into())
}
fn machine_serial() -> String {
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_BIOS).SerialNumber",
            ])
            .output();
        if let Ok(output) = output {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    format!("unknown-{}", hostname())
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
            .and_then(|v| v.trim().parse().ok())
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
fn config_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()?.join("config.json"))
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
fn save_config(config: &AgentConfig) -> anyhow::Result<()> {
    fs::write(config_path()?, serde_json::to_vec_pretty(config)?)?;
    Ok(())
}
fn load_config() -> anyhow::Result<AgentConfig> {
    let path = config_path()?;
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .context("parse agent config")
}

#[allow(dead_code)]
fn _is_file(path: &Path) -> bool {
    path.is_file()
}
