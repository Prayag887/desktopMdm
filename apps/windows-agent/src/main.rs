use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use emi_core::{BiosProvider, DeviceHealth};
use emi_device_agent::agent_api::{
    AgentApi, CommandAction, DEFAULT_API_BASE, LockState, LockStateKind, PersistedRemoteState,
};
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
#[command(version, about = "Windows EMI device agent")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Initialize this PC's local identity and state directory.
    Init,
    /// Enroll this PC after an administrator creates its pending device agent.
    Enroll {
        #[arg(long, default_value = DEFAULT_API_BASE)]
        server: String,
    },
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
    #[serde(default = "default_api_base")]
    api_base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_device_id: Option<Uuid>,
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
        AgentCommand::Enroll { server } => enroll(&server),
        AgentCommand::Run { once } => run(once, false),
        AgentCommand::Bootstrap => bootstrap(),
        AgentCommand::Status => {
            let config = initialize()?;
            println!(
                "local device {} ({})",
                config.device_id,
                if config.agent_token.is_some() {
                    "enrolled"
                } else {
                    "not enrolled"
                }
            );
            Ok(())
        }
        AgentCommand::Service => service_entry(),
    }
}

fn initialize() -> anyhow::Result<AgentConfig> {
    let path = data_dir()?.join("config.json");
    let mut config = match fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice::<AgentConfig>(&bytes).context("parse local device config")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentConfig {
            device_id: Uuid::new_v4(),
            api_base: default_api_base(),
            agent_token: None,
            remote_device_id: None,
        },
        Err(error) => return Err(error).context("read local device config"),
    };
    // A token without its server-issued device UUID (or vice versa) is an
    // incomplete/legacy enrollment and must not be treated as authenticated.
    if config.agent_token.is_some() != config.remote_device_id.is_some() {
        config.agent_token = None;
        config.remote_device_id = None;
    }
    write_json_safely(&path, &config)?;
    write_json_safely(
        &data_dir()?.join("ui-config.json"),
        &serde_json::json!({
            "device_id": config.device_id,
            "remote_device_id": config.remote_device_id,
            "enrolled": config.agent_token.is_some(),
            "api_base": config.api_base,
        }),
    )?;
    Ok(config)
}

fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

fn enroll(server: &str) -> anyhow::Result<()> {
    let mut config = initialize()?;
    if config.agent_token.is_some() {
        info!(device_id=%config.device_id, "device is already enrolled");
        return Ok(());
    }
    enroll_config(&mut config, server)?;
    Ok(())
}

fn enroll_config(config: &mut AgentConfig, server: &str) -> anyhow::Result<()> {
    let serial = hardware_serial_number()?;
    let enrollment = AgentApi::new(server)?
        .enroll(&serial, env!("CARGO_PKG_VERSION"))
        .with_context(|| {
            format!(
                "enroll BIOS serial {serial}; first create its PENDING Device Agent in the admin panel"
            )
        })?;
    config.api_base = server.trim_end_matches('/').to_string();
    config.agent_token = Some(enrollment.token);
    config.remote_device_id = Some(enrollment.device_uuid);
    write_json_safely(&data_dir()?.join("config.json"), &config)?;
    write_json_safely(
        &data_dir()?.join("ui-config.json"),
        &serde_json::json!({
            "device_id": config.device_id,
            "remote_device_id": config.remote_device_id,
            "enrolled": true,
            "api_base": config.api_base,
        }),
    )?;
    info!(serial, device_uuid=%enrollment.device_uuid, "device enrolled with EMI admin API");
    Ok(())
}

fn run(once: bool, auto_enroll: bool) -> anyhow::Result<()> {
    let mut config = initialize()?;
    let mut next_health = Instant::now();
    let mut next_check_in = Instant::now();
    let mut next_enrollment = Instant::now();
    let mut api = config
        .agent_token
        .as_ref()
        .map(|_| AgentApi::new(&config.api_base))
        .transpose()?;
    loop {
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return Ok(());
        }
        let resumed = RESUME_REQUESTED.swap(false, Ordering::Relaxed);
        if auto_enroll
            && config.agent_token.is_none()
            && (Instant::now() >= next_enrollment || resumed)
        {
            let server = config.api_base.clone();
            match enroll_config(&mut config, &server) {
                Ok(()) => api = Some(AgentApi::new(&config.api_base)?),
                Err(error) => tracing::warn!(%error, "device enrollment is still pending"),
            }
            next_enrollment = Instant::now() + Duration::from_secs(300);
        }
        if Instant::now() >= next_health || resumed {
            let health = collect_health(config.device_id);
            let directory = data_dir()?;
            let temporary = directory.join("health.json.tmp");
            fs::write(&temporary, serde_json::to_vec_pretty(&health)?)?;
            fs::rename(temporary, directory.join("health.json"))?;
            info!(device_id=%config.device_id, "local health snapshot refreshed");
            next_health = Instant::now() + Duration::from_secs(300);
        }
        if (Instant::now() >= next_check_in || resumed)
            && let (Some(api), Some(token), Some(device_uuid)) = (
                api.as_ref(),
                config.agent_token.as_deref(),
                config.remote_device_id,
            )
        {
            if let Err(error) = synchronize_remote_state(api, token, device_uuid) {
                tracing::warn!(%error, "EMI admin synchronization failed; retaining last applied state");
            }
            next_check_in = Instant::now() + Duration::from_secs(60);
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn synchronize_remote_state(api: &AgentApi, token: &str, device_uuid: Uuid) -> anyhow::Result<()> {
    let check_in = api.check_in(token, env!("CARGO_PKG_VERSION"))?;
    let Some(command) = check_in.pending_command else {
        return persist_remote_state(&PersistedRemoteState {
            device_uuid,
            lock_state: check_in.lock_state,
            checked_at: Utc::now(),
            server_time: check_in.server_time,
        });
    };
    let mut patch_uuid = None;
    let result = (|| -> anyhow::Result<()> {
        if command.expires_at <= check_in.server_time {
            bail!("pending command is expired");
        }
        if command.nonce.trim().is_empty() {
            bail!("pending command has no nonce");
        }
        let patch = api
            .current_patch(token)?
            .context("server reported a pending command but returned no patch")?;
        patch_uuid = Some(patch.uuid);
        if patch.lock_command_uuid != command.uuid || patch.action != command.action {
            bail!("patch metadata does not match the pending command");
        }
        if patch.expires_at <= check_in.server_time {
            bail!("command patch is expired");
        }
        if patch.version == 0 || patch.signed_payload.trim().is_empty() || patch.signing_key_id == 0
        {
            bail!("command patch is missing signing metadata");
        }
        api.verify_patch_download(token, &patch)?;
        let state = command_target_state(command.action)?;
        persist_remote_state(&PersistedRemoteState {
            device_uuid,
            lock_state: LockState {
                state,
                reason: command.reason.clone(),
                changed_at: check_in.server_time,
            },
            checked_at: Utc::now(),
            server_time: check_in.server_time,
        })
    })();
    match result {
        Ok(()) => api.acknowledge(
            token,
            patch_uuid.context("validated patch has no identifier")?,
            true,
            None,
        ),
        Err(error) => {
            let reason = error.to_string();
            if let Some(patch_uuid) = patch_uuid {
                let _ = api.acknowledge(token, patch_uuid, false, Some(&reason));
            }
            Err(error)
        }
    }
}

fn command_target_state(action: CommandAction) -> anyhow::Result<LockStateKind> {
    match action {
        CommandAction::Lock => Ok(LockStateKind::Locked),
        CommandAction::Unlock => Ok(LockStateKind::Unlocked),
        CommandAction::Warn => Ok(LockStateKind::Warning),
        CommandAction::Release => Ok(LockStateKind::PermanentlyReleased),
        CommandAction::Uninstall => {
            bail!("remote uninstall is not enabled; an administrator must uninstall locally")
        }
    }
}

fn persist_remote_state(state: &PersistedRemoteState) -> anyhow::Result<()> {
    write_json_safely(&data_dir()?.join("remote-state.json"), &state)
}

fn write_json_safely(path: &std::path::Path, value: &impl Serialize) -> anyhow::Result<()> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    // `rename` replaces an existing file on Unix but not on Windows. The UI
    // retains its in-memory state during this tiny replacement window.
    if cfg!(windows) && path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
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
    let exit_code = match run(false, true) {
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

fn hardware_serial_number() -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_BIOS).SerialNumber",
            ])
            .output()
            .context("read BIOS serial number")?;
        if !output.status.success() {
            bail!("Windows could not read the BIOS serial number");
        }
        let serial = String::from_utf8(output.stdout)
            .context("BIOS serial number is not valid UTF-8")?
            .trim()
            .to_string();
        if serial.is_empty() || serial.eq_ignore_ascii_case("To Be Filled By O.E.M.") {
            bail!("this PC does not report a usable BIOS serial number");
        }
        Ok(serial)
    }
    #[cfg(not(windows))]
    {
        bail!("device enrollment is only supported on Windows")
    }
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
        assert!(!health.manufacturer.is_empty());
        assert!(!health.model.is_empty());
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
    #[test]
    fn local_config_uses_the_documented_agent_auth_fields() {
        let config: AgentConfig = serde_json::from_str(r#"{"device_id":"6fa459ea-ee8a-3ca4-894e-db77e160355e","api_base":"https://emi-api.yajtech.com","agent_token":"1|secret","remote_device_id":"7fa459ea-ee8a-3ca4-894e-db77e160355e","server":"https://old.invalid"}"#).unwrap();
        let encoded = serde_json::to_value(config).unwrap();
        assert!(encoded.get("server").is_none());
        assert_eq!(encoded["agent_token"], "1|secret");
        assert_eq!(
            encoded["remote_device_id"],
            "7fa459ea-ee8a-3ca4-894e-db77e160355e"
        );
    }

    #[test]
    fn admin_commands_map_to_safe_local_states() {
        assert_eq!(
            command_target_state(CommandAction::Lock).unwrap(),
            LockStateKind::Locked
        );
        assert_eq!(
            command_target_state(CommandAction::Release).unwrap(),
            LockStateKind::PermanentlyReleased
        );
        assert!(command_target_state(CommandAction::Uninstall).is_err());
    }
}
