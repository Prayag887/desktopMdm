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
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
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
static RESUME_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    let server = server.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    if let Ok(config) = load_config() {
        if config.server == server {
            client
                .get(format!(
                    "{server}/api/v1/devices/{}/commands",
                    config.device_id
                ))
                .bearer_auth(&config.agent_token)
                .send()
                .await?
                .error_for_status()?;
            info!(device_id=%config.device_id, "existing enrollment verified");
            save_config(&config)?;
            return Ok(());
        }
        bail!(
            "device is already enrolled to a different server; use administrator recovery before re-enrolling"
        );
    }
    let name = name.unwrap_or_else(hostname);
    let serial = serial.unwrap_or_else(machine_serial);
    let response = client
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
    if once {
        return check_in(&client, &config, true).await;
    }
    let wake = std::sync::Arc::new(tokio::sync::Notify::new());
    let socket_task = tokio::spawn(socket_signals(config.clone(), std::sync::Arc::clone(&wake)));
    let mut fallback = tokio::time::interval(Duration::from_secs(60));
    let mut stop_check = tokio::time::interval(Duration::from_secs(1));
    let mut last_health = None;
    loop {
        tokio::select! {
            () = wake.notified() => {},
            _ = fallback.tick() => {},
            _ = stop_check.tick() => {
                if STOP_REQUESTED.load(Ordering::Relaxed) {
                    socket_task.abort();
                    return Ok(());
                }
                if !RESUME_REQUESTED.swap(false, Ordering::Relaxed) { continue; }
            }
        }
        let health_due = last_health
            .is_none_or(|time: tokio::time::Instant| time.elapsed() >= Duration::from_secs(300));
        if let Err(error) = check_in(&client, &config, health_due).await {
            error!(%error, "check-in failed");
        } else if health_due {
            last_health = Some(tokio::time::Instant::now());
        }
    }
}

async fn socket_signals(config: AgentConfig, wake: std::sync::Arc<tokio::sync::Notify>) {
    let mut backoff = 1_u64;
    loop {
        let result = socket_session(&config, &wake).await;
        if result.is_ok() {
            backoff = 1;
        }
        // Never include the request or token in diagnostic output.
        info!(
            retry_seconds = backoff,
            "command socket disconnected; durable sync remains available"
        );
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn socket_session(config: &AgentConfig, wake: &tokio::sync::Notify) -> anyhow::Result<()> {
    let mut url = reqwest::Url::parse(&format!(
        "{}/api/v1/devices/{}/socket",
        config.server, config.device_id
    ))?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => bail!("unsupported server scheme"),
    };
    url.set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("invalid socket scheme"))?;
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", config.agent_token).parse()?,
    );
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(request),
    )
    .await??;
    wake.notify_one();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(45), socket.next()).await?;
        match message {
            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) if text == "sync" => {
                wake.notify_one();
            }
            Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => return Ok(()),
            Some(Err(error)) => return Err(error.into()),
            Some(Ok(_)) => {}
        }
        socket.flush().await?;
    }
}

async fn report_health_to_server(
    client: &reqwest::Client,
    config: &AgentConfig,
) -> anyhow::Result<()> {
    let device_id = config.device_id;
    let health = tokio::task::spawn_blocking(move || collect_health(device_id)).await?;
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
    Ok(())
}

async fn check_in(
    client: &reqwest::Client,
    config: &AgentConfig,
    report_health: bool,
) -> anyhow::Result<()> {
    let mut policy_changed = false;
    loop {
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return Ok(());
        }
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
        if commands.is_empty() {
            break;
        }
        policy_changed |= commands.iter().any(|queued| {
            matches!(
                queued.command,
                DeviceCommand::SetManagedLockPin { .. }
                    | DeviceCommand::SetManagementEnabled { .. }
                    | DeviceCommand::ClearManagedRestrictions
            )
        });
        for queued in commands {
            let result =
                execute(&queued.command).unwrap_or_else(|error| format!("error: {error:#}"));
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
    }
    if policy_changed || report_health {
        report_health_to_server(client, config).await?;
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
        battery_percent: battery_status(),
        secure_boot: secure_boot_status(),
        winget_available: executable_available("winget"),
        bios_provider: detect_bios_provider(),
        management_enabled: management_is_enabled(),
        observed_at: Utc::now(),
    }
}

fn execute(command: &DeviceCommand) -> anyhow::Result<String> {
    match command {
        DeviceCommand::ShowPaymentReminder { title, message } => show_notification(title, message),
        DeviceCommand::SetManagedLockPin { pin_hash } => {
            if !argon2::PasswordHash::new(pin_hash)
                .is_ok_and(|hash| hash.algorithm.as_str() == "argon2id")
            {
                bail!("invalid managed PIN verifier");
            }
            fs::write(data_dir()?.join("managed-pin.verifier"), pin_hash)
                .context("store managed PIN verifier")?;
            Ok("managed lock PIN verifier updated".into())
        }
        DeviceCommand::RotateBiosPassword { .. } => bail!(
            "BIOS secret envelope execution requires a configured OEM adapter; no secret was applied"
        ),
        DeviceCommand::SetManagementEnabled { enabled } => {
            fs::write(
                data_dir()?.join("management.enabled"),
                if *enabled { "1" } else { "0" },
            )?;
            if !enabled {
                let pin = data_dir()?.join("managed-pin.verifier");
                if pin.exists() {
                    fs::remove_file(pin)?;
                }
            }
            Ok(format!(
                "management mode {}",
                if *enabled { "enabled" } else { "disabled" }
            ))
        }
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
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::PowerEvent(
            PowerEventParam::ResumeAutomatic
            | PowerEventParam::ResumeSuspend
            | PowerEventParam::ResumeCritical,
        ) => {
            RESUME_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::PowerEvent(_) => ServiceControlHandlerResult::NoError,
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
        fs::write(
            data_dir()?.join("payment-notice.json"),
            serde_json::to_vec(&serde_json::json!({
                "title": title,
                "message": message,
                "created_at": Utc::now().to_rfc3339(),
            }))?,
        )?;
        let text = format!("{}: {}", sanitize_message(title), sanitize_message(message));
        let status = Command::new("msg.exe")
            .args(["*", "/TIME:120", &text])
            .status();
        if !status.is_ok_and(|status| status.success()) {
            return Ok(
                "payment notice saved for the desktop UI; active-session popup unavailable".into(),
            );
        }
        Ok("notification displayed and saved in desktop UI".into())
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
fn management_is_enabled() -> bool {
    data_dir()
        .ok()
        .and_then(|path| fs::read_to_string(path.join("management.enabled")).ok())
        .is_none_or(|value| value.trim() != "0")
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
    fs::write(
        data_dir()?.join("ui-config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "server": config.server,
            "device_id": config.device_id,
        }))?,
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_identity_is_never_empty() {
        assert!(!hostname().is_empty());
        assert!(!machine_serial().is_empty());
    }

    #[test]
    fn a_missing_executable_is_not_reported_as_available() {
        assert!(!executable_available(
            "emi-definitely-not-a-real-executable-name"
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_only_probes_degrade_gracefully_off_windows() {
        assert_eq!(secure_boot_status(), None);
        assert_eq!(detect_bios_provider(), BiosProvider::Unsupported);
    }

    #[test]
    fn collected_health_describes_this_host() {
        let device_id = Uuid::new_v4();
        let health = collect_health(device_id);
        assert_eq!(health.device_id, device_id);
        assert_eq!(health.agent_version, env!("CARGO_PKG_VERSION"));
        assert!(!health.hostname.is_empty());
        assert!(!health.os_version.is_empty());
        assert!(
            health.observed_at <= Utc::now(),
            "observed_at must not be in the future"
        );
        assert!(
            serde_json::to_string(&health).is_ok(),
            "health must be serializable for the control plane"
        );
    }

    #[test]
    fn agent_config_round_trips_through_its_on_disk_form() {
        let config = AgentConfig {
            server: "https://control.example".into(),
            device_id: Uuid::new_v4(),
            agent_token: "6fa459ea-ee8a-3ca4-894e-db77e160355e".into(),
        };
        let encoded = serde_json::to_vec_pretty(&config).expect("serialize");
        let decoded: AgentConfig = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded.server, config.server);
        assert_eq!(decoded.device_id, config.device_id);
        assert_eq!(decoded.agent_token, config.agent_token);
    }

    #[test]
    fn the_enrollment_response_shape_matches_the_control_plane() {
        let body = r#"{"device_id":"6fa459ea-ee8a-3ca4-894e-db77e160355e","agent_token":"tok"}"#;
        let decoded: EnrollResponse = serde_json::from_str(body).expect("deserialize");
        assert_eq!(decoded.agent_token, "tok");
        assert_eq!(
            decoded.device_id,
            Uuid::parse_str("6fa459ea-ee8a-3ca4-894e-db77e160355e").expect("uuid")
        );
    }

    #[test]
    fn the_queued_command_shape_matches_the_control_plane() {
        let body = r#"[{"id":"cmd-1","command":{"type":"show_payment_reminder","parameters":{"title":"T","message":"M"}}}]"#;
        let decoded: Vec<QueuedCommand> = serde_json::from_str(body).expect("deserialize");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].id, "cmd-1");
        match &decoded[0].command {
            DeviceCommand::ShowPaymentReminder { title, message } => {
                assert_eq!(title, "T");
                assert_eq!(message, "M");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn a_short_managed_pin_verifier_is_refused() {
        let error = execute(&DeviceCommand::SetManagedLockPin {
            pin_hash: "too-short".into(),
        })
        .expect_err("a weak verifier must be refused");
        assert!(error.to_string().contains("invalid managed PIN verifier"));
    }

    #[test]
    fn bios_password_rotation_refuses_to_claim_success() {
        let error = execute(&DeviceCommand::RotateBiosPassword {
            encrypted_secret: "envelope".into(),
        })
        .expect_err("BIOS rotation has no OEM adapter and must not report success");
        assert!(error.to_string().contains("no secret was applied"));
    }

    #[test]
    fn reminders_are_acknowledged_on_every_platform() {
        let result = execute(&DeviceCommand::ShowPaymentReminder {
            title: "Payment reminder".into(),
            message: "Your EMI payment is due.".into(),
        })
        .expect("reminders must not fail the check-in");
        assert!(!result.is_empty());
    }

    #[test]
    fn managed_pin_lifecycle_writes_then_clears_the_verifier() {
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        let salt = SaltString::encode_b64(b"test-agent-salt").expect("salt");
        let verifier = Argon2::default()
            .hash_password(b"294817", &salt)
            .expect("hash")
            .to_string();
        let path = data_dir().expect("data dir").join("managed-pin.verifier");

        let result = execute(&DeviceCommand::SetManagedLockPin {
            pin_hash: verifier.clone(),
        })
        .expect("store verifier");
        assert!(result.contains("updated"));
        assert_eq!(fs::read_to_string(&path).expect("read verifier"), verifier);

        let result = execute(&DeviceCommand::ClearManagedRestrictions).expect("clear restrictions");
        assert!(result.contains("cleared"));
        assert!(!path.exists(), "the verifier must be removed");

        // Clearing again must stay successful so a retried command does not fail the queue.
        execute(&DeviceCommand::ClearManagedRestrictions).expect("clearing twice must succeed");
    }

    #[test]
    fn the_data_directory_is_created_on_demand() {
        let path = data_dir().expect("data dir");
        assert!(path.is_dir());
        assert_eq!(
            config_path().expect("config path"),
            path.join("config.json")
        );
    }

    #[cfg(windows)]
    #[test]
    fn notification_text_is_stripped_of_control_characters_and_bounded() {
        let dirty = format!("a\r\nb\u{7}c{}", "x".repeat(500));
        let clean = sanitize_message(&dirty);
        assert!(!clean.contains('\r') && !clean.contains('\n') && !clean.contains('\u{7}'));
        assert!(clean.chars().count() <= 300);
    }
}
