use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use emi_core::{BiosProvider, DeviceHealth};
use emi_device_agent::agent_api::{
    AgentApi, ApiActivity, ApiActivityEvent, CommandAction, DEFAULT_API_BASE, EnrollmentStatus,
    LockState, LockStateKind, PersistedRemoteState,
};
use emi_device_agent::command_security::{
    CommandSecurityState, applied_security_state, normalize_public_key, verify_command_patch,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
        /// Check enrollment before the one-shot health and API synchronization.
        ///
        /// The Windows desktop UI uses this at launch so a newly installed
        /// agent does not wait for the five-minute service retry interval.
        #[arg(long)]
        auto_enroll: bool,
    },
    /// Install `WinGet` when it is missing (Windows only).
    Bootstrap,
    /// Show this PC's local identity.
    Status,
    /// Trust an admin command-signing key after validating its Ed25519 encoding.
    TrustCommandKey {
        #[arg(long)]
        key_id: u64,
        #[arg(long)]
        public_key: String,
    },
    /// Validate deployment public keys without changing any local state.
    ValidatePublicKeys {
        #[arg(long)]
        command_public_key: Option<String>,
        #[arg(long)]
        recovery_public_key_hex: Option<String>,
    },
    /// Provision the offline recovery public key; no built-in recovery secret.
    TrustRecoveryKey {
        #[arg(long)]
        public_key_hex: String,
    },
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
    /// Ed25519 verification keys keyed by the API's `signing_key_id`.
    /// There is deliberately no built-in key or permissive fallback.
    #[serde(default)]
    trusted_command_signing_keys: BTreeMap<u64, String>,
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
        AgentCommand::Run { once, auto_enroll } => run(once, auto_enroll),
        AgentCommand::Bootstrap => bootstrap(),
        AgentCommand::Status => {
            let config = initialize()?;
            println!(
                "local device {} ({})",
                config.device_id,
                if config.agent_token.is_some() {
                    "local credentials stored; verify server enrollment with check-enroll"
                } else {
                    "no local enrollment credentials"
                }
            );
            Ok(())
        }
        AgentCommand::TrustCommandKey { key_id, public_key } => {
            trust_command_key(key_id, &public_key)
        }
        AgentCommand::ValidatePublicKeys {
            command_public_key,
            recovery_public_key_hex,
        } => {
            if let Some(key) = command_public_key {
                normalize_public_key(&key)?;
            }
            if let Some(key) = recovery_public_key_hex {
                emi_device_agent::recovery_service::validate_public_key(&key)?;
            }
            Ok(())
        }
        AgentCommand::TrustRecoveryKey { public_key_hex } => {
            emi_device_agent::recovery_service::provision(&data_dir()?, &public_key_hex)
        }
        AgentCommand::Service => service_entry(),
    }
}

fn trust_command_key(key_id: u64, public_key: &str) -> anyhow::Result<()> {
    if key_id == 0 {
        bail!("command signing key ID must be greater than zero");
    }
    // Validate before reading or rewriting configuration, so invalid input can
    // never mutate an otherwise healthy installation.
    let public_key = normalize_public_key(public_key)?;
    let mut config = initialize()?;
    config
        .trusted_command_signing_keys
        .insert(key_id, public_key);
    write_json_safely(&data_dir()?.join("config.json"), &config)?;
    info!(key_id, "trusted command signing key configured");
    Ok(())
}

fn initialize() -> anyhow::Result<AgentConfig> {
    let path = data_dir()?.join("config.json");
    let mut config = match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<AgentConfig>(&bytes) {
            Ok(config) => config,
            Err(error) => {
                let backup = backup_invalid_config(&path)?;
                tracing::warn!(
                    %error,
                    backup = %backup.display(),
                    "invalid local device config was preserved and regenerated"
                );
                AgentConfig {
                    device_id: Uuid::new_v4(),
                    api_base: default_api_base(),
                    agent_token: None,
                    remote_device_id: None,
                    trusted_command_signing_keys: BTreeMap::new(),
                }
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentConfig {
            device_id: Uuid::new_v4(),
            api_base: default_api_base(),
            agent_token: None,
            remote_device_id: None,
            trusted_command_signing_keys: BTreeMap::new(),
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

fn backup_invalid_config(path: &std::path::Path) -> anyhow::Result<PathBuf> {
    let directory = path
        .parent()
        .context("device config has no parent directory")?;
    for suffix in 0..=u16::MAX {
        let name = if suffix == 0 {
            "config.invalid.json".to_string()
        } else {
            format!("config.invalid-{suffix}.json")
        };
        let backup = directory.join(name);
        if !backup.exists() {
            fs::rename(path, &backup).with_context(|| {
                format!("preserve invalid device config as {}", backup.display())
            })?;
            return Ok(backup);
        }
    }
    bail!("could not choose a backup name for the invalid device config")
}

fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

fn enroll(server: &str) -> anyhow::Result<()> {
    let mut config = initialize()?;
    let _api_guard = emi_device_agent::state_store::lock(&data_dir()?, "api.lock")?;
    check_or_enroll_config(&mut config, Some(server))
}

fn enroll_config(config: &mut AgentConfig, server: &str) -> anyhow::Result<()> {
    let serial = hardware_serial_number()?;
    let enrollment = match AgentApi::new(server)?.enroll(&serial, env!("CARGO_PKG_VERSION")) {
        Ok(enrollment) => {
            record_api_activity(
                "/api/agent/enroll/",
                format!(
                    "device_serial_no={serial}; agent_version={}",
                    env!("CARGO_PKG_VERSION")
                ),
                format!("success; device_uuid={}", enrollment.device_uuid),
            );
            enrollment
        }
        Err(error) => {
            record_api_activity(
                "/api/agent/enroll/",
                format!(
                    "device_serial_no={serial}; agent_version={}",
                    env!("CARGO_PKG_VERSION")
                ),
                format!("error: {error}"),
            );
            return Err(error).with_context(|| format!("enroll BIOS serial {serial}; first create its PENDING Device Agent in the admin panel"));
        }
    };
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

/// Resolve enrollment from the backend before deciding whether the one-time
/// enrollment endpoint is appropriate for this Windows installation.
fn check_or_enroll_config(
    config: &mut AgentConfig,
    server_override: Option<&str>,
) -> anyhow::Result<()> {
    let directory = data_dir()?;
    let _guard = emi_device_agent::state_store::lock(&directory, "enrollment.lock")?;
    // Another process may have replaced the token while this process waited
    // for the lock. Use the latest committed identity for the decision.
    *config = serde_json::from_slice(&fs::read(directory.join("config.json"))?)
        .context("read current enrollment credentials")?;
    if let Some(server) = server_override {
        config.api_base = server.trim_end_matches('/').to_string();
    }
    let serial = hardware_serial_number()?;
    let api = AgentApi::new(&config.api_base)?;
    let enrollment = match api.check_enrollment(&serial) {
        Ok(enrollment) => {
            record_enrollment_status(&EnrollmentStatus {
                checked_at: Utc::now(),
                device_serial_no: serial.clone(),
                enrolled: Some(enrollment.enrolled),
                status: Some(enrollment.status.clone()),
                error: None,
            });
            record_api_activity(
                "/api/agent/check-enroll/",
                format!("device_serial_no={serial}"),
                format!(
                    "enrolled={}; status={}",
                    enrollment.enrolled, enrollment.status
                ),
            );
            enrollment
        }
        Err(error) => {
            record_enrollment_status(&EnrollmentStatus {
                checked_at: Utc::now(),
                device_serial_no: serial.clone(),
                enrolled: None,
                status: None,
                error: Some(error.to_string()),
            });
            record_api_activity(
                "/api/agent/check-enroll/",
                format!("device_serial_no={serial}"),
                format!("error: {error}"),
            );
            return Err(error)
                .with_context(|| format!("check enrollment for BIOS serial {serial}"));
        }
    };
    if enrollment.enrolled {
        if config.agent_token.is_none() || config.remote_device_id.is_none() {
            bail!(
                "the server reports BIOS serial {serial} is enrolled ({}) but this Windows installation has no local agent credentials; an administrator must reset or reissue enrollment",
                enrollment.status
            );
        }
        info!(serial, status = %enrollment.status, "device enrollment confirmed by EMI admin API");
        return Ok(());
    }

    // The backend is authoritative. Never keep sending check-ins with a token
    // once it says this serial is not enrolled; doing so produced misleading
    // 401 events ahead of the enrollment decision in the restriction UI.
    clear_enrollment_credentials(config)?;
    info!(serial, status = %enrollment.status, "device is not enrolled; starting enrollment");
    let server = config.api_base.clone();
    enroll_config(config, &server)
}

fn clear_enrollment_credentials(config: &mut AgentConfig) -> anyhow::Result<()> {
    config.agent_token = None;
    config.remote_device_id = None;
    write_json_safely(&data_dir()?.join("config.json"), config)?;
    write_json_safely(
        &data_dir()?.join("ui-config.json"),
        &serde_json::json!({
            "device_id": config.device_id,
            "remote_device_id": null,
            "enrolled": false,
            "api_base": config.api_base,
        }),
    )
}

fn run(once: bool, auto_enroll: bool) -> anyhow::Result<()> {
    let mut config = initialize()?;
    let recovery_directory = data_dir()?;
    let recovery_device = config.device_id;
    // One worker in the Windows service only; short-lived health runs never
    // compete for mailbox processing. Filesystem locking serializes transactions.
    if auto_enroll {
        std::thread::spawn(move || {
            while !STOP_REQUESTED.load(Ordering::Relaxed) {
                if let Err(error) = emi_device_agent::recovery_service::process(
                    &recovery_directory,
                    recovery_device,
                    Utc::now(),
                ) {
                    tracing::warn!(%error, "offline recovery unavailable; administrator recovery remains available");
                    std::thread::sleep(Duration::from_secs(5));
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }
    let mut next_health = Instant::now();
    let mut next_check_in = Instant::now();
    let mut next_enrollment = Instant::now();
    // Recheck every five minutes even while a token exists: an administrator
    // may reset the backend enrollment after this service has started.
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
        if Instant::now() >= next_health || resumed {
            write_health_snapshot(config.device_id)?;
            next_health = Instant::now() + Duration::from_secs(300);
        }
        let enrollment_due = auto_enroll && (Instant::now() >= next_enrollment || resumed);
        let check_in_due = Instant::now() >= next_check_in || resumed;
        // The service and the UI's one-shot sync are separate processes. Hold
        // one lock across config reload, check-enroll, enroll and check-in so
        // their API calls never interleave and each sees the other's result.
        let api_guard = if enrollment_due || check_in_due {
            Some(emi_device_agent::state_store::lock(
                &data_dir()?,
                "api.lock",
            )?)
        } else {
            None
        };
        // The UI and service are separate processes. Re-read credentials so a
        // reset or enrollment performed by either process is respected here.
        let disk_config: AgentConfig = serde_json::from_slice(
            &fs::read(data_dir()?.join("config.json")).context("read current agent config")?,
        )
        .context("decode current agent config")?;
        if config.agent_token != disk_config.agent_token
            || config.remote_device_id != disk_config.remote_device_id
            || config.api_base != disk_config.api_base
        {
            config = disk_config;
            api = config
                .agent_token
                .as_ref()
                .map(|_| AgentApi::new(&config.api_base))
                .transpose()?;
        }
        if enrollment_due {
            match check_or_enroll_config(&mut config, None) {
                Ok(()) => api = Some(AgentApi::new(&config.api_base)?),
                Err(error) => {
                    tracing::warn!(%error, "device enrollment check did not complete");
                    // An unsuccessful check/enroll attempt leaves this PC
                    // without trusted current credentials. Do not let a
                    // previously constructed client send a stale check-in.
                    api = None;
                    // A one-shot sync is invoked by the desktop UI. Its exit
                    // status must distinguish a real API enrollment from a
                    // local health refresh, otherwise the UI can claim this
                    // Windows installation is enrolled when it is not.
                    if once {
                        return Err(error).context("device enrollment check did not complete");
                    }
                }
            }
            next_enrollment = Instant::now() + Duration::from_secs(300);
        }
        if check_in_due
            && let (Some(api), Some(token), Some(device_uuid)) = (
                api.as_ref(),
                config.agent_token.as_deref(),
                config.remote_device_id,
            )
        {
            if let Err(error) = synchronize_remote_state(
                api,
                token,
                device_uuid,
                &config.trusted_command_signing_keys,
            ) {
                tracing::warn!(%error, "EMI admin synchronization failed; retaining last applied state");
                // The long-running service keeps retrying. A UI-triggered
                // one-shot run, however, must accurately surface a failed
                // first check-in instead of returning success.
                if once {
                    return Err(error).context("initial EMI check-in failed");
                }
            }
            next_check_in = Instant::now() + Duration::from_secs(60);
        }
        drop(api_guard);
        if once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn write_health_snapshot(device_id: Uuid) -> anyhow::Result<()> {
    let health = collect_health(device_id);
    let directory = data_dir()?;
    let temporary = directory.join("health.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&health)?)?;
    fs::rename(temporary, directory.join("health.json"))?;
    info!(%device_id, "local health snapshot refreshed");
    Ok(())
}

fn synchronize_remote_state(
    api: &AgentApi,
    token: &str,
    device_uuid: Uuid,
    trusted_signing_keys: &BTreeMap<u64, String>,
) -> anyhow::Result<()> {
    let _guard = emi_device_agent::state_store::lock(&data_dir()?, "command.lock")?;
    let check_in = match api.check_in(token, env!("CARGO_PKG_VERSION")) {
        Ok(check_in) => {
            record_api_activity(
                "/api/agent/check-in/",
                format!("agent_version={}", env!("CARGO_PKG_VERSION")),
                format!(
                    "success; lock_state={:?}; pending_command={}",
                    check_in.lock_state.state,
                    check_in.pending_command.is_some()
                ),
            );
            check_in
        }
        Err(error) => {
            record_api_activity(
                "/api/agent/check-in/",
                format!("agent_version={}", env!("CARGO_PKG_VERSION")),
                format!("error: {error}"),
            );
            return Err(error);
        }
    };
    let Some(command) = check_in.pending_command else {
        // A bare check-in state has no signature. It may refresh liveness but
        // must never change an already-applied security state; every state
        // transition is authorized by a signed command patch.
        return refresh_remote_check_in(device_uuid, check_in.server_time);
    };
    let mut patch_uuid = None;
    let result = (|| -> anyhow::Result<()> {
        let patch = api
            .current_patch(token)?
            .context("server reported a pending command but returned no patch")?;
        patch_uuid = Some(patch.uuid);
        let security_state = load_command_security_state()?;
        verify_command_patch(
            device_uuid,
            &command,
            &patch,
            check_in.server_time.max(Utc::now()),
            trusted_signing_keys,
            &security_state,
        )?;
        api.verify_patch_download(token, &patch)?;
        if command.expires_at <= Utc::now() || patch.expires_at <= Utc::now() {
            bail!("command expired while downloading its patch");
        }
        let state = command_target_state(command.action)?;
        persist_remote_state(&SecuredRemoteState {
            command_security: applied_security_state(
                device_uuid,
                &security_state,
                &command,
                &patch,
            )?,
            remote: PersistedRemoteState {
                device_uuid,
                lock_state: LockState {
                    state,
                    reason: command.reason.clone(),
                    changed_at: check_in.server_time,
                },
                checked_at: Utc::now(),
                server_time: check_in.server_time,
            },
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

fn refresh_remote_check_in(
    device_uuid: Uuid,
    server_time: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    let path = data_dir()?.join("remote-state.json");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("read applied remote state"),
    };
    let mut state: SecuredRemoteState =
        serde_json::from_slice(&bytes).context("decode applied remote state")?;
    if state.remote.device_uuid != device_uuid {
        bail!("applied remote state belongs to another device");
    }
    state.remote.checked_at = Utc::now();
    state.remote.server_time = server_time;
    persist_remote_state(&state)
}

fn load_command_security_state() -> anyhow::Result<CommandSecurityState> {
    let path = data_dir()?.join("remote-state.json");
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice::<SecuredRemoteState>(&bytes)
            .context("decode command replay state")?
            .command_security),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(CommandSecurityState::default())
        }
        Err(error) => Err(error).context("read command replay state"),
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

#[derive(Serialize, Deserialize)]
struct SecuredRemoteState {
    #[serde(flatten)]
    remote: PersistedRemoteState,
    #[serde(default)]
    command_security: CommandSecurityState,
}

fn persist_remote_state(state: &SecuredRemoteState) -> anyhow::Result<()> {
    write_json_safely(&data_dir()?.join("remote-state.json"), &state)
}

fn record_api_activity(endpoint: &str, request: String, response: String) {
    const MAX_EVENTS: usize = 8;
    let Ok(path) = data_dir().map(|directory| directory.join("api-activity.json")) else {
        return;
    };
    let mut activity = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ApiActivity>(&bytes).ok())
        .unwrap_or(ApiActivity {
            recorded_at: Utc::now(),
            events: Vec::new(),
        });
    activity.recorded_at = Utc::now();
    activity.events.push(ApiActivityEvent {
        endpoint: endpoint.to_string(),
        request,
        response,
    });
    if activity.events.len() > MAX_EVENTS {
        let excess = activity.events.len() - MAX_EVENTS;
        activity.events.drain(..excess);
    }
    let _ = write_json_safely(&path, &activity);
}

fn record_enrollment_status(status: &EnrollmentStatus) {
    if let Ok(directory) = data_dir() {
        let _ = write_json_safely(&directory.join("enrollment-status.json"), status);
    }
}

fn write_json_safely(path: &std::path::Path, value: &impl Serialize) -> anyhow::Result<()> {
    emi_device_agent::state_store::write_json(
        path,
        value,
        path.file_name().is_some_and(|name| name == "config.json"),
    )
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
