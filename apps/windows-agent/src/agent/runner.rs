//! The agent's main loop, shared by the Windows service and one-shot runs.

use super::config::{AgentConfig, initialize};
use super::enrollment::check_or_enroll_config;
use super::health::write_health_snapshot;
use super::remote_sync::synchronize_remote_state;
use super::storage::data_dir;
use anyhow::Context;
use chrono::Utc;
use emi_device_agent::agent_api::AgentApi;
use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(crate) static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub(crate) static RESUME_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn run(once: bool, auto_enroll: bool) -> anyhow::Result<()> {
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
