//! Serial-based enrollment: check-enroll first, enroll only when the backend
//! reports this BIOS serial as not enrolled.

use super::config::{AgentConfig, initialize, write_ui_config};
use super::storage::{
    data_dir, read_enrollment_status, record_api_activity, record_enrollment_status,
    write_json_safely,
};
use anyhow::{Context, bail};
use chrono::{Duration, Utc};
use emi_device_agent::agent_api::{AgentApi, EnrollmentStatus};
use std::fs;
#[cfg(windows)]
use std::process::Command;
use tracing::info;

pub(crate) fn enroll(server: &str) -> anyhow::Result<()> {
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
    write_ui_config(config)?;
    info!(serial, device_uuid=%enrollment.device_uuid, "device enrolled with EMI admin API");
    Ok(())
}

/// Resolve enrollment from the backend before deciding whether the one-time
/// enrollment endpoint is appropriate for this Windows installation.
/// The service's startup check and the UI's launch sync usually run seconds
/// apart at logon. Reuse a fresh positive answer instead of calling
/// check-enroll twice in a row; negative or failed answers are always rechecked.
fn recently_confirmed(config: &AgentConfig) -> bool {
    config.agent_token.is_some()
        && config.remote_device_id.is_some()
        && read_enrollment_status().is_some_and(|status| {
            status.enrolled == Some(true)
                && status.error.is_none()
                && Utc::now() - status.checked_at < Duration::seconds(60)
        })
}

pub(crate) fn check_or_enroll_config(
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
    } else if recently_confirmed(config) {
        info!("enrollment confirmed by EMI admin API moments ago; skipping duplicate check");
        return Ok(());
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
    write_ui_config(config)
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
