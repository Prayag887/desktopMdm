//! State-directory paths and the JSON files shared with the desktop UI.

use anyhow::Context;
use chrono::Utc;
use emi_device_agent::agent_api::{ApiActivity, ApiActivityEvent, EnrollmentStatus};
use serde::Serialize;
use std::{fs, path::PathBuf};

pub(crate) fn data_dir() -> anyhow::Result<PathBuf> {
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

pub(crate) fn write_json_safely(
    path: &std::path::Path,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    emi_device_agent::state_store::write_json(
        path,
        value,
        path.file_name().is_some_and(|name| name == "config.json"),
    )
}

pub(crate) fn record_api_activity(endpoint: &str, request: String, response: String) {
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

pub(crate) fn record_enrollment_status(status: &EnrollmentStatus) {
    if let Ok(directory) = data_dir() {
        let _ = write_json_safely(&directory.join("enrollment-status.json"), status);
    }
}

pub(crate) fn read_enrollment_status() -> Option<EnrollmentStatus> {
    let path = data_dir().ok()?.join("enrollment-status.json");
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}
