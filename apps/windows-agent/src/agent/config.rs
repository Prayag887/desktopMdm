//! Local agent configuration: identity, API credentials and trusted keys.

use super::storage::{data_dir, write_json_safely};
use anyhow::{Context, bail};
use emi_device_agent::agent_api::DEFAULT_API_BASE;
use emi_device_agent::command_security::normalize_public_key;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AgentConfig {
    pub(crate) device_id: Uuid,
    #[serde(default = "default_api_base")]
    pub(crate) api_base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) remote_device_id: Option<Uuid>,
    /// Ed25519 verification keys keyed by the API's `signing_key_id`.
    /// There is deliberately no built-in key or permissive fallback.
    #[serde(default)]
    pub(crate) trusted_command_signing_keys: BTreeMap<u64, String>,
}

pub(crate) fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

pub(crate) fn initialize() -> anyhow::Result<AgentConfig> {
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
    write_ui_config(&config)?;
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

pub(crate) fn trust_command_key(key_id: u64, public_key: &str) -> anyhow::Result<()> {
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

/// Mirror the non-secret enrollment identity for the unprivileged desktop UI.
pub(crate) fn write_ui_config(config: &AgentConfig) -> anyhow::Result<()> {
    write_json_safely(
        &data_dir()?.join("ui-config.json"),
        &serde_json::json!({
            "device_id": config.device_id,
            "remote_device_id": config.remote_device_id,
            "enrolled": config.agent_token.is_some(),
            "api_base": config.api_base,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
