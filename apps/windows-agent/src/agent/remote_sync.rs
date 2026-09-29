//! Admin check-in and signed command-patch application.

use super::storage::{data_dir, record_api_activity, write_json_safely};
use anyhow::{Context, bail};
use chrono::Utc;
use emi_device_agent::agent_api::{
    AgentApi, CommandAction, LockState, LockStateKind, PersistedRemoteState,
};
use emi_device_agent::command_security::{
    CommandSecurityState, applied_security_state, verify_command_patch,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs};
use uuid::Uuid;

pub(crate) fn synchronize_remote_state(
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

#[cfg(test)]
mod tests {
    use super::*;

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
