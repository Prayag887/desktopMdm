//! Admin check-in, lock-state application and command-patch acknowledgement.

use super::storage::{data_dir, record_api_activity, write_json_safely};
use anyhow::{Context, bail};
use chrono::Utc;
use emi_device_agent::agent_api::{
    AgentApi, CheckInResponse, CommandAction, LockState, LockStateKind, PendingCommand,
    PersistedRemoteState,
};
use emi_device_agent::command_security::{
    CommandSecurityState, applied_security_state, verify_command_patch, verify_patch_binding,
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
    let security_state = load_command_security_state()?;
    // The check-in lock state is the admin panel's authoritative view of this
    // device, received over HTTPS with this device's own bearer token. Apply
    // it on every check-in so an admin LOCK/UNLOCK takes effect even when no
    // command-signing key is provisioned or the command was already delivered.
    persist_remote_state(&SecuredRemoteState {
        remote: PersistedRemoteState {
            device_uuid,
            lock_state: check_in.lock_state.clone(),
            checked_at: Utc::now(),
            server_time: check_in.server_time,
        },
        command_security: security_state.clone(),
    })?;
    let Some(command) = &check_in.pending_command else {
        return Ok(());
    };
    apply_pending_command(
        api,
        token,
        device_uuid,
        &check_in,
        command,
        trusted_signing_keys,
        &security_state,
    )
}

/// Fetches the pending command's patch, applies its target state and acks it
/// so the admin panel shows the command as applied (or why it failed).
fn apply_pending_command(
    api: &AgentApi,
    token: &str,
    device_uuid: Uuid,
    check_in: &CheckInResponse,
    command: &PendingCommand,
    trusted_signing_keys: &BTreeMap<u64, String>,
    security_state: &CommandSecurityState,
) -> anyhow::Result<()> {
    let patch = match api.current_patch(token) {
        Ok(Some(patch)) => patch,
        // 204: the command was superseded or completed since the check-in.
        Ok(None) => return Ok(()),
        Err(error) => {
            record_api_activity(
                "/api/agent/patch-files/current/",
                format!("command={}", command.uuid),
                format!("error: {error}"),
            );
            return Err(error);
        }
    };
    let result = (|| -> anyhow::Result<()> {
        let now = check_in.server_time.max(Utc::now());
        // With a provisioned key, a patch must also carry a valid signature and
        // pass replay checks. Without one, the authenticated check-in is the
        // trust anchor and the patch only has to match the pending command.
        let command_security = if trusted_signing_keys.is_empty() {
            verify_patch_binding(command, &patch, now)?;
            security_state.clone()
        } else {
            verify_command_patch(
                device_uuid,
                command,
                &patch,
                now,
                trusted_signing_keys,
                security_state,
            )?;
            applied_security_state(device_uuid, security_state, command, &patch)?
        };
        api.verify_patch_download(token, &patch)?;
        if command.expires_at <= Utc::now() || patch.expires_at <= Utc::now() {
            bail!("command expired while downloading its patch");
        }
        persist_remote_state(&SecuredRemoteState {
            command_security,
            remote: PersistedRemoteState {
                device_uuid,
                lock_state: LockState {
                    state: command_target_state(command.action)?,
                    reason: command.reason.clone(),
                    changed_at: check_in.server_time,
                },
                checked_at: Utc::now(),
                server_time: check_in.server_time,
            },
        })
    })();
    let (applied, reason) = match &result {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    let ack = api.acknowledge(token, patch.uuid, applied, reason.as_deref());
    record_api_activity(
        &format!("/api/agent/patch-files/{}/ack/", patch.uuid),
        format!("action={:?}; applied={applied}", command.action),
        match &ack {
            Ok(()) => "success".into(),
            Err(error) => format!("error: {error}"),
        },
    );
    result?;
    ack
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
