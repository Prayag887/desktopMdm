//! Fail-closed verification and replay protection for remote lock commands.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::agent_api::{CommandAction, PatchFile, PendingCommand};

const SIGNING_DOMAIN: &str = "emi-command-patch-v1";

#[derive(Serialize)]
struct CanonicalPatchMessage<'a> {
    domain: &'static str,
    device_uuid: Uuid,
    patch_uuid: Uuid,
    command_uuid: Uuid,
    version: u32,
    action: &'static str,
    reason: &'a str,
    nonce: &'a str,
    command_expires_at: String,
    patch_expires_at: String,
    checksum: String,
    size_bytes: u64,
}

/// Durable anti-replay state. This must be stored beside the applied remote state.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CommandSecurityState {
    pub highest_patch_version: u32,
    pub last_patch_uuid: Option<Uuid>,
    pub last_command_uuid: Option<Uuid>,
    #[serde(default)]
    pub last_message_sha256: Option<String>,
    /// SHA-256 digests are retained so a nonce can never be reused by a later
    /// higher-version command without persisting the server-provided nonce.
    pub consumed_nonce_sha256: BTreeSet<String>,
}

/// Verifies identity, freshness, monotonic versioning, and an Ed25519 signature.
///
/// `signed_payload` is a base64-encoded detached Ed25519 signature over the
/// bytes returned by [`canonical_patch_message`]. The key is selected by the
/// API's `signing_key_id`; unknown and malformed keys fail closed.
///
/// # Errors
/// Returns an error for stale, replayed, mismatched, unsigned, or incorrectly
/// signed commands.
pub fn verify_command_patch(
    device_uuid: Uuid,
    command: &PendingCommand,
    patch: &PatchFile,
    server_time: DateTime<Utc>,
    trusted_keys: &BTreeMap<u64, String>,
    state: &CommandSecurityState,
) -> anyhow::Result<()> {
    if command.expires_at <= server_time || patch.expires_at <= server_time {
        bail!("pending command or patch is expired");
    }
    if command.nonce.trim().is_empty() {
        bail!("pending command has no nonce");
    }
    if patch.lock_command_uuid != command.uuid || patch.action != command.action {
        bail!("patch metadata does not match the pending command");
    }
    if patch.version == 0 {
        bail!("command patch version must be greater than zero");
    }

    let message = canonical_patch_message(device_uuid, command, patch)?;
    let message_digest = format!("{:x}", Sha256::digest(message.as_bytes()));
    let exact_retry = state.last_message_sha256.as_deref() == Some(message_digest.as_str())
        && state.last_patch_uuid == Some(patch.uuid)
        && state.last_command_uuid == Some(command.uuid)
        && state
            .consumed_nonce_sha256
            .contains(&nonce_digest(&command.nonce))
        && state.highest_patch_version == patch.version;
    if patch.version < state.highest_patch_version
        || (patch.version == state.highest_patch_version && !exact_retry)
    {
        bail!("command patch version is a replay or rollback");
    }
    if !exact_retry
        && state
            .consumed_nonce_sha256
            .contains(&nonce_digest(&command.nonce))
    {
        bail!("command nonce was already used by another patch");
    }

    let encoded_key = trusted_keys
        .get(&patch.signing_key_id)
        .context("command patch uses an untrusted signing key")?;
    let key_bytes = decode_fixed::<32>(encoded_key, "Ed25519 public key")?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("invalid Ed25519 public key")?;
    let signature_bytes = decode_fixed::<64>(&patch.signed_payload, "Ed25519 signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(message.as_bytes(), &signature)
        .context("command patch Ed25519 signature is invalid")
}

/// Computes replay state to commit atomically with the applied remote state.
///
/// # Errors
/// Returns an error if canonical serialization fails.
pub fn applied_security_state(
    device_uuid: Uuid,
    previous: &CommandSecurityState,
    command: &PendingCommand,
    patch: &PatchFile,
) -> anyhow::Result<CommandSecurityState> {
    let mut next = previous.clone();
    next.last_message_sha256 = Some(format!(
        "{:x}",
        Sha256::digest(canonical_patch_message(device_uuid, command, patch)?.as_bytes())
    ));
    next.highest_patch_version = patch.version;
    next.last_patch_uuid = Some(patch.uuid);
    next.last_command_uuid = Some(command.uuid);
    next.consumed_nonce_sha256
        .insert(nonce_digest(&command.nonce));
    Ok(next)
}

/// Produces the stable, domain-separated message the backend must sign.
///
/// # Errors
/// Returns an error if canonical JSON serialization fails.
pub fn canonical_patch_message(
    device_uuid: Uuid,
    command: &PendingCommand,
    patch: &PatchFile,
) -> anyhow::Result<String> {
    serde_json::to_string(&CanonicalPatchMessage {
        domain: SIGNING_DOMAIN,
        device_uuid,
        patch_uuid: patch.uuid,
        command_uuid: command.uuid,
        version: patch.version,
        action: action_name(patch.action),
        reason: &command.reason,
        nonce: &command.nonce,
        command_expires_at: command
            .expires_at
            .to_rfc3339_opts(SecondsFormat::Micros, true),
        patch_expires_at: patch
            .expires_at
            .to_rfc3339_opts(SecondsFormat::Micros, true),
        checksum: patch.checksum.trim().to_ascii_lowercase(),
        size_bytes: patch.size_bytes,
    })
    .context("serialize canonical command patch")
}

/// Validates and canonicalizes a configured Ed25519 public key.
///
/// # Errors
/// Returns an error unless `encoded` is standard or unpadded URL-safe base64
/// containing exactly one valid 32-byte Ed25519 public key.
pub fn normalize_public_key(encoded: &str) -> anyhow::Result<String> {
    let bytes = decode_fixed::<32>(encoded, "Ed25519 public key")?;
    let key = VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")?;
    if key.is_weak() {
        bail!("weak Ed25519 public key is not allowed");
    }
    Ok(general_purpose::STANDARD.encode(bytes))
}

fn action_name(action: CommandAction) -> &'static str {
    match action {
        CommandAction::Lock => "LOCK",
        CommandAction::Unlock => "UNLOCK",
        CommandAction::Warn => "WARN",
        CommandAction::Release => "RELEASE",
        CommandAction::Uninstall => "UNINSTALL",
    }
}

fn nonce_digest(nonce: &str) -> String {
    format!("{:x}", Sha256::digest(nonce.as_bytes()))
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> anyhow::Result<[u8; N]> {
    let value = value.trim();
    let decoded = general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
        .with_context(|| format!("{label} is not valid base64"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong length"))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn fixtures() -> (Uuid, PendingCommand, PatchFile, SigningKey) {
        let device = Uuid::new_v4();
        let command_uuid = Uuid::new_v4();
        let command = PendingCommand {
            uuid: command_uuid,
            action: CommandAction::Lock,
            reason: "LOST_DEVICE".into(),
            nonce: "nonce-1".into(),
            expires_at: "2030-01-01T01:00:00Z".parse().unwrap(),
        };
        let patch = PatchFile {
            uuid: Uuid::new_v4(),
            lock_command_uuid: command_uuid,
            version: 7,
            action: CommandAction::Lock,
            checksum: format!("sha256:{}", "ab".repeat(32)),
            size_bytes: 123,
            signed_payload: String::new(),
            signing_key_id: 42,
            expires_at: "2030-01-01T01:00:00Z".parse().unwrap(),
            download_url: "https://example.invalid/patch".into(),
        };
        (device, command, patch, SigningKey::from_bytes(&[9; 32]))
    }

    fn sign(device: Uuid, command: &PendingCommand, patch: &mut PatchFile, key: &SigningKey) {
        let message = canonical_patch_message(device, command, patch).unwrap();
        let signature = key.sign(message.as_bytes());
        patch.signed_payload = general_purpose::STANDARD.encode(signature.to_bytes());
    }

    fn keys(key: &SigningKey) -> BTreeMap<u64, String> {
        BTreeMap::from([(
            42,
            general_purpose::STANDARD.encode(key.verifying_key().to_bytes()),
        )])
    }

    #[test]
    fn accepts_valid_signature_and_exact_idempotent_retry() {
        let (device, command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        let trusted = keys(&key);
        verify_command_patch(
            device,
            &command,
            &patch,
            "2030-01-01T00:00:00Z".parse().unwrap(),
            &trusted,
            &CommandSecurityState::default(),
        )
        .unwrap();
        let state =
            applied_security_state(device, &CommandSecurityState::default(), &command, &patch)
                .unwrap();
        verify_command_patch(
            device,
            &command,
            &patch,
            "2030-01-01T00:00:00Z".parse().unwrap(),
            &trusted,
            &state,
        )
        .unwrap();
    }

    #[test]
    fn canonical_message_is_byte_stable_for_backend_interop() {
        let device = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let command = PendingCommand {
            uuid: Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            action: CommandAction::Lock,
            reason: "THEFT".into(),
            nonce: "test-nonce-001".into(),
            expires_at: "2030-01-02T03:04:05.123456Z".parse().unwrap(),
        };
        let patch = PatchFile {
            uuid: Uuid::parse_str("01234567-89ab-cdef-8123-456789abcdef").unwrap(),
            lock_command_uuid: command.uuid,
            version: 9,
            action: CommandAction::Lock,
            checksum: format!(" SHA256:{} ", "AB".repeat(32)),
            size_bytes: 456,
            signed_payload: String::new(),
            signing_key_id: 42,
            expires_at: "2030-01-02T03:05:06Z".parse().unwrap(),
            download_url: "https://example.invalid/patch".into(),
        };

        assert_eq!(
            canonical_patch_message(device, &command, &patch).unwrap(),
            concat!(
                r#"{"domain":"emi-command-patch-v1","device_uuid":"11111111-2222-3333-4444-555555555555","patch_uuid":"01234567-89ab-cdef-8123-456789abcdef","command_uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","version":9,"action":"LOCK","reason":"THEFT","nonce":"test-nonce-001","command_expires_at":"2030-01-02T03:04:05.123456Z","patch_expires_at":"2030-01-02T03:05:06.000000Z","checksum":"sha256:"#,
                "abababababababababababababababababababababababababababababababab",
                r#"","size_bytes":456}"#
            )
        );
    }

    #[test]
    fn rejects_tampered_metadata_and_unknown_key() {
        let (device, command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        patch.size_bytes += 1;
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &keys(&key),
                &CommandSecurityState::default(),
            )
            .unwrap_err()
            .to_string()
            .contains("signature")
        );
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &BTreeMap::new(),
                &CommandSecurityState::default(),
            )
            .unwrap_err()
            .to_string()
            .contains("untrusted")
        );
    }

    #[test]
    fn rejects_tampered_user_visible_reason() {
        let (device, mut command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        command.reason = "PAYMENT_OVERDUE".into();
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &keys(&key),
                &CommandSecurityState::default(),
            )
            .unwrap_err()
            .to_string()
            .contains("signature")
        );
    }

    #[test]
    fn public_key_normalization_rejects_bad_encoding_and_length() {
        let key = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes());
        assert_eq!(
            normalize_public_key(&encoded).unwrap(),
            general_purpose::STANDARD.encode(key.to_bytes())
        );
        assert!(normalize_public_key("not base64!").is_err());
        assert!(normalize_public_key(&general_purpose::STANDARD.encode([0; 31])).is_err());
    }

    #[test]
    fn rejects_resigned_substitution_disguised_as_exact_retry() {
        let (device, mut command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        let state =
            applied_security_state(device, &CommandSecurityState::default(), &command, &patch)
                .unwrap();
        command.reason = "different signed reason".into();
        sign(device, &command, &mut patch, &key);
        let result = verify_command_patch(
            device,
            &command,
            &patch,
            "2030-01-01T00:00:00Z".parse().unwrap(),
            &keys(&key),
            &state,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("replay or rollback")
        );
    }

    #[test]
    fn rejects_rollback_and_nonce_reuse() {
        let (device, command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        let mut state =
            applied_security_state(device, &CommandSecurityState::default(), &command, &patch)
                .unwrap();
        state.highest_patch_version = patch.version + 1;
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &keys(&key),
                &state,
            )
            .is_err()
        );

        state.highest_patch_version = patch.version - 1;
        state.last_patch_uuid = Some(Uuid::new_v4());
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &keys(&key),
                &state,
            )
            .is_err()
        );
    }

    #[test]
    fn signature_is_bound_to_device_and_expiry() {
        let (device, command, mut patch, key) = fixtures();
        sign(device, &command, &mut patch, &key);
        assert!(
            verify_command_patch(
                Uuid::new_v4(),
                &command,
                &patch,
                "2030-01-01T00:00:00Z".parse().unwrap(),
                &keys(&key),
                &CommandSecurityState::default(),
            )
            .is_err()
        );
        assert!(
            verify_command_patch(
                device,
                &command,
                &patch,
                "2030-01-01T02:00:00Z".parse().unwrap(),
                &keys(&key),
                &CommandSecurityState::default(),
            )
            .is_err()
        );
    }
}
