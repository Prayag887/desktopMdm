//! Service-owned offline recovery. Only the request mailbox is user-writable.
use crate::state_store;
use anyhow::{Context as _, ensure};
use chrono::{DateTime, Utc};
use emi_core::recovery::{parse_public_key_hex, verify_unlock};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read as _, path::Path};
use uuid::Uuid;

const LAB_KEY: &str = "ac1473ba71d2cd322163ccc8a8f64e1226cfcb815bfc270cbe7417f16d8ae7ba";

#[derive(Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub request_id: Uuid,
    pub token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    pub request_id: Uuid,
    pub accepted: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct RecoveryState {
    pub public_key_hex: String,
    pub counter: u64,
    pub receipt: Option<RecoveryReceipt>,
}

/// Validate a provisionable recovery public key without modifying state.
/// # Errors
/// Rejects malformed, weak, and published lab keys.
pub fn validate_public_key(key_hex: &str) -> anyhow::Result<String> {
    let normalized = key_hex.trim().to_ascii_lowercase();
    let key = parse_public_key_hex(&normalized).context("invalid recovery public key")?;
    ensure!(
        !key.is_weak() && normalized != LAB_KEY,
        "lab/weak recovery keys are not allowed"
    );
    Ok(normalized)
}

/// Provision/rotate the public key without resetting the consumed counter.
/// # Errors
/// Rejects the published lab key, malformed keys, weak keys, and unreadable state.
pub fn provision(directory: &Path, key_hex: &str) -> anyhow::Result<()> {
    let normalized = validate_public_key(key_hex)?;
    let _guard = state_store::lock(directory, "recovery.lock")?;
    let path = directory.join("recovery-state.json");
    let counter = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<RecoveryState>(&bytes)?.counter,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    state_store::write_json(
        &path,
        &RecoveryState {
            public_key_hex: normalized,
            counter,
            receipt: None,
        },
        false,
    )
}

/// Validate one bounded mailbox request and atomically commit counter + receipt.
/// Run on the service thread; remote API availability is not required.
/// # Errors
/// Returns state/IO errors. No success receipt is exposed on persistence failure.
pub fn process(directory: &Path, device: Uuid, now: DateTime<Utc>) -> anyhow::Result<()> {
    let file = match fs::File::open(directory.join("recovery-request.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Ok(());
    }
    // A UI may still be writing; retry next service tick without logging input.
    let Ok(request) = serde_json::from_slice::<RecoveryRequest>(&bytes) else {
        return Ok(());
    };
    let _guard = state_store::lock(directory, "recovery.lock")?;
    let path = directory.join("recovery-state.json");
    let mut state: RecoveryState =
        serde_json::from_slice(&fs::read(&path).context("recovery key is not provisioned")?)?;
    if state
        .receipt
        .as_ref()
        .is_some_and(|receipt| receipt.request_id == request.request_id)
    {
        return Ok(());
    }
    let key =
        parse_public_key_hex(&state.public_key_hex).context("invalid provisioned recovery key")?;
    ensure!(
        !key.is_weak() && !state.public_key_hex.eq_ignore_ascii_case(LAB_KEY),
        "lab/weak recovery keys are not allowed"
    );
    let result = verify_unlock(&request.token, &key, device, now, state.counter);
    let accepted = result.is_ok();
    if let Ok(token) = result {
        state.counter = token.counter;
    }
    state.receipt = Some(RecoveryReceipt {
        request_id: request.request_id,
        accepted,
        expires_at: now + chrono::Duration::seconds(30),
    });
    state_store::write_json(&path, &state, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emi_core::recovery::{SigningKey, UnlockToken};
    fn fixture() -> (tempfile::TempDir, SigningKey, Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[37; 32]);
        let public =
            key.verifying_key()
                .to_bytes()
                .iter()
                .fold(String::new(), |mut output, byte| {
                    use std::fmt::Write as _;
                    write!(output, "{byte:02x}").unwrap();
                    output
                });
        provision(dir.path(), &public).unwrap();
        (dir, key, Uuid::new_v4())
    }
    fn state(dir: &Path) -> RecoveryState {
        serde_json::from_slice(&fs::read(dir.join("recovery-state.json")).unwrap()).unwrap()
    }
    fn submit(dir: &Path, token: &str) -> Uuid {
        let id = Uuid::new_v4();
        fs::write(
            dir.join("recovery-request.json"),
            serde_json::to_vec(&RecoveryRequest {
                request_id: id,
                token: token.into(),
            })
            .unwrap(),
        )
        .unwrap();
        id
    }
    #[test]
    fn service_consumes_once_and_counter_survives_restart_and_rotation() {
        let (dir, key, device) = fixture();
        let now = Utc::now();
        let code = UnlockToken {
            device_id: device,
            counter: 3,
            expires_unix: (now + chrono::Duration::minutes(5)).timestamp(),
        }
        .sign_to_string(&key);
        let id = submit(dir.path(), &code);
        process(dir.path(), device, now).unwrap();
        assert_eq!(state(dir.path()).counter, 3);
        assert!(state(dir.path()).receipt.unwrap().accepted);
        process(dir.path(), device, now).unwrap();
        assert_eq!(state(dir.path()).receipt.unwrap().request_id, id);
        submit(dir.path(), &code);
        process(dir.path(), device, now).unwrap();
        assert!(!state(dir.path()).receipt.unwrap().accepted);
        let public = state(dir.path()).public_key_hex;
        provision(dir.path(), &public).unwrap();
        assert_eq!(state(dir.path()).counter, 3);
    }
    #[test]
    fn wrong_device_word_and_missing_or_corrupt_state_never_authorize() {
        let (dir, key, device) = fixture();
        let now = Utc::now();
        let code = UnlockToken {
            device_id: Uuid::new_v4(),
            counter: 1,
            expires_unix: (now + chrono::Duration::minutes(5)).timestamp(),
        }
        .sign_to_string(&key);
        for input in [&code, "shared-unlock-word"] {
            submit(dir.path(), input);
            process(dir.path(), device, now).unwrap();
            assert!(!state(dir.path()).receipt.unwrap().accepted);
            assert_eq!(state(dir.path()).counter, 0);
        }
        submit(dir.path(), &code);
        fs::write(dir.path().join("recovery-state.json"), "corrupt").unwrap();
        assert!(process(dir.path(), device, now).is_err());
        fs::remove_file(dir.path().join("recovery-state.json")).unwrap();
        assert!(process(dir.path(), device, now).is_err());
    }
    #[test]
    fn lab_key_cannot_be_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        assert!(provision(dir.path(), LAB_KEY).is_err());
        assert!(!dir.path().join("recovery-state.json").exists());
    }
}
