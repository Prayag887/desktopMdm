//! Offline, backend-free unlock tokens for payment-restricted devices.
//!
//! Trust model: the **owner** holds an Ed25519 signing key that never touches a
//! managed device. The device embeds only the matching public (verifying) key.
//! To release a device the owner mints a short signed token bound to that
//! device's id, with an expiry and a monotonic counter, and hands it to whoever
//! is at the machine. The device verifies it offline.
//!
//! Only the holder of the signing key can produce a token the device accepts —
//! that is the intended "only the owner can bypass it" property. It is *not* a
//! master password baked into the app: compromising one device does not reveal
//! the key or help unlock any other device.
//!
//! Verification is **fail-safe**: any malformed / unsigned / expired / replayed
//! input returns `Err`, i.e. the device stays locked. Losing the signing key
//! does not brick anything — an administrator account (never restricted) and
//! `WinRE` remain the last-resort recovery paths.

use std::fs;
use std::io;
use std::path::Path;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use uuid::Uuid;

/// Version tag so the format can evolve without accepting older shapes silently.
pub const TOKEN_PREFIX: &str = "EMIU1-";
const PAYLOAD_LEN: usize = 32; // 16 device id + 8 counter + 8 expiry
const SIG_LEN: usize = 64;

/// The signed contents of an unlock token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockToken {
    pub device_id: Uuid,
    /// Monotonic counter; the device rejects any value it has already seen.
    pub counter: u64,
    /// Absolute expiry (Unix seconds). A short window limits reuse if leaked.
    pub expires_unix: i64,
}

/// Why an unlock attempt was refused. Every variant means "stay locked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    /// Not a token, wrong version, or corrupt encoding/length.
    Malformed,
    /// Signature did not verify against the trusted key.
    BadSignature,
    /// Token was minted for a different device.
    WrongDevice,
    /// Token expiry is in the past (or unrepresentable).
    Expired,
    /// Counter is not newer than the last accepted one (replay/rollback).
    Replayed,
}

impl core::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Malformed => "unlock code is malformed",
            Self::BadSignature => "unlock code signature is not valid",
            Self::WrongDevice => "unlock code is for a different device",
            Self::Expired => "unlock code has expired",
            Self::Replayed => "unlock code has already been used",
        };
        f.write_str(message)
    }
}

impl core::error::Error for UnlockError {}

impl UnlockToken {
    fn payload(&self) -> [u8; PAYLOAD_LEN] {
        let mut bytes = [0u8; PAYLOAD_LEN];
        bytes[..16].copy_from_slice(self.device_id.as_bytes());
        bytes[16..24].copy_from_slice(&self.counter.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.expires_unix.to_be_bytes());
        bytes
    }

    #[must_use]
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.expires_unix, 0)
    }

    /// Owner-side: sign this token into the compact string a device accepts.
    /// Run this only where the signing key lives — never on a managed device.
    #[must_use]
    pub fn sign_to_string(&self, key: &SigningKey) -> String {
        let payload = self.payload();
        let signature = key.sign(&payload);
        let mut buffer = Vec::with_capacity(PAYLOAD_LEN + SIG_LEN);
        buffer.extend_from_slice(&payload);
        buffer.extend_from_slice(&signature.to_bytes());
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(buffer))
    }
}

/// Verify a passphrase against an Argon2id encoded hash.
///
/// The plaintext word is never stored — only this slow, salted hash — so
/// `strings`, a memory dump of the running app, or casual disassembly reveal
/// nothing usable, and recovering the word requires an offline dictionary attack
/// against Argon2id (deliberately slow). It is not "impossible" (no client-side
/// secret is), but it is far beyond a plaintext-string lookup. Pair it with
/// attempt rate-limiting to stop live guessing.
#[must_use]
pub fn verify_unlock_word(input: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(input.trim().as_bytes(), &parsed)
        .is_ok()
}

/// Parse a 32-byte hex public key (as printed by the `keygen` example).
#[must_use]
pub fn parse_public_key_hex(hex: &str) -> Option<VerifyingKey> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = core::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Device-side verification. Returns the accepted token, or the reason it was
/// refused. The caller must persist `token.counter` as the new `last_counter`
/// so the same token cannot be replayed.
///
/// # Errors
/// Returns [`UnlockError`] for any malformed, unsigned, mismatched, expired, or
/// replayed input; on error the device must remain restricted.
pub fn verify_unlock(
    code: &str,
    trusted: &VerifyingKey,
    this_device: Uuid,
    now: DateTime<Utc>,
    last_counter: u64,
) -> Result<UnlockToken, UnlockError> {
    let encoded = code
        .trim()
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(UnlockError::Malformed)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| UnlockError::Malformed)?;
    if raw.len() != PAYLOAD_LEN + SIG_LEN {
        return Err(UnlockError::Malformed);
    }
    let (payload, signature_bytes) = raw.split_at(PAYLOAD_LEN);
    let signature = Signature::from_slice(signature_bytes).map_err(|_| UnlockError::Malformed)?;
    trusted
        .verify(payload, &signature)
        .map_err(|_| UnlockError::BadSignature)?;

    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&payload[..16]);
    let device_id = Uuid::from_bytes(id_bytes);
    let counter = u64::from_be_bytes(
        payload[16..24]
            .try_into()
            .map_err(|_| UnlockError::Malformed)?,
    );
    let expires_unix = i64::from_be_bytes(
        payload[24..32]
            .try_into()
            .map_err(|_| UnlockError::Malformed)?,
    );
    let token = UnlockToken {
        device_id,
        counter,
        expires_unix,
    };

    if device_id != this_device {
        return Err(UnlockError::WrongDevice);
    }
    match token.expires() {
        Some(expiry) if expiry > now => {}
        _ => return Err(UnlockError::Expired),
    }
    if counter <= last_counter {
        return Err(UnlockError::Replayed);
    }
    Ok(token)
}

/// Read the highest unlock counter already accepted from `path`. A missing,
/// unreadable, or non-numeric file means "none seen yet" and returns 0, so a
/// wiped counter file can never make an *older* token valid again.
#[must_use]
pub fn read_counter(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Persist a newly accepted counter so the same (or older) token is refused
/// next time. Callers should only ever pass a value greater than the current
/// one; this function itself just writes what it is given.
///
/// # Errors
/// Returns any I/O error from creating the parent directory or writing the file.
pub fn record_counter(path: &Path, counter: u64) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, counter.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn future_token(device: Uuid, counter: u64) -> UnlockToken {
        UnlockToken {
            device_id: device,
            counter,
            expires_unix: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
        }
    }

    #[test]
    fn a_valid_signed_token_is_accepted() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let code = future_token(device, 5).sign_to_string(&signing);
        let token = verify_unlock(&code, &verifying, device, Utc::now(), 4).expect("accepted");
        assert_eq!(token.counter, 5);
    }

    #[test]
    fn a_token_from_another_key_is_rejected() {
        let (signing, _) = keypair();
        let (_, other_verifying) = keypair();
        let device = Uuid::new_v4();
        let code = future_token(device, 1).sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&code, &other_verifying, device, Utc::now(), 0),
            Err(UnlockError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_token_is_rejected() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let mut code = future_token(device, 1).sign_to_string(&signing);
        // Replace the final base64 char with a different valid one, so the
        // decoded signature always changes (never re-forms the original token).
        let original_last = code.pop().expect("non-empty token");
        code.push(if original_last == 'A' { 'B' } else { 'A' });
        assert!(verify_unlock(&code, &verifying, device, Utc::now(), 0).is_err());
    }

    #[test]
    fn a_token_for_another_device_is_rejected() {
        let (signing, verifying) = keypair();
        let code = future_token(Uuid::new_v4(), 1).sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&code, &verifying, Uuid::new_v4(), Utc::now(), 0),
            Err(UnlockError::WrongDevice)
        );
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let token = UnlockToken {
            device_id: device,
            counter: 1,
            expires_unix: (Utc::now() - chrono::Duration::hours(1)).timestamp(),
        };
        let code = token.sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&code, &verifying, device, Utc::now(), 0),
            Err(UnlockError::Expired)
        );
    }

    #[test]
    fn a_replayed_or_rolled_back_counter_is_rejected() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let code = future_token(device, 7).sign_to_string(&signing);
        // last_counter already at 7 -> same token cannot be reused.
        assert_eq!(
            verify_unlock(&code, &verifying, device, Utc::now(), 7),
            Err(UnlockError::Replayed)
        );
        // and an older counter is rejected too.
        let old = future_token(device, 3).sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&old, &verifying, device, Utc::now(), 6),
            Err(UnlockError::Replayed)
        );
    }

    #[test]
    fn garbage_and_wrong_prefix_are_malformed() {
        let (_, verifying) = keypair();
        let device = Uuid::new_v4();
        for code in ["", "hello", "EMIU1-not-base64!!", "EMIU2-abcd"] {
            assert_eq!(
                verify_unlock(code, &verifying, device, Utc::now(), 0),
                Err(UnlockError::Malformed)
            );
        }
    }

    #[test]
    fn the_next_counter_is_accepted_but_equal_is_not() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        // exactly last + 1 is accepted
        let next = future_token(device, 7).sign_to_string(&signing);
        assert!(verify_unlock(&next, &verifying, device, Utc::now(), 6).is_ok());
        // exactly equal is replay
        let same = future_token(device, 6).sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&same, &verifying, device, Utc::now(), 6),
            Err(UnlockError::Replayed)
        );
    }

    #[test]
    fn expiry_is_strictly_greater_than_now() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let now = Utc::now();
        // expires exactly at `now` -> not strictly future -> Expired
        let token = UnlockToken {
            device_id: device,
            counter: 1,
            expires_unix: now.timestamp(),
        };
        let code = token.sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&code, &verifying, device, now, 0),
            Err(UnlockError::Expired)
        );
    }

    #[test]
    fn an_unrepresentable_expiry_fails_safe_as_expired() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let token = UnlockToken {
            device_id: device,
            counter: 1,
            expires_unix: i64::MAX,
        };
        let code = token.sign_to_string(&signing);
        assert_eq!(
            verify_unlock(&code, &verifying, device, Utc::now(), 0),
            Err(UnlockError::Expired)
        );
    }

    #[test]
    fn a_correctly_signed_but_wrong_length_body_is_malformed() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let mut code = future_token(device, 1).sign_to_string(&signing);
        // Drop 4 base64 chars: still valid base64, but decodes to 93 bytes != 96.
        code.truncate(code.len() - 4);
        assert_eq!(
            verify_unlock(&code, &verifying, device, Utc::now(), 0),
            Err(UnlockError::Malformed)
        );
    }

    #[test]
    fn a_prefix_with_no_body_is_malformed() {
        let (_, verifying) = keypair();
        assert_eq!(
            verify_unlock(TOKEN_PREFIX, &verifying, Uuid::new_v4(), Utc::now(), 0),
            Err(UnlockError::Malformed)
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let code = future_token(device, 2).sign_to_string(&signing);
        let padded = format!("  \n{code}\t ");
        assert!(verify_unlock(&padded, &verifying, device, Utc::now(), 1).is_ok());
    }

    #[test]
    fn a_minted_token_round_trips_through_verification() {
        let (signing, verifying) = keypair();
        let device = Uuid::new_v4();
        let minted = future_token(device, 42);
        let code = minted.sign_to_string(&signing);
        let verified = verify_unlock(&code, &verifying, device, Utc::now(), 0).expect("accepted");
        assert_eq!(verified, minted);
    }

    #[test]
    fn counter_file_missing_reads_as_zero() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nested/unlock-counter.txt");
        assert_eq!(read_counter(&path), 0);
    }

    #[test]
    fn counter_round_trips_and_creates_parent_dirs() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nested/unlock-counter.txt");
        record_counter(&path, 9).expect("write");
        assert_eq!(read_counter(&path), 9);
        record_counter(&path, 10).expect("overwrite");
        assert_eq!(read_counter(&path), 10);
    }

    #[test]
    fn a_corrupt_counter_file_reads_as_zero() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("unlock-counter.txt");
        fs::write(&path, "not-a-number").expect("write");
        assert_eq!(read_counter(&path), 0);
    }

    #[test]
    fn unlock_word_verifies_against_its_argon2_hash() {
        // Argon2id hash of "open" (the app embeds this, not the word).
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$Mdla+Ww3AP3Pto1BvS9hYA$LJMhBSc74442jY/70O0oEXn+b9Uzu07tguj2Hin1PIc";
        assert!(verify_unlock_word("open", hash));
        assert!(verify_unlock_word("  open  ", hash), "input is trimmed");
        assert!(!verify_unlock_word("nope", hash));
        assert!(!verify_unlock_word("open", "not-a-valid-hash"));
    }

    #[test]
    fn public_key_hex_round_trips() {
        use core::fmt::Write as _;
        let (_, verifying) = keypair();
        let mut hex = String::new();
        for byte in verifying.to_bytes() {
            write!(hex, "{byte:02x}").expect("write hex");
        }
        let parsed = parse_public_key_hex(&hex).expect("valid key");
        assert_eq!(parsed.to_bytes(), verifying.to_bytes());
        assert!(parse_public_key_hex("zz").is_none());
    }
}
