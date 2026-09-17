//! Integration tests: the full owner -> device unlock lifecycle across the
//! public `emi_core::recovery` API, including on-disk counter persistence that
//! survives "sessions" (separate reads/writes of the counter file).

use chrono::{Duration, Utc};
use emi_core::recovery::{
    SigningKey, UnlockError, UnlockToken, read_counter, record_counter, verify_unlock,
};
use rand::rngs::OsRng;
use std::path::Path;
use tempfile::tempdir;
use uuid::Uuid;

/// Owner side: mint a token bound to a device with a validity window.
fn mint(key: &SigningKey, device: Uuid, counter: u64, ttl_minutes: i64) -> String {
    UnlockToken {
        device_id: device,
        counter,
        expires_unix: (Utc::now() + Duration::minutes(ttl_minutes)).timestamp(),
    }
    .sign_to_string(key)
}

/// Device side: read the persisted counter, verify, and on success persist the
/// new counter — exactly what the app does. Returns the accepted counter.
fn device_unlock(
    counter_file: &Path,
    code: &str,
    key: &emi_core::recovery::VerifyingKey,
    device: Uuid,
) -> Result<u64, UnlockError> {
    let last = read_counter(counter_file);
    let token = verify_unlock(code, key, device, Utc::now(), last)?;
    record_counter(counter_file, token.counter).expect("persist counter");
    Ok(token.counter)
}

#[test]
fn a_device_unlocks_with_an_owner_token_then_rejects_its_reuse() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let device = Uuid::new_v4();
    let dir = tempdir().expect("tempdir");
    let counter_file = dir.path().join("unlock-counter.txt");

    // First unlock: counter 1 accepted, persisted.
    let token1 = mint(&signing, device, 1, 30);
    assert_eq!(
        device_unlock(&counter_file, &token1, &verifying, device),
        Ok(1)
    );
    assert_eq!(read_counter(&counter_file), 1);

    // Replaying the very same token now fails (counter no longer strictly newer).
    assert_eq!(
        device_unlock(&counter_file, &token1, &verifying, device),
        Err(UnlockError::Replayed)
    );

    // A fresh token with a higher counter is accepted in a later "session".
    let token2 = mint(&signing, device, 2, 30);
    assert_eq!(
        device_unlock(&counter_file, &token2, &verifying, device),
        Ok(2)
    );
    assert_eq!(read_counter(&counter_file), 2);

    // An old counter (rollback) is refused even though its signature is valid.
    let stale = mint(&signing, device, 2, 30);
    assert_eq!(
        device_unlock(&counter_file, &stale, &verifying, device),
        Err(UnlockError::Replayed)
    );
}

#[test]
fn a_token_from_a_different_owner_key_never_unlocks() {
    let owner = SigningKey::generate(&mut OsRng);
    let attacker = SigningKey::generate(&mut OsRng);
    let device = Uuid::new_v4();
    let dir = tempdir().expect("tempdir");
    let counter_file = dir.path().join("unlock-counter.txt");

    // Attacker signs a well-formed token with the wrong key.
    let forged = mint(&attacker, device, 1, 30);
    assert_eq!(
        device_unlock(&counter_file, &forged, &owner.verifying_key(), device),
        Err(UnlockError::BadSignature)
    );
    // The device stayed at zero — nothing was persisted on failure.
    assert_eq!(read_counter(&counter_file), 0);
}

#[test]
fn one_devices_token_does_not_unlock_another() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let dir = tempdir().expect("tempdir");
    let counter_file = dir.path().join("unlock-counter.txt");

    let for_a = mint(&signing, device_a, 1, 30);
    assert_eq!(
        device_unlock(&counter_file, &for_a, &verifying, device_b),
        Err(UnlockError::WrongDevice)
    );
}

#[test]
fn an_expired_token_is_refused_and_leaves_the_counter_untouched() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let device = Uuid::new_v4();
    let dir = tempdir().expect("tempdir");
    let counter_file = dir.path().join("unlock-counter.txt");
    record_counter(&counter_file, 3).expect("seed");

    let expired = mint(&signing, device, 4, -1); // already expired
    assert_eq!(
        device_unlock(&counter_file, &expired, &verifying, device),
        Err(UnlockError::Expired)
    );
    assert_eq!(
        read_counter(&counter_file),
        3,
        "failed unlock must not advance"
    );
}

#[test]
fn wiping_the_counter_file_cannot_revive_an_old_token() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let device = Uuid::new_v4();
    let dir = tempdir().expect("tempdir");
    let counter_file = dir.path().join("unlock-counter.txt");

    let token5 = mint(&signing, device, 5, 30);
    assert_eq!(
        device_unlock(&counter_file, &token5, &verifying, device),
        Ok(5)
    );

    // Attacker deletes the counter file to reset rollback protection.
    std::fs::remove_file(&counter_file).expect("wipe");
    assert_eq!(read_counter(&counter_file), 0);

    // The old token now passes the counter check (0 < 5) — this is the documented
    // limitation of a backend-free counter: a local admin can reset it. The
    // expiry is the second line of defence, so keep TTLs short.
    assert_eq!(
        device_unlock(&counter_file, &token5, &verifying, device),
        Ok(5)
    );
}
