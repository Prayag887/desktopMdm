//! Service-owned, read-only UI snapshot. Failure never interrupts EMI synchronization.
use super::{
    integrity,
    model::{Check, DeviceProtectionStatus, State},
    windows,
};
use chrono::Utc;
use std::path::Path;

/// Publish a verified snapshot through the existing ACL-protected state store.
///
/// # Errors
/// Returns an error for failed integrity checks, probes or state writes.
pub fn refresh(directory: &Path) -> anyhow::Result<()> {
    let installation = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no installation directory"))?
        .to_path_buf();
    let acl = super::acl::verify_protection_acl(&installation)?;
    if !acl.verified {
        anyhow::bail!("installation ACL mismatch: {}", acl.failures.join("; "));
    }
    super::acl::state_acl(false)?;
    let integrity = integrity::verify_installation(&installation)?;
    if !integrity.verified {
        anyhow::bail!("integrity failures: {}", integrity.failures.join("; "));
    }
    let bytes = windows::invoke_file(&installation.join("Get-DeviceProtection.ps1"))?;
    let mut snapshot: DeviceProtectionStatus = serde_json::from_slice(&bytes)?;
    snapshot.last_verified_at = Utc::now();
    snapshot.integrity = Check {
        state: State::Protected,
        detail: "Publisher-authenticated SHA-256 manifest verified".into(),
    };
    let previous = std::fs::read(directory.join("protection-status.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<DeviceProtectionStatus>(&bytes).ok());
    if previous.as_ref().is_none_or(|old| {
        old.bit_locker.check.state != snapshot.bit_locker.check.state
            || old.tpm.check.state != snapshot.tpm.check.state
            || old.secure_boot.check.state != snapshot.secure_boot.check.state
    }) {
        tracing::info!(event="security_posture_changed", bitlocker=?snapshot.bit_locker.check,
            tpm=?snapshot.tpm.check, secure_boot=?snapshot.secure_boot.check);
    }
    crate::state_store::write_json(&directory.join("protection-status.json"), &snapshot, false)?;
    Ok(())
}

pub fn record_failure(directory: &Path, error: &anyhow::Error) {
    let _ = crate::state_store::write_json(
        &directory.join("protection-error.json"),
        &serde_json::json!({"detail": error.to_string(), "observedAt": Utc::now()}),
        false,
    );
}
