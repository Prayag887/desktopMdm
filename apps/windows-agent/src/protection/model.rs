use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Errors and unsupported hardware are deliberately distinct from disabled protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Protected,
    PartiallyProtected,
    NeedsAttention,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub state: State,
    pub detail: String,
}

impl Check {
    pub fn error(detail: impl Into<String>) -> Self {
        Self {
            state: State::Error,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitLockerStatus {
    pub supported: Option<bool>,
    pub windows_edition: Option<String>,
    pub volume: String,
    pub encryption_state: Option<String>,
    pub encryption_percentage: Option<u8>,
    pub protection_enabled: Option<bool>,
    pub lock_state: Option<String>,
    pub encryption_method: Option<String>,
    pub key_protector_types: Vec<String>,
    pub tpm_protector_present: bool,
    pub recovery_protector_present: bool,
    pub check: Check,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmStatus {
    pub present: Option<bool>,
    pub ready: Option<bool>,
    pub enabled: Option<bool>,
    pub activated: Option<bool>,
    pub owned: Option<bool>,
    pub specification_version: Option<String>,
    pub manufacturer: Option<String>,
    pub manufacturer_version: Option<String>,
    pub check: Check,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureBootStatus {
    pub uefi: Option<bool>,
    pub supported: Option<bool>,
    pub enabled: Option<bool>,
    pub detection_error: Option<String>,
    pub check: Check,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProtectionStatus {
    pub acl_protection: Check,
    pub core_service: Check,
    pub watchdog: Check,
    pub integrity: Check,
    pub bit_locker: BitLockerStatus,
    pub tpm: TpmStatus,
    pub secure_boot: SecureBootStatus,
    pub last_verified_at: DateTime<Utc>,
}

impl DeviceProtectionStatus {
    #[must_use]
    pub fn overall(&self) -> State {
        aggregate(&[
            self.acl_protection.state,
            self.core_service.state,
            self.watchdog.state,
            self.integrity.state,
            self.bit_locker.check.state,
            self.tpm.check.state,
            self.secure_boot.check.state,
        ])
    }
}

#[must_use]
pub fn aggregate(states: &[State]) -> State {
    if states.is_empty() || states.contains(&State::Error) {
        State::Error
    } else if states.contains(&State::NeedsAttention) {
        State::NeedsAttention
    } else if states.iter().all(|s| *s == State::Unsupported) {
        State::Unsupported
    } else if states.iter().all(|s| *s == State::Protected) {
        State::Protected
    } else {
        State::PartiallyProtected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_and_unsupported_are_not_protected() {
        assert_eq!(aggregate(&[State::Protected, State::Error]), State::Error);
        assert_eq!(
            aggregate(&[State::Protected, State::Unsupported]),
            State::PartiallyProtected
        );
        assert_eq!(aggregate(&[State::Unsupported]), State::Unsupported);
        assert_eq!(
            aggregate(&[State::NeedsAttention, State::Protected]),
            State::NeedsAttention
        );
        assert_eq!(aggregate(&[State::Protected; 7]), State::Protected);
    }
}
