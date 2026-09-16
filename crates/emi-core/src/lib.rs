//! Shared, dependency-light domain types for the control plane and Windows agent.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmiPlan {
    pub device_id: Uuid,
    pub currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub installment_amount: Decimal,
    pub period_count: u16,
    pub periods: Vec<PaymentPeriod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentPeriod {
    pub sequence: u16,
    pub due_on: NaiveDate,
    pub status: PaymentStatus,
    pub paid_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    Paid,
    Overdue,
}

impl EmiPlan {
    /// Creates a plan while enforcing the invariants used by every application.
    ///
    /// # Errors
    ///
    /// Returns a [`DomainError`] when the currency, amount, count, or sequence is invalid.
    pub fn new(
        device_id: Uuid,
        currency: impl Into<String>,
        installment_amount: Decimal,
        periods: Vec<PaymentPeriod>,
    ) -> Result<Self, DomainError> {
        let currency = currency.into().to_uppercase();
        if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(DomainError::InvalidCurrency);
        }
        if installment_amount <= Decimal::ZERO {
            return Err(DomainError::NonPositiveAmount);
        }
        if periods.is_empty() || periods.len() > usize::from(u16::MAX) {
            return Err(DomainError::InvalidPeriodCount);
        }
        for (index, period) in periods.iter().enumerate() {
            if usize::from(period.sequence) != index + 1 {
                return Err(DomainError::NonSequentialPeriods);
            }
        }
        let period_count =
            u16::try_from(periods.len()).map_err(|_| DomainError::InvalidPeriodCount)?;
        Ok(Self {
            device_id,
            currency,
            installment_amount,
            period_count,
            periods,
        })
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.periods
            .iter()
            .all(|period| period.status == PaymentStatus::Paid)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("currency must be a three-letter ISO-style code")]
    InvalidCurrency,
    #[error("installment amount must be positive")]
    NonPositiveAmount,
    #[error("payment plan must contain between 1 and 65535 periods")]
    InvalidPeriodCount,
    #[error("payment period sequence must start at 1 and remain contiguous")]
    NonSequentialPeriods,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceHealth {
    pub device_id: Uuid,
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
    pub disk_free_bytes: u64,
    pub battery_percent: Option<u8>,
    pub secure_boot: Option<bool>,
    pub winget_available: bool,
    pub bios_provider: BiosProvider,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BiosProvider {
    Dell,
    Hp,
    Lenovo,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "parameters", rename_all = "snake_case")]
pub enum DeviceCommand {
    ShowPaymentReminder { title: String, message: String },
    SetManagedLockPin { pin_hash: String },
    RotateBiosPassword { encrypted_secret: String },
    ClearManagedRestrictions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_sequential_plan() {
        let result = EmiPlan::new(
            Uuid::new_v4(),
            "NPR",
            Decimal::new(25_000, 2),
            vec![PaymentPeriod {
                sequence: 2,
                due_on: NaiveDate::from_ymd_opt(2026, 10, 1).expect("valid date"),
                status: PaymentStatus::Pending,
                paid_at: None,
            }],
        );
        assert_eq!(result, Err(DomainError::NonSequentialPeriods));
    }
}
