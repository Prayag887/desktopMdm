//! Dependency-light local EMI plan and desktop device-health types.

pub mod recovery;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "EmiPlanWire")]
pub struct EmiPlan {
    pub device_id: Uuid,
    pub currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub installment_amount: Decimal,
    pub period_count: u16,
    pub periods: Vec<PaymentPeriod>,
}

#[derive(Deserialize)]
struct EmiPlanWire {
    device_id: Uuid,
    currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    installment_amount: Decimal,
    period_count: u16,
    periods: Vec<PaymentPeriod>,
}

impl TryFrom<EmiPlanWire> for EmiPlan {
    type Error = DomainError;

    fn try_from(wire: EmiPlanWire) -> Result<Self, Self::Error> {
        if usize::from(wire.period_count) != wire.periods.len() {
            return Err(DomainError::InvalidPeriodCount);
        }
        Self::new(
            wire.device_id,
            wire.currency,
            wire.installment_amount,
            wire.periods,
        )
    }
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BiosProvider {
    Dell,
    Hp,
    Lenovo,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn period(sequence: u16) -> PaymentPeriod {
        PaymentPeriod {
            sequence,
            due_on: NaiveDate::from_ymd_opt(2026, 10, 1).expect("valid date"),
            status: PaymentStatus::Pending,
            paid_at: None,
        }
    }

    fn amount() -> Decimal {
        Decimal::new(25_000, 2)
    }

    #[test]
    fn builds_a_valid_plan() {
        let device = Uuid::new_v4();
        let plan = EmiPlan::new(
            device,
            "NPR",
            amount(),
            vec![period(1), period(2), period(3)],
        )
        .expect("valid plan");
        assert_eq!(plan.device_id, device);
        assert_eq!(plan.currency, "NPR");
        assert_eq!(plan.period_count, 3);
        assert_eq!(plan.periods.len(), 3);
    }

    #[test]
    fn normalizes_currency_case() {
        let plan =
            EmiPlan::new(Uuid::new_v4(), "npr", amount(), vec![period(1)]).expect("valid plan");
        assert_eq!(plan.currency, "NPR");
    }

    #[test]
    fn rejects_malformed_currency() {
        for currency in ["", "NP", "NPRX", "N9R", "np-", "  r"] {
            assert_eq!(
                EmiPlan::new(Uuid::new_v4(), currency, amount(), vec![period(1)]),
                Err(DomainError::InvalidCurrency),
                "currency {currency:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_non_positive_amounts() {
        for value in [Decimal::ZERO, Decimal::new(-1, 0), Decimal::new(-25_000, 2)] {
            assert_eq!(
                EmiPlan::new(Uuid::new_v4(), "NPR", value, vec![period(1)]),
                Err(DomainError::NonPositiveAmount),
                "amount {value} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_an_empty_schedule() {
        assert_eq!(
            EmiPlan::new(Uuid::new_v4(), "NPR", amount(), Vec::new()),
            Err(DomainError::InvalidPeriodCount)
        );
    }

    #[test]
    fn rejects_non_sequential_plan() {
        let result = EmiPlan::new(Uuid::new_v4(), "NPR", amount(), vec![period(2)]);
        assert_eq!(result, Err(DomainError::NonSequentialPeriods));
    }

    #[test]
    fn rejects_a_schedule_with_a_gap() {
        let result = EmiPlan::new(
            Uuid::new_v4(),
            "NPR",
            amount(),
            vec![period(1), period(2), period(4)],
        );
        assert_eq!(result, Err(DomainError::NonSequentialPeriods));
    }

    #[test]
    fn rejects_a_schedule_with_duplicate_sequences() {
        let result = EmiPlan::new(Uuid::new_v4(), "NPR", amount(), vec![period(1), period(1)]);
        assert_eq!(result, Err(DomainError::NonSequentialPeriods));
    }

    #[test]
    fn accepts_the_largest_representable_schedule_boundary() {
        let periods: Vec<PaymentPeriod> = (1..=1000).map(period).collect();
        let plan = EmiPlan::new(Uuid::new_v4(), "NPR", amount(), periods).expect("valid plan");
        assert_eq!(plan.period_count, 1000);
    }

    #[test]
    fn completion_requires_every_period_to_be_paid() {
        let mut plan = EmiPlan::new(Uuid::new_v4(), "NPR", amount(), vec![period(1), period(2)])
            .expect("valid plan");
        assert!(!plan.is_complete());

        plan.periods[0].status = PaymentStatus::Paid;
        assert!(!plan.is_complete());

        plan.periods[1].status = PaymentStatus::Paid;
        assert!(plan.is_complete());
    }

    #[test]
    fn an_overdue_period_is_not_complete() {
        let mut plan =
            EmiPlan::new(Uuid::new_v4(), "NPR", amount(), vec![period(1)]).expect("valid plan");
        plan.periods[0].status = PaymentStatus::Overdue;
        assert!(!plan.is_complete());
    }

    #[test]
    fn plans_round_trip_through_json() {
        let plan = EmiPlan::new(Uuid::new_v4(), "NPR", amount(), vec![period(1), period(2)])
            .expect("valid plan");
        let encoded = serde_json::to_string(&plan).expect("serialize");
        assert!(
            encoded.contains("\"installment_amount\":\"250.00\""),
            "the decimal amount must serialize as a string: {encoded}"
        );
        let decoded: EmiPlan = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, plan);
    }

    #[test]
    fn deserialization_enforces_the_same_invariants_as_the_constructor() {
        // `EmiPlan::new` is the only guard today; a plan arriving over the wire can
        // claim a `period_count` that disagrees with its own schedule.
        let malformed = r#"{
            "device_id": "6fa459ea-ee8a-3ca4-894e-db77e160355e",
            "currency": "zz9",
            "installment_amount": "-10.00",
            "period_count": 99,
            "periods": []
        }"#;
        let decoded = serde_json::from_str::<EmiPlan>(malformed);
        assert!(
            decoded.is_err(),
            "deserializing an invalid plan must fail, got {:?}",
            decoded.map(|plan| plan.period_count)
        );
    }

    #[test]
    fn payment_status_uses_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&PaymentStatus::Overdue).expect("serialize"),
            "\"overdue\""
        );
        assert_eq!(
            serde_json::from_str::<PaymentStatus>("\"paid\"").expect("deserialize"),
            PaymentStatus::Paid
        );
    }

    #[test]
    fn bios_provider_uses_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&BiosProvider::Hp).expect("serialize"),
            "\"hp\""
        );
        assert_eq!(
            serde_json::from_str::<BiosProvider>("\"unsupported\"").expect("deserialize"),
            BiosProvider::Unsupported
        );
    }

    #[test]
    fn device_health_round_trips_through_json() {
        let health = DeviceHealth {
            device_id: Uuid::new_v4(),
            hostname: "host".into(),
            os_version: "Windows 11".into(),
            agent_version: "0.2.0".into(),
            disk_free_bytes: 42,
            battery_percent: Some(77),
            secure_boot: Some(true),
            winget_available: false,
            bios_provider: BiosProvider::Lenovo,
            observed_at: DateTime::parse_from_rfc3339("2026-09-16T10:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
        };
        let encoded = serde_json::to_string(&health).expect("serialize");
        assert_eq!(
            serde_json::from_str::<DeviceHealth>(&encoded).expect("deserialize"),
            health
        );
    }

    #[test]
    fn domain_errors_carry_actionable_messages() {
        assert!(
            DomainError::InvalidCurrency
                .to_string()
                .contains("three-letter")
        );
        assert!(
            DomainError::NonPositiveAmount
                .to_string()
                .contains("positive")
        );
    }
}
