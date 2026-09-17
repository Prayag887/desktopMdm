//! Integration tests for the public `EmiPlan` API as an external consumer sees
//! it: construction invariants, a pay-off lifecycle, and JSON round-tripping
//! through the same serde entry points the app uses.

use emi_core::{DomainError, EmiPlan, PaymentPeriod, PaymentStatus};
use rust_decimal::Decimal;
use uuid::Uuid;

fn period(sequence: u16) -> PaymentPeriod {
    PaymentPeriod {
        sequence,
        due_on: chrono::NaiveDate::from_ymd_opt(2026, 10, u32::from(sequence.clamp(1, 28)))
            .expect("valid date"),
        status: PaymentStatus::Pending,
        paid_at: None,
    }
}

fn plan(periods: u16) -> EmiPlan {
    let schedule: Vec<PaymentPeriod> = (1..=periods).map(period).collect();
    EmiPlan::new(Uuid::new_v4(), "NPR", Decimal::new(25_000, 2), schedule).expect("valid plan")
}

#[test]
fn a_plan_completes_only_after_every_period_is_paid() {
    let mut emi = plan(3);
    assert!(!emi.is_complete());

    for index in 0..emi.periods.len() {
        emi.periods[index].status = PaymentStatus::Paid;
        let done = index == emi.periods.len() - 1;
        assert_eq!(
            emi.is_complete(),
            done,
            "complete only after the last payment"
        );
    }
}

#[test]
fn an_overdue_period_blocks_completion() {
    let mut emi = plan(2);
    emi.periods[0].status = PaymentStatus::Paid;
    emi.periods[1].status = PaymentStatus::Overdue;
    assert!(!emi.is_complete());
}

#[test]
fn construction_rejects_invalid_inputs() {
    let device = Uuid::new_v4();
    let good = vec![period(1)];
    assert_eq!(
        EmiPlan::new(device, "US", Decimal::ONE, good.clone()),
        Err(DomainError::InvalidCurrency)
    );
    assert_eq!(
        EmiPlan::new(device, "NPR", Decimal::ZERO, good.clone()),
        Err(DomainError::NonPositiveAmount)
    );
    assert_eq!(
        EmiPlan::new(device, "NPR", Decimal::ONE, Vec::new()),
        Err(DomainError::InvalidPeriodCount)
    );
    assert_eq!(
        EmiPlan::new(device, "NPR", Decimal::ONE, vec![period(2)]),
        Err(DomainError::NonSequentialPeriods)
    );
}

#[test]
fn a_plan_round_trips_through_json_and_keeps_its_invariants() {
    let emi = plan(4);
    let encoded = serde_json::to_string(&emi).expect("serialize");
    let decoded: EmiPlan = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, emi);
    // amount serializes as a string to avoid float drift
    assert!(encoded.contains("\"installment_amount\":\"250.00\""));
}

#[test]
fn deserializing_a_plan_with_a_lying_period_count_fails() {
    let malformed = r#"{
        "device_id": "6fa459ea-ee8a-3ca4-894e-db77e160355e",
        "currency": "NPR",
        "installment_amount": "250.00",
        "period_count": 5,
        "periods": []
    }"#;
    assert!(serde_json::from_str::<EmiPlan>(malformed).is_err());
}
