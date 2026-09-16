//! Payment-plan creation and settlement through the admin web UI.

mod common;

use axum::http::StatusCode;
use common::{admin, body_string, enroll_device, get, harness, post_empty, post_form, send};

async fn detail(router: &axum::Router, device_id: &str) -> String {
    body_string(
        send(
            router,
            get(&format!("/devices/{device_id}"), Some(&admin())),
        )
        .await,
    )
    .await
}

#[tokio::test]
async fn creating_a_plan_schedules_monthly_instalments() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Plan Box", "SER-PLAN").await;

    let response = send(
        &router,
        post_form(
            &format!("/devices/{device_id}/plans"),
            Some(&admin()),
            "amount=2500.00&currency=npr&periods=3&first_due=2026-10-31",
        ),
    )
    .await;
    assert!(
        response.status().is_redirection(),
        "plan creation should redirect, got {}",
        response.status()
    );

    let page = detail(&router, &device_id).await;
    assert!(page.contains("2500.00 NPR"), "instalment amount: {page}");
    assert!(page.contains("2026-10-31"), "first due date: {page}");
    assert!(
        page.contains("2026-11-30"),
        "month-end rollover for period 2: {page}"
    );
    assert!(
        page.contains("2026-12-31"),
        "month-end rollover for period 3: {page}"
    );
}

#[tokio::test]
async fn plan_input_is_validated() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Plan Box", "SER-PLAN-VALID").await;
    let uri = format!("/devices/{device_id}/plans");

    let rejected = [
        (
            "non-numeric amount",
            "amount=abc&currency=NPR&periods=3&first_due=2026-10-01",
        ),
        (
            "three decimals",
            "amount=25.123&currency=NPR&periods=3&first_due=2026-10-01",
        ),
        (
            "zero amount",
            "amount=0&currency=NPR&periods=3&first_due=2026-10-01",
        ),
        (
            "negative amount",
            "amount=-25.00&currency=NPR&periods=3&first_due=2026-10-01",
        ),
        (
            "zero periods",
            "amount=25.00&currency=NPR&periods=0&first_due=2026-10-01",
        ),
        (
            "too many periods",
            "amount=25.00&currency=NPR&periods=121&first_due=2026-10-01",
        ),
        (
            "short currency",
            "amount=25.00&currency=NP&periods=3&first_due=2026-10-01",
        ),
        (
            "long currency",
            "amount=25.00&currency=NPRX&periods=3&first_due=2026-10-01",
        ),
        (
            "numeric currency",
            "amount=25.00&currency=N9R&periods=3&first_due=2026-10-01",
        ),
        (
            "bad date",
            "amount=25.00&currency=NPR&periods=3&first_due=not-a-date",
        ),
        (
            "impossible date",
            "amount=25.00&currency=NPR&periods=3&first_due=2026-02-30",
        ),
        (
            "overflowing amount",
            "amount=99999999999999999999&currency=NPR&periods=3&first_due=2026-10-01",
        ),
    ];

    for (label, form) in rejected {
        let response = send(&router, post_form(&uri, Some(&admin()), form)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{label} should be rejected"
        );
    }

    let page = detail(&router, &device_id).await;
    assert!(
        !page.contains("Mark paid"),
        "no instalment row may survive a rejected plan: {page}"
    );
}

#[tokio::test]
async fn a_plan_cannot_be_created_twice() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Plan Box", "SER-PLAN-TWICE").await;
    let uri = format!("/devices/{device_id}/plans");
    let form = "amount=10.00&currency=NPR&periods=2&first_due=2026-10-01";

    let first = send(&router, post_form(&uri, Some(&admin()), form)).await;
    assert!(first.status().is_redirection());

    let second = send(&router, post_form(&uri, Some(&admin()), form)).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);

    let page = detail(&router, &device_id).await;
    assert_eq!(
        page.matches("Mark paid").count(),
        2,
        "the rejected second plan must not add rows: {page}"
    );
}

#[tokio::test]
async fn a_plan_cannot_be_created_for_an_unknown_device() {
    let router = harness().await;
    let unknown = uuid::Uuid::new_v4();

    let response = send(
        &router,
        post_form(
            &format!("/devices/{unknown}/plans"),
            Some(&admin()),
            "amount=10.00&currency=NPR&periods=2&first_due=2026-10-01",
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "creating a plan for a device that does not exist must be a 404, got {}",
        response.status()
    );
}

#[tokio::test]
async fn reminders_cannot_be_queued_for_an_unknown_device() {
    let router = harness().await;
    let unknown = uuid::Uuid::new_v4();

    let response = send(
        &router,
        post_empty(
            &format!("/devices/{unknown}/commands/remind"),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "queueing a command for a device that does not exist must be a 404, got {}",
        response.status()
    );
}

#[tokio::test]
async fn an_unknown_device_detail_page_is_a_404() {
    let router = harness().await;
    let response = send(
        &router,
        get(
            &format!("/devices/{}", uuid::Uuid::new_v4()),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn marking_an_instalment_paid_is_idempotent_and_reflected_in_the_ui() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Pay Box", "SER-PAY").await;
    send(
        &router,
        post_form(
            &format!("/devices/{device_id}/plans"),
            Some(&admin()),
            "amount=10.00&currency=NPR&periods=2&first_due=2026-10-01",
        ),
    )
    .await;

    let uri = format!("/devices/{device_id}/payments/1/paid");
    let first = send(&router, post_empty(&uri, Some(&admin()))).await;
    assert_eq!(first.status(), StatusCode::OK);
    let fragment = body_string(first).await;
    assert!(
        fragment.starts_with("<tr>") && fragment.contains("Paid"),
        "htmx swap fragment must be a table row: {fragment}"
    );

    let second = send(&router, post_empty(&uri, Some(&admin()))).await;
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "an instalment may only be settled once"
    );

    let dashboard = body_string(send(&router, get("/", Some(&admin()))).await).await;
    assert!(
        dashboard.contains("1/2"),
        "paid counter on dashboard: {dashboard}"
    );

    let page = detail(&router, &device_id).await;
    assert_eq!(
        page.matches("Mark paid").count(),
        1,
        "the settled instalment must no longer offer the button: {page}"
    );
}

#[tokio::test]
async fn marking_an_unknown_instalment_is_rejected() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Pay Box", "SER-PAY-UNKNOWN").await;

    let response = send(
        &router,
        post_empty(
            &format!("/devices/{device_id}/payments/99/paid"),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn one_devices_instalment_cannot_be_settled_through_another_device() {
    let router = harness().await;
    let (device_a, _) = enroll_device(&router, "A", "SER-PAY-A").await;
    let (device_b, _) = enroll_device(&router, "B", "SER-PAY-B").await;
    send(
        &router,
        post_form(
            &format!("/devices/{device_a}/plans"),
            Some(&admin()),
            "amount=10.00&currency=NPR&periods=1&first_due=2026-10-01",
        ),
    )
    .await;

    let response = send(
        &router,
        post_empty(
            &format!("/devices/{device_b}/payments/1/paid"),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let page = detail(&router, &device_a).await;
    assert!(
        page.contains("Mark paid"),
        "device A's instalment must still be outstanding: {page}"
    );
}

#[tokio::test]
async fn sub_unit_amounts_render_with_two_decimals() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Cents", "SER-CENTS").await;
    send(
        &router,
        post_form(
            &format!("/devices/{device_id}/plans"),
            Some(&admin()),
            "amount=10.05&currency=USD&periods=1&first_due=2026-10-01",
        ),
    )
    .await;

    let page = detail(&router, &device_id).await;
    assert!(
        page.contains("10.05 USD"),
        "minor units must be zero-padded: {page}"
    );
}
