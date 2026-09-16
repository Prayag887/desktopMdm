//! Device-facing API: enrollment, health reporting, and the command queue.

mod common;

use axum::http::StatusCode;
use common::{
    ENROLLMENT_KEY, admin, bearer, body_json, body_string, enroll_device, get, harness,
    health_payload, post_empty, post_json, post_raw_json, send,
};

#[tokio::test]
async fn duplicate_serial_numbers_are_rejected() {
    let router = harness().await;
    let (_, _) = enroll_device(&router, "First", "SER-DUP").await;

    let response = send(
        &router,
        post_json(
            "/api/v1/enroll",
            None,
            &serde_json::json!({
                "enrollment_key": ENROLLMENT_KEY,
                "name": "Second",
                "serial_number": "SER-DUP",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn health_report_updates_last_seen_and_is_visible_to_the_admin() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "Health Box", "SER-HEALTH").await;

    let dashboard = body_string(send(&router, get("/", Some(&admin()))).await).await;
    assert!(
        dashboard.contains("never"),
        "a device that never checked in should render as `never`: {dashboard}"
    );

    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_id}/health"),
            Some(&bearer(&token)),
            &health_payload(&device_id),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let dashboard = body_string(send(&router, get("/", Some(&admin()))).await).await;
    assert!(
        !dashboard.contains("never"),
        "last_seen_at must be recorded after a health report: {dashboard}"
    );

    let detail = body_string(
        send(
            &router,
            get(&format!("/devices/{device_id}"), Some(&admin())),
        )
        .await,
    )
    .await;
    assert!(
        detail.contains("Windows 11 Pro") && detail.contains("test-host"),
        "the stored health document must be rendered: {detail}"
    );
}

#[tokio::test]
async fn health_report_rejects_a_device_id_mismatch() {
    let router = harness().await;
    let (device_a, token_a) = enroll_device(&router, "A", "SER-MM-A").await;
    let (device_b, _) = enroll_device(&router, "B", "SER-MM-B").await;

    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_a}/health"),
            Some(&bearer(&token_a)),
            &health_payload(&device_b),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_report_rejects_a_malformed_body() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "A", "SER-BAD-BODY").await;

    let response = send(
        &router,
        post_raw_json(
            &format!("/api/v1/devices/{device_id}/health"),
            Some(&bearer(&token)),
            r#"{"device_id":"not-a-uuid"}"#,
        ),
    )
    .await;
    assert!(
        response.status().is_client_error(),
        "malformed health body must be a client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn unauthenticated_callers_cannot_probe_body_validation() {
    // The body extractor must not run before the bearer check: an anonymous caller
    // sending a malformed body should be told 401, never 4xx-from-deserialization.
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "A", "SER-PROBE").await;

    let response = send(
        &router,
        post_raw_json(
            &format!("/api/v1/devices/{device_id}/health"),
            None,
            "{ not json at all",
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "anonymous callers must be rejected before the body is parsed"
    );
}

#[tokio::test]
async fn command_queue_round_trip() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "Cmd Box", "SER-CMD").await;

    let response = send(
        &router,
        get(
            &format!("/api/v1/devices/{device_id}/commands"),
            Some(&bearer(&token)),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, serde_json::json!([]));

    let response = send(
        &router,
        post_empty(
            &format!("/devices/{device_id}/commands/remind"),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let queued = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    let list = queued.as_array().expect("array of commands");
    assert_eq!(list.len(), 1, "one reminder should be queued: {queued}");

    // Contract the Windows agent depends on: {"id": "...", "command": {"type": ..., "parameters": {...}}}
    let entry = &list[0];
    let command_id = entry["id"].as_str().expect("command id").to_owned();
    assert_eq!(entry["command"]["type"], "show_payment_reminder");
    assert!(entry["command"]["parameters"]["title"].is_string());
    assert!(entry["command"]["parameters"]["message"].is_string());

    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_id}/commands/{command_id}/complete"),
            Some(&bearer(&token)),
            &serde_json::json!({"result": "notification displayed"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let queued = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        queued,
        serde_json::json!([]),
        "a completed command must not be redelivered"
    );
}

#[tokio::test]
async fn commands_are_scoped_to_their_device() {
    let router = harness().await;
    let (device_a, token_a) = enroll_device(&router, "A", "SER-SCOPE-A").await;
    let (device_b, token_b) = enroll_device(&router, "B", "SER-SCOPE-B").await;

    send(
        &router,
        post_empty(
            &format!("/devices/{device_a}/commands/remind"),
            Some(&admin()),
        ),
    )
    .await;

    let for_b = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_b}/commands"),
                Some(&bearer(&token_b)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        for_b,
        serde_json::json!([]),
        "device B must not see A's queue"
    );

    let for_a = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_a}/commands"),
                Some(&bearer(&token_a)),
            ),
        )
        .await,
    )
    .await;
    let command_id = for_a[0]["id"].as_str().expect("command id").to_owned();

    // B must not be able to complete A's command.
    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_b}/commands/{command_id}/complete"),
            Some(&bearer(&token_b)),
            &serde_json::json!({"result": "stolen"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let for_a = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_a}/commands"),
                Some(&bearer(&token_a)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        for_a.as_array().map(Vec::len),
        Some(1),
        "device B must not be able to complete device A's command"
    );
}

#[tokio::test]
async fn completing_an_unknown_command_is_reported_as_not_found() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "A", "SER-UNKNOWN-CMD").await;

    let response = send(
        &router,
        post_json(
            &format!(
                "/api/v1/devices/{device_id}/commands/{}/complete",
                uuid::Uuid::new_v4()
            ),
            Some(&bearer(&token)),
            &serde_json::json!({"result": "done"}),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "completing a command that does not exist must not report success"
    );
}

#[tokio::test]
async fn completing_a_command_twice_is_rejected() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "A", "SER-DOUBLE-CMD").await;
    send(
        &router,
        post_empty(
            &format!("/devices/{device_id}/commands/remind"),
            Some(&admin()),
        ),
    )
    .await;
    let queued = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{device_id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    let command_id = queued[0]["id"].as_str().expect("command id").to_owned();
    let uri = format!("/api/v1/devices/{device_id}/commands/{command_id}/complete");
    let done = serde_json::json!({"result": "ok"});

    let first = send(&router, post_json(&uri, Some(&bearer(&token)), &done)).await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    let second = send(&router, post_json(&uri, Some(&bearer(&token)), &done)).await;
    assert_eq!(
        second.status(),
        StatusCode::NOT_FOUND,
        "a command may only be completed once"
    );
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "A", "SER-BIG").await;
    let mut health = health_payload(&device_id);
    health["hostname"] = serde_json::Value::String("x".repeat(100 * 1024));

    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_id}/health"),
            Some(&bearer(&token)),
            &health,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
