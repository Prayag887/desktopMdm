//! Authentication and authorization boundaries for every route.

mod common;

use axum::http::StatusCode;
use common::{
    ADMIN_PASSWORD, ENROLLMENT_KEY, admin, basic, bearer, body_json, enroll_device, get, harness,
    health_payload, post_empty, post_form, post_json, post_raw_json, send,
};

#[tokio::test]
async fn healthz_is_public() {
    let router = harness().await;
    let response = send(&router, get("/healthz", None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(common::body_string(response).await, "ok");
}

#[tokio::test]
async fn admin_pages_require_credentials() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Laptop", "SER-AUTH-1").await;

    for uri in ["/".to_owned(), format!("/devices/{device_id}")] {
        let response = send(&router, get(&uri, None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "GET {uri}");
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some("Basic realm=\"EMI Control\""),
            "GET {uri} must advertise the Basic realm"
        );
    }

    let response = send(
        &router,
        post_form(
            &format!("/devices/{device_id}/plans"),
            None,
            "amount=10.00&currency=NPR&periods=3&first_due=2026-10-01",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send(
        &router,
        post_empty(&format!("/devices/{device_id}/payments/1/paid"), None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send(
        &router,
        post_empty(&format!("/devices/{device_id}/commands/remind"), None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_rejects_wrong_password_and_wrong_scheme() {
    let router = harness().await;

    for header in [
        basic("not-the-password"),
        basic(&format!("{ADMIN_PASSWORD}x")),
        format!("Basic {ADMIN_PASSWORD}"),
        bearer(ADMIN_PASSWORD),
        "Basic !!!not-base64!!!".to_owned(),
        String::new(),
    ] {
        let response = send(&router, get("/", Some(&header))).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "header {header:?} must not authenticate"
        );
    }

    let response = send(&router, get("/", Some(&admin()))).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn agent_routes_reject_missing_wrong_and_foreign_tokens() {
    let router = harness().await;
    let (device_a, token_a) = enroll_device(&router, "A", "SER-AUTH-A").await;
    let (device_b, token_b) = enroll_device(&router, "B", "SER-AUTH-B").await;

    let health = health_payload(&device_a);
    let cases: Vec<Option<String>> = vec![
        None,
        Some(bearer("00000000-0000-0000-0000-000000000000")),
        Some(bearer(&token_b)),
        Some(format!("Basic {token_a}")),
        Some(token_a.clone()),
    ];

    for authorization in cases {
        let response = send(
            &router,
            post_json(
                &format!("/api/v1/devices/{device_a}/health"),
                authorization.as_deref(),
                &health,
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "health accepted {authorization:?}"
        );

        let response = send(
            &router,
            get(
                &format!("/api/v1/devices/{device_a}/commands"),
                authorization.as_deref(),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "poll accepted {authorization:?}"
        );
    }

    // The correct token still works, and device B's token is valid only for B.
    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_a}/health"),
            Some(&bearer(&token_a)),
            &health,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = send(
        &router,
        get(
            &format!("/api/v1/devices/{device_b}/commands"),
            Some(&bearer(&token_b)),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_credentials_do_not_authorize_agent_routes() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Laptop", "SER-AUTH-2").await;

    let response = send(
        &router,
        get(
            &format!("/api/v1/devices/{device_id}/commands"),
            Some(&admin()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_token_does_not_authorize_admin_routes() {
    let router = harness().await;
    let (_, token) = enroll_device(&router, "Laptop", "SER-AUTH-3").await;

    let response = send(&router, get("/", Some(&bearer(&token)))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enrollment_requires_the_shared_key_and_non_empty_identity() {
    let router = harness().await;

    let rejected = [
        serde_json::json!({"enrollment_key": "wrong", "name": "A", "serial_number": "S1"}),
        serde_json::json!({"enrollment_key": "", "name": "A", "serial_number": "S1"}),
        serde_json::json!({"enrollment_key": ENROLLMENT_KEY, "name": "", "serial_number": "S1"}),
        serde_json::json!({"enrollment_key": ENROLLMENT_KEY, "name": "   ", "serial_number": "S1"}),
        serde_json::json!({"enrollment_key": ENROLLMENT_KEY, "name": "A", "serial_number": ""}),
        serde_json::json!({"enrollment_key": ENROLLMENT_KEY, "name": "A", "serial_number": "\t "}),
    ];
    for payload in rejected {
        let response = send(&router, post_json("/api/v1/enroll", None, &payload)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "enrollment accepted {payload}"
        );
    }

    let response = send(
        &router,
        post_json(
            "/api/v1/enroll",
            None,
            &serde_json::json!({
                "enrollment_key": ENROLLMENT_KEY,
                "name": "  Padded Name  ",
                "serial_number": "  SER-TRIM  ",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let value = body_json(response).await;
    assert!(
        uuid::Uuid::parse_str(value["device_id"].as_str().expect("device_id")).is_ok(),
        "device_id must be a UUID"
    );
    assert!(
        uuid::Uuid::parse_str(value["agent_token"].as_str().expect("agent_token")).is_ok(),
        "agent_token must be a UUID"
    );
}

#[tokio::test]
async fn malformed_enrollment_body_is_rejected_without_a_device() {
    let router = harness().await;
    let response = send(&router, post_raw_json("/api/v1/enroll", None, "{ not json")).await;
    assert!(
        response.status().is_client_error(),
        "malformed enrollment body must be a client error, got {}",
        response.status()
    );
}
