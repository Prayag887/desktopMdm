//! Admin management actions and the Windows command contract.

mod common;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::StatusCode;
use common::{
    admin, bearer, body_json, body_string, enroll_device, get, harness, post_empty, post_form, send,
};

#[tokio::test]
async fn pin_is_hashed_and_the_queue_only_contains_a_verifier() {
    let router = harness().await;
    let (id, token) = enroll_device(&router, "PIN Box", "PIN-1").await;
    let response = send(
        &router,
        post_form(
            &format!("/devices/{id}/commands/pin"),
            Some(&admin()),
            "pin=294817&confirm_pin=294817",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let commands = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(commands[0]["command"]["type"], "set_managed_lock_pin");
    let verifier = commands[0]["command"]["parameters"]["pin_hash"]
        .as_str()
        .expect("PIN verifier");
    assert!(!verifier.contains("294817"));
    let hash = PasswordHash::new(verifier).expect("valid Argon2 hash");
    assert!(Argon2::default().verify_password(b"294817", &hash).is_ok());
    assert!(Argon2::default().verify_password(b"wrong", &hash).is_err());
}

#[tokio::test]
async fn invalid_or_mismatched_pins_are_rejected() {
    let router = harness().await;
    let (id, _) = enroll_device(&router, "PIN Box", "PIN-2").await;
    for form in [
        "pin=123&confirm_pin=123",
        "pin=abcd&confirm_pin=abcd",
        "pin=1234&confirm_pin=5678",
    ] {
        let response = send(
            &router,
            post_form(&format!("/devices/{id}/commands/pin"), Some(&admin()), form),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn maintenance_mode_is_queued_and_visible_in_the_console() {
    let router = harness().await;
    let (id, token) = enroll_device(&router, "Mode Box", "MODE-1").await;
    let response = send(
        &router,
        post_form(
            &format!("/devices/{id}/management"),
            Some(&admin()),
            "enabled=false",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page =
        body_string(send(&router, get(&format!("/devices/{id}"), Some(&admin()))).await).await;
    assert!(page.contains("Maintenance"));
    assert!(page.contains("Enable managed mode"));
    let commands = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(commands[0]["command"]["type"], "set_management_enabled");
    assert_eq!(commands[0]["command"]["parameters"]["enabled"], false);
}

#[tokio::test]
async fn clear_restrictions_is_an_authenticated_remote_action() {
    let router = harness().await;
    let (id, _) = enroll_device(&router, "Clear Box", "CLEAR-1").await;
    for auth in [None, Some(admin())] {
        let response = send(
            &router,
            post_empty(
                &format!("/devices/{id}/commands/clear-restrictions"),
                auth.as_deref(),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            if auth.is_some() {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }
}

#[tokio::test]
async fn cross_site_admin_mutations_are_refused_before_queueing() {
    let router = harness().await;
    let (id, token) = enroll_device(&router, "CSRF Box", "CSRF-1").await;
    let mut request = post_form(
        &format!("/devices/{id}/management"),
        Some(&admin()),
        "enabled=false",
    );
    request
        .headers_mut()
        .insert("host", "mdm.example".parse().expect("host"));
    request.headers_mut().insert(
        "origin",
        "https://attacker.example".parse().expect("origin"),
    );
    assert_eq!(send(&router, request).await.status(), StatusCode::FORBIDDEN);
    let commands = body_json(
        send(
            &router,
            get(
                &format!("/api/v1/devices/{id}/commands"),
                Some(&bearer(&token)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(commands, serde_json::json!([]));
}
