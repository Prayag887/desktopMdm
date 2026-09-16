#![allow(dead_code, clippy::missing_panics_doc)]

//! Shared harness for the control-plane HTTP integration tests.

use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use emi_control_plane::{AppState, app};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

pub const ADMIN_PASSWORD: &str = "admin-test-password";
pub const ENROLLMENT_KEY: &str = "enrollment-test-key";

/// Builds a router backed by a private in-memory SQLite database.
pub async fn harness() -> Router {
    let state = AppState::connect(
        "sqlite::memory:",
        ADMIN_PASSWORD.to_owned(),
        ENROLLMENT_KEY.to_owned(),
    )
    .await
    .expect("in-memory control plane state");
    app(state)
}

pub fn basic(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("admin:{password}")))
}

pub fn admin() -> String {
    basic(ADMIN_PASSWORD)
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub async fn send(router: &Router, request: Request<Body>) -> Response<Body> {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router is infallible")
}

pub async fn body_string(response: Response<Body>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub async fn body_json(response: Response<Body>) -> serde_json::Value {
    let text = body_string(response).await;
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("body is not JSON ({error}): {text}"))
}

pub fn get(uri: &str, authorization: Option<&str>) -> Request<Body> {
    build(Method::GET, uri, authorization, Body::empty(), None)
}

pub fn post_json(
    uri: &str,
    authorization: Option<&str>,
    value: &serde_json::Value,
) -> Request<Body> {
    build(
        Method::POST,
        uri,
        authorization,
        Body::from(value.to_string()),
        Some("application/json"),
    )
}

pub fn post_raw_json(uri: &str, authorization: Option<&str>, raw: &str) -> Request<Body> {
    build(
        Method::POST,
        uri,
        authorization,
        Body::from(raw.to_owned()),
        Some("application/json"),
    )
}

pub fn post_form(uri: &str, authorization: Option<&str>, form: &str) -> Request<Body> {
    build(
        Method::POST,
        uri,
        authorization,
        Body::from(form.to_owned()),
        Some("application/x-www-form-urlencoded"),
    )
}

pub fn post_empty(uri: &str, authorization: Option<&str>) -> Request<Body> {
    build(Method::POST, uri, authorization, Body::empty(), None)
}

fn build(
    method: Method,
    uri: &str,
    authorization: Option<&str>,
    body: Body,
    content_type: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    if let Some(value) = content_type {
        builder = builder.header("content-type", value);
    }
    builder.body(body).expect("valid request")
}

/// Enrolls a device and returns `(device_id, agent_token)`.
pub async fn enroll_device(router: &Router, name: &str, serial: &str) -> (String, String) {
    let response = send(
        router,
        post_json(
            "/api/v1/enroll",
            None,
            &serde_json::json!({
                "enrollment_key": ENROLLMENT_KEY,
                "name": name,
                "serial_number": serial,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "enrollment failed");
    let value = body_json(response).await;
    (
        value["device_id"].as_str().expect("device_id").to_owned(),
        value["agent_token"]
            .as_str()
            .expect("agent_token")
            .to_owned(),
    )
}

/// A syntactically valid `DeviceHealth` payload for `device_id`.
pub fn health_payload(device_id: &str) -> serde_json::Value {
    serde_json::json!({
        "device_id": device_id,
        "hostname": "test-host",
        "os_version": "Windows 11 Pro",
        "agent_version": "0.2.0",
        "disk_free_bytes": 123_456_789_u64,
        "battery_percent": 84,
        "secure_boot": true,
        "winget_available": true,
        "bios_provider": "dell",
        "observed_at": "2026-09-16T10:00:00Z",
    })
}
