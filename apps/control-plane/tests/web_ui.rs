//! Rendering, escaping, and front-end asset integrity for the admin web UI.

mod common;

use axum::http::StatusCode;
use common::{
    admin, bearer, body_string, enroll_device, get, harness, health_payload, post_json, send,
};

/// Subresource Integrity digest for `htmx.org@2.0.7/dist/htmx.min.js`.
///
/// A wrong or truncated digest makes the browser refuse the script, which silently
/// disables every `hx-post` control on the dashboard and device pages.
const HTMX_SRI: &str = "sha384-ZBXiYtYQ6hJ2Y0ZNoYuI+Nq5MqWBr+chMrS/RkXpNzQCApHEhOt2aY8EJgqwHLkJ";

#[tokio::test]
async fn polling_does_not_suppress_actions_and_plan_inputs_have_labels() {
    let router = harness().await;
    let (id, _) = enroll_device(&router, "UI Box", "UI-REGRESSION").await;
    let page =
        body_string(send(&router, get(&format!("/devices/{id}"), Some(&admin()))).await).await;
    assert!(page.contains("hx-disinherit=\"hx-swap\""));
    for label in [
        "Installment amount",
        "Currency",
        "Number of periods",
        "First due date",
    ] {
        assert!(page.contains(label), "missing label: {label}");
    }
    assert!(page.contains(&format!("hx-post=\"/devices/{id}/plans\"")));
    assert!(page.contains("aria-live=\"polite\""));
}

#[tokio::test]
async fn pages_reference_htmx_with_a_well_formed_integrity_digest() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Box", "SER-SRI").await;

    for uri in ["/".to_owned(), format!("/devices/{device_id}")] {
        let page = body_string(send(&router, get(&uri, Some(&admin()))).await).await;
        let digest = page
            .split("integrity=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("{uri} must carry an SRI digest: {page}"));

        let encoded = digest
            .strip_prefix("sha384-")
            .unwrap_or_else(|| panic!("{uri} digest must be sha384, got {digest}"));
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .unwrap_or_else(|error| panic!("{uri} digest is not valid base64: {error}"));
        assert_eq!(
            decoded.len(),
            48,
            "{uri} sha384 digest must decode to 48 bytes, got {} from {digest}",
            decoded.len()
        );
        assert_eq!(
            digest, HTMX_SRI,
            "{uri} digest does not match htmx.org@2.0.7; the browser will block the script"
        );
    }
}

#[tokio::test]
async fn pages_are_well_formed_html_documents() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Box", "SER-HTML").await;

    for uri in ["/".to_owned(), format!("/devices/{device_id}")] {
        let response = send(&router, get(&uri, Some(&admin()))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8"),
            "{uri} content type"
        );
        let page = body_string(response).await;
        assert!(page.starts_with("<!doctype html>"), "{uri} doctype: {page}");
        assert!(page.contains("<meta charset=\"utf-8\">"), "{uri} charset");
        assert!(page.contains("name=\"viewport\""), "{uri} viewport");
        assert!(page.contains("</html>"), "{uri} closing tag");
        assert!(page.contains("<style>"), "{uri} inlined stylesheet");
    }
}

#[tokio::test]
async fn device_names_and_serials_are_html_escaped_on_the_dashboard() {
    let router = harness().await;
    let payload = "<script>alert('xss')</script>";
    enroll_device(&router, payload, &format!("SER\"{payload}")).await;

    let page = body_string(send(&router, get("/", Some(&admin()))).await).await;
    assert!(
        !page.contains("<script>alert"),
        "device name must be escaped on the dashboard: {page}"
    );
    assert!(
        page.contains("&lt;script&gt;"),
        "device name must appear escaped: {page}"
    );
    assert!(
        !page.contains("SER\"<"),
        "serial number must be escaped: {page}"
    );
}

#[tokio::test]
async fn device_names_are_html_escaped_on_the_detail_page() {
    let router = harness().await;
    let (device_id, _) =
        enroll_device(&router, "<img src=x onerror=alert(1)>", "SER-XSS-DETAIL").await;

    let page = body_string(
        send(
            &router,
            get(&format!("/devices/{device_id}"), Some(&admin())),
        )
        .await,
    )
    .await;
    assert!(
        !page.contains("<img src=x"),
        "device name must be escaped on the detail page: {page}"
    );
    assert!(page.contains("&lt;img src=x"), "escaped form must appear");
}

#[tokio::test]
async fn reported_health_is_html_escaped_before_rendering() {
    let router = harness().await;
    let (device_id, token) = enroll_device(&router, "Box", "SER-XSS-HEALTH").await;
    let mut health = health_payload(&device_id);
    health["hostname"] = serde_json::Value::String("</pre><script>alert(1)</script>".into());

    let response = send(
        &router,
        post_json(
            &format!("/api/v1/devices/{device_id}/health"),
            Some(&bearer(&token)),
            &health,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let page = body_string(
        send(
            &router,
            get(&format!("/devices/{device_id}"), Some(&admin())),
        )
        .await,
    )
    .await;
    assert!(
        !page.contains("</pre><script>"),
        "agent-supplied health must not break out of the <pre> block: {page}"
    );
    assert!(
        page.contains("&lt;/pre&gt;&lt;script&gt;"),
        "escaped form must appear"
    );
}

#[tokio::test]
async fn single_quotes_in_rendered_values_are_escaped() {
    let router = harness().await;
    enroll_device(&router, "O'Brien's Laptop", "SER-QUOTE").await;

    let page = body_string(send(&router, get("/", Some(&admin()))).await).await;
    assert!(
        !page.contains("O'Brien"),
        "apostrophes must be escaped so single-quoted attribute contexts stay safe: {page}"
    );
    assert!(
        page.contains("&#39;") || page.contains("&apos;"),
        "escaped form must appear"
    );
}

#[tokio::test]
async fn the_dashboard_lists_every_enrolled_device() {
    let router = harness().await;
    enroll_device(&router, "Alpha", "SER-LIST-1").await;
    enroll_device(&router, "Bravo", "SER-LIST-2").await;
    enroll_device(&router, "Charlie", "SER-LIST-3").await;

    let page = body_string(send(&router, get("/", Some(&admin()))).await).await;
    for name in ["Alpha", "Bravo", "Charlie"] {
        assert!(
            page.contains(name),
            "{name} missing from the dashboard: {page}"
        );
    }
    assert_eq!(
        page.matches("0/0").count(),
        3,
        "unplanned devices show 0/0: {page}"
    );
}

#[tokio::test]
async fn an_empty_dashboard_still_renders() {
    let router = harness().await;
    let response = send(&router, get("/", Some(&admin()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_string(response).await;
    assert!(page.contains("<tbody></tbody>"), "empty table body: {page}");
}

#[tokio::test]
async fn live_status_is_protected_and_returns_swappable_panels() {
    let router = harness().await;
    let (device_id, _) = enroll_device(&router, "Live Box", "SER-LIVE").await;
    let uri = format!("/devices/{device_id}/status");
    assert_eq!(
        send(&router, get(&uri, None)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = send(&router, get(&uri, Some(&admin()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(body.contains("id=\"health-panel\" hx-swap-oob=\"outerHTML\""));
    assert!(body.contains("id=\"command-panel\" hx-swap-oob=\"outerHTML\""));
    assert!(body.contains("Waiting for the first check-in"));
}
