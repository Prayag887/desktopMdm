use emi_control_plane::{AppState, app};
use futures_util::StreamExt;
use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

#[tokio::test]
async fn authenticated_socket_signals_connection_and_committed_commands() {
    let directory = tempfile::tempdir().unwrap();
    let database = format!("sqlite://{}", directory.path().join("queue.db").display());
    let state = AppState::connect(&database, "admin-secret".into(), "enroll".into())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let device: serde_json::Value = client.post(format!("{base}/api/v1/enroll"))
        .json(&serde_json::json!({"enrollment_key":"enroll","name":"Socket QA","serial_number":"WS-QA"}))
        .send().await.unwrap().json().await.unwrap();
    let id = device["device_id"].as_str().unwrap();
    let url = format!("ws://{addr}/api/v1/devices/{id}/socket");
    assert!(
        connect_async(&url).await.is_err(),
        "unauthenticated socket must be refused"
    );
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", device["agent_token"].as_str().unwrap())
            .parse()
            .unwrap(),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().to_text().unwrap(),
        "sync"
    );
    client
        .post(format!("{base}/devices/{id}/commands/remind"))
        .basic_auth("admin", Some("admin-secret"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let signal = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(signal.to_text().unwrap(), "sync");
    let commands: serde_json::Value = client
        .get(format!("{base}/api/v1/devices/{id}/commands"))
        .bearer_auth(device["agent_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        commands.as_array().unwrap().len(),
        1,
        "socket delivery must not remove durable work"
    );
    server.abort();
    let _ = server.await;
    drop(socket);
    // Simulate a server restart while the endpoint is offline. Its command is
    // recovered from SQLite, not from the old process's notification channel.
    let state = AppState::connect(&database, "admin-secret".into(), "enroll".into())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });
    let mut request = format!("ws://{addr}/api/v1/devices/{id}/socket")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", device["agent_token"].as_str().unwrap())
            .parse()
            .unwrap(),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().to_text().unwrap(),
        "sync"
    );
    let pending: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/devices/{id}/commands"))
        .bearer_auth(device["agent_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending, commands);
    server.abort();
}
