//! Typed client for the backend's `Device Agent` API surface.

use std::time::Duration;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use reqwest::{StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const DEFAULT_API_BASE: &str = "https://emi-api.yajtech.com";

#[derive(Debug, Clone, Serialize)]
struct EnrollRequest<'a> {
    device_serial_no: &'a str,
    agent_version: &'a str,
    platform: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub token: String,
    pub device_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize)]
struct CheckInRequest<'a> {
    agent_version: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LockState {
    pub state: LockStateKind,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PersistedRemoteState {
    pub device_uuid: Uuid,
    pub lock_state: LockState,
    pub checked_at: DateTime<Utc>,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LockStateKind {
    Unlocked,
    Warning,
    Locked,
    PermanentlyReleased,
}

impl LockStateKind {
    #[must_use]
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::Locked)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingCommand {
    pub uuid: Uuid,
    pub action: CommandAction,
    pub reason: String,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandAction {
    Lock,
    Unlock,
    Warn,
    Release,
    Uninstall,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckInResponse {
    pub server_time: DateTime<Utc>,
    pub lock_state: LockState,
    pub pending_command: Option<PendingCommand>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchFile {
    pub uuid: Uuid,
    pub lock_command_uuid: Uuid,
    pub version: u32,
    pub action: CommandAction,
    pub checksum: String,
    pub size_bytes: u64,
    pub signed_payload: String,
    pub signing_key_id: u64,
    pub expires_at: DateTime<Utc>,
    pub download_url: String,
}

#[derive(Debug, Serialize)]
struct AckRequest<'a> {
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<&'a str>,
}

pub struct AgentApi {
    base_url: String,
    client: Client,
}

impl AgentApi {
    /// Builds a bounded blocking client for the single-threaded Windows service loop.
    ///
    /// # Errors
    /// Returns an error for an invalid/insecure server URL or TLS client failure.
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base_url = base_url.trim_end_matches('/');
        let parsed = reqwest::Url::parse(base_url).context("invalid EMI API URL")?;
        let local_http = parsed.scheme() == "http"
            && parsed
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"));
        if parsed.scheme() != "https" && !local_http {
            bail!("the EMI API must use HTTPS");
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("emi-device-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build EMI API client")?;
        Ok(Self {
            base_url: base_url.to_string(),
            client,
        })
    }

    /// Enrolls a device previously placed in PENDING state by an administrator.
    ///
    /// # Errors
    /// Returns transport errors or the server's validation response.
    pub fn enroll(&self, serial: &str, agent_version: &str) -> anyhow::Result<EnrollResponse> {
        let response = self
            .client
            .post(self.url("/api/agent/enroll/"))
            .json(&EnrollRequest {
                device_serial_no: serial,
                agent_version,
                platform: "WINDOWS",
            })
            .send()
            .context("contact EMI enrollment API")?;
        Self::decode(response, "enroll device")
    }

    /// Sends the authenticated startup/heartbeat status request.
    ///
    /// # Errors
    /// Returns transport, authentication, or response-format errors.
    pub fn check_in(&self, token: &str, agent_version: &str) -> anyhow::Result<CheckInResponse> {
        let response = self
            .client
            .post(self.url("/api/agent/check-in/"))
            .bearer_auth(token)
            .json(&CheckInRequest { agent_version })
            .send()
            .context("contact EMI check-in API")?;
        Self::decode(response, "check in device")
    }

    /// Fetches the currently pending command patch, returning `None` for HTTP 204.
    ///
    /// # Errors
    /// Returns transport, authentication, expiry, or response-format errors.
    pub fn current_patch(&self, token: &str) -> anyhow::Result<Option<PatchFile>> {
        let response = self
            .client
            .get(self.url("/api/agent/patch-files/current/"))
            .bearer_auth(token)
            .send()
            .context("fetch pending EMI command")?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        Self::decode(response, "fetch pending EMI command").map(Some)
    }

    /// Verifies the downloaded patch size and SHA-256 checksum supplied by the API.
    ///
    /// # Errors
    /// Returns an error if download, size, or checksum validation fails.
    pub fn verify_patch_download(&self, token: &str, patch: &PatchFile) -> anyhow::Result<()> {
        let url = reqwest::Url::parse(&patch.download_url)
            .or_else(|_| reqwest::Url::parse(&self.base_url)?.join(&patch.download_url))
            .context("invalid patch download URL")?;
        if url.scheme() != "https"
            && !url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"))
        {
            bail!("patch downloads must use HTTPS");
        }
        let api_url = reqwest::Url::parse(&self.base_url).context("invalid configured API URL")?;
        let mut request = self.client.get(url.clone());
        if url.scheme() == api_url.scheme()
            && url.host_str() == api_url.host_str()
            && url.port_or_known_default() == api_url.port_or_known_default()
        {
            request = request.bearer_auth(token);
        }
        let bytes = request
            .send()
            .context("download EMI command patch")?
            .error_for_status()
            .context("download EMI command patch")?
            .bytes()
            .context("read EMI command patch")?;
        if bytes.len() as u64 != patch.size_bytes {
            bail!("patch size does not match the API metadata");
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let expected = patch
            .checksum
            .trim()
            .strip_prefix("sha256:")
            .unwrap_or(patch.checksum.trim());
        if !digest.eq_ignore_ascii_case(expected) {
            bail!("patch SHA-256 checksum does not match");
        }
        Ok(())
    }

    /// Acknowledges whether the pending patch was applied.
    ///
    /// # Errors
    /// Returns transport, authentication, or response errors.
    pub fn acknowledge(
        &self,
        token: &str,
        patch_uuid: Uuid,
        applied: bool,
        failure_reason: Option<&str>,
    ) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.url(&format!("/api/agent/patch-files/{patch_uuid}/ack/")))
            .bearer_auth(token)
            .json(&AckRequest {
                applied,
                failure_reason,
            })
            .send()
            .context("acknowledge EMI command")?;
        response
            .error_for_status()
            .context("EMI API rejected command acknowledgement")?;
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
        operation: &str,
    ) -> anyhow::Result<T> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            bail!("could not {operation}: HTTP {status}: {}", body.trim());
        }
        response
            .json()
            .with_context(|| format!("decode response while trying to {operation}"))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
    };

    use super::*;

    #[derive(Debug)]
    struct RecordedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl RecordedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    struct MockResponse {
        status: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl MockResponse {
        fn json(status: &'static str, body: &serde_json::Value) -> Self {
            Self {
                status,
                content_type: "application/json",
                body: serde_json::to_vec(&body).unwrap(),
            }
        }

        fn bytes(body: &[u8]) -> Self {
            Self {
                status: "200 OK",
                content_type: "application/octet-stream",
                body: body.to_vec(),
            }
        }
    }

    fn spawn_server(
        responses: Vec<MockResponse>,
    ) -> (String, Arc<Mutex<Vec<RecordedRequest>>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                captured.lock().unwrap().push(read_request(&mut stream));
                write!(
                    stream,
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.content_type,
                    response.body.len()
                )
                .unwrap();
                stream.write_all(&response.body).unwrap();
            }
        });
        (base_url, requests, handle)
    }

    fn read_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 1024];
        let header_end = loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "client closed before sending complete headers");
            raw.extend_from_slice(&buffer[..count]);
            if let Some(position) = raw.windows(4).position(|part| part == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header_text = String::from_utf8(raw[..header_end].to_vec()).unwrap();
        let mut lines = header_text.split("\r\n");
        let request_line: Vec<_> = lines.next().unwrap().split_whitespace().collect();
        let headers: Vec<_> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.to_string(), value.trim().to_string()))
            .collect();
        let content_length = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        while raw.len() < header_end + content_length {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "client closed before sending complete body");
            raw.extend_from_slice(&buffer[..count]);
        }
        RecordedRequest {
            method: request_line[0].to_string(),
            path: request_line[1].to_string(),
            headers,
            body: raw[header_end..header_end + content_length].to_vec(),
        }
    }

    fn patch(download_url: String, bytes: &[u8]) -> PatchFile {
        PatchFile {
            uuid: Uuid::nil(),
            lock_command_uuid: Uuid::nil(),
            version: 1,
            action: CommandAction::Lock,
            checksum: format!("sha256:{:x}", Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
            signed_payload: "signed".to_string(),
            signing_key_id: 1,
            expires_at: "2026-09-26T00:00:00Z".parse().unwrap(),
            download_url,
        }
    }

    #[test]
    fn rejects_plain_http_except_for_local_test_servers() {
        assert!(AgentApi::new("http://emi-api.example").is_err());
        assert!(AgentApi::new("http://127.0.0.1:8080").is_ok());
        assert!(AgentApi::new(DEFAULT_API_BASE).is_ok());
    }

    #[test]
    fn lock_state_only_restricts_for_locked() {
        assert!(LockStateKind::Locked.is_locked());
        assert!(!LockStateKind::Unlocked.is_locked());
        assert!(!LockStateKind::Warning.is_locked());
        assert!(!LockStateKind::PermanentlyReleased.is_locked());
    }

    #[test]
    fn parses_the_documented_check_in_contract() {
        let response: CheckInResponse = serde_json::from_value(serde_json::json!({
            "server_time": "2026-09-25T05:00:00Z",
            "lock_state": {
                "state": "LOCKED",
                "reason": "EMI_OVERDUE",
                "changed_at": "2026-09-25T04:59:00Z"
            },
            "pending_command": {
                "uuid": "6fa459ea-ee8a-3ca4-894e-db77e160355e",
                "action": "LOCK",
                "reason": "EMI_OVERDUE",
                "nonce": "unique-command",
                "expires_at": "2026-09-25T06:00:00Z"
            }
        }))
        .unwrap();
        assert!(response.lock_state.state.is_locked());
        assert_eq!(
            response.pending_command.unwrap().action,
            CommandAction::Lock
        );
    }

    #[test]
    fn enrollment_sends_documented_payload_and_parses_credentials() {
        let device_uuid = Uuid::new_v4();
        let (base_url, requests, server) = spawn_server(vec![MockResponse::json(
            "201 Created",
            &serde_json::json!({"token": "agent-token", "device_uuid": device_uuid}),
        )]);

        let enrolled = AgentApi::new(&base_url)
            .unwrap()
            .enroll("SERIAL-123", "1.2.3")
            .unwrap();
        server.join().unwrap();

        assert_eq!(enrolled.token, "agent-token");
        assert_eq!(enrolled.device_uuid, device_uuid);
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/api/agent/enroll/");
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["device_serial_no"], "SERIAL-123");
        assert_eq!(body["agent_version"], "1.2.3");
        assert_eq!(body["platform"], "WINDOWS");
    }

    #[test]
    fn check_in_uses_bearer_auth_and_parses_state() {
        let (base_url, requests, server) = spawn_server(vec![MockResponse::json(
            "200 OK",
            &serde_json::json!({
                "server_time": "2026-09-25T05:00:00Z",
                "lock_state": {
                    "state": "UNLOCKED",
                    "reason": "PAID",
                    "changed_at": "2026-09-25T04:59:00Z"
                },
                "pending_command": null
            }),
        )]);

        let response = AgentApi::new(&base_url)
            .unwrap()
            .check_in("9|secret", "1.2.3")
            .unwrap();
        server.join().unwrap();

        assert_eq!(response.lock_state.state, LockStateKind::Unlocked);
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].path, "/api/agent/check-in/");
        assert_eq!(requests[0].header("authorization"), Some("Bearer 9|secret"));
    }

    #[test]
    fn current_patch_handles_no_content() {
        let (base_url, requests, server) = spawn_server(vec![MockResponse {
            status: "204 No Content",
            content_type: "application/json",
            body: Vec::new(),
        }]);

        let result = AgentApi::new(&base_url)
            .unwrap()
            .current_patch("token")
            .unwrap();
        server.join().unwrap();

        assert!(result.is_none());
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].header("authorization"), Some("Bearer token"));
    }

    #[test]
    fn patch_download_validates_size_and_sha256() {
        let bytes = b"signed patch bytes";
        let (base_url, requests, server) = spawn_server(vec![MockResponse::bytes(bytes)]);
        let metadata = patch(format!("{base_url}/patch.bin"), bytes);

        AgentApi::new(&base_url)
            .unwrap()
            .verify_patch_download("token", &metadata)
            .unwrap();
        server.join().unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].path, "/patch.bin");
        assert_eq!(requests[0].header("authorization"), Some("Bearer token"));
    }

    #[test]
    fn patch_download_rejects_wrong_checksum() {
        let bytes = b"tampered patch";
        let (base_url, _requests, server) = spawn_server(vec![MockResponse::bytes(bytes)]);
        let mut metadata = patch(format!("{base_url}/patch.bin"), bytes);
        metadata.checksum = "00".repeat(32);

        let error = AgentApi::new(&base_url)
            .unwrap()
            .verify_patch_download("token", &metadata)
            .unwrap_err();
        server.join().unwrap();

        assert!(error.to_string().contains("SHA-256 checksum"));
    }

    #[test]
    fn patch_download_does_not_leak_token_cross_origin() {
        let bytes = b"signed patch bytes";
        let (download_url, requests, server) = spawn_server(vec![MockResponse::bytes(bytes)]);
        let metadata = patch(format!("{download_url}/patch.bin"), bytes);
        let api = AgentApi::new("http://localhost:9").unwrap();

        api.verify_patch_download("private-token", &metadata)
            .unwrap();
        server.join().unwrap();

        assert_eq!(requests.lock().unwrap()[0].header("authorization"), None);
    }

    #[test]
    fn acknowledgement_serializes_success_and_failure() {
        let command_uuid = Uuid::new_v4();
        let responses = vec![
            MockResponse::json("200 OK", &serde_json::json!({})),
            MockResponse::json("200 OK", &serde_json::json!({})),
        ];
        let (base_url, requests, server) = spawn_server(responses);
        let api = AgentApi::new(&base_url).unwrap();

        api.acknowledge("token", command_uuid, true, None).unwrap();
        api.acknowledge("token", command_uuid, false, Some("invalid patch"))
            .unwrap();
        server.join().unwrap();

        let requests = requests.lock().unwrap();
        let success: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let failure: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(success, serde_json::json!({"applied": true}));
        assert_eq!(failure["applied"], false);
        assert_eq!(failure["failure_reason"], "invalid patch");
        assert_eq!(requests[0].header("authorization"), Some("Bearer token"));
    }

    #[test]
    fn api_errors_include_status_and_server_detail() {
        let (base_url, _requests, server) = spawn_server(vec![MockResponse::json(
            "401 Unauthorized",
            &serde_json::json!({"detail": "bad token"}),
        )]);

        let error = AgentApi::new(&base_url)
            .unwrap()
            .check_in("bad", "1.2.3")
            .unwrap_err();
        server.join().unwrap();
        let message = error.to_string();
        assert!(message.contains("401 Unauthorized"));
        assert!(message.contains("bad token"));
    }
}
