//! End-to-end tests that drive the real agent binary against a real control plane.

use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use emi_control_plane::{AppState, app};

const ADMIN_PASSWORD: &str = "e2e-admin-password";
const ENROLLMENT_KEY: &str = "e2e-enrollment-key";

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct ControlPlane {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl ControlPlane {
    async fn start() -> Self {
        let state = AppState::connect(
            "sqlite::memory:",
            ADMIN_PASSWORD.to_owned(),
            ENROLLMENT_KEY.to_owned(),
        )
        .await
        .expect("control plane state");
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind ephemeral port");
        let address = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app(state)).await;
        });
        Self {
            base_url: format!("http://{address}"),
            handle,
        }
    }

    fn stop(&self) {
        self.handle.abort();
    }
}

/// An isolated `%PROGRAMDATA%`/`TMPDIR` for one agent process.
struct AgentHome {
    root: PathBuf,
}

impl AgentHome {
    fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("emi-e2e-{label}-{}-{unique}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create agent home");
        Self { root }
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("EmiDeviceAgent").join("config.json")
    }

    fn agent(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_emi-device-agent"));
        // The agent stores its state under PROGRAMDATA on Windows and TMPDIR elsewhere.
        command
            .env("PROGRAMDATA", &self.root)
            .env("TMPDIR", &self.root)
            .env("TMP", &self.root)
            .env("TEMP", &self.root);
        command
    }

    fn config(&self) -> serde_json::Value {
        let bytes = fs::read(self.config_path()).expect("agent config was not written");
        serde_json::from_slice(&bytes).expect("agent config is valid JSON")
    }
}

impl Drop for AgentHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn describe(output: &Output) -> String {
    format!(
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn admin_client() -> reqwest::Client {
    reqwest::Client::new()
}

fn admin_header() -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("admin:{ADMIN_PASSWORD}"))
    )
}

fn enrolled(server: &ControlPlane, home: &AgentHome, serial: &str) -> (String, String) {
    let output = home
        .agent()
        .args([
            "enroll",
            "--server",
            &server.base_url,
            "--enrollment-key",
            ENROLLMENT_KEY,
            "--name",
            "E2E Device",
            "--serial",
            serial,
        ])
        .output()
        .expect("run agent enroll");
    assert!(
        output.status.success(),
        "enrollment failed: {}",
        describe(&output)
    );

    let config = home.config();
    (
        config["device_id"].as_str().expect("device_id").to_owned(),
        config["agent_token"]
            .as_str()
            .expect("agent_token")
            .to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_persists_a_usable_configuration() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("enroll");

    let (device_id, token) = enrolled(&server, &home, "SER-E2E-ENROLL");
    assert!(uuid::Uuid::parse_str(&device_id).is_ok());
    assert!(!token.is_empty());
    assert_eq!(
        home.config()["server"].as_str(),
        Some(server.base_url.as_str())
    );

    let output = home.agent().arg("status").output().expect("run status");
    assert!(output.status.success(), "{}", describe(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&device_id), "status output: {stdout}");

    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trailing_slash_in_the_server_url_is_normalized() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("slash");

    let output = home
        .agent()
        .args([
            "enroll",
            "--server",
            &format!("{}/", server.base_url),
            "--enrollment-key",
            ENROLLMENT_KEY,
            "--serial",
            "SER-E2E-SLASH",
        ])
        .output()
        .expect("run agent enroll");
    assert!(output.status.success(), "{}", describe(&output));
    assert_eq!(
        home.config()["server"].as_str(),
        Some(server.base_url.as_str()),
        "the trailing slash must be trimmed so request URLs stay well formed"
    );

    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_is_refused_with_the_wrong_key_and_writes_no_configuration() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("badkey");

    let output = home
        .agent()
        .args([
            "enroll",
            "--server",
            &server.base_url,
            "--enrollment-key",
            "wrong-key",
            "--serial",
            "SER-E2E-BADKEY",
        ])
        .output()
        .expect("run agent enroll");
    assert!(
        !output.status.success(),
        "a rejected enrollment must exit non-zero: {}",
        describe(&output)
    );
    assert!(
        !home.config_path().exists(),
        "no configuration may be persisted after a rejected enrollment"
    );

    server.stop();
}

/// Re-running `install.ps1` on an already-enrolled machine re-runs `agent enroll`
/// with the same BIOS serial. The control plane answers 409 and the agent exits
/// non-zero, which aborts the installer (`$ErrorActionPreference = 'Stop'`).
#[tokio::test(flavor = "multi_thread")]
async fn reinstalling_an_already_enrolled_device_does_not_break_the_installer() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("reinstall");
    let (device_id, _) = enrolled(&server, &home, "SER-E2E-REPAIR");

    let output = home
        .agent()
        .args([
            "enroll",
            "--server",
            &server.base_url,
            "--enrollment-key",
            ENROLLMENT_KEY,
            "--serial",
            "SER-E2E-REPAIR",
        ])
        .output()
        .expect("run agent enroll");
    assert!(
        output.status.success(),
        "repairing an installation must not fail: {}",
        describe(&output)
    );
    assert_eq!(
        home.config()["device_id"].as_str(),
        Some(device_id.as_str()),
        "a repair must keep the existing device identity"
    );

    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_check_in_reports_health_and_drains_the_command_queue() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("checkin");
    let (device_id, token) = enrolled(&server, &home, "SER-E2E-CHECKIN");
    let client = admin_client();

    let queued = client
        .post(format!(
            "{}/devices/{device_id}/commands/remind",
            server.base_url
        ))
        .header("authorization", admin_header())
        .send()
        .await
        .expect("queue reminder");
    assert!(queued.status().is_success());

    let output = home
        .agent()
        .args(["run", "--once"])
        .output()
        .expect("run agent check-in");
    assert!(
        output.status.success(),
        "check-in failed: {}",
        describe(&output)
    );

    let detail = client
        .get(format!("{}/devices/{device_id}", server.base_url))
        .header("authorization", admin_header())
        .send()
        .await
        .expect("fetch device detail")
        .text()
        .await
        .expect("detail body");
    assert!(
        detail.contains("agent_version"),
        "the check-in must have stored a health document: {detail}"
    );

    let remaining = client
        .get(format!(
            "{}/api/v1/devices/{device_id}/commands",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("poll queue")
        .json::<serde_json::Value>()
        .await
        .expect("queue body");
    assert_eq!(
        remaining,
        serde_json::json!([]),
        "the reminder must be acknowledged by a single check-in"
    );

    server.stop();
}

/// The desktop UI shells out to `emi-device-agent run --once` and reports
/// "Check-in completed successfully" purely from the child's exit status.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_check_in_exits_non_zero_so_the_desktop_ui_can_see_it() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("offline");
    let _ = enrolled(&server, &home, "SER-E2E-OFFLINE");
    server.stop();
    // Give the aborted listener a moment to release the port.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let output = home
        .agent()
        .args(["run", "--once"])
        .output()
        .expect("run agent check-in");
    assert!(
        !output.status.success(),
        "an unreachable control plane must be reported as a failure, not success: {}",
        describe(&output)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_token_makes_the_check_in_fail() {
    let server = ControlPlane::start().await;
    let home = AgentHome::new("revoked");
    let _ = enrolled(&server, &home, "SER-E2E-REVOKED");

    let mut config: serde_json::Value = home.config();
    config["agent_token"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    fs::write(
        home.config_path(),
        serde_json::to_vec_pretty(&config).expect("serialize"),
    )
    .expect("rewrite config");

    let output = home
        .agent()
        .args(["run", "--once"])
        .output()
        .expect("run agent check-in");
    assert!(
        !output.status.success(),
        "a rejected token must be reported as a failure: {}",
        describe(&output)
    );

    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_run_before_the_agent_is_enrolled_fail_clearly() {
    let home = AgentHome::new("unenrolled");

    for arguments in [vec!["status"], vec!["run", "--once"]] {
        let output = home.agent().args(&arguments).output().expect("run agent");
        assert!(
            !output.status.success(),
            "`{arguments:?}` must fail before enrollment: {}",
            describe(&output)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("config.json") || stderr.contains("read"),
            "the error must name the missing configuration: {stderr}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupt_configuration_is_reported_rather_than_ignored() {
    let home = AgentHome::new("corrupt");
    fs::create_dir_all(home.config_path().parent().expect("parent")).expect("create dir");
    fs::write(home.config_path(), b"{ this is not json").expect("write corrupt config");

    let output = home.agent().arg("status").output().expect("run status");
    assert!(!output.status.success(), "{}", describe(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("parse agent config"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn service_mode_is_refused_off_windows() {
    if cfg!(windows) {
        return;
    }
    let home = AgentHome::new("service");
    let output = home.agent().arg("service").output().expect("run service");
    assert!(!output.status.success(), "{}", describe(&output));
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_is_refused_off_windows() {
    if cfg!(windows) {
        return;
    }
    let home = AgentHome::new("bootstrap");
    let output = home
        .agent()
        .arg("bootstrap")
        .output()
        .expect("run bootstrap");
    assert!(!output.status.success(), "{}", describe(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("only supported on Windows"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
