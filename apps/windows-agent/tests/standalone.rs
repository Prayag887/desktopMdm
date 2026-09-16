use std::{fs, process::Command};

#[test]
fn desktop_service_runs_without_enrollment_and_keeps_a_local_identity() {
    let home = tempfile::tempdir().unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_emi-device-agent"))
            .env("PROGRAMDATA", home.path())
            .env("TMPDIR", home.path())
            .env("TMP", home.path())
            .env("TEMP", home.path())
            .args(["run", "--once"])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "standalone startup failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let directory = home.path().join("EmiDeviceAgent");
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("config.json")).unwrap()).unwrap();
    assert!(config.get("server").is_none() && config.get("agent_token").is_none());
    let health: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("health.json")).unwrap()).unwrap();
    assert_eq!(health["device_id"], config["device_id"]);
    assert!(
        health["hostname"]
            .as_str()
            .is_some_and(|name| !name.is_empty())
    );
    assert!(run().status.success());
    let next: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("config.json")).unwrap()).unwrap();
    assert_eq!(next, config, "local identity must survive restarts");
}

#[test]
fn desktop_cli_does_not_offer_server_enrollment() {
    let output = Command::new(env!("CARGO_BIN_EXE_emi-device-agent"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(!help.contains("enroll"));
    assert!(help.contains("init"));
}

#[test]
fn legacy_initialization_keeps_identity_and_historical_data_but_removes_credentials() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join("EmiDeviceAgent");
    fs::create_dir(&directory).unwrap();
    let id = "6fa459ea-ee8a-3ca4-894e-db77e160355e";
    fs::write(
        directory.join("config.json"),
        format!(
            r#"{{"device_id":"{id}","server":"https://old.invalid","agent_token":"obsolete"}}"#
        ),
    )
    .unwrap();
    fs::write(directory.join("historical-plan.json"), "preserved").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_emi-device-agent"))
        .env("PROGRAMDATA", home.path())
        .env("TMPDIR", home.path())
        .env("TMP", home.path())
        .env("TEMP", home.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(output.status.success());
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("config.json")).unwrap()).unwrap();
    assert_eq!(config, serde_json::json!({"device_id":id}));
    assert_eq!(
        fs::read_to_string(directory.join("historical-plan.json")).unwrap(),
        "preserved"
    );
}

#[test]
fn corrupt_configuration_is_reported_and_not_overwritten() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join("EmiDeviceAgent");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("config.json");
    fs::write(&path, "corrupt").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_emi-device-agent"))
        .env("PROGRAMDATA", home.path())
        .env("TMPDIR", home.path())
        .env("TMP", home.path())
        .env("TEMP", home.path())
        .args(["run", "--once"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), "corrupt");
    assert!(!directory.join("health.json").exists());
}
