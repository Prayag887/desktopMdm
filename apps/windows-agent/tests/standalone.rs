use std::{fs, process::Command};

#[test]
fn desktop_service_keeps_a_local_identity_before_enrollment() {
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
    assert!(config.get("agent_token").is_none());
    assert_eq!(config["api_base"], "https://emi-api.yajtech.com");
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
fn desktop_cli_offers_device_enrollment() {
    let output = Command::new(env!("CARGO_BIN_EXE_emi-device-agent"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("enroll"));
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
    assert_eq!(config["device_id"], id);
    assert_eq!(config["api_base"], "https://emi-api.yajtech.com");
    assert!(config.get("agent_token").is_none());
    assert_eq!(
        fs::read_to_string(directory.join("historical-plan.json")).unwrap(),
        "preserved"
    );
}

#[test]
fn corrupt_configuration_is_preserved_and_reinitialized() {
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
    assert!(
        output.status.success(),
        "recovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(directory.join("config.invalid.json")).unwrap(),
        "corrupt"
    );
    let config: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(config["device_id"].as_str().is_some());
    assert_eq!(config["api_base"], "https://emi-api.yajtech.com");
    assert!(directory.join("health.json").exists());
}
