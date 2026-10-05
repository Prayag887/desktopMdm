//! Independent reliability monitor. Only SCM restart; repairs require an administrator.
#[cfg(windows)]
use super::{integrity, retry::RecoveryBudget, windows};
#[cfg(windows)]
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[cfg(windows)]
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(not(windows))]
/// Enter the independent watchdog SCM dispatcher.
///
/// # Errors
/// Returns an error outside Windows or when SCM dispatch fails.
pub fn service_entry() -> anyhow::Result<()> {
    anyhow::bail!("Watchdog service is Windows only")
}
#[cfg(windows)]
/// Enter the independent watchdog SCM dispatcher.
///
/// # Errors
/// Returns an error outside Windows or when SCM dispatch fails.
pub fn service_entry() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start("EmiDeviceWatchdog", ffi_service_main)?;
    Ok(())
}
#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_: Vec<std::ffi::OsString>) {
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let Ok(handle) =
        service_control_handler::register("EmiDeviceWatchdog", |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
    else {
        return;
    };
    let status = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if handle
        .set_service_status(status(ServiceState::Running, 0))
        .is_err()
    {
        return;
    }
    tracing::info!(event = "service_started", service = "EmiDeviceWatchdog");
    let code = match monitor() {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(%error, "watchdog stopped");
            1
        }
    };
    tracing::info!(
        event = "service_stopped",
        service = "EmiDeviceWatchdog",
        exit_code = code
    );
    let _ = handle.set_service_status(status(ServiceState::Stopped, code));
}

#[cfg(windows)]
fn monitor() -> anyhow::Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let installation = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no installation directory"))?
        .to_path_buf();
    let state = std::path::PathBuf::from(
        std::env::var_os("PROGRAMDATA").ok_or_else(|| anyhow::anyhow!("ProgramData missing"))?,
    )
    .join("EmiDeviceAgent");
    let mut budget = RecoveryBudget::default();
    let mut repair_budget = RecoveryBudget::default();
    let mut next_integrity = Instant::now();
    let mut verified = false;
    let mut next_health = Instant::now();
    while !STOP.load(Ordering::Relaxed) {
        if Instant::now() < next_health {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        next_health = Instant::now() + Duration::from_secs(30);
        // Persistent admin-owned lease survives watchdog/SCM restart during servicing.
        if maintenance_active(&state) {
            continue;
        }
        if Instant::now() >= next_integrity {
            verified = verify_and_repair(&installation);
            next_integrity = Instant::now() + Duration::from_secs(300);
        }
        if !verified {
            if let Err(error) = super::repair::observe_unhealthy(&state) {
                tracing::warn!(%error, "repair ledger unavailable; automatic repair fails closed");
            }
        }
        if !verified && repair_budget.attempt(Instant::now()).is_some() {
            if let Err(error) = super::repair::dispatch(&installation, &state) {
                tracing::warn!(%error, "trusted cached repair unavailable; administrator repair required");
            }
        }
        let outcome = (|| -> anyhow::Result<String> {
            let config: serde_json::Value =
                serde_json::from_slice(&std::fs::read(state.join("config.json"))?)?;
            let _identity: uuid::Uuid = serde_json::from_value(config["device_id"].clone())?;
            let service = manager.open_service(
                "EmiDeviceAgent",
                ServiceAccess::QUERY_STATUS | ServiceAccess::START,
            )?;
            match service.query_status()?.current_state {
                ServiceState::Running => {
                    let heartbeat = std::fs::metadata(state.join("health.json"))?.modified()?;
                    if heartbeat.elapsed()?.as_secs() > 900 {
                        anyhow::bail!(
                            "Core service heartbeat stale; administrator investigation required"
                        );
                    }
                    budget.observe_healthy(Instant::now());
                    if verified {
                        repair_budget.observe_healthy(Instant::now());
                        super::repair::observe_healthy(&state)?;
                    }
                    Ok("Core service running".into())
                }
                ServiceState::Stopped if verified => {
                    if budget.attempt(Instant::now()).is_some() {
                        // Rehash immediately before SCM loads the executable, not only on a timer.
                        if !integrity::verify_installation(&installation)?.verified {
                            anyhow::bail!("restart refused: installation integrity failed");
                        }
                        verify_registration(&installation)?;
                        service.start::<&str>(&[])?;
                        tracing::warn!(
                            "watchdog recovery action: core service restarted through SCM"
                        );
                    }
                    Ok(if budget.exhausted() {
                        "Recovery budget exhausted; administrator required"
                    } else {
                        "Core stopped; bounded recovery active"
                    }
                    .into())
                }
                other => Ok(format!("Core state {other:?}; restart not attempted")),
            }
        })();
        let healthy = outcome.is_ok();
        let detail = outcome.unwrap_or_else(|error| {
            tracing::warn!(%error, "watchdog verification failure");
            error.to_string()
        });
        let _ = crate::state_store::write_json(
            &state.join("watchdog-status.json"),
            &serde_json::json!({"detail":detail,"healthy":healthy,"integrityVerified":verified,"recoveryExhausted":budget.exhausted(),"observedAt":chrono::Utc::now()}),
            false,
        );
    }
    Ok(())
}

#[cfg(windows)]
fn verify_registration(installation: &std::path::Path) -> anyhow::Result<()> {
    let expected = format!(
        "\"{}\" service",
        installation.join("emi-device-agent.exe").display()
    );
    let command = format!(
        "$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_Service -Filter \"Name='EmiDeviceAgent'\"; if($s.StartName -ne 'LocalSystem' -or $s.StartMode -ne 'Auto' -or $s.PathName -ne {}){{throw 'Unsafe service registration'}}",
        windows::quote(std::path::Path::new(&expected))
    );
    windows::powershell(&command, &[])?;
    Ok(())
}

#[cfg(windows)]
fn maintenance_active(state: &std::path::Path) -> bool {
    std::fs::read(state.join("maintenance.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value["expiresAt"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        })
        .is_some_and(|expires| expires > chrono::Utc::now())
}

#[cfg(windows)]
fn verify_and_repair(installation: &std::path::Path) -> bool {
    let result = (|| -> anyhow::Result<()> {
        super::acl::repair_protection_acl(installation, None)?;
        super::acl::state_acl(true)?;
        let report = integrity::verify_installation(installation)?;
        if !report.verified {
            anyhow::bail!("integrity failures: {}", report.failures.join("; "));
        }
        verify_registration(installation)?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(%error, "watchdog integrity/ACL/registration verification failed; authorized signed repair required");
            false
        }
    }
}
