//! Windows service control-manager integration.

#[cfg(windows)]
use super::runner::{RESUME_REQUESTED, STOP_REQUESTED, run};
#[cfg(not(windows))]
use anyhow::bail;
#[cfg(windows)]
use std::{sync::atomic::Ordering, time::Duration};
#[cfg(windows)]
use tracing::error;

#[cfg(windows)]
pub(crate) fn service_entry() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start("EmiDeviceAgent", ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn service_entry() -> anyhow::Result<()> {
    bail!("Windows service mode is only available on Windows")
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    use windows_service::{
        service::{
            PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
            ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::PowerEvent(
            PowerEventParam::ResumeAutomatic
            | PowerEventParam::ResumeSuspend
            | PowerEventParam::ResumeCritical,
        ) => {
            RESUME_REQUESTED.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate | ServiceControl::PowerEvent(_) => {
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register("EmiDeviceAgent", handler) else {
        return;
    };
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::POWER_EVENT,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if handle.set_service_status(running).is_err() {
        return;
    }
    tracing::info!(event = "service_started", service = "EmiDeviceAgent");
    let exit_code = match run(false, true) {
        Ok(()) => 0,
        Err(error) => {
            error!(%error, "service stopped with an error");
            1
        }
    };
    tracing::info!(
        event = "service_stopped",
        service = "EmiDeviceAgent",
        exit_code
    );
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });
}
