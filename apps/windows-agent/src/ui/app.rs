//! `DeviceApp` state, the eframe update loop, and the `run` entry point.

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use eframe::egui::{self, Color32, RichText};
use emi_core::DeviceHealth;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::system::{
    current_user_is_admin, launched_as_user_shell, probe_service_running, read_device_id,
    read_health, read_remote_state,
};
use crate::bluescreen::BluescreenSession;

pub(crate) enum OperationEvent {
    Progress { fraction: f32, message: String },
    Finished(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BiosPasswordAction {
    Create,
    Change,
    Disable,
}

impl BiosPasswordAction {
    pub(crate) const fn script_mode(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Change => "Change",
            Self::Disable => "Disable",
        }
    }
}

// A UI state bag; a state machine would be overkill for a demo panel.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct DeviceApp {
    pub(crate) health: Option<DeviceHealth>,
    pub(crate) protection: Option<crate::protection::model::DeviceProtectionStatus>,
    pub(crate) protection_error: Option<String>,
    pub(crate) service_running: bool,
    pub(crate) service_probe: Option<Receiver<bool>>,
    pub(crate) status: String,
    pub(crate) result_rx: Option<Receiver<OperationEvent>>,
    pub(crate) operation_progress: Option<f32>,
    pub(crate) operation_label: String,
    pub(crate) last_refresh: Instant,
    pub(crate) tab: usize,
    pub(crate) current_password: Zeroizing<String>,
    pub(crate) new_password: Zeroizing<String>,
    pub(crate) confirm_password: Zeroizing<String>,
    pub(crate) bios_password_action: BiosPasswordAction,
    pub(crate) confirm_disable_bios: bool,
    pub(crate) confirm_firmware_restart: bool,
    pub(crate) consent: bool,
    pub(crate) bluescreen: Option<BluescreenSession>,
    pub(crate) qr: Option<egui::TextureHandle>,
    pub(crate) recovery_input: Zeroizing<String>,
    pub(crate) recovery_focused: bool,
    pub(crate) enforced: bool,
    pub(crate) lock_started: Option<Instant>,
    pub(crate) manual_lock: bool,
    pub(crate) remote_locked: bool,
    pub(crate) remote_lock_reason: String,
    pub(crate) last_remote_refresh: Instant,
    pub(crate) remote_unlock_override_at: Option<DateTime<Utc>>,
    pub(crate) device_id: Option<Uuid>,
    pub(crate) recovery_directory: Option<std::path::PathBuf>,
    pub(crate) pending_recovery: Option<(Uuid, Instant)>,
    /// Manual override: block the keyboard even when no lock screen is showing.
    pub(crate) keyboard_disabled: bool,
    /// Consecutive failed unlock attempts, and a lockout deadline, to stop live
    /// repeated invalid recovery submissions.
    pub(crate) unlock_fail_count: u32,
    pub(crate) unlock_locked_until: Option<Instant>,
}

impl DeviceApp {
    pub(crate) fn load() -> Self {
        let is_admin = current_user_is_admin();
        // Enforced mode: launched as the enrolled user's shell AND
        // not an administrator. Admins and normal launches stay in the reversible
        // demo, keeping an Exit button.
        let enforced = !is_admin && launched_as_user_shell();
        let remote_state = read_remote_state();
        // An admin-panel LOCK applies to every account on this PC, Windows
        // administrators included; the admin UNLOCK or an offline recovery
        // token releases it.
        let remote_locked = remote_state
            .as_ref()
            .is_some_and(|state| state.lock_state.state.is_locked());
        let remote_lock_reason = remote_state
            .as_ref()
            .map_or_else(String::new, |state| state.lock_state.reason.clone());
        Self {
            health: read_health(),
            protection: super::protection::read_status(),
            protection_error: super::protection::read_error(),
            service_running: false,
            service_probe: Some(probe_service_running()),
            // Enrollment and check-in run in the SYSTEM service; launching the
            // UI must not raise a UAC prompt to repeat them.
            status: "Enrollment and check-in are handled by the EMI service.".into(),
            result_rx: None,
            operation_progress: None,
            operation_label: String::new(),
            last_refresh: Instant::now(),
            tab: 0,
            current_password: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            bios_password_action: BiosPasswordAction::Create,
            confirm_disable_bios: false,
            confirm_firmware_restart: false,
            consent: false,
            bluescreen: None,
            qr: None,
            recovery_input: Zeroizing::new(String::new()),
            recovery_focused: false,
            enforced,
            lock_started: None,
            manual_lock: false,
            remote_locked,
            remote_lock_reason,
            last_remote_refresh: Instant::now(),
            remote_unlock_override_at: None,
            device_id: read_device_id(),
            recovery_directory: std::env::var_os("PROGRAMDATA")
                .map(|base| std::path::PathBuf::from(base).join("EmiDeviceAgent")),
            pending_recovery: None,
            keyboard_disabled: false,
            unlock_fail_count: 0,
            unlock_locked_until: None,
        }
    }

    pub(crate) fn clear_passwords(&mut self) {
        use zeroize::Zeroize as _;
        self.current_password.zeroize();
        self.new_password.zeroize();
        self.confirm_password.zeroize();
        self.confirm_disable_bios = false;
    }

    fn render_operation_status(&self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        if let Some(progress) = self.operation_progress {
            ui.add(
                egui::ProgressBar::new(progress)
                    .show_percentage()
                    .text(&self.operation_label),
            );
            ui.add_space(8.0);
        }
        ui.label(&self.status);
    }

    fn poll_service_probe(&mut self) {
        let Some(probe) = &self.service_probe else {
            return;
        };
        match probe.try_recv() {
            Ok(running) => {
                self.service_running = running;
                self.service_probe = None;
            }
            Err(mpsc::TryRecvError::Disconnected) => self.service_probe = None,
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }

    fn sync_remote_lock_state(&mut self, context: &egui::Context) {
        if self.last_remote_refresh.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_remote_refresh = Instant::now();
        let Some(remote) = read_remote_state() else {
            return;
        };
        let locked = remote.lock_state.state.is_locked();
        self.remote_lock_reason = remote.lock_state.reason;
        if locked && self.remote_unlock_override_at == Some(remote.checked_at) {
            self.remote_locked = false;
            return;
        }
        self.remote_unlock_override_at = None;
        if self.remote_locked && !locked {
            self.remote_locked = false;
            self.end_blue_screen(context);
            self.status = "The administrator released this device.".into();
        } else if !self.remote_locked && locked {
            self.remote_locked = true;
            self.status = "The administrator restricted this device.".into();
        }
    }
}

impl eframe::App for DeviceApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_recovery_unlock(context);
        self.sync_remote_lock_state(context);
        self.poll_service_probe();
        let locked = self.blue_screen_active(context);
        // Drive the global keyboard hook: block the keyboard while a lock screen
        // is showing OR the manual "disable keyboard" toggle is on.
        crate::keyboard_guard::set_locked(locked || self.keyboard_disabled);
        if locked {
            self.tick_locked(context);
            return;
        }
        context.request_repaint_after(Duration::from_secs(2));
        if self.last_refresh.elapsed() >= Duration::from_secs(5) {
            self.health = read_health();
            self.protection = super::protection::read_status();
            self.protection_error = super::protection::read_error();
            self.last_refresh = Instant::now();
        }
        if let Some(receiver) = &self.result_rx {
            match receiver.try_recv() {
                Ok(OperationEvent::Progress { fraction, message }) => {
                    self.operation_progress = Some(fraction.clamp(0.0, 1.0));
                    self.operation_label = message;
                    context.request_repaint_after(Duration::from_millis(100));
                }
                Ok(OperationEvent::Finished(result)) => {
                    self.status = result;
                    self.result_rx = None;
                    self.operation_progress = None;
                    self.operation_label.clear();
                    self.reload();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Health refresh worker stopped unexpectedly".into();
                    self.result_rx = None;
                    self.operation_progress = None;
                    self.operation_label.clear();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    context.request_repaint_after(Duration::from_millis(200));
                }
            }
        }
        egui::CentralPanel::default().show(context, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(10.0);
                ui.heading(RichText::new("EMI Device").size(28.0));
                ui.label("Standalone desktop companion");
                ui.add_space(12.0);
                let previous = self.tab;
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, 0, "Overview");
                    ui.selectable_value(&mut self.tab, 1, "BIOS passwords");
                    ui.selectable_value(&mut self.tab, 2, "Payment-restriction mode");
                });
                if previous == 1 && self.tab != 1 {
                    self.clear_passwords();
                }
                ui.separator();
                if self.tab == 1 {
                    self.render_firmware(ui);
                } else if self.tab == 2 {
                    self.render_bluescreen(ui, context);
                } else {
                    ui.add_space(16.0);
                    let (label, color) = if self.service_running {
                        ("Local health service running", Color32::from_rgb(30, 150, 85))
                    } else {
                        (
                            "Local service not installed or stopped",
                            Color32::from_rgb(155, 105, 35),
                        )
                    };
                    ui.colored_label(color, label);
                    ui.add_space(12.0);
                    self.render_health(ui);
                    self.render_protection(ui);
                    ui.add_space(16.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                self.result_rx.is_none(),
                                egui::Button::new("Refresh device health (admin)"),
                            )
                            .clicked()
                        {
                            self.refresh_health();
                        }
                        if ui.button("Reload status").clicked() {
                            self.reload();
                            self.status = "Local status reloaded".into();
                        }
                    });
                }
                if self.tab != 1 {
                    self.render_operation_status(ui);
                }
                ui.separator();
                ui.small("Managed Windows EMI agent. Lock state is synchronized by the service; an authorized administrator can uninstall normally.");
            });
        });
    }
}

/// Run the desktop UI event loop.
///
/// # Errors
/// Returns any error from `eframe::run_native` (window/graphics init failure).
pub fn run() -> eframe::Result<()> {
    // Install the global keyboard hook on this (UI) thread before the event loop
    // starts; it stays dormant until a lock screen sets it active.
    crate::keyboard_guard::install();
    // DeviceApp::load performs a pair of short Windows account/registry probes.
    // Complete those before eframe creates the native window: during profile
    // initialization after a reboot, a helper process can be delayed, and a
    // visible window that has not started its event loop is reported by Windows
    // as "Not responding".
    let app = DeviceApp::load();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([840.0, 720.0])
            .with_min_inner_size([560.0, 450.0]),
        ..Default::default()
    };
    eframe::run_native(
        "EMI Device",
        options,
        Box::new(move |context| {
            context.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluescreen::BluescreenSession;

    #[test]
    fn app_loads_and_renders_while_waiting_for_management() {
        let app = DeviceApp::load();
        let status = app.status.to_ascii_lowercase();
        assert!(
            status.contains("administrator") || status.contains("enrollment"),
            "the UI should explain its management state"
        );
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| app.render_health(ui));
        });
        assert_ne!(output.shapes.len(), 0);
    }

    #[test]
    fn firmware_and_simulation_render_and_restart_is_unchecked() {
        let mut app = DeviceApp::load();
        assert!(app.bluescreen.is_none());
        assert!(!app.consent);
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                app.render_firmware(ui);
                app.render_bluescreen(ui, context);
            });
        });
        assert_ne!(output.shapes.len(), 0);
        let output = context.run(egui::RawInput::default(), |context| {
            app.render_blue_screen(context);
        });
        assert_ne!(output.shapes.len(), 0);
        app.current_password.push_str("test-only");
        app.clear_passwords();
        assert_eq!(app.current_password.as_str(), "");
        assert!(!app.confirm_disable_bios);
        for action in [
            BiosPasswordAction::Create,
            BiosPasswordAction::Change,
            BiosPasswordAction::Disable,
        ] {
            app.bios_password_action = action;
            let output = context.run(egui::RawInput::default(), |context| {
                egui::CentralPanel::default().show(context, |ui| app.render_firmware(ui));
            });
            assert_ne!(output.shapes.len(), 0);
        }
    }

    #[test]
    fn escape_does_not_dismiss_but_explicit_exit_resets_mode() {
        let mut app = DeviceApp::load();
        app.bluescreen = Some(BluescreenSession::start(std::net::Ipv4Addr::LOCALHOST).unwrap());
        app.consent = true;
        let context = egui::Context::default();
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::default(),
            }],
            ..Default::default()
        };
        let _ = context.run(input, |context| {
            assert!(context.input(|input| input.key_pressed(egui::Key::Escape)));
            assert!(app.blue_screen_active(context));
        });
        assert!(app.bluescreen.is_some());
        app.end_blue_screen(&context);
        assert!(app.bluescreen.is_none());
        assert!(!app.consent);
    }

    fn key_event() -> egui::Event {
        egui::Event::Key {
            key: egui::Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::default(),
        }
    }

    #[test]
    fn keyboard_is_suppressed_unless_the_recovery_field_is_focused() {
        let app = DeviceApp::load();
        assert!(!app.recovery_focused);
        let context = egui::Context::default();
        let input = egui::RawInput {
            events: vec![key_event(), egui::Event::Text("a".into())],
            ..Default::default()
        };
        let _ = context.run(input, |context| {
            app.suppress_keyboard(context);
            context.input(|i| {
                assert!(
                    !i.events
                        .iter()
                        .any(|e| matches!(e, egui::Event::Key { .. } | egui::Event::Text(_))),
                    "key and text events must be drained while suppressed"
                );
            });
        });
    }

    #[test]
    fn recovery_field_focus_keeps_the_keyboard_alive() {
        let mut app = DeviceApp::load();
        app.recovery_focused = true;
        let context = egui::Context::default();
        let input = egui::RawInput {
            events: vec![egui::Event::Text("x".into())],
            ..Default::default()
        };
        let _ = context.run(input, |context| {
            app.suppress_keyboard(context);
            context.input(|i| {
                assert!(
                    i.events.iter().any(|e| matches!(e, egui::Event::Text(_))),
                    "recovery entry must survive suppression"
                );
            });
        });
    }

    #[test]
    fn submitting_a_token_does_not_unlock_without_service_receipt() {
        let mut app = DeviceApp::load();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("recovery-request.json"), "").unwrap();
        app.recovery_directory = Some(dir.path().to_path_buf());
        app.enforced = true;
        app.recovery_input.push_str("EMIU1-test");
        let context = egui::Context::default();
        assert!(!app.try_recovery_unlock(&context));
        app.poll_recovery_unlock(&context);
        assert!(app.enforced);
        assert!(app.pending_recovery.is_some());
    }

    #[test]
    fn valid_service_receipt_releases_and_clears_token() {
        use emi_core::recovery::{SigningKey, UnlockToken};
        let mut app = DeviceApp::load();
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[37; 32]);
        let public =
            key.verifying_key()
                .to_bytes()
                .iter()
                .fold(String::new(), |mut output, byte| {
                    use std::fmt::Write as _;
                    write!(output, "{byte:02x}").unwrap();
                    output
                });
        crate::recovery_service::provision(dir.path(), &public).unwrap();
        std::fs::write(dir.path().join("recovery-request.json"), "").unwrap();
        app.recovery_directory = Some(dir.path().to_path_buf());
        let device = Uuid::new_v4();
        app.device_id = Some(device);
        app.enforced = true;
        let token = UnlockToken {
            device_id: device,
            counter: 1,
            expires_unix: (Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        }
        .sign_to_string(&key);
        app.recovery_input.push_str(&token);
        let context = egui::Context::default();
        assert!(!app.try_recovery_unlock(&context));
        crate::recovery_service::process(dir.path(), device, Utc::now()).unwrap();
        app.poll_recovery_unlock(&context);
        assert!(!app.enforced);
        assert_eq!(app.recovery_input.as_str(), "");
        assert!(app.pending_recovery.is_none());
    }
}
