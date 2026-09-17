//! `DeviceApp` state, the eframe update loop, and the `run` entry point.

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use emi_core::DeviceHealth;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::system::{
    current_user_is_admin, launched_as_user_shell, read_device_id, read_health, read_last_counter,
    service_is_running,
};
use crate::bluescreen::BluescreenSession;

/// Trusted owner public key (Ed25519, hex). The matching SIGNING key stays
/// offline with the owner and mints unlock tokens; only its holder can release a
/// device. Replace this LAB key with your own from
/// `cargo run --example keygen -p emi-core` before production. If it is not a
/// valid key, token recovery is disabled and only admin/WinRE recovery works.
pub(crate) const OWNER_PUBLIC_KEY_HEX: &str =
    "ac1473ba71d2cd322163ccc8a8f64e1226cfcb815bfc270cbe7417f16d8ae7ba";

// A UI state bag; a state machine would be overkill for a demo panel.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct DeviceApp {
    pub(crate) health: Option<DeviceHealth>,
    pub(crate) service_running: bool,
    pub(crate) status: String,
    pub(crate) result_rx: Option<Receiver<String>>,
    pub(crate) last_refresh: Instant,
    pub(crate) tab: usize,
    pub(crate) current_password: Zeroizing<String>,
    pub(crate) new_password: Zeroizing<String>,
    pub(crate) confirm_password: Zeroizing<String>,
    pub(crate) lan_ip: String,
    pub(crate) consent: bool,
    pub(crate) bluescreen: Option<BluescreenSession>,
    pub(crate) qr: Option<egui::TextureHandle>,
    pub(crate) recovery_input: Zeroizing<String>,
    pub(crate) recovery_focused: bool,
    pub(crate) enforced: bool,
    pub(crate) fullscreen_applied: bool,
    pub(crate) manual_lock: bool,
    pub(crate) device_id: Option<Uuid>,
    pub(crate) last_counter: u64,
    pub(crate) lock_user: String,
    pub(crate) opt_shell: bool,
    pub(crate) opt_keyboard_filter: bool,
    pub(crate) opt_applocker: bool,
}

impl DeviceApp {
    pub(crate) fn load() -> Self {
        let is_admin = current_user_is_admin();
        // Enforced (unbreakable) mode: launched as the enrolled user's shell AND
        // not an administrator. Admins and normal launches stay in the reversible
        // demo, keeping an Exit button.
        let enforced = !is_admin && launched_as_user_shell();
        Self {
            health: read_health(),
            service_running: service_is_running(),
            status: "Standalone mode — no server or enrollment required".into(),
            result_rx: None,
            last_refresh: Instant::now(),
            tab: 0,
            current_password: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            lan_ip: local_ip_address::local_ip()
                .map_or_else(|_| "127.0.0.1".into(), |ip| ip.to_string()),
            consent: false,
            bluescreen: None,
            qr: None,
            recovery_input: Zeroizing::new(String::new()),
            recovery_focused: false,
            enforced,
            fullscreen_applied: false,
            manual_lock: false,
            device_id: read_device_id(),
            last_counter: read_last_counter(),
            lock_user: String::new(),
            opt_shell: true,
            opt_keyboard_filter: true,
            opt_applocker: true,
        }
    }

    pub(crate) fn clear_passwords(&mut self) {
        use zeroize::Zeroize as _;
        self.current_password.zeroize();
        self.new_password.zeroize();
        self.confirm_password.zeroize();
    }
}

impl eframe::App for DeviceApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        let locked = self.blue_screen_active(context);
        // Drive the global keyboard hook: swallow escape shortcuts only while a
        // lock screen is showing.
        crate::keyboard_guard::set_locked(locked);
        if locked {
            context.request_repaint_after(Duration::from_millis(100));
            // Force and hold fullscreen for ANY active lock (demo, manual, or
            // enforced), so the window cannot be un-maximised out of the way.
            if !self.fullscreen_applied {
                context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                self.fullscreen_applied = true;
            }
            self.suppress_keyboard(context);
            // Veto Alt+F4 / title-bar close / window-close in every lock mode.
            // Window-scoped only: it CANNOT stop OS-global Alt+Tab / Win /
            // Ctrl+Shift+Esc — the keyboard_guard hook and WEKF handle those.
            if context.input(|input| input.viewport().close_requested()) {
                context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.status = "Close is disabled while the device is restricted.".into();
            }
            self.render_blue_screen(context);
            return;
        }
        context.request_repaint_after(Duration::from_secs(2));
        if self.last_refresh.elapsed() >= Duration::from_secs(5) {
            self.health = read_health();
            self.last_refresh = Instant::now();
        }
        if let Some(receiver) = &self.result_rx {
            match receiver.try_recv() {
                Ok(result) => {
                    self.status = result;
                    self.result_rx = None;
                    self.reload();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Health refresh worker stopped unexpectedly".into();
                    self.result_rx = None;
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
                ui.add_space(12.0);
                ui.label(&self.status);
                ui.separator();
                ui.small("Local-first Rust desktop app. QR dismissal uses a temporary one-time LAN link only during the simulation. An administrator can uninstall normally.");
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
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([840.0, 720.0])
            .with_min_inner_size([560.0, 450.0]),
        ..Default::default()
    };
    eframe::run_native(
        "EMI Device",
        options,
        Box::new(|context| {
            context.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(DeviceApp::load()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluescreen::BluescreenSession;

    #[test]
    fn standalone_app_loads_and_renders_without_enrollment() {
        let app = DeviceApp::load();
        assert!(app.status.contains("Standalone"));
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| app.render_health(ui));
        });
        assert!(!output.shapes.is_empty());
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
        assert!(!output.shapes.is_empty());
        let output = context.run(egui::RawInput::default(), |context| {
            app.render_blue_screen(context);
        });
        assert!(!output.shapes.is_empty());
        app.current_password.push_str("test-only");
        app.clear_passwords();
        assert!(app.current_password.is_empty());
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

    // Mints a token with the LAB signing key that matches OWNER_PUBLIC_KEY_HEX.
    // Owner tools do this off-device; the test mirrors them.
    fn lab_token(device: Uuid, counter: u64) -> String {
        use chrono::Utc;
        use ed25519_dalek::SigningKey;
        use emi_core::recovery::UnlockToken;
        let hex = "5883eb5073327073c82d56cd745a95c9e1e9ef50f7f3dcb28a3da473ee387418";
        let mut bytes = [0u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        let token = UnlockToken {
            device_id: device,
            counter,
            expires_unix: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };
        token.sign_to_string(&SigningKey::from_bytes(&bytes))
    }

    #[test]
    fn a_valid_owner_token_ends_restriction_and_zeroizes_input() {
        let mut app = DeviceApp::load();
        app.bluescreen = Some(BluescreenSession::start(std::net::Ipv4Addr::LOCALHOST).unwrap());
        let device = Uuid::new_v4();
        app.device_id = Some(device);
        app.last_counter = 0;
        app.recovery_input.push_str(&lab_token(device, 1));
        let context = egui::Context::default();
        assert!(app.try_recovery_unlock(&context));
        assert!(
            app.bluescreen.is_none(),
            "valid token must release the device"
        );
        assert_eq!(
            app.last_counter, 1,
            "counter advances for rollback protection"
        );
        assert!(
            app.recovery_input.is_empty(),
            "token must be cleared on exit"
        );
    }

    #[test]
    fn a_token_for_another_device_is_refused() {
        let mut app = DeviceApp::load();
        app.enforced = true;
        app.device_id = Some(Uuid::new_v4());
        app.recovery_input.push_str(&lab_token(Uuid::new_v4(), 1));
        let context = egui::Context::default();
        assert!(
            !app.try_recovery_unlock(&context),
            "wrong-device token refused"
        );
        assert!(app.enforced, "device stays locked on refusal");
    }

    #[test]
    fn enforced_mode_stays_active_without_a_session_and_releases_by_token() {
        let mut app = DeviceApp::load();
        app.enforced = true;
        let device = Uuid::new_v4();
        app.device_id = Some(device);
        app.last_counter = 0;
        let context = egui::Context::default();
        // Locked with no QR / network session at all.
        assert!(app.bluescreen.is_none());
        assert!(app.blue_screen_active(&context));
        // Renders (no Exit button) without panicking despite no session/QR.
        let output = context.run(egui::RawInput::default(), |context| {
            app.render_blue_screen(context);
        });
        assert!(!output.shapes.is_empty());
        // A signed owner token is the in-session release path.
        app.recovery_input.push_str(&lab_token(device, 1));
        assert!(app.try_recovery_unlock(&context));
        assert!(!app.enforced);
        assert!(!app.blue_screen_active(&context));
    }
}
