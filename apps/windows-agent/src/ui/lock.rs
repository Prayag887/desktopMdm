//! The fullscreen lock screen, keyboard suppression, and owner-token recovery.

use std::time::{Duration, Instant};

use crate::recovery_service::{RecoveryRequest, RecoveryState};
use chrono::Utc;
use eframe::egui::{self, Color32, RichText};
use std::io::Write as _;
use zeroize::Zeroize as _;

use super::app::DeviceApp;
use super::system::{read_remote_state, set_task_manager_disabled};
use crate::bluescreen::BluescreenSession;

impl DeviceApp {
    /// Per-frame handling while a lock screen is showing: fullscreen + always-on-
    /// top on entry, Task Manager disabled, a 5-minute hard auto-close safety
    /// valve, focus snap-back if a switch slipped past the keyboard hook, keyboard
    /// suppression, close veto, and the lock screen itself.
    pub(crate) fn tick_locked(&mut self, context: &egui::Context) {
        context.request_repaint_after(Duration::from_millis(100));
        // One-shot on entering a lock: force fullscreen and always-on-top, and
        // disable Task Manager for this user (registry policy; re-enabled on
        // unlock). No auto-close — the in-session recovery uses a service-verified token.
        self.lock_started.get_or_insert_with(|| {
            context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
            context.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                egui::WindowLevel::AlwaysOnTop,
            ));
            set_task_manager_disabled(true);
            Instant::now()
        });
        // If focus was stolen (e.g. an Alt+Tab that slipped past the hook), snap
        // the lock window straight back to the foreground, on top and fullscreen.
        // Runs every ~100 ms, so a switch can never persist.
        if !context.input(|input| input.viewport().focused.unwrap_or(true)) {
            context.send_viewport_cmd(egui::ViewportCommand::Focus);
            context.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                egui::WindowLevel::AlwaysOnTop,
            ));
            context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
        }
        self.suppress_keyboard(context);
        // Veto Alt+F4 / title-bar close / window-close in every lock mode.
        // Window-scoped only: OS-global Alt+Tab / Win / Ctrl+Shift+Esc are handled
        // by the keyboard_guard hook and, robustly, by WEKF.
        if context.input(|input| input.viewport().close_requested()) {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.status = "Close is disabled while the device is restricted.".into();
        }
        self.render_blue_screen(context);
    }
    pub(crate) fn end_blue_screen(&mut self, context: &egui::Context) {
        self.bluescreen = None;
        self.qr = None;
        self.consent = false;
        self.recovery_input.zeroize();
        self.recovery_focused = false;
        // Releasing also clears enforced mode for this session. On the next login
        // the app is still the shell and re-locks until the signed
        // "payment restored" policy is applied and the shell is restored by
        // Remove-PaymentRestriction.ps1.
        self.enforced = false;
        self.manual_lock = false;
        self.lock_started = None;
        // Re-enable Task Manager that the lock disabled for this user.
        set_task_manager_disabled(false);
        self.status = "Payment-restriction mode ended. The checkbox is reset.".into();
        context.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
            egui::WindowLevel::Normal,
        ));
        context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
    }

    /// Window-scoped keyboard suppression for the restriction screen.
    ///
    /// Drains the app's own key and text events so escape shortcuts do nothing
    /// inside the window — EXCEPT while the recovery field has focus, so the
    /// customer can always type a recovery token and accessibility keeps working.
    /// OS-global Alt+Tab / Win / Ctrl+Shift+Esc are handled by the keyboard hook
    /// (`keyboard_guard`) and, robustly, by the Windows Keyboard Filter (WEKF).
    pub(crate) fn suppress_keyboard(&self, context: &egui::Context) {
        if self.recovery_focused {
            return;
        }
        context.input_mut(|input| {
            input
                .events
                .retain(|event| !matches!(event, egui::Event::Key { .. } | egui::Event::Text(_)));
        });
    }

    pub(crate) fn blue_screen_active(&mut self, context: &egui::Context) -> bool {
        // A dismissed QR session is the owner's controlled release. Timeouts do
        // NOT unlock — the 5-minute safety valve closes the whole app instead, so
        // the only in-place exits are an owner token or dismissal, plus a restart.
        if !self.enforced
            && self
                .bluescreen
                .as_ref()
                .is_some_and(BluescreenSession::dismissed)
        {
            self.end_blue_screen(context);
        }
        self.bluescreen.is_some() || self.enforced || self.manual_lock || self.remote_locked
    }

    /// Submit a token to the service. Only its protected receipt may release UI.
    pub(crate) fn try_recovery_unlock(&mut self, _context: &egui::Context) -> bool {
        if self.pending_recovery.is_some() {
            return false;
        }
        if let Some(until) = self.unlock_locked_until {
            if let Some(remaining) = until.checked_duration_since(Instant::now()) {
                self.status = format!("Too many attempts. Wait {}s.", remaining.as_secs() + 1);
                return false;
            }
        }
        let request = RecoveryRequest {
            request_id: uuid::Uuid::new_v4(),
            token: self.recovery_input.trim().to_string(),
        };
        if !request.token.starts_with(emi_core::recovery::TOKEN_PREFIX) || request.token.len() > 256
        {
            self.recovery_refused();
            return false;
        }
        let result = (|| -> anyhow::Result<()> {
            let directory = self
                .recovery_directory
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing state directory"))?;
            // The installer creates this fixed file, owned by Administrators.
            // Users may write bytes but cannot replace/delete it or write receipts.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(directory.join("recovery-request.json"))?;
            file.write_all(&serde_json::to_vec(&request)?)?;
            file.sync_all()?;
            Ok(())
        })();
        if result.is_ok() {
            self.pending_recovery = Some((request.request_id, Instant::now()));
            self.recovery_input.zeroize();
            self.status = "Verifying recovery token with the local service…".into();
        } else {
            self.status =
                "Recovery service unavailable. Sign in with the administrator recovery account."
                    .into();
        }
        false
    }

    pub(crate) fn poll_recovery_unlock(&mut self, context: &egui::Context) {
        let Some((id, started)) = self.pending_recovery else {
            return;
        };
        let state = self
            .recovery_directory
            .as_ref()
            .and_then(|directory| std::fs::read(directory.join("recovery-state.json")).ok())
            .and_then(|bytes| serde_json::from_slice::<RecoveryState>(&bytes).ok());
        if let Some(receipt) = state.and_then(|state| state.receipt) {
            if receipt.request_id == id && receipt.expires_at > Utc::now() {
                self.pending_recovery = None;
                if receipt.accepted {
                    self.unlock_released(context, "Device unlocked with a valid owner token.");
                } else {
                    self.recovery_refused();
                }
                return;
            }
        }
        if started.elapsed() > Duration::from_secs(30) {
            self.pending_recovery = None;
            self.status =
                "Recovery service did not respond. Use the administrator recovery account.".into();
        }
    }

    fn recovery_refused(&mut self) {
        self.unlock_fail_count = self.unlock_fail_count.saturating_add(1);
        if self.unlock_fail_count >= 5 {
            let backoff = 5u64 << (self.unlock_fail_count - 5).min(5);
            self.unlock_locked_until = Some(Instant::now() + Duration::from_secs(backoff));
            self.status = format!("Recovery token refused. Wait {backoff}s.");
        } else {
            self.status = "Recovery token refused.".into();
        }
    }

    fn unlock_released(&mut self, context: &egui::Context, message: &str) {
        self.unlock_fail_count = 0;
        self.unlock_locked_until = None;
        self.remote_unlock_override_at = read_remote_state().map(|state| state.checked_at);
        self.remote_locked = false;
        self.end_blue_screen(context);
        self.status = message.into();
    }

    /// Mouse-only on-screen keyboard for entering the owner unlock token while
    /// the physical keyboard is fully disabled. Clicks are pointer events, so the
    /// keyboard hook never sees them.
    fn render_onscreen_keyboard(&mut self, ui: &mut egui::Ui) {
        // Scope out the lock screen's white text override so keys are dark letters
        // on light caps (high contrast, readable).
        ui.scope(|ui| {
            let ink = Color32::from_gray(20);
            let cap = Color32::from_rgb(232, 238, 246);
            ui.visuals_mut().override_text_color = Some(ink);
            let key = |ui: &mut egui::Ui, label: &str, width: f32| {
                ui.add_sized(
                    [width, 34.0],
                    egui::Button::new(RichText::new(label).size(17.0).color(ink)).fill(cap),
                )
            };
            for row in [
                "ABCDEFGHIJKLM",
                "NOPQRSTUVWXYZ",
                "abcdefghijklm",
                "nopqrstuvwxyz",
                "0123456789-_",
            ] {
                ui.horizontal_wrapped(|ui| {
                    for ch in row.chars() {
                        if key(ui, &ch.to_string(), 34.0).clicked()
                            && self.recovery_input.len() < 256
                        {
                            self.recovery_input.push(ch);
                        }
                    }
                });
            }
            ui.horizontal(|ui| {
                if key(ui, "Backspace", 110.0).clicked() {
                    self.recovery_input.pop();
                }
                if key(ui, "Clear", 90.0).clicked() {
                    self.recovery_input.clear();
                }
            });
        });
    }

    fn render_remote_lock_reason(&self, ui: &mut egui::Ui) {
        if !self.remote_lock_reason.is_empty() {
            ui.add_space(10.0);
            ui.label(
                RichText::new(format!("Administrator note: {}", self.remote_lock_reason))
                    .size(17.0)
                    .color(Color32::from_rgb(205, 224, 244)),
            );
        }
    }

    pub(crate) fn render_blue_screen(&mut self, context: &egui::Context) {
        // Branded payment-restriction screen — deliberately NOT a Windows BSOD:
        // no ":(", no fake stop code, no crash language. It states plainly that
        // the device is company-owned and access is paused pending payment.
        let mut recovery_focused = false;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(11, 37, 69))
                    .inner_margin(40.0),
            )
            .show(context, |ui| {
                ui.visuals_mut().override_text_color = Some(Color32::WHITE);
                // No Exit button in any mode. The only way out is typing the
                // recovery token (or a valid signed token). No click-to-leave.
                ui.add_space(20.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let (banner, title, description) = lock_screen_copy(&self.remote_lock_reason);
                    ui.label(
                        RichText::new(banner)
                            .size(15.0)
                            .color(Color32::from_rgb(143, 198, 255)),
                    );
                    self.render_remote_lock_reason(ui);
                    ui.add_space(12.0);
                    ui.label(RichText::new(title).size(34.0).strong());
                    ui.add_space(10.0);
                    ui.label(RichText::new(description).size(20.0));
                    ui.add_space(28.0);
                    ui.horizontal_wrapped(|ui| {
                        if let Some(qr) = &self.qr {
                            ui.add(
                                egui::Image::new(qr).fit_to_exact_size(egui::vec2(220.0, 220.0)),
                            );
                        }
                        ui.vertical(|ui| {
                            ui.heading("Restore access");
                            ui.label(
                                RichText::new("The physical keyboard is disabled.")
                                    .color(Color32::from_rgb(143, 198, 255)),
                            );
                            ui.label("Type the recovery token to release this device.");
                        });
                    });
                    ui.add_space(24.0);
                    ui.separator();
                    ui.add_space(12.0);
                    ui.heading("Enter the recovery token to continue");
                    if let Some(device) = self.device_id {
                        ui.label(format!("Device ID: {device}"));
                    }
                    ui.label(
                        "Enter the owner-signed recovery token, \
                         then press Unlock.",
                    );
                    ui.add_space(8.0);
                    // Black text on a light field so the token is readable
                    // despite the lock screen's white text override.
                    let field = ui
                        .scope(|ui| {
                            ui.visuals_mut().override_text_color = Some(Color32::from_gray(20));
                            ui.visuals_mut().extreme_bg_color = Color32::from_rgb(232, 238, 246);
                            ui.add(
                                egui::TextEdit::singleline(&mut *self.recovery_input)
                                    .desired_width(460.0)
                                    .char_limit(256)
                                    .hint_text("EMIU1-… recovery token"),
                            )
                        })
                        .inner;
                    recovery_focused = field.has_focus();
                    ui.add_space(8.0);
                    self.render_onscreen_keyboard(ui);
                    ui.add_space(8.0);
                    // Explicit high-contrast primary button: dark text on a light
                    // fill, scoped past the lock screen's white text override.
                    let unlock = ui
                        .scope(|ui| {
                            ui.visuals_mut().override_text_color = Some(Color32::from_gray(20));
                            ui.add(
                                egui::Button::new(
                                    RichText::new("Unlock")
                                        .size(18.0)
                                        .color(Color32::from_gray(20)),
                                )
                                .min_size(egui::vec2(140.0, 36.0))
                                .fill(Color32::from_rgb(143, 198, 255)),
                            )
                        })
                        .inner;
                    if unlock.clicked() && self.try_recovery_unlock(context) {
                        return;
                    }
                    ui.label(&self.status);
                    ui.small(
                        "The physical keyboard is fully disabled while locked; type the unlock \
                         token with the on-screen keys above. Ctrl+Alt+Del and Win+L are OS-\
                         protected. Administrator sign-in remains available for recovery.",
                    );
                });
            });
        self.recovery_focused = recovery_focused;
    }
}

fn is_theft_reason(reason: &str) -> bool {
    reason.trim().eq_ignore_ascii_case("THEFT")
}

fn lock_screen_copy(reason: &str) -> (&'static str, &'static str, &'static str) {
    if is_theft_reason(reason) {
        (
            "MANAGED DEVICE · REPORTED LOST OR STOLEN",
            "This device has been reported lost or stolen",
            "Access has been restricted by the device administrator. If you found this device, return it to its owner or contact the organization identified on the device. Windows has not crashed and files remain protected.",
        )
    } else {
        (
            "EMI DEVICE · ACCESS PAUSED",
            "Payment required to continue",
            "This company-owned device is under an EMI financing agreement. Access is paused until the outstanding installment is recorded. Windows has not crashed and your files are safe.",
        )
    }
}

#[cfg(test)]
mod theft_tests {
    use super::{is_theft_reason, lock_screen_copy};

    #[test]
    fn theft_reason_detection_is_explicit_and_case_insensitive() {
        assert!(is_theft_reason("THEFT"));
        assert!(is_theft_reason(" theft "));
        assert!(!is_theft_reason("PAYMENT_OVERDUE"));
        assert!(!is_theft_reason("suspected theft"));
        let (banner, title, description) = lock_screen_copy("theft");
        assert!(banner.contains("REPORTED LOST OR STOLEN"));
        assert!(title.contains("reported lost or stolen"));
        assert!(description.contains("return it to its owner"));
        assert!(!description.to_ascii_lowercase().contains("payment"));
    }
}
