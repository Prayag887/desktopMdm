//! The fullscreen lock screen, keyboard suppression, and owner-token recovery.

use chrono::Utc;
use eframe::egui::{self, Color32, RichText};
use emi_core::recovery::{parse_public_key_hex, verify_unlock};
use zeroize::Zeroize as _;

use super::app::{DeviceApp, OWNER_PUBLIC_KEY_HEX};
use super::system::write_last_counter;

impl DeviceApp {
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
        self.fullscreen_applied = false;
        self.status = "Payment-restriction mode ended. The checkbox is reset.".into();
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
        // The demo (QR) session can auto-dismiss or time out. Enforced mode never
        // auto-releases — it stays locked until a token or signed policy clears it.
        if !self.enforced
            && self
                .bluescreen
                .as_ref()
                .is_some_and(|session| session.dismissed() || session.expired())
        {
            self.end_blue_screen(context);
        }
        self.bluescreen.is_some() || self.enforced || self.manual_lock
    }

    /// Verify an owner-signed unlock token against the embedded public key.
    /// Fail-safe: any problem leaves the device locked. On success the token's
    /// counter is persisted so it cannot be replayed. Returns true if released.
    pub(crate) fn try_recovery_unlock(&mut self, context: &egui::Context) -> bool {
        let Some(trusted) = parse_public_key_hex(OWNER_PUBLIC_KEY_HEX) else {
            self.status = "Recovery key not configured; use admin/WinRE recovery.".into();
            return false;
        };
        let Some(device) = self.device_id else {
            self.status = "Device identity unknown; cannot verify unlock token.".into();
            return false;
        };
        match verify_unlock(
            self.recovery_input.trim(),
            &trusted,
            device,
            Utc::now(),
            self.last_counter,
        ) {
            Ok(token) => {
                self.last_counter = token.counter;
                write_last_counter(token.counter);
                self.end_blue_screen(context);
                self.status = "Device unlocked with a valid owner token.".into();
                true
            }
            Err(error) => {
                self.status = format!("Unlock refused: {error}");
                false
            }
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
                // The Exit button exists only in the reversible demo. In enforced
                // mode the customer cannot close the screen; release is via an
                // owner token, signed policy, or an administrator signing into
                // their own (never-restricted) account.
                if !self.enforced
                    && ui
                        .button("Technician exit (authorized administrator)")
                        .clicked()
                {
                    self.end_blue_screen(context);
                    return;
                }
                ui.add_space(20.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(
                        RichText::new("EMI DEVICE · ACCESS PAUSED")
                            .size(15.0)
                            .color(Color32::from_rgb(143, 198, 255)),
                    );
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("Payment required to continue")
                            .size(34.0)
                            .strong(),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "This company-owned device is under an EMI financing agreement. \
                             Access is paused until the outstanding installment is recorded. \
                             Windows has not crashed and your files are safe.",
                        )
                        .size(20.0),
                    );
                    ui.add_space(28.0);
                    ui.horizontal_wrapped(|ui| {
                        if let Some(qr) = &self.qr {
                            ui.add(
                                egui::Image::new(qr).fit_to_exact_size(egui::vec2(220.0, 220.0)),
                            );
                        }
                        ui.vertical(|ui| {
                            ui.heading("Restore access");
                            ui.label("Scan the code on a phone on the same network,");
                            ui.label("then confirm to release this device.");
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new(
                                    "Keyboard is suppressed except the recovery field below.",
                                )
                                .color(Color32::from_rgb(143, 198, 255)),
                            );
                            ui.label("Restart clears this mode · Ends after 5 minutes");
                        });
                    });
                    ui.add_space(24.0);
                    ui.separator();
                    ui.add_space(12.0);
                    ui.heading("Restore access with an owner unlock token");
                    let device_line = self.device_id.map_or_else(
                        || "Device ID: unknown".to_string(),
                        |id| format!("Device ID: {id}"),
                    );
                    ui.label(RichText::new(device_line).monospace());
                    ui.label(
                        "Give the Device ID to the owner. Paste the signed unlock token they \
                         return. The keyboard stays enabled here for entry and accessibility.",
                    );
                    ui.add_space(8.0);
                    let field = ui.add(
                        egui::TextEdit::singleline(&mut *self.recovery_input)
                            .desired_width(460.0)
                            .char_limit(256)
                            .hint_text("EMIU1-…"),
                    );
                    recovery_focused = field.has_focus();
                    ui.add_space(8.0);
                    if ui.button("Unlock with token").clicked() && self.try_recovery_unlock(context)
                    {
                        return;
                    }
                    ui.small(
                        "Escape shortcuts are blocked by the app's keyboard hook while locked; \
                         Ctrl+Alt+Del and the most robust blocking need the Windows Keyboard \
                         Filter (Enterprise/IoT), never a custom driver.",
                    );
                });
            });
        self.recovery_focused = recovery_focused;
    }
}
