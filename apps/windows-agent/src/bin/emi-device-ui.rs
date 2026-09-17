#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("EMI Device UI is available only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use chrono::Utc;
    use eframe::egui::{self, Color32, RichText};
    use emi_core::recovery::{parse_public_key_hex, verify_unlock};
    use emi_core::{BiosProvider, DeviceHealth};
    use emi_device_agent::bluescreen::BluescreenSession;
    use qrcode::{Color, QrCode};
    use std::os::windows::process::CommandExt as _;
    use std::{
        fs,
        path::PathBuf,
        process::Command,
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };
    use uuid::Uuid;
    use zeroize::{Zeroize, Zeroizing};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // A UI state bag; a state machine would be overkill for a demo panel.
    #[allow(clippy::struct_excessive_bools)]
    struct DeviceApp {
        health: Option<DeviceHealth>,
        service_running: bool,
        status: String,
        result_rx: Option<Receiver<String>>,
        last_refresh: Instant,
        tab: usize,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
        confirm_password: Zeroizing<String>,
        lan_ip: String,
        consent: bool,
        bluescreen: Option<BluescreenSession>,
        qr: Option<egui::TextureHandle>,
        recovery_input: Zeroizing<String>,
        recovery_focused: bool,
        enforced: bool,
        fullscreen_applied: bool,
        manual_lock: bool,
        device_id: Option<Uuid>,
        last_counter: u64,
        lock_user: String,
        opt_shell: bool,
        opt_keyboard_filter: bool,
        opt_applocker: bool,
    }

    /// Trusted owner public key (Ed25519, hex). The matching SIGNING key stays
    /// offline with the owner and mints unlock tokens; only its holder can
    /// release a device. Replace this LAB key with your own from
    /// `cargo run --example keygen -p emi-core` before production. If it is not a
    /// valid key, token recovery is disabled and only admin/WinRE recovery works.
    const OWNER_PUBLIC_KEY_HEX: &str =
        "ac1473ba71d2cd322163ccc8a8f64e1226cfcb815bfc270cbe7417f16d8ae7ba";

    /// True when the current account is a member of the local Administrators
    /// group (SID S-1-5-32-544). Authorized administrators are never restricted.
    fn current_user_is_admin() -> bool {
        Command::new("whoami")
            .args(["/groups", "/fo", "csv", "/nh"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("S-1-5-32-544"))
    }

    /// True when this exe is the enrolled account's Winlogon shell — i.e. the
    /// provisioning script made the app replace Explorer for this user. Read-only
    /// registry query of the current user's own hive; no elevation required.
    fn launched_as_user_shell() -> bool {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        Command::new("reg.exe")
            .args([
                "query",
                r"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "/v",
                "Shell",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .to_lowercase()
                        .contains(&exe.to_string_lossy().to_lowercase())
            })
    }

    impl DeviceApp {
        fn load() -> Self {
            let is_admin = current_user_is_admin();
            // Enforced (unbreakable) mode: launched as the enrolled user's shell
            // AND not an administrator. Admins and normal launches stay in the
            // reversible demo, keeping an Exit button.
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

        fn clear_passwords(&mut self) {
            self.current_password.zeroize();
            self.new_password.zeroize();
            self.confirm_password.zeroize();
        }

        fn render_firmware(&mut self, ui: &mut egui::Ui) {
            ui.heading("Firmware credentials");
            ui.label("Prepare a BIOS password change");
            ui.add_space(12.0);
            ui.colored_label(
                Color32::from_rgb(230, 180, 100),
                "Not connected to a supported OEM adapter",
            );
            ui.label("Firmware passwords cannot be read back. Enter the current password only if you know it. Your exact manufacturer and model are required before changes can be enabled.");
            ui.add_space(16.0);
            for (label, value) in [
                ("Current BIOS password", &mut *self.current_password),
                ("New BIOS password", &mut *self.new_password),
                ("Confirm new password", &mut *self.confirm_password),
            ] {
                ui.label(label);
                ui.add(
                    egui::TextEdit::singleline(value)
                        .password(true)
                        .desired_width(360.0)
                        .char_limit(128),
                );
                ui.add_space(10.0);
            }
            if !self.confirm_password.is_empty() && self.new_password != self.confirm_password {
                ui.colored_label(Color32::LIGHT_RED, "New passwords do not match.");
            }
            ui.horizontal(|ui| {
                ui.add_enabled(false, egui::Button::new("Apply BIOS password change"));
                if ui.button("Clear fields").clicked() {
                    self.clear_passwords();
                }
            });
            ui.small("Fields are masked and never saved, logged or sent to the QR page. Leaving this tab clears them. No firmware change is performed in this build.");
        }

        fn render_bluescreen(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
            ui.heading("Payment-restriction mode");
            ui.label("Reversible branded lock demo — Windows keeps running normally.");
            ui.add_space(16.0);
            ui.label("PC's private LAN IPv4 address");
            ui.text_edit_singleline(&mut self.lan_ip);
            ui.small("Phone and PC must share a trusted network. Windows Firewall may require approval for this app on a Private network. No firewall rules are changed automatically. 127.0.0.1 works only on this PC.");
            ui.add_space(16.0);
            ui.checkbox(
                &mut self.consent,
                "I am authorized to run this reversible restriction demo on this PC",
            );
            let mut enabled = false;
            if ui
                .add_enabled(
                    self.consent,
                    egui::Checkbox::new(&mut enabled, "Show payment-restriction screen"),
                )
                .changed()
                && enabled
            {
                match self
                    .lan_ip
                    .parse()
                    .map_err(|_| "Enter a valid IPv4 address".to_string())
                    .and_then(|ip| BluescreenSession::start(ip).map_err(|error| error.to_string()))
                {
                    Ok(session) => match QrCode::new(session.url()) {
                        Ok(code) => {
                            let width = code.width();
                            let side = width + 8;
                            let mut image = egui::ColorImage::new([side, side], Color32::WHITE);
                            for y in 0..width {
                                for x in 0..width {
                                    if code[(x, y)] == Color::Dark {
                                        image[(x + 4, y + 4)] = Color32::BLACK;
                                    }
                                }
                            }
                            self.qr = Some(context.load_texture(
                                "dismiss-qr",
                                image,
                                egui::TextureOptions::NEAREST,
                            ));
                            self.bluescreen = Some(session);
                            context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                        }
                        Err(error) => self.status = format!("QR generation failed: {error}"),
                    },
                    Err(error) => self.status = format!("Simulation could not start: {error}"),
                }
            }
            ui.add_space(12.0);
            ui.label("Escape does not dismiss the restriction. Exit via technician button, recovery code, QR dismissal, closing the app, or reboot. Automatic safety timeout: 5 minutes. Restart always begins unchecked.");
            ui.small("This does not crash Windows, block OS recovery keys, change BIOS settings, or disable the keyboard globally. The recovery field stays typable.");

            ui.add_space(20.0);
            ui.separator();
            self.render_manual_lock(ui, context);
        }

        /// Administrator controls to pick and apply lock methods by hand.
        fn render_manual_lock(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
            ui.heading("Manual lock controls");
            ui.small(
                "Session lock is in-app and reversible with Exit. OS lockdown runs the \
                 provisioning script elevated and needs an administrator plus Enterprise/IoT \
                 for the keyboard-filter and AppLocker layers. Test on a VM only.",
            );
            ui.add_space(10.0);

            if ui.button("Lock this session now (reversible)").clicked() {
                self.manual_lock = true;
                self.fullscreen_applied = false;
                context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                self.status = "Session locked. Use the Exit or a recovery token to leave.".into();
            }

            ui.add_space(14.0);
            ui.label("OS lockdown target (enrolled standard account):");
            ui.text_edit_singleline(&mut self.lock_user);
            ui.checkbox(
                &mut self.opt_shell,
                "Replace shell (app becomes the desktop)",
            );
            ui.checkbox(
                &mut self.opt_keyboard_filter,
                "Keyboard Filter — block Alt+Tab / Win / Ctrl+Shift+Esc (Enterprise/IoT)",
            );
            ui.checkbox(
                &mut self.opt_applocker,
                "AppLocker — only the signed app may run (Enterprise/IoT)",
            );
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                let ready = self.result_rx.is_none() && !self.lock_user.trim().is_empty();
                if ui
                    .add_enabled(ready, egui::Button::new("Apply OS lockdown (admin)"))
                    .clicked()
                {
                    self.run_lockdown(true);
                }
                if ui
                    .add_enabled(
                        self.result_rx.is_none(),
                        egui::Button::new("Remove OS lockdown (admin)"),
                    )
                    .clicked()
                {
                    self.run_lockdown(false);
                }
            });
            ui.small(
                "Task Manager and Fast User Switching are always part of the base lockdown. \
                 Administrators and WinRE are never restricted.",
            );
        }

        /// Launch the elevated provisioning/teardown script with the chosen
        /// options. Non-selected layers are skipped. Reversible via the same UI.
        fn run_lockdown(&mut self, apply: bool) {
            if self.result_rx.is_some() {
                return;
            }
            let script = if apply {
                "Set-PaymentRestriction.ps1"
            } else {
                "Remove-PaymentRestriction.ps1"
            };
            let script_path = match std::env::current_exe() {
                Ok(exe) => exe.with_file_name(script),
                Err(error) => {
                    self.status = format!("Cannot locate script: {error}");
                    return;
                }
            };
            if !script_path.exists() {
                self.status = format!("{script} not found beside the app.");
                return;
            }
            // Build the PowerShell ArgumentList as discrete single-quoted items so
            // values containing spaces stay intact. Escape embedded quotes.
            let quote = |value: &str| format!("'{}'", value.replace('\'', "''"));
            let mut arg_items: Vec<String> = vec![
                quote("-NoProfile"),
                quote("-ExecutionPolicy"),
                quote("Bypass"),
                quote("-File"),
                quote(&script_path.to_string_lossy()),
            ];
            if apply {
                let exe = std::env::current_exe()
                    .map(|exe| exe.to_string_lossy().into_owned())
                    .unwrap_or_default();
                arg_items.push(quote("-EnrolledUser"));
                arg_items.push(quote(self.lock_user.trim()));
                arg_items.push(quote("-AppPath"));
                arg_items.push(quote(&exe));
                arg_items.push(quote("-LabVm"));
                if !self.opt_shell {
                    arg_items.push(quote("-SkipShell"));
                }
                if !self.opt_keyboard_filter {
                    arg_items.push(quote("-SkipKeyboardFilter"));
                }
                if !self.opt_applocker {
                    arg_items.push(quote("-SkipAppLocker"));
                }
            } else {
                arg_items.push(quote("-LabVm"));
            }
            let argument_list = arg_items.join(",");

            self.status = format!("Running {script} (elevated)…");
            let (tx, rx) = mpsc::channel();
            self.result_rx = Some(rx);
            thread::spawn(move || {
                let inner = format!(
                    "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath 'powershell.exe' -ArgumentList {argument_list} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
                );
                let result = Command::new("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &inner])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status()
                    .map_or_else(
                        |error| format!("Lockdown command failed: {error}"),
                        |status| {
                            if status.success() {
                                "OS lockdown command completed.".into()
                            } else {
                                format!("Lockdown canceled or failed: {status}")
                            }
                        },
                    );
                let _ = tx.send(result);
            });
        }

        fn end_blue_screen(&mut self, context: &egui::Context) {
            self.bluescreen = None;
            self.qr = None;
            self.consent = false;
            self.recovery_input.zeroize();
            self.recovery_focused = false;
            // Releasing also clears enforced mode for this session. On the next
            // login the app is still the shell and re-locks until the signed
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
        /// This drains the app's own key and text events so escape shortcuts do
        /// nothing inside the window — EXCEPT while the recovery field has focus,
        /// so the customer can always type a recovery code and an accessibility
        /// user can operate it. It is a lab demonstration only: it cannot block
        /// OS-global Alt+Tab / Win / Ctrl+Shift+Esc. Production must use the
        /// Windows Keyboard Filter (WEKF) feature for that. Never a driver.
        fn suppress_keyboard(&self, context: &egui::Context) {
            if self.recovery_focused {
                return;
            }
            context.input_mut(|input| {
                input.events.retain(|event| {
                    !matches!(event, egui::Event::Key { .. } | egui::Event::Text(_))
                });
            });
        }

        fn blue_screen_active(&mut self, context: &egui::Context) -> bool {
            // The demo (QR) session can auto-dismiss or time out. Enforced mode
            // never auto-releases — it stays locked until a recovery code or a
            // signed payment-restored policy clears it.
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
        fn try_recovery_unlock(&mut self, context: &egui::Context) -> bool {
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

        fn render_blue_screen(&mut self, context: &egui::Context) {
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
                    // The Exit button exists only in the reversible demo. In
                    // enforced mode the customer cannot close the screen; release
                    // is via recovery code, signed policy, or an administrator
                    // signing into their own (never-restricted) account.
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
                                    egui::Image::new(qr)
                                        .fit_to_exact_size(egui::vec2(220.0, 220.0)),
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
                        if ui.button("Unlock with token").clicked()
                            && self.try_recovery_unlock(context)
                        {
                            return;
                        }
                        ui.small(
                            "Prototype: window-scoped suppression only. Production blocks \
                             OS-global Alt+Tab / Win / Ctrl+Shift+Esc via the Windows \
                             Keyboard Filter feature, never a custom driver.",
                        );
                    });
                });
            self.recovery_focused = recovery_focused;
        }

        fn refresh_health(&mut self) {
            if self.result_rx.is_some() {
                return;
            }
            self.status = "Refreshing local device health…".into();
            let (tx, rx) = mpsc::channel();
            self.result_rx = Some(rx);
            thread::spawn(move || {
                let result = agent_path().and_then(|agent| {
                    let script = format!(
                        "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '{}' -ArgumentList 'run','--once' -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
                        agent.to_string_lossy().replace('\'', "''")
                    );
                    Command::new("powershell.exe")
                        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                        .creation_flags(CREATE_NO_WINDOW).status().map_err(|error| error.to_string())
                }).map_or_else(
                    |error| format!("Refresh failed: {error}"),
                    |status| if status.success() { "Local device health refreshed".into() } else { format!("Refresh canceled or failed: {status}") }
                );
                let _ = tx.send(result);
            });
        }

        fn reload(&mut self) {
            self.health = read_health();
            self.service_running = service_is_running();
            self.last_refresh = Instant::now();
        }

        fn render_health(&self, ui: &mut egui::Ui) {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.heading("This PC");
                if let Some(health) = &self.health {
                    egui::Grid::new("local_health")
                        .num_columns(2)
                        .spacing([18.0, 10.0])
                        .show(ui, |ui| {
                            for (label, value) in [
                                ("Device", health.hostname.clone()),
                                ("Operating system", health.os_version.clone()),
                                ("Device ID", health.device_id.to_string()),
                                ("App version", env!("CARGO_PKG_VERSION").into()),
                                (
                                    "Free storage",
                                    format!(
                                        "{}.{:01} GiB",
                                        health.disk_free_bytes / 1_073_741_824,
                                        health.disk_free_bytes % 1_073_741_824 * 10 / 1_073_741_824
                                    ),
                                ),
                                (
                                    "Battery",
                                    health.battery_percent.map_or_else(
                                        || "Not reported".into(),
                                        |value| format!("{value}%"),
                                    ),
                                ),
                                (
                                    "Secure Boot",
                                    health
                                        .secure_boot
                                        .map_or("Not reported", |enabled| {
                                            if enabled { "Enabled" } else { "Disabled" }
                                        })
                                        .into(),
                                ),
                                (
                                    "WinGet",
                                    if health.winget_available {
                                        "Available"
                                    } else {
                                        "Not detected"
                                    }
                                    .into(),
                                ),
                                (
                                    "Manufacturer",
                                    match health.bios_provider {
                                        BiosProvider::Dell => "Dell",
                                        BiosProvider::Hp => "HP",
                                        BiosProvider::Lenovo => "Lenovo",
                                        BiosProvider::Unsupported => "Other / unknown",
                                    }
                                    .into(),
                                ),
                                (
                                    "Last health refresh",
                                    health.observed_at.format("%d %b %Y, %H:%M UTC").to_string(),
                                ),
                            ] {
                                ui.label(label);
                                ui.label(value);
                                ui.end_row();
                            }
                        });
                } else {
                    ui.label("No local health snapshot yet.");
                    ui.small("Install the companion service or use Refresh device health below.");
                }
            });
        }
    }

    impl eframe::App for DeviceApp {
        fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
            if self.blue_screen_active(context) {
                context.request_repaint_after(Duration::from_millis(100));
                if self.enforced && !self.fullscreen_applied {
                    context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                    self.fullscreen_applied = true;
                }
                self.suppress_keyboard(context);
                // Veto Alt+F4 / window-close while enforced. Within the app only;
                // OS-global Alt+Tab / Win / Ctrl+Shift+Esc need Keyboard Filter.
                if self.enforced && context.input(|input| input.viewport().close_requested()) {
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
                    if previous == 1 && self.tab != 1 { self.clear_passwords(); }
                    ui.separator();
                    if self.tab == 1 { self.render_firmware(ui); }
                    else if self.tab == 2 { self.render_bluescreen(ui, context); }
                    else {
                    ui.add_space(16.0);
                    let (label, color) = if self.service_running {
                        ("Local health service running", Color32::from_rgb(30, 150, 85))
                    } else { ("Local service not installed or stopped", Color32::from_rgb(155, 105, 35)) };
                    ui.colored_label(color, label);
                    ui.add_space(12.0);
                    self.render_health(ui);
                    ui.add_space(16.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(self.result_rx.is_none(), egui::Button::new("Refresh device health (admin)")).clicked() { self.refresh_health(); }
                        if ui.button("Reload status").clicked() { self.reload(); self.status = "Local status reloaded".into(); }
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

    fn read_health() -> Option<DeviceHealth> {
        let base = std::env::var_os("PROGRAMDATA")?;
        fs::read(PathBuf::from(base).join("EmiDeviceAgent/health.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn read_device_id() -> Option<Uuid> {
        read_health().map(|health| health.device_id)
    }

    fn counter_path() -> Option<PathBuf> {
        std::env::var_os("PROGRAMDATA")
            .map(|base| PathBuf::from(base).join("EmiDeviceAgent/unlock-counter.txt"))
    }

    /// Highest unlock-token counter already accepted. Rollback protection: a
    /// token must exceed this. Missing/unreadable file means "none seen yet".
    /// Backed by the tested `emi_core::recovery` persistence helpers.
    fn read_last_counter() -> u64 {
        counter_path().map_or(0, |path| emi_core::recovery::read_counter(&path))
    }

    fn write_last_counter(counter: u64) {
        if let Some(path) = counter_path() {
            let _ = emi_core::recovery::record_counter(&path, counter);
        }
    }

    fn agent_path() -> Result<PathBuf, String> {
        let current = std::env::current_exe().map_err(|error| error.to_string())?;
        Ok(current.with_file_name("emi-device-agent.exe"))
    }

    fn service_is_running() -> bool {
        Command::new("sc.exe")
            .args(["query", "EmiDeviceAgent"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("RUNNING")
            })
    }

    pub fn run() -> eframe::Result<()> {
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
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    use std::os::windows::process::CommandExt as _;
    let result = windows_app::run();
    if let Err(error) = &result {
        let _ = std::fs::write(
            std::env::temp_dir().join("emi-device-ui-startup-error.log"),
            format!("EMI Device UI startup failed: {error}"),
        );
        let _ = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('The desktop UI could not start. See emi-device-ui-startup-error.log in your TEMP folder for details.', 'EMI Device')"])
            .creation_flags(0x0800_0000)
            .status();
    }
    result
}
