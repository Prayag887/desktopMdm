#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("EMI Device UI is available only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use eframe::egui::{self, Color32, RichText};
    use emi_core::{BiosProvider, DeviceHealth};
    use emi_device_agent::prank::PrankSession;
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
    use zeroize::{Zeroize, Zeroizing};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
        prank: Option<PrankSession>,
        qr: Option<egui::TextureHandle>,
    }

    impl DeviceApp {
        fn load() -> Self {
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
                prank: None,
                qr: None,
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

        fn render_prank(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
            ui.heading("Blue screen mode");
            ui.label("A temporary visual prank — Windows keeps running normally.");
            ui.add_space(16.0);
            ui.label("PC's private LAN IPv4 address");
            ui.text_edit_singleline(&mut self.lan_ip);
            ui.small("Phone and PC must share a trusted network. Windows Firewall may require approval for this app on a Private network. No firewall rules are changed automatically. 127.0.0.1 works only on this PC.");
            ui.add_space(16.0);
            ui.checkbox(
                &mut self.consent,
                "I have permission to run this harmless simulation on this PC",
            );
            let mut enabled = false;
            if ui
                .add_enabled(
                    self.consent,
                    egui::Checkbox::new(&mut enabled, "Show simulated blue screen"),
                )
                .changed()
                && enabled
            {
                match self
                    .lan_ip
                    .parse()
                    .map_err(|_| "Enter a valid IPv4 address".to_string())
                    .and_then(|ip| PrankSession::start(ip).map_err(|error| error.to_string()))
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
                            self.prank = Some(session);
                            context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                        }
                        Err(error) => self.status = format!("QR generation failed: {error}"),
                    },
                    Err(error) => self.status = format!("Simulation could not start: {error}"),
                }
            }
            ui.add_space(12.0);
            ui.label("Escape does not dismiss Blue screen mode. Use Exit, scan the QR and tap Dismiss, close the app, or reboot. Automatic safety timeout: 5 minutes. Restart always begins unchecked.");
            ui.small("This does not crash Windows, block recovery keys, change BIOS settings or prevent switching apps.");
        }

        fn end_blue_screen(&mut self, context: &egui::Context) {
            self.prank = None;
            self.qr = None;
            self.consent = false;
            self.status = "Blue screen mode ended. The checkbox is reset.".into();
            context.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        }

        fn blue_screen_active(&mut self, context: &egui::Context) -> bool {
            if self
                .prank
                .as_ref()
                .is_some_and(|session| session.dismissed() || session.expired())
            {
                self.end_blue_screen(context);
            }
            self.prank.is_some()
        }

        fn render_blue_screen(&mut self, context: &egui::Context) {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(0, 100, 180))
                        .inner_margin(40.0),
                )
                .show(context, |ui| {
                    ui.visuals_mut().override_text_color = Some(Color32::WHITE);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.label(RichText::new(":(").size(100.0));
                        ui.add_space(20.0);
                        ui.label(RichText::new("Your PC ran into a pretend problem.").size(32.0));
                        ui.label(
                            RichText::new("No data is being collected. Windows has not crashed.")
                                .size(22.0),
                        );
                        ui.add_space(28.0);
                        ui.label("SIMULATED STOP CODE: JUST_A_PRANK");
                        ui.add_space(24.0);
                        ui.horizontal_wrapped(|ui| {
                            if let Some(qr) = &self.qr {
                                ui.add(
                                    egui::Image::new(qr)
                                        .fit_to_exact_size(egui::vec2(220.0, 220.0)),
                                );
                            }
                            ui.vertical(|ui| {
                                ui.heading("Scan to return to the app");
                                ui.label("Open the link on a phone on the same network,");
                                ui.label("then tap Dismiss simulated blue screen.");
                                ui.add_space(12.0);
                                ui.label("Escape is disabled · Restart clears this mode");
                                ui.label("Automatically ends after 5 minutes");
                            });
                        });
                    });
                    ui.add_space(16.0);
                    if ui.button("Exit blue screen mode").clicked() {
                        self.end_blue_screen(context);
                    }
                });
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
                        ui.selectable_value(&mut self.tab, 2, "Blue screen mode");
                    });
                    if previous == 1 && self.tab != 1 { self.clear_passwords(); }
                    ui.separator();
                    if self.tab == 1 { self.render_firmware(ui); }
                    else if self.tab == 2 { self.render_prank(ui, context); }
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
            assert!(app.prank.is_none());
            assert!(!app.consent);
            let context = egui::Context::default();
            let output = context.run(egui::RawInput::default(), |context| {
                egui::CentralPanel::default().show(context, |ui| {
                    app.render_firmware(ui);
                    app.render_prank(ui, context);
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
            app.prank = Some(PrankSession::start(std::net::Ipv4Addr::LOCALHOST).unwrap());
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
            assert!(app.prank.is_some());
            app.end_blue_screen(&context);
            assert!(app.prank.is_none());
            assert!(!app.consent);
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
