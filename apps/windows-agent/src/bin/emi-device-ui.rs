#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("EMI Device UI is available only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use std::{
        fs,
        path::PathBuf,
        process::Command,
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };

    use eframe::egui::{self, Color32, RichText};
    use serde::Deserialize;
    use uuid::Uuid;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Deserialize)]
    struct AgentConfig {
        server: String,
        device_id: Uuid,
    }

    #[derive(Deserialize)]
    struct PaymentNotice {
        title: String,
        message: String,
        created_at: String,
    }

    struct DeviceApp {
        server: String,
        device_id: String,
        service_running: bool,
        status: String,
        result_rx: Option<Receiver<String>>,
        unlock_rx: Option<Receiver<bool>>,
        management_enabled: bool,
        pin_verifier: Option<String>,
        pin_attempt: String,
        unlocked: bool,
        next_pin_attempt: Instant,
        last_policy_refresh: Instant,
        payment_notice: Option<PaymentNotice>,
        dismissed_notice: Option<String>,
    }

    impl DeviceApp {
        fn load() -> Self {
            match read_config() {
                Ok(config) => Self {
                    server: config.server,
                    device_id: config.device_id.to_string(),
                    service_running: service_is_running(),
                    status: "Ready".into(),
                    result_rx: None,
                    unlock_rx: None,
                    management_enabled: true,
                    pin_verifier: None,
                    pin_attempt: String::new(),
                    unlocked: false,
                    next_pin_attempt: Instant::now(),
                    last_policy_refresh: Instant::now() - Duration::from_secs(10),
                    payment_notice: None,
                    dismissed_notice: None,
                },
                Err(error) => Self {
                    server: "Not enrolled".into(),
                    device_id: "—".into(),
                    service_running: service_is_running(),
                    status: format!("Configuration error: {error}"),
                    result_rx: None,
                    unlock_rx: None,
                    management_enabled: true,
                    pin_verifier: None,
                    pin_attempt: String::new(),
                    unlocked: false,
                    next_pin_attempt: Instant::now(),
                    last_policy_refresh: Instant::now() - Duration::from_secs(10),
                    payment_notice: None,
                    dismissed_notice: None,
                },
            }
        }

        fn check_now(&mut self) {
            if self.result_rx.is_some() {
                return;
            }
            self.status = "Checking in…".into();
            let (tx, rx) = mpsc::channel();
            self.result_rx = Some(rx);
            thread::spawn(move || {
                let result = agent_path()
                    .and_then(|agent| {
                        use std::os::windows::process::CommandExt as _;
                        let script = format!(
                            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '{}' -ArgumentList 'run','--once' -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
                            agent.to_string_lossy().replace('\'', "''")
                        );
                        Command::new("powershell.exe")
                            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                            .creation_flags(CREATE_NO_WINDOW)
                            .status()
                            .map_err(|error| error.to_string())
                    })
                    .map_or_else(
                        |error| format!("Check-in failed: {error}"),
                        |status| {
                            if status.success() {
                                "Check-in completed successfully".into()
                            } else {
                                format!("Check-in exited with {status}")
                            }
                        },
                    );
                let _ = tx.send(result);
            });
        }

        fn open_portal(&mut self) {
            if !(self.server.starts_with("https://") || self.server.starts_with("http://")) {
                self.status = "No valid control-plane URL is configured".into();
                return;
            }
            use std::os::windows::process::CommandExt as _;
            match Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", &self.server])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
            {
                Ok(_) => self.status = "Opened the admin portal".into(),
                Err(error) => self.status = format!("Could not open portal: {error}"),
            }
        }

        fn refresh(&mut self) {
            self.service_running = service_is_running();
            if let Ok(config) = read_config() {
                self.server = config.server;
                self.device_id = config.device_id.to_string();
            }
            self.status = "Status refreshed".into();
            self.refresh_policy();
        }

        fn refresh_policy(&mut self) {
            if let Ok(base) = program_data() {
                let directory = base.join("EmiDeviceAgent");
                self.management_enabled = fs::read_to_string(directory.join("management.enabled"))
                    .ok()
                    .is_none_or(|value| value.trim() != "0");
                let verifier = fs::read_to_string(directory.join("managed-pin.verifier")).ok();
                if verifier != self.pin_verifier {
                    self.unlocked = false;
                    self.unlock_rx = None;
                    self.pin_attempt.clear();
                }
                self.pin_verifier = verifier;
                self.payment_notice = fs::read(directory.join("payment-notice.json"))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            }
            self.last_policy_refresh = Instant::now();
        }

        fn render_device_card(&mut self, ui: &mut egui::Ui) {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (label, color) = if self.service_running {
                        ("Background service running", Color32::from_rgb(30, 150, 85))
                    } else {
                        ("Service is not running", Color32::from_rgb(210, 65, 65))
                    };
                    ui.colored_label(color, RichText::new("●").size(18.0));
                    ui.strong(label);
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Management mode");
                    ui.strong(if self.management_enabled { "Managed" } else { "Maintenance" });
                });
                ui.small("Maintenance clears app restrictions while health reporting stays available.");
                ui.add_space(10.0);
                let app_locked = self.management_enabled && self.pin_verifier.is_some() && !self.unlocked;
                if app_locked {
                    ui.strong("App details are PIN protected");
                    ui.small("Use the PIN supplied by your financing administrator. This is not your Windows password.");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.pin_attempt).password(true).hint_text("Managed PIN").char_limit(12));
                        if ui.add_enabled(self.unlock_rx.is_none() && Instant::now() >= self.next_pin_attempt, egui::Button::new("Unlock app")).clicked() {
                            self.unlock();
                        }
                    });
                } else {
                egui::Grid::new("device_details")
                    .num_columns(2)
                    .spacing([18.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Device ID");
                        ui.monospace(&self.device_id);
                        ui.end_row();
                        ui.label("Server");
                        ui.label(&self.server);
                        ui.end_row();
                        ui.label("Agent version");
                        ui.label(env!("CARGO_PKG_VERSION"));
                        ui.end_row();
                    });
                    if self.unlocked && ui.button("Lock app details").clicked() {
                        self.unlocked = false;
                    }
                }
            });
        }

        fn unlock(&mut self) {
            let Some(verifier) = self.pin_verifier.clone() else {
                return;
            };
            let pin = std::mem::take(&mut self.pin_attempt);
            let (sender, receiver) = mpsc::channel();
            self.unlock_rx = Some(receiver);
            thread::spawn(move || {
                let _ = sender.send(super::pin_matches(&pin, &verifier));
            });
        }
    }

    impl eframe::App for DeviceApp {
        fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
            context.request_repaint_after(Duration::from_secs(2));
            if self.last_policy_refresh.elapsed() >= Duration::from_secs(5) {
                self.refresh_policy();
            }
            if let Some(receiver) = &self.unlock_rx {
                if let Ok(valid) = receiver.try_recv() {
                    self.unlocked = valid;
                    self.status = if valid {
                        "App screen unlocked"
                    } else {
                        "Incorrect PIN"
                    }
                    .into();
                    self.next_pin_attempt = Instant::now() + Duration::from_secs(3);
                    self.unlock_rx = None;
                } else {
                    context.request_repaint_after(Duration::from_millis(100));
                }
            }
            if let Some(receiver) = &self.result_rx {
                if let Ok(result) = receiver.try_recv() {
                    self.status = result;
                    self.service_running = service_is_running();
                    self.result_rx = None;
                } else {
                    context.request_repaint_after(Duration::from_millis(200));
                }
            }

            egui::CentralPanel::default().show(context, |ui| {
                ui.add_space(10.0);
                ui.heading(RichText::new("EMI Device").size(28.0));
                ui.label("Payment-plan device management");
                ui.add_space(20.0);

                if let Some(notice) = &self.payment_notice {
                    if self.dismissed_notice.as_deref() != Some(notice.created_at.as_str()) {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.strong(&notice.title);
                            ui.label(&notice.message);
                            if ui.button("Dismiss this notice").clicked() {
                                self.dismissed_notice = Some(notice.created_at.clone());
                            }
                        });
                        ui.add_space(12.0);
                    }
                }

                self.render_device_card(ui);

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.result_rx.is_none(), egui::Button::new("Check in now (admin)"))
                        .clicked()
                    {
                        self.check_now();
                    }
                    if ui.button("Refresh status").clicked() {
                        self.refresh();
                    }
                    if ui.button("Open admin portal").clicked() {
                        self.open_portal();
                    }
                });
                ui.add_space(12.0);
                ui.label(&self.status);
                ui.add_space(18.0);
                ui.separator();
                ui.small("The background service continues health reporting and payment notifications when this window is closed. An authorized administrator retains recovery and uninstall access.");
            });
        }
    }

    fn read_config() -> Result<AgentConfig, String> {
        let path = program_data()?
            .join("EmiDeviceAgent")
            .join("ui-config.json");
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }

    fn program_data() -> Result<PathBuf, String> {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "PROGRAMDATA is unavailable".into())
    }

    fn agent_path() -> Result<PathBuf, String> {
        let current = std::env::current_exe().map_err(|error| error.to_string())?;
        Ok(current.with_file_name("emi-device-agent.exe"))
    }

    fn service_is_running() -> bool {
        use std::os::windows::process::CommandExt as _;
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
                .with_inner_size([680.0, 500.0])
                .with_min_inner_size([560.0, 450.0]),
            ..Default::default()
        };
        eframe::run_native(
            "EMI Device",
            options,
            Box::new(|_context| Ok(Box::new(DeviceApp::load()))),
        )
    }
}

#[cfg(any(windows, test))]
fn pin_matches(pin: &str, verifier: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    PasswordHash::new(verifier).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(pin.as_bytes(), &hash)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

    #[test]
    fn app_pin_accepts_only_the_correct_verifier() {
        let salt = SaltString::encode_b64(b"test-salt-for-ui").expect("salt");
        let verifier = Argon2::default()
            .hash_password(b"294817", &salt)
            .expect("hash")
            .to_string();
        assert!(super::pin_matches("294817", &verifier));
        assert!(!super::pin_matches("wrong", &verifier));
        assert!(!super::pin_matches("294817", "invalid-verifier"));
    }
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    windows_app::run()
}
