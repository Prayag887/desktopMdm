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
        time::Duration,
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

    struct DeviceApp {
        server: String,
        device_id: String,
        service_running: bool,
        status: String,
        result_rx: Option<Receiver<String>>,
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
                },
                Err(error) => Self {
                    server: "Not enrolled".into(),
                    device_id: "—".into(),
                    service_running: service_is_running(),
                    status: format!("Configuration error: {error}"),
                    result_rx: None,
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
                        Command::new(agent)
                            .args(["run", "--once"])
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
        }
    }

    impl eframe::App for DeviceApp {
        fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
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

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (label, color) = if self.service_running {
                            ("Protected and connected", Color32::from_rgb(30, 150, 85))
                        } else {
                            ("Service is not running", Color32::from_rgb(210, 65, 65))
                        };
                        ui.colored_label(color, RichText::new("●").size(18.0));
                        ui.strong(label);
                    });
                    ui.separator();
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
                });

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.result_rx.is_none(), egui::Button::new("Check in now"))
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
                ui.small("The background service continues health reporting and payment notifications when this window is closed.");
            });
        }
    }

    fn read_config() -> Result<AgentConfig, String> {
        let path = program_data()?.join("EmiDeviceAgent").join("config.json");
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
                .with_inner_size([620.0, 400.0])
                .with_min_inner_size([520.0, 340.0]),
            ..Default::default()
        };
        eframe::run_native(
            "EMI Device",
            options,
            Box::new(|_context| Ok(Box::new(DeviceApp::load()))),
        )
    }
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    windows_app::run()
}
