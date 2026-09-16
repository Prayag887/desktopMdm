#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("EMI Device UI is available only on Windows");
}

#[cfg(windows)]
mod windows_app {
    use eframe::egui::{self, Color32, RichText};
    use emi_core::{BiosProvider, DeviceHealth};
    use std::os::windows::process::CommandExt as _;
    use std::{
        fs,
        path::PathBuf,
        process::Command,
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    struct DeviceApp {
        health: Option<DeviceHealth>,
        service_running: bool,
        status: String,
        result_rx: Option<Receiver<String>>,
        last_refresh: Instant,
    }

    impl DeviceApp {
        fn load() -> Self {
            Self {
                health: read_health(),
                service_running: service_is_running(),
                status: "Standalone mode — no server or enrollment required".into(),
                result_rx: None,
                last_refresh: Instant::now(),
            }
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
                    ui.add_space(12.0);
                    ui.label(&self.status);
                    ui.separator();
                    ui.small("All device data stays on this PC. No web portal, backend, remote commands, or socket connection. An administrator can uninstall the companion normally.");
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
                .with_inner_size([680.0, 600.0])
                .with_min_inner_size([560.0, 450.0]),
            ..Default::default()
        };
        eframe::run_native(
            "EMI Device",
            options,
            Box::new(|_context| Ok(Box::new(DeviceApp::load()))),
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
