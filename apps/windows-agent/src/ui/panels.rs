//! The non-locked tabs: overview/health, firmware prep, and restriction setup
//! plus the manual lock controls that drive the provisioning scripts.

use std::os::windows::process::CommandExt as _;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use base64::Engine as _;
use eframe::egui::{self, Color32};
use emi_core::BiosProvider;
use qrcode::{Color, QrCode};

use super::app::DeviceApp;
use super::system::{
    CREATE_NO_WINDOW, agent_path, bios_adapter_status, read_health, service_is_running,
};
use crate::bluescreen::BluescreenSession;

impl DeviceApp {
    pub(crate) fn render_firmware(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firmware credentials");
        ui.label("Prepare a BIOS password change");
        ui.add_space(12.0);
        let provider = self
            .health
            .as_ref()
            .map_or(BiosProvider::Unsupported, |health| health.bios_provider);
        let (adapter_present, adapter_status) = bios_adapter_status(provider);
        let color = if adapter_present {
            Color32::from_rgb(30, 150, 85)
        } else {
            Color32::from_rgb(230, 180, 100)
        };
        ui.colored_label(color, &adapter_status);
        if ui
            .add_enabled(
                self.result_rx.is_none(),
                egui::Button::new("Check & install OEM adapter (admin)"),
            )
            .clicked()
        {
            self.install_bios_adapter();
        }
        ui.small("Fully automatic: fetches winget first if the device lacks it, then installs the signed OEM tool via winget (Dell) or PSGallery (HP). Lenovo needs none. This never writes to firmware; applying a password stays disabled pending exact-model support and testing.");
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

    /// Auto-install the OEM firmware adapter for the detected manufacturer from a
    /// signed source (winget for Dell, `PSGallery` for HP), bootstrapping winget
    /// itself first if the device lacks it. Lenovo needs none. This installs a
    /// vendor tool only; it never writes to firmware.
    fn install_bios_adapter(&mut self) {
        if self.result_rx.is_some() {
            return;
        }
        let provider = self
            .health
            .as_ref()
            .map_or(BiosProvider::Unsupported, |health| health.bios_provider);
        // Inner elevated script. The Dell path bootstraps winget automatically
        // (download the official App Installer bundle) when it is missing, then
        // installs the tool. HP uses PSGallery (no winget). Lenovo/other: nothing.
        let inner: &str = match provider {
            BiosProvider::Dell => {
                "if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { $ProgressPreference='SilentlyContinue'; $b=Join-Path $env:TEMP 'winget-bootstrap.msixbundle'; Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile $b; Add-AppxPackage -Path $b; Remove-Item $b -Force -ErrorAction SilentlyContinue } ; winget install --id Dell.CommandConfigure -e --accept-source-agreements --accept-package-agreements"
            }
            BiosProvider::Hp => "Install-Module -Name HPCMSL -Force -AcceptLicense -Scope AllUsers",
            BiosProvider::Lenovo => {
                self.status = "Lenovo uses built-in BIOS WMI; no adapter download needed.".into();
                return;
            }
            BiosProvider::Unsupported => {
                self.status = "Manufacturer not supported; no OEM adapter to install.".into();
                return;
            }
        };
        // Pass the multi-step script as a base64 UTF-16LE -EncodedCommand so its
        // quotes/semicolons survive the elevated Start-Process invocation intact.
        let utf16: Vec<u8> = inner.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        self.status = "Installing OEM adapter (elevated; fetches winget if missing)…".into();
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);
        thread::spawn(move || {
            let outer = format!(
                "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}' -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
            );
            let result = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &outer])
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_or_else(
                    |error| format!("Adapter install failed: {error}"),
                    |status| {
                        if status.success() {
                            "OEM adapter installed.".into()
                        } else {
                            format!("Adapter install canceled or failed: {status}")
                        }
                    },
                );
            let _ = tx.send(result);
        });
    }

    pub(crate) fn render_bluescreen(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
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
                Ok(session) => {
                    // The payment screen's QR encodes this fixed link.
                    let rick_roll = "https://www.youtube.com/watch?v=Aq5WXmQQooo";
                    match QrCode::new(rick_roll) {
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
                    }
                }
                Err(error) => self.status = format!("Simulation could not start: {error}"),
            }
        }
        ui.add_space(12.0);
        ui.label("There is no Exit button while locked. The only way out is typing the unlock word on the on-screen keyboard. A restart just re-locks on boot.");
        ui.small("This does not crash Windows, block OS recovery keys, change BIOS settings, or install a driver. The recovery field stays typable.");

        ui.add_space(20.0);
        ui.separator();
        self.render_manual_lock(ui);
    }

    /// Administrator controls to pick and apply lock methods by hand.
    fn render_manual_lock(&mut self, ui: &mut egui::Ui) {
        ui.heading("Manual lock controls");
        ui.small(
            "Session lock has no Exit button: it clears only when the unlock word is typed on \
             the on-screen keyboard. OS lockdown runs the provisioning script elevated and \
             needs an administrator plus Enterprise/IoT for the keyboard-filter and AppLocker \
             layers. Test on a VM only.",
        );
        ui.add_space(10.0);

        // Manual keyboard kill switch, independent of the lock screen. Toggle it
        // back off with the mouse (the checkbox is a pointer control).
        let mut disabled = self.keyboard_disabled;
        if ui
            .checkbox(&mut disabled, "Disable keyboard now (block every key)")
            .changed()
        {
            self.keyboard_disabled = disabled;
            self.status = if disabled {
                "Keyboard disabled. Uncheck (mouse) to re-enable.".into()
            } else {
                "Keyboard enabled.".into()
            };
        }
        ui.add_space(10.0);

        if ui.button("Lock this session now").clicked() {
            self.manual_lock = true;
            self.status = "Locked. Type the unlock word on the on-screen keyboard to leave.".into();
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

    /// Launch the elevated provisioning/teardown script with the chosen options.
    /// Non-selected layers are skipped. Reversible via the same UI.
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

    pub(crate) fn refresh_health(&mut self) {
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

    pub(crate) fn reload(&mut self) {
        self.health = read_health();
        self.service_running = service_is_running();
        self.last_refresh = Instant::now();
    }

    pub(crate) fn render_health(&self, ui: &mut egui::Ui) {
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
