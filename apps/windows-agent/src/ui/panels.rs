//! The non-locked tabs: overview/health, firmware prep, and restriction setup
//! plus the manual lock controls that drive the provisioning scripts.

use std::fs;
use std::io::Write as _;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32};
use emi_core::BiosProvider;
use qrcode::{Color, QrCode};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use super::app::{BiosPasswordAction, DeviceApp, OperationEvent};
use super::system::{
    CREATE_NO_WINDOW, agent_path, bios_adapter_status, read_health, service_is_running,
};
use crate::bluescreen::BluescreenSession;

fn provider_name(provider: BiosProvider) -> &'static str {
    match provider {
        BiosProvider::Dell => "Dell",
        BiosProvider::Hp => "HP",
        BiosProvider::Lenovo => "Lenovo",
        BiosProvider::Asus => "Asus",
        BiosProvider::Acer => "Acer",
        BiosProvider::Unsupported => "Other",
    }
}

fn adjacent_script(name: &str) -> Result<PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("Cannot locate {name}: {error}"))?
        .with_file_name(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("{name} was not found beside the app."))
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn read_progress(path: &Path) -> Option<(f32, String)> {
    let value = fs::read_to_string(path).ok()?;
    let (percent, message) = value
        .trim_start_matches('\u{feff}')
        .trim()
        .split_once('|')?;
    Some((percent.parse::<f32>().ok()? / 100.0, message.to_string()))
}

fn run_elevated_script(
    script: &Path,
    arguments: &[(&str, &str)],
    progress_path: &Path,
    tx: &Sender<OperationEvent>,
) -> Result<(), String> {
    let mut items = vec![
        powershell_quote("-NoProfile"),
        powershell_quote("-NonInteractive"),
        powershell_quote("-ExecutionPolicy"),
        powershell_quote("Bypass"),
        powershell_quote("-File"),
        powershell_quote(&script.to_string_lossy()),
    ];
    for (name, value) in arguments {
        items.push(powershell_quote(name));
        items.push(powershell_quote(value));
    }
    let outer = format!(
        "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath 'powershell.exe' -ArgumentList {} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
        items.join(",")
    );
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &outer])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut last_progress = None;
    let mut last_message = None;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let _ = fs::remove_file(progress_path);
            return if status.success() {
                Ok(())
            } else {
                Err(last_message.unwrap_or_else(|| {
                    format!("administrator action canceled or failed: {status}")
                }))
            };
        }
        if let Some((fraction, message)) = read_progress(progress_path)
            && last_progress != Some(fraction)
        {
            let _ = tx.send(OperationEvent::Progress {
                fraction,
                message: message.clone(),
            });
            last_progress = Some(fraction);
            last_message = Some(message);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn protect_secret(secret: &str) -> Result<String, String> {
    let command = "$v=[Console]::In.ReadToEnd(); $b=[Text.Encoding]::UTF8.GetBytes($v); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)); [Array]::Clear($b,0,$b.Length)";
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("could not protect credentials: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open the credential protector".to_string())?
        .write_all(secret.as_bytes())
        .map_err(|error| format!("could not protect credentials: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("credential protector failed: {error}"))?;
    if !output.status.success() {
        return Err("Windows could not protect the BIOS credentials".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "Windows returned an invalid protected credential".into())
}

impl DeviceApp {
    fn render_bios_action_selector(&mut self, ui: &mut egui::Ui) -> BiosPasswordAction {
        ui.label("What do you want to do?");
        let previous_action = self.bios_password_action;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut self.bios_password_action,
                BiosPasswordAction::Create,
                "Enable / create new",
            );
            ui.selectable_value(
                &mut self.bios_password_action,
                BiosPasswordAction::Change,
                "Change password",
            );
            ui.selectable_value(
                &mut self.bios_password_action,
                BiosPasswordAction::Disable,
                "Disable password",
            );
        });
        if previous_action != self.bios_password_action {
            self.clear_passwords();
        }
        let action = self.bios_password_action;
        ui.small(match action {
            BiosPasswordAction::Create => {
                "Use this when the laptop does not currently have a BIOS administrator password."
            }
            BiosPasswordAction::Change => {
                "Enter the existing password, then choose its replacement."
            }
            BiosPasswordAction::Disable => {
                "Remove the existing BIOS password. This reduces firmware protection."
            }
        });
        action
    }

    fn render_bios_password_fields(&mut self, ui: &mut egui::Ui, action: BiosPasswordAction) {
        if action != BiosPasswordAction::Create {
            ui.label("Current BIOS password");
            ui.add(
                egui::TextEdit::singleline(&mut *self.current_password)
                    .password(true)
                    .desired_width(360.0)
                    .char_limit(128),
            );
            ui.add_space(10.0);
        }
        if action != BiosPasswordAction::Disable {
            for (label, value) in [
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
        }
        if action == BiosPasswordAction::Disable {
            ui.checkbox(
                &mut self.confirm_disable_bios,
                "I understand this removes the BIOS administrator password",
            );
            ui.add_space(8.0);
        }
    }

    fn render_bios_adapter(
        &mut self,
        ui: &mut egui::Ui,
        provider: BiosProvider,
        adapter_present: bool,
        adapter_status: &str,
    ) {
        let color = if adapter_present {
            Color32::from_rgb(30, 150, 85)
        } else {
            Color32::from_rgb(230, 180, 100)
        };
        ui.colored_label(color, adapter_status);
        if matches!(provider, BiosProvider::Dell | BiosProvider::Hp) {
            if ui
                .add_enabled(
                    self.result_rx.is_none(),
                    egui::Button::new("Download & install OEM adapter (admin)"),
                )
                .clicked()
            {
                self.install_bios_adapter();
            }
            ui.small("Download and installation progress is shown below. Dell uses WinGet; HP uses the PowerShell Gallery.");
        } else if provider == BiosProvider::Asus && !adapter_present {
            ui.small("Install ASUS BIOS Configuration Tool (ACT) from the support page for this exact business model, then reopen this screen.");
        } else if provider == BiosProvider::Lenovo {
            ui.small("No download is needed. Lenovo exposes its supported password-change interface through built-in WMI.");
        } else {
            ui.small("This manufacturer does not expose a safe universal Windows password API. Use the UEFI fallback below.");
        }
    }

    fn render_firmware_fallback(&mut self, ui: &mut egui::Ui) {
        ui.add_space(18.0);
        ui.separator();
        ui.label("Universal fallback");
        ui.checkbox(
            &mut self.confirm_firmware_restart,
            "I have saved my work and want to restart into UEFI firmware settings",
        );
        if ui
            .add_enabled(
                self.confirm_firmware_restart && self.result_rx.is_none(),
                egui::Button::new("Restart into UEFI settings"),
            )
            .clicked()
        {
            self.restart_into_firmware();
        }
        ui.small("Available on UEFI systems from Acer, ASUS, Dell, HP, Lenovo, Microsoft, MSI, Samsung, and other manufacturers. The firmware screen itself controls which password types the model supports.");
    }

    pub(crate) fn render_firmware(&mut self, ui: &mut egui::Ui) {
        ui.heading("BIOS password");
        ui.label("Create, replace, or remove this laptop's BIOS administrator password.");
        ui.add_space(12.0);
        let provider = self
            .health
            .as_ref()
            .map_or(BiosProvider::Unsupported, |health| health.bios_provider);
        if let Some(health) = &self.health {
            let manufacturer = if health.manufacturer.is_empty() {
                provider_name(provider)
            } else {
                &health.manufacturer
            };
            let model = if health.model.is_empty() {
                "Model not reported"
            } else {
                &health.model
            };
            ui.label(format!("Detected device: {manufacturer} {model}"));
        }
        let (adapter_present, adapter_status) = bios_adapter_status(provider);
        ui.add_space(16.0);
        self.render_bios_password_controls(ui, provider, adapter_present, &adapter_status);
    }

    fn render_bios_password_controls(
        &mut self,
        ui: &mut egui::Ui,
        provider: BiosProvider,
        adapter_present: bool,
        adapter_status: &str,
    ) {
        let action = self.render_bios_action_selector(ui);
        ui.add_space(14.0);
        self.render_bios_password_fields(ui, action);
        if action != BiosPasswordAction::Disable
            && !self.confirm_password.is_empty()
            && self.new_password != self.confirm_password
        {
            ui.colored_label(Color32::LIGHT_RED, "New passwords do not match.");
        }
        let has_line_break = self
            .current_password
            .chars()
            .chain(self.new_password.chars())
            .any(|character| matches!(character, '\r' | '\n' | '\0'));
        if has_line_break {
            ui.colored_label(
                Color32::LIGHT_RED,
                "BIOS passwords cannot contain line breaks or NUL characters.",
            );
        }
        let lenovo_delimiter = provider == BiosProvider::Lenovo
            && self
                .current_password
                .chars()
                .chain(self.new_password.chars())
                .any(|character| character == ';');
        if lenovo_delimiter {
            ui.colored_label(
                Color32::LIGHT_RED,
                "Lenovo's WMI interface cannot safely accept a semicolon in a password.",
            );
        }
        let provider_supported =
            adapter_present && !matches!(provider, BiosProvider::Acer | BiosProvider::Unsupported);
        let action_supported =
            !(provider == BiosProvider::Lenovo && action == BiosPasswordAction::Create);
        if !action_supported {
            ui.colored_label(
                Color32::from_rgb(230, 180, 100),
                "Lenovo requires the first supervisor password to be created in UEFI setup. After that, this app can change or disable it.",
            );
        }
        let fields_valid = match action {
            BiosPasswordAction::Create => {
                !self.new_password.is_empty() && self.new_password == self.confirm_password
            }
            BiosPasswordAction::Change => {
                !self.current_password.is_empty()
                    && !self.new_password.is_empty()
                    && self.new_password == self.confirm_password
            }
            BiosPasswordAction::Disable => {
                !self.current_password.is_empty() && self.confirm_disable_bios
            }
        } && !has_line_break
            && !lenovo_delimiter;
        let action_label = match action {
            BiosPasswordAction::Create => "Enable BIOS password",
            BiosPasswordAction::Change => "Change BIOS password",
            BiosPasswordAction::Disable => "Disable BIOS password",
        };
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    provider_supported
                        && action_supported
                        && fields_valid
                        && self.result_rx.is_none(),
                    egui::Button::new(action_label),
                )
                .clicked()
            {
                self.apply_bios_password(provider, action);
            }
            if ui.button("Clear fields").clicked() {
                self.clear_passwords();
            }
        });
        ui.small("Administrator approval is required. Credentials are masked, DPAPI-protected while crossing the UAC boundary, deleted immediately afterward, never logged, and cleared when you leave this tab.");

        if let Some(progress) = self.operation_progress {
            ui.add_space(14.0);
            ui.add(
                egui::ProgressBar::new(progress)
                    .show_percentage()
                    .text(&self.operation_label),
            );
        }
        ui.add_space(8.0);
        ui.label(&self.status);

        ui.add_space(12.0);
        ui.collapsing("OEM adapter and compatibility", |ui| {
            self.render_bios_adapter(ui, provider, adapter_present, adapter_status);
        });

        if !provider_supported {
            ui.colored_label(
                Color32::from_rgb(230, 180, 100),
                "Direct desktop changes are not available for this model. Use the UEFI option below.",
            );
        }

        self.render_firmware_fallback(ui);
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
        if !matches!(provider, BiosProvider::Dell | BiosProvider::Hp) {
            self.status = "This manufacturer has no automatic adapter download.".into();
            return;
        }
        let script = match adjacent_script("Install-BiosAdapter.ps1") {
            Ok(path) => path,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let progress_path =
            std::env::temp_dir().join(format!("emi-bios-progress-{}.txt", Uuid::new_v4()));
        self.status = "Downloading the OEM firmware adapter…".into();
        self.operation_progress = Some(0.01);
        self.operation_label = "Preparing download".into();
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);
        thread::spawn(move || {
            let provider = provider_name(provider);
            let progress = progress_path.to_string_lossy().into_owned();
            let result = run_elevated_script(
                &script,
                &[("-Provider", provider), ("-ProgressPath", &progress)],
                &progress_path,
                &tx,
            )
            .map_or_else(
                |error| format!("Adapter installation failed: {error}"),
                |()| "OEM firmware adapter installed and ready.".into(),
            );
            let _ = tx.send(OperationEvent::Finished(result));
        });
    }

    fn apply_bios_password(&mut self, provider: BiosProvider, action: BiosPasswordAction) {
        if self.result_rx.is_some() {
            return;
        }
        let script = match adjacent_script("Manage-BiosPassword.ps1") {
            Ok(path) => path,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let current = Zeroizing::new(std::mem::take(&mut *self.current_password));
        let new = Zeroizing::new(std::mem::take(&mut *self.new_password));
        self.confirm_password.zeroize();
        self.confirm_disable_bios = false;
        let identifier = Uuid::new_v4();
        let secret_path = std::env::temp_dir().join(format!("emi-bios-secrets-{identifier}.json"));
        let progress_path =
            std::env::temp_dir().join(format!("emi-bios-progress-{identifier}.txt"));
        self.status = format!("Applying {} BIOS password action…", provider_name(provider));
        self.operation_progress = Some(0.01);
        self.operation_label = "Protecting credentials".into();
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);
        thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let protected_current = if current.is_empty() {
                    String::new()
                } else {
                    protect_secret(&current)?
                };
                let protected_new = if new.is_empty() {
                    String::new()
                } else {
                    protect_secret(&new)?
                };
                let payload = serde_json::json!({
                    "current": protected_current,
                    "new": protected_new,
                });
                fs::write(
                    &secret_path,
                    serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("could not stage protected credentials: {error}"))?;
                let provider = provider_name(provider);
                let secret = secret_path.to_string_lossy().into_owned();
                let progress = progress_path.to_string_lossy().into_owned();
                run_elevated_script(
                    &script,
                    &[
                        ("-Provider", provider),
                        ("-Mode", action.script_mode()),
                        ("-SecretPath", &secret),
                        ("-ProgressPath", &progress),
                    ],
                    &progress_path,
                    &tx,
                )
            })();
            let _ = fs::remove_file(&secret_path);
            let message = result.map_or_else(
                |error| format!("BIOS password action failed: {error}"),
                |()| match action {
                    BiosPasswordAction::Create => "BIOS password enabled. Restart the PC before relying on the new credential.".into(),
                    BiosPasswordAction::Change => "BIOS password changed. Restart the PC before relying on the new credential.".into(),
                    BiosPasswordAction::Disable => "BIOS password disabled. Restart the PC to confirm the firmware state.".into(),
                },
            );
            let _ = tx.send(OperationEvent::Finished(message));
        });
    }

    fn restart_into_firmware(&mut self) {
        self.clear_passwords();
        self.confirm_firmware_restart = false;
        let command = "$ErrorActionPreference='Stop'; Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r','/fw','/t','0' -Verb RunAs -Wait";
        let result = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", command])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        self.status = match result {
            Ok(status) if status.success() => "Restarting into UEFI firmware settings…".into(),
            Ok(status) => format!("Windows could not schedule the UEFI restart: {status}"),
            Err(error) => format!("Windows could not open UEFI settings: {error}"),
        };
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
            let _ = tx.send(OperationEvent::Finished(result));
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
            let _ = tx.send(OperationEvent::Finished(result));
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
                            (
                                "Manufacturer",
                                if health.manufacturer.is_empty() {
                                    provider_name(health.bios_provider).into()
                                } else {
                                    health.manufacturer.clone()
                                },
                            ),
                            (
                                "Model",
                                if health.model.is_empty() {
                                    "Not reported".into()
                                } else {
                                    health.model.clone()
                                },
                            ),
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
