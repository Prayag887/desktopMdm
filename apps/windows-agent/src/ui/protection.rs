//! Render cached service diagnostics without privileged commands or WMI in the UI.
use super::app::DeviceApp;
use crate::protection::model::{DeviceProtectionStatus, State};
use chrono::Utc;
use eframe::egui::{self, Color32};

pub(crate) fn read_status() -> Option<DeviceProtectionStatus> {
    let directory =
        std::path::PathBuf::from(std::env::var_os("PROGRAMDATA")?).join("EmiDeviceAgent");
    serde_json::from_slice(&std::fs::read(directory.join("protection-status.json")).ok()?).ok()
}

pub(crate) fn read_error() -> Option<String> {
    let directory =
        std::path::PathBuf::from(std::env::var_os("PROGRAMDATA")?).join("EmiDeviceAgent");
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("protection-error.json")).ok()?)
            .ok()?;
    value["detail"].as_str().map(str::to_owned)
}

impl DeviceApp {
    pub(crate) fn render_protection(&self, ui: &mut egui::Ui) {
        ui.separator();
        ui.heading("Device Protection");
        if let Some(error) = &self.protection_error {
            ui.colored_label(Color32::LIGHT_RED, format!("Verification failed: {error}"));
        }
        let Some(status) = &self.protection else {
            ui.label("Protection status unavailable; waiting for a verified service snapshot.");
            return;
        };
        let stale = Utc::now()
            .signed_duration_since(status.last_verified_at)
            .num_seconds()
            > 600;
        if stale || !self.service_running {
            ui.colored_label(Color32::YELLOW, "Status is stale or core service is stopped; current protection cannot be confirmed.");
        } else if self.protection_error.is_none() {
            ui.label(format!("Overall: {:?}", status.overall()));
        }
        for (name, check) in [
            ("NTFS Application Protection", &status.acl_protection),
            ("Core SYSTEM Service", &status.core_service),
            ("Watchdog", &status.watchdog),
            ("File Integrity", &status.integrity),
            ("BitLocker", &status.bit_locker.check),
            ("TPM", &status.tpm.check),
            ("Secure Boot", &status.secure_boot.check),
        ] {
            let color = match check.state {
                State::Protected => Color32::from_rgb(30, 150, 85),
                State::Error => Color32::LIGHT_RED,
                _ => Color32::YELLOW,
            };
            ui.collapsing(format!("{name}: {:?}", check.state), |ui| {
                ui.colored_label(color, &check.detail);
                let details = match name {
                    "BitLocker" => serde_json::to_string_pretty(&status.bit_locker).ok(),
                    "TPM" => serde_json::to_string_pretty(&status.tpm).ok(),
                    "Secure Boot" => serde_json::to_string_pretty(&status.secure_boot).ok(),
                    _ => None,
                };
                if let Some(details) = details {
                    ui.monospace(details);
                }
            });
        }
        ui.small(format!("Last verified: {}", status.last_verified_at));
    }
}
