#![cfg_attr(windows, windows_subsystem = "windows")]

//! Thin entry point. All UI logic lives in `emi_device_agent::ui` so it can be
//! split across small, focused modules and unit-tested.

#[cfg(not(windows))]
fn main() {
    eprintln!("EMI Device UI is available only on Windows");
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    use std::os::windows::process::CommandExt as _;

    let result = emi_device_agent::ui::run();
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
