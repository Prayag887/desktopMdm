//! Embed a Windows version resource so Task Manager (Processes/Details), the
//! services console, and the file property sheet show a neutral "Windows
//! Watchdog" descriptor instead of the raw executable name.
//!
//! This is display metadata only. The executable file names stay fixed on
//! purpose: the signed release manifest (`protection-manifest.ps1`) and the
//! integrity allow-list (`protection::integrity::REQUIRED`) key off the exact
//! names, so renaming a file in the installation folder is rejected as tamper.
//! The resource bytes are covered by the per-release SHA-256 manifest generated
//! in CI, so embedding this needs no manifest edit.
//!
//! The same resource is linked into every binary the crate builds
//! (emi-device-agent, emi-device-ui, emi-device-updater, RepairWatchdog).

#[cfg(windows)]
fn main() {
    let mut resource = winresource::WindowsResource::new();
    // Blank OriginalFilename/InternalName so the property sheet does not leak the
    // real binary name. FileDescription is the string Task Manager surfaces.
    resource.set("FileDescription", "Windows Watchdog");
    resource.set("ProductName", "Windows Watchdog");
    resource.set("InternalName", "Windows Watchdog");
    resource.set("OriginalFilename", "");
    resource.set("CompanyName", "Windows Watchdog");
    resource
        .compile()
        .expect("embed Windows version resource");
}

#[cfg(not(windows))]
fn main() {}
