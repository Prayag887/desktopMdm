# desktopMdm — managed Windows EMI agent

A Windows device agent written in Rust with a native egui/eframe GUI. It enrolls against the YajTech EMI admin API and applies administrator-issued lock state on the managed PC.

## What remains

- Native desktop window: local device identity, operating system, storage, battery, Secure Boot status, and manufacturer detection.
- BIOS administrator-password workflow with masked current/new/confirmation fields, OEM adapter download progress, manufacturer/model detection, and elevated set/change actions for supported Dell, HP, Lenovo, and ASUS firmware interfaces. Acer and every other UEFI laptop can be restarted directly into firmware settings from the same screen.
- Administrator-controlled payment restriction screen driven by the documented Device Agent API.
- Automatic enrollment retry, immediate boot/resume check-in, 60-second heartbeats, pending-command fetch, patch checksum validation, and success/failure acknowledgement.
- Windows companion service that persists the last confirmed remote state so a restart or temporary outage cannot silently change the administrator's decision.
- Local device/EMI domain types for future desktop workflows.
- Administrator installer/uninstaller and Windows builds in GitHub Actions.

Payment and customer administration remain in the hosted admin product. BIOS password management is local-only, requires UAC approval, and is enabled only when the detected model exposes a documented OEM interface. The app remains uninstallable by an authorized administrator.

## BIOS passwords

Open **BIOS passwords** to install the detected OEM adapter and watch its staged download/install progress. Enter matching new-password values, plus the current password when changing an existing credential. Dell uses Command | Configure, HP uses CMSL, Lenovo uses built-in WMI for changes, and compatible ASUS business devices use ACT. Lenovo requires the first supervisor password to be created in UEFI setup; Acer does not publish a universal in-Windows adapter. The **Restart into UEFI settings** fallback covers those devices and other manufacturers.

Firmware support is model-specific even within one brand. The app verifies that the vendor tool or interface exists and reports the OEM error instead of trying an unrecognized generic command. Forgotten passwords cannot be recovered by this app.

## Administrator-controlled locking

Before installation, create the device in the admin system using the laptop's BIOS serial number, then create its **PENDING Device Agent**. The installer calls `/api/agent/enroll/`; the Windows service retries enrollment every five minutes if the pending record is not ready yet.

Once enrolled, the service calls `/api/agent/check-in/` immediately on service startup and resume, and every 60 seconds. Pending commands are fetched from `/api/agent/patch-files/current/`, validated against command metadata, expiry, size, and SHA-256 checksum, persisted locally, and acknowledged only after application. `LOCK` restricts the UI; `UNLOCK`, `WARN`, and `RELEASE` remove the restriction. Remote `UNINSTALL` is deliberately refused and reported as failed because removal requires a local administrator.

There are no local lock/unlock buttons. The status page shows the server state, reason, managed device UUID, and last successful check-in. If the network is unavailable during boot, the last confirmed state remains active until the service reconnects.

## Windows setup

Download the Windows release and extract it. In the admin panel, create the pending device agent for the laptop's BIOS serial before installation.

For installation, open PowerShell as administrator in the extracted folder:

```powershell
.\\install.ps1
```

The installer copies both binaries, reads the BIOS serial, enrolls with `https://emi-api.yajtech.com`, collects health, installs the automatic service, creates the UI startup shortcut, and opens the window. Enrollment uses the one-time pending-agent workflow documented by the API; no admin username or password is stored on the PC.

WinGet bootstrap downloads Microsoft Desktop App Installer only when WinGet is missing. For an offline install or when bootstrap is unwanted:

```powershell
.\\install.ps1 -SkipWingetBootstrap
```

To uninstall, run `.\\uninstall.ps1` as administrator. Local data is retained for recovery.

## Local data and migration

State lives in `%PROGRAMDATA%\\EmiDeviceAgent`:

- `config.json`: service-only API URL, bearer token, and local/remote device IDs. Its ACL permits only SYSTEM and Administrators.
- `ui-config.json`: non-secret enrollment metadata for the desktop UI.
- `remote-state.json`: last successfully confirmed server lock state and check-in time.
- `health.json`: local health snapshot, including manufacturer/model.

When the companion initializes an existing installation, it reuses the old local device UUID. Incomplete legacy credentials are discarded; a complete current enrollment is retained. Other historical device data is not deleted. Corrupt configuration returns an error instead of silently replacing an identity.

The desktop agent does not run a local Docker backend. An ignored old `.env`, if present, is unused by this app.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Windows:

```powershell
cargo run --package emi-device-agent --bin emi-device-ui
cargo run --package emi-device-agent --bin emi-device-agent -- run --once
```

The GUI is Windows-only; other platforms compile the domain library, QR listener and local-service tests. `cargo run --package emi-device-agent --example qr-preview` previews the exact phone page on loopback without running a bluescreen. GitHub Actions checks the Windows GUI and installer syntax and builds both binaries for tagged releases. Real Windows rendering, fullscreen/Exit behavior, phone/firewall connectivity, UAC, service install/uninstall, and resume still need a PC/VM smoke test.

## Repository

```text
apps/windows-agent/   Native Windows GUI and local companion
crates/emi-core/     Local device health and EMI domain types
packaging/windows/  Installer and uninstaller
.github/workflows/  Rust/Windows CI and desktop release
```
