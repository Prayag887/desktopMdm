# desktopMdm — desktop only

A lightweight, standalone Windows desktop app written in Rust with a native egui/eframe GUI. No admin website, hosted backend, Docker deployment, enrollment or socket client remains.

## What remains

- Native desktop window: local device identity, operating system, storage, battery, Secure Boot status, and manufacturer detection.
- BIOS password preparation form with masked current/new/confirmation fields. Actual writes are disabled until a supported, exact-model OEM adapter is implemented. Passwords are never saved or sent to the QR page and are cleared when leaving the tab.
- Permission-gated fullscreen blue-screen **simulation**, with a QR dismissal page served temporarily by the desktop app on one private LAN interface. No actual crash or OS lockout.
- Optional Windows companion service: refreshes a local health snapshot every five minutes and after resume.
- Local device/EMI domain types for future desktop workflows.
- Administrator installer/uninstaller and Windows builds in GitHub Actions.

This is the desktop-only foundation, not a complete EMI administration product. Payment editing, reminder scheduling, local administrator controls, BIOS password changes, Windows account password changes, and remote device control are not implemented in this version. They must be designed as desktop workflows separately. The app is normally uninstallable by an authorized administrator.

## Blue screen mode

Open Blue screen mode, verify the PC's private IPv4 address, acknowledge permission, and check Show simulated blue screen. The blue screen displays a QR code. On a phone on the same trusted network, scan it and tap Dismiss simulated blue screen. Merely scanning/opening the link does not dismiss it.

Escape does not dismiss Blue screen mode. The explicit Exit button, closing the app, rebooting, or the five-minute safety timeout ends the simulation. OS recovery keys and switching applications remain available. The simulation is memory-only: restarting always starts unchecked, and it never alters firmware or Windows settings.

Windows Firewall may ask for Private-network access; the app does not change firewall rules itself. Guest-network isolation/VPNs may prevent phone access. The loopback fallback `127.0.0.1` works only on the PC. The single-use QR link grants dismissal only, uses plain HTTP on the LAN, expires with the session, and should not be shared outside the trusted network. No separate server deployment is required.

## Windows setup

Download the current desktop-only Windows release, extract it, and open **emi-device-ui.exe** for the native window. The window opens without enrollment or a configured server. Health is shown after the local companion has initialized this PC.

For installation, open PowerShell as administrator in the extracted folder:

```powershell
.\\install.ps1
```

The installer copies both binaries, initializes a local identity, collects health, installs the auto-start companion service, creates the desktop app startup shortcut, and opens the window. No username, password, server URL, or enrollment key is required.

WinGet bootstrap downloads Microsoft Desktop App Installer only when WinGet is missing. For an offline install or when bootstrap is unwanted:

```powershell
.\\install.ps1 -SkipWingetBootstrap
```

To uninstall, run `.\\uninstall.ps1` as administrator. Local data is retained for recovery.

## Local data and migration

State lives in `%PROGRAMDATA%\\EmiDeviceAgent`:

- `config.json` / `ui-config.json`: local UUID only.
- `health.json`: local health snapshot, never uploaded.

When the updated companion initializes an existing installation, it reuses the old device UUID and rewrites configuration without the old server/token fields. Other historical device data is not deleted. Corrupt configuration returns an error instead of silently replacing an identity.

The previous local Docker container/network was removed without deleting the database volume. Server source is recoverable from Git history. Historical server-based releases remain available; use version 0.5.0 or later for the desktop-only architecture. An ignored old `.env`, if present, is unused by this app.

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

The GUI is Windows-only; other platforms compile the domain library, QR listener and local-service tests. `cargo run --package emi-device-agent --example qr-preview` previews the exact phone page on loopback without running a prank. GitHub Actions checks the Windows GUI and installer syntax and builds both binaries for tagged releases. Real Windows rendering, fullscreen/Exit behavior, phone/firewall connectivity, UAC, service install/uninstall, and resume still need a PC/VM smoke test.

## Repository

```text
apps/windows-agent/   Native Windows GUI and local companion
crates/emi-core/     Local device health and EMI domain types
packaging/windows/  Installer and uninstaller
.github/workflows/  Rust/Windows CI and desktop release
```
