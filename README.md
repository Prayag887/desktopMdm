# desktopMdm — managed Windows EMI agent

A Windows device agent written in Rust with a native egui/eframe GUI. It enrolls against the YajTech EMI admin API and applies administrator-issued lock state on the managed PC.

## What is implemented

- Native desktop window: local device identity, operating system, storage, battery, Secure Boot status, and manufacturer detection.
- BIOS administrator-password workflow with masked current/new/confirmation fields, OEM adapter download progress, manufacturer/model detection, and elevated set/change actions for supported Dell, HP, Lenovo, and ASUS firmware interfaces. Acer and every other UEFI laptop can be restarted directly into firmware settings from the same screen.
- Administrator-controlled payment restriction screen driven by the documented Device Agent API.
- Automatic enrollment retry, immediate boot/resume check-in, 60-second heartbeats, pending-command fetch, fail-closed Ed25519 verification, rollback/replay protection, patch checksum validation, and success/failure acknowledgement.
- Windows companion service that persists the last confirmed remote state so a restart or temporary outage cannot silently change the administrator's decision.
- Local device/EMI domain types for future desktop workflows.
- Administrator installer/uninstaller and Windows builds in GitHub Actions.

Payment and customer administration remain in the hosted admin product. BIOS password management is local-only, requires UAC approval, and is enabled only when the detected model exposes a documented OEM interface. The app remains uninstallable by an authorized administrator.

## Enterprise anti-theft deployment

This repository provides the Windows agent and its administrator-controlled restriction state. It does **not** make a Windows program undeletable, survive a bare-metal disk image by itself, prevent an SSD owner from formatting the media, or enroll a device into a Microsoft tenant. Those outcomes require an organization-owned deployment stack:

- Register the motherboard/device identity with Windows Autopilot, preferably through the OEM or reseller. Registration and an assigned deployment profile are prerequisites for organizational provisioning to return after Windows Setup or a supported reset.
- Enroll the device in Microsoft Intune and assign this agent as a **Required** Win32 app in SYSTEM context. A detection rule must verify the installed version and service, so Intune offers the package again when it is missing.
- On supported, OEM-enabled hardware, use DFCI policy to manage permitted UEFI settings such as external boot. DFCI is not available on every Dell, ASUS, Acer, or other model and cannot be emulated safely by this application.
- Require TPM 2.0, Secure Boot, and BitLocker with recovery keys escrowed to the organization. BitLocker protects data on a removed SSD; it cannot prevent the physical owner from erasing or replacing that SSD.

After a standard reset, the expected recovery chain is Windows OOBE → Autopilot tenant recognition → Microsoft Entra/Intune enrollment → required-app installation → agent enrollment/check-in. The current API's one-time enrollment rule blocks that last step after a clean reinstall unless an administrator can reset/reissue enrollment for the asset; see the [Intune deployment guide](packaging/windows/intune/README.md). A completely offline installation, unsupported recovery image, motherboard replacement, or deliberate hardware attack can also break the chain. See [Enterprise anti-theft deployment](docs/enterprise-antitheft-deployment.md) for prerequisites, rollout, recovery, and acceptance tests.

For an existing organization-owned laptop, the [Intune deployment guide](packaging/windows/intune/README.md) includes an Autopilot hardware-hash export helper and the tenant setup sequence for a Standard-user profile, Required-app installation, BitLocker recovery-key escrow, and compliance policy.

The current Device Agent API has no separate `LOST` action. Until the server contract adds one, operators may use `LOCK` with a non-sensitive ownership/return message as the reason. The client must not infer theft from missed check-ins, and it must never transmit location or personal data that the API has not explicitly authorized.

## BIOS passwords

Open **BIOS passwords** to install the detected OEM adapter and watch its staged download/install progress. Enter matching new-password values, plus the current password when changing an existing credential. Dell uses Command | Configure, HP uses CMSL, Lenovo uses built-in WMI for changes, and compatible ASUS business devices use ACT. Lenovo requires the first supervisor password to be created in UEFI setup; Acer does not publish a universal in-Windows adapter. The **Restart into UEFI settings** fallback covers those devices and other manufacturers.

Firmware support is model-specific even within one brand. The app verifies that the vendor tool or interface exists and reports the OEM error instead of trying an unrecognized generic command. Forgotten passwords cannot be recovered by this app.

## Administrator-controlled locking

Before installation, create the device in the admin system using the laptop's BIOS serial number, then create its **PENDING Device Agent**. The installer calls `/api/agent/enroll/`; the Windows service retries enrollment every five minutes if the pending record is not ready yet.

Once enrolled, the service calls `/api/agent/check-in/` immediately on service startup and resume, and every 60 seconds. Pending commands are fetched from `/api/agent/patch-files/current/`, verified with a provisioned Ed25519 admin key, validated against command metadata, expiry, monotonic version, nonce history, size, and SHA-256 checksum, persisted locally, and acknowledged only after application. `LOCK` restricts the UI; `UNLOCK`, `WARN`, and `RELEASE` remove the restriction. `LOCK` with reason `THEFT` uses explicit lost/stolen-device copy. Remote `UNINSTALL` is deliberately refused and reported as failed because removal requires a local administrator.

There are no local lock/unlock buttons. The status page shows the server state, reason, managed device UUID, and last successful check-in. If the network is unavailable during boot, the last confirmed state remains active until the service reconnects.

## Windows setup

Download the Windows release and extract it. In the admin panel, create the pending device agent for the laptop's BIOS serial before installation.

For installation, open PowerShell as administrator in the extracted folder:

```powershell
.\\install.ps1
```

The installer copies both binaries, reads the BIOS serial, enrolls with `https://emi-api.yajtech.com`, collects health, installs the automatic service, creates the UI startup shortcut, and opens the window. Enrollment uses the one-time pending-agent workflow documented by the API; no admin username or password is stored on the PC. Production deployment must also pass `-CommandSigningKeyId` and `-CommandSigningPublicKey`; without a trusted public key, remote state transitions deliberately fail closed.

WinGet bootstrap downloads Microsoft Desktop App Installer only when WinGet is missing. For an offline install or when bootstrap is unwanted:

```powershell
.\\install.ps1 -SkipWingetBootstrap
```

To uninstall, run `.\\uninstall.ps1` as administrator. Local data is retained for recovery. In an Intune deployment, first remove the device from the Required assignment or place it in an authorized retirement/exclusion group; otherwise Intune can reinstall the agent on its next evaluation.

## Local data and migration

State lives in `%PROGRAMDATA%\\EmiDeviceAgent`:

- `config.json`: service-only API URL, bearer token, local/remote device IDs, and trusted command-signing public keys. Its ACL permits only SYSTEM and Administrators.
- `ui-config.json`: non-secret enrollment metadata for the desktop UI.
- `remote-state.json`: last successfully applied signed server state and check-in time.
- Replay protection (version, message digest, nonce history) is committed atomically inside `remote-state.json`.
- `recovery-state.json`: provisioned public key, consumed counter, and service receipt; users have read access only.
- `recovery-request.json`: fixed administrator-owned mailbox; users may write tokens but cannot replace or delete it.
- `health.json`: local health snapshot, including manufacturer/model.

When the companion initializes an existing installation, it reuses the old local device UUID. Incomplete legacy credentials are discarded; a complete current enrollment is retained. Other historical device data is not deleted. Corrupt configuration is preserved as `config.invalid.json` (with numbered backups when needed) before a new local identity is initialized.

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

## Production hardening setup

See [production-hardening.md](docs/production-hardening.md) for recovery-key custody, command-signing integration, mandatory release signing, and staged BitLocker/LAPS/App Control deployment. There is no shared unlock word or built-in lab-key fallback.

## Windows recovery configuration (v0.6.36)

After `install.ps1` succeeds, the elevated `install.cmd` first exports the BCD
store to `C:\bcd-backup`, then runs `reagentc /disable` and `reagentc /info`.
It sets `recoveryenabled No` and `bootstatuspolicy IgnoreAllFailures` for both
`{current}` and `{default}`. It then sets the `ShutdownWithoutLogon` DWORD to
`0` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
disabling shutdown without logging on. It also deletes `recoverysequence` for both
boot entries, disables `advancedoptions` and `optionsedit` for `{globalsettings}`,
sets the current boot menu policy to `Standard`, and sets the boot timeout to `0`.
Deletion failures are reported as warnings because WinRE may already have removed
the recovery-sequence values. Other BCD failures stop configuration.
Final diagnostics print WinRE and BCD settings, Secure Boot, TPM, and BitLocker
status. These queries do not enable Secure Boot, provision a TPM, or encrypt C:.
Unsupported or failed hardware-status queries are reported as warnings.
The registry write overwrites an existing
value without prompting and returns a nonzero exit code on failure.
If the BCD export fails, recovery settings are not
changed. A failed recovery command or required BCD command stops configuration with a nonzero exit code
and explicitly reports that the agent has already been installed. Failed agent
installation does not change Windows RE through this wrapper. Running
`install.ps1` directly does not apply this recovery configuration.

Disabling Windows RE removes the built-in recovery environment and prevents
Windows Autopilot Reset, which requires WinRE. It does not prevent a clean OS
installation or disk replacement. Retain an administrator account and external
Windows recovery media. An administrator can restore recovery with
`reagentc /enable`, then check `reagentc /info`; uninstalling the agent does not
restore WinRE automatically. The BCD settings are separate from WinRE; enabling
WinRE alone does not undo them. The pre-change BCD store is saved at
`C:\bcd-backup` for administrator recovery. See [Microsoft's Autopilot Reset prerequisites](https://learn.microsoft.com/en-us/autopilot/windows-autopilot-reset).

## Installer enrollment and desktop-launch warnings

`No pending agent for this device serial number` means the backend has no eligible
PENDING Device Agent for that exact BIOS serial. Create or reset the intended
agent record through the authorized admin workflow; the service retries every
five minutes. Reinstalling does not create that server record.

If Windows cancels or blocks the optional desktop UI launch, the installer now
reports a warning after verifying the service installation instead of reporting
the entire install as failed. Open the companion manually to inspect any Windows
security prompt. The message alone does not identify whether UAC, SmartScreen,
or another Windows control canceled the launch. `-SkipUiLaunch` skips this
interactive step; the Intune wrapper uses it for SYSTEM/session-0 deployment.
