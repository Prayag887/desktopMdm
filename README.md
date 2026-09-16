# EMI Device Control

A small Rust monorepo for consent-based management of Windows devices sold on installment plans. It includes an Axum + HTMX admin control plane, a SQLite data store, and a Windows service agent.

## What works

- Enrollment with per-device bearer tokens
- Admin dashboard protected with HTTP Basic authentication
- Fixed-point payment schedules and transactional “mark paid” actions
- Append-only audit events for plans, payments, and commands
- Device health check-ins (OS, disk, Secure Boot, WinGet, OEM detection)
- Payment reminders delivered to the logged-in Windows session
- Windows service installation and official WinGet bootstrap
- Tag-driven Windows builds and GitHub releases

## Safety boundaries

This is an authorized device-management starter, not spyware. The service is difficult for a standard user to remove because it is installed under Program Files and managed by the Service Control Manager, but a local/domain administrator always retains a documented recovery and uninstall path. The software does not bypass Windows security, hide itself, or attempt absolute persistence.

BIOS password rotation is deliberately fail-closed in this baseline. The agent detects Dell, HP, and Lenovo hardware, but it will not accept a firmware secret until an OEM-specific adapter and end-to-end encrypted secret envelope are configured. See [docs/security.md](docs/security.md).

## Run the control plane

```sh
cp .env.example .env
# edit both secrets, then:
docker compose up --build
```

Open `http://localhost:3000` and sign in as `admin` with `ADMIN_PASSWORD`.

For local Rust development:

```sh
ADMIN_PASSWORD=dev-password ENROLLMENT_KEY=dev-enrollment-key cargo run -p emi-control-plane
```

## Install a Windows agent

Download the Windows release ZIP, extract it, then run an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -Server 'https://mdm.example.com' -EnrollmentKey 'one-time-or-rotated-key'
```

The installer copies the signed executable to Program Files, bootstraps WinGet if needed, enrolls the machine, and registers an automatic Windows service. Put the control plane behind TLS before enrolling real devices.

## Release

After configuring the GitHub remote, push a semantic-version tag:

```sh
git tag v0.1.0
git push origin main --tags
```

GitHub Actions builds `emi-device-agent.exe`, packages the scripts, uploads the artifact, and creates the release. Production distribution should add Authenticode signing before public rollout.

