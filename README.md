# EMI Device Control

A small Rust monorepo for consent-based management of Windows devices sold on installment plans. It includes an Axum + HTMX admin control plane, a SQLite data store, a Windows service agent, and a native Rust desktop UI.

## What works

- Enrollment with per-device bearer tokens
- Admin dashboard protected with HTTP Basic authentication
- Fixed-point payment schedules and transactional “mark paid” actions
- Append-only audit events for plans, payments, and commands
- Device health check-ins (OS, disk, Secure Boot, WinGet, OEM detection)
- Payment reminders delivered to the logged-in Windows session
- Windows service installation and official WinGet bootstrap
- Native `egui`/`eframe` Windows status UI installed for all user sessions
- Tag-driven Windows builds and GitHub releases
- Remote app PIN updates (Argon2id verifier only), clear restrictions, and managed/maintenance mode
- Responsive device console with health metrics, online/stale status, and queued/completed/failed command history

## Remote management console

Open a device from the dashboard to send a payment reminder, set a matching 4–12 digit app PIN, clear the PIN, or switch between managed and maintenance modes. Agents maintain an authenticated outbound WebSocket for immediate command signals. Commands are committed to SQLite before signaling and stay pending until execution is acknowledged. Offline PCs drain the backlog on service startup/reconnection; Windows resume events request an immediate sync once networking is available. Full health telemetry refreshes every five minutes and after policy changes. The web page refreshes health and acknowledgements every 30 seconds. The policy target is separate from the agent's reported mode until acknowledgement.

### Socket delivery and offline recovery

Use agent version 0.4.1 or later for socket delivery; existing 0.3.0 agents still work through their polling API. Re-run the installer with the updated release on existing PCs. The same server URL and enrollment are reused; no extra inbound PC ports are needed.

The socket endpoint is `/api/v1/devices/{id}/socket`. HTTPS server URLs become `wss://` with certificate verification. Configure the reverse proxy to forward WebSocket Upgrade/Connection headers and preserve Authorization and Host; use a read timeout over 45 seconds. Socket authentication uses the per-device bearer token in a header, never a query string. Plain HTTP/WS is only for local development.

Delivery is **at least once**, not exactly once: losing an acknowledgement can replay an action. Existing policy commands are idempotent assignments/removals; a payment reminder can be repeated. Commands run sequentially and multiple 20-command batches are drained without waiting for another poll. Executed errors are acknowledged as failed, not silently retried forever. SQLite storage must remain on the persistent Docker volume and be backed up; deleting it deletes pending commands.

Sockets reconnect with a 1–30 second backoff. A 20-second server heartbeat also requests reconciliation, and a 60-second HTTP fallback recovers lost signals or proxy incompatibility. Windows resume triggers sync within about a second when the agent is idle, but a PC cannot execute while powered off, asleep, or disconnected from the network. Delivery requires the installed service to run and networking/server reachability to return. The lightweight single-server implementation caps concurrent socket connections at 256 and uses a bounded 128-entry signal channel; overflow triggers durable reconciliation rather than discarding commands.

The desktop PIN protects the application's details screen only. It does not lock the entire PC, alter a Windows account password, or change Windows Hello. Maintenance disables app restrictions but deliberately keeps telemetry and administrator recovery available. Remote desktop viewing, arbitrary shell execution, Windows password resets, and BIOS credential rotation are not implemented.

Upgrade an existing Windows installation using the new release's `install.ps1`; it stops the existing service/UI, preserves verified enrollment on the same server, and installs both new binaries. Agent credentials are kept in a restricted file while the desktop reads a token-free public configuration. “Check in now” requests administrator elevation.

## Safety boundaries

This is an authorized device-management starter, not spyware. The service is difficult for a standard user to remove because it is installed under Program Files and managed by the Service Control Manager, but a local/domain administrator always retains a documented recovery and uninstall path. The software does not bypass Windows security, hide itself, or attempt absolute persistence.

BIOS password rotation is deliberately fail-closed in this baseline. The agent detects Dell, HP, and Lenovo hardware, but it will not accept a firmware secret until an OEM-specific adapter and end-to-end encrypted secret envelope are configured. See [docs/security.md](docs/security.md).

## Run the control plane

```sh
cp .env.example .env
# edit both secrets, then:
docker compose up --build
```

For a server deployment, copy `.env.example` to `.env`, replace both secrets, and run:

```sh
docker compose up -d --build
docker compose ps
```

The production image runs as an unprivileged user on a distroless Debian base, drops Linux capabilities, uses a read-only root filesystem, persists only `/data`, handles `SIGTERM`, and includes a shell-free health check. Rebuilds reuse BuildKit caches for Cargo dependencies and compiled artifacts.

### Server sizing

Do not plan a Docker deployment around a 100 MB RAM or 100 MB disk limit. The control-plane process is lightweight, but the Docker daemon, unpacked image layers, SQLite data, and logs need headroom. Use at least 256 MB RAM and 500 MB free disk for a very small installation; 512 MB RAM and 1 GB free disk is the recommended practical minimum.

Open the host port from `CONTROL_PLANE_PORT` (3000 by default; this workspace uses 3100) and sign in as `admin` with `ADMIN_PASSWORD`.

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

The installer copies the service and UI executables to Program Files, bootstraps WinGet if needed, enrolls the machine, registers an automatic Windows service, installs a common Startup shortcut, and opens the UI. The service remains active after the window is closed. Put the control plane behind TLS before enrolling real devices.

## Release

After configuring the GitHub remote, push a semantic-version tag:

```sh
git tag v0.1.0
git push origin main --tags
```

GitHub Actions builds `emi-device-agent.exe`, packages the scripts, uploads the artifact, and creates the release. Production distribution should add Authenticode signing before public rollout.
