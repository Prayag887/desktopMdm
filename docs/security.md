# Desktop-only security boundaries

- No hosted backend, socket client, enrollment, remote command handler, or portal is present. Device health stays on this PC. A temporary embedded LAN listener serves QR dismissal only during an explicitly started simulation.
- The installer requires administrator access. Program Files protects the installed binaries; ProgramData permissions give administrators/System write access and ordinary users read access to local health.
- The GUI's health refresh requests UAC approval to run the local companion. Denial is reported; it is not bypassed.
- An administrator retains ordinary recovery and uninstall access. Absolute uninstall prevention and operating-system lockout are not implemented.
- BIOS manufacturer detection is read-only. Firmware passwords, Windows account passwords, managed PINs, and remote control are not implemented in the desktop-only foundation.
- BIOS preparation fields are masked, not persisted or transmitted, and cleared on tab exit. Zeroizing buffers reduce retained application memory; GUI/text input and allocator copies cannot be guaranteed erased. No guessed firmware command is executed; actual Apply remains disabled pending exact-model OEM integration.
- The simulated blue screen never invokes crash APIs, disables recovery/input, makes itself unkillable, or saves/relaunches prank state. Escape, normal close, QR dismissal, reboot and a five-minute timeout remain available. The health service never starts a simulation.
- QR dismissal uses a random per-session UUID token and explicit POST; GET/prefetch is non-mutating. Host/Origin checks, no-store/CSP headers, private-interface binding, 8 KiB header limit, a one-second request deadline, one serial worker and no request-body processing limit exposure. The listener is closed on session teardown. Requests do not access device health or credentials. Plain HTTP means a trusted LAN is required; no public forwarding/tunnel is supported.
- Payment schedules remain domain types, not an implemented storage/editor/payment-processing system. Do not treat local files as payment confirmation from a financial provider.
- Existing database volumes, historical files, and previous releases are retained. Updated initialization removes obsolete server/token fields from configuration while keeping the local UUID. It does not delete other historical state.
- The optional WinGet bootstrap downloads from Microsoft's official endpoint. Use SkipWingetBootstrap for offline installation; the Rust app itself does not require WinGet.
- Release binaries are not yet code-signed. Windows CI compilation/tests do not replace a real GUI/UAC/service/resume smoke test.
