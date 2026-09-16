# Desktop-only security boundaries

- No network backend, socket connection, enrollment, remote command handler, or portal is present. Device health stays on this PC.
- The installer requires administrator access. Program Files protects the installed binaries; ProgramData permissions give administrators/System write access and ordinary users read access to local health.
- The GUI's health refresh requests UAC approval to run the local companion. Denial is reported; it is not bypassed.
- An administrator retains ordinary recovery and uninstall access. Absolute uninstall prevention and operating-system lockout are not implemented.
- BIOS manufacturer detection is read-only. Firmware passwords, Windows account passwords, managed PINs, and remote control are not implemented in the desktop-only foundation.
- Payment schedules remain domain types, not an implemented storage/editor/payment-processing system. Do not treat local files as payment confirmation from a financial provider.
- Existing database volumes, historical files, and previous releases are retained. Updated initialization removes obsolete server/token fields from configuration while keeping the local UUID. It does not delete other historical state.
- The optional WinGet bootstrap downloads from Microsoft's official endpoint. Use SkipWingetBootstrap for offline installation; the Rust app itself does not require WinGet.
- Release binaries are not yet code-signed. Windows CI compilation/tests do not replace a real GUI/UAC/service/resume smoke test.
