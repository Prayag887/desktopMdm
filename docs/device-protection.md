# Windows device protection

The existing core service owns enrollment, signed commands, lock-state synchronization and offline recovery. These flows remain in their existing modules. A separate, slow worker collects protection status every five minutes without blocking check-in or the lock-screen loop. The UI reads `protection-status.json` and shows failed verification and stale data explicitly. There is no numerical security score.

## File responsibilities

`apps/windows-agent/src/protection/` contains `model.rs` (wire models/status aggregation), `acl.rs` (compiled-in ACL operations), `integrity.rs` (manifest validation/streaming SHA-256), `windows.rs` (bounded Windows helper processes), `retry.rs` (recovery budget), `watchdog.rs` (independent SCM monitor), `repair.rs` (authenticated cache dispatch and durable retry ledger), `snapshot.rs` (service-owned status publication) and `logging.rs` (bounded structured logs). `src/ui/protection.rs` renders cached diagnostics. `src/bin/emi-device-watchdog.rs` is the watchdog entry point; `src/bin/emi-device-updater.rs` is the separate elevated repair executor.

The packaging files have separate responsibilities: `Protection-Acl.ps1` for program ACLs, `Set-EmiStateAcl.ps1` for private state and the recovery mailbox, `Protection-Integrity.ps1` for package authentication, `Protection-Package.ps1` for immutable artifact installation/repair caching, `Protection-Transaction.ps1` for backup/rollback, `Get-SecurityPosture.ps1` for hardware/volume queries, `Get-DeviceProtection.ps1` for aggregation, `Provision-BitLocker.ps1` for explicit encryption provisioning and `Maintain-Protection.ps1` for authorized servicing. Installer, uninstaller, CI and release packaging integrate these components. The ACL implementations are embedded in Rust binaries so repair never executes a helper from a damaged installation.

## Services and recovery

`EmiDeviceAgent` remains the core LocalSystem service. `EmiDeviceWatchdog` is an independent LocalSystem service. Both start automatically with quoted absolute executable paths and SCM recovery delays of 30 seconds, 60 seconds and 300 seconds, with a one-day failure-count reset. Normal stop/shutdown returns success. Unexpected failures return a nonzero exit status. SCM can continue retrying at five-minute intervals; Windows does not provide a finite retry count through these recovery settings.

The watchdog checks SCM status, configuration identity and health-file freshness every 30 seconds. Installation hashes, registration and ACL checks occur every five minutes and immediately before restarting a stopped service. The watchdog allows five attempts with delays of 30/60/120/240/480 seconds, resets only after five healthy minutes, and never kills a running core. A stale core heartbeat is reported for administrator investigation. Neither service relaunches the other. Integrity failure refuses watchdog restart and records the affected files. SCM recovery is independent of watchdog recovery and does not itself authenticate executable signatures; use Windows Defender Application Control for OS-enforced publisher restrictions.

The installer caches a verified release under `ProgramData\EmiDeviceAgentRepair\<manifest-hash>` with protected ACLs, and records the source in private `repair-source.json`. Missing/corrupt files dispatch the verified cached updater as a separate process so installation can stop the watchdog without a deadlock. Cache ACLs, publisher signature and all hashes are verified before execution. A durable `repair-attempts.json` ledger caps repair at five attempts with exponential cooldowns starting at five minutes, survives service reinstalls, and resets after five uninterrupted healthy minutes. An absent/untrusted cache requires administrator repair. There is no remote executable download protocol. Protection events are recorded locally rather than sent to an invented backend endpoint. Existing health/check-in schemas remain compatible.

## Exact ACL policy

Program files and subdirectories use protected DACLs (inheritance removed), an Administrators owner, SYSTEM FullControl, Administrators FullControl, and Users ReadAndExecute. There are no deny entries, Everyone grants or user write/delete/ACL-change/ownership grants. The policy covers all installed binaries, scripts and signed manifest. Reparse points are rejected before recursion. Functions `Apply-ProtectionAcl`, `Verify-ProtectionAcl`, `Repair-ProtectionAcl` and Rust equivalents return detailed reports. Expected permissions are verified after application; unchanged policies are idempotent.

ProgramData retains the existing split: SYSTEM/Admin FullControl; Users read/execute on public snapshots; no Users access to `config*`, the maintenance lease or `repair-source.json`; the single fixed `recovery-request.json` mailbox permits Read/Write without Delete, ChangePermissions or TakeOwnership. The recovery service validates signed, device-bound, expiring tokens and durable replay counters. State verification accepts inherited equivalent rights and either SYSTEM or Administrators ownership because atomic writes legitimately change owners. Unpublished `.tmp*` files are excluded from repair to avoid exposing private configuration during atomic writes.

Installation saves previous files, ACL descriptors and service registration into an administrator/SYSTEM-only `ProgramData\EmiProtectionBackup-<id>` directory, and retains its location in `installation-report.json`. Backups contain credentials: retain/delete them through an administrator-controlled retention policy. Failure rolls back files, ACLs, service path/start mode and the scheduled UI task. Rollback restores the documented recovery policy rather than arbitrary old recovery actions. An interrupted transaction or failed rollback needs administrator recovery from the retained backup; this is not a crash-atomic MSI transaction.

## Trusted manifest and packages

The release workflow signs all four executables, hashes final binaries and executable packaging scripts, stores hashes in a JSON comment in `protection-manifest.ps1`, and Authenticode-signs that manifest with the configured release certificate. Runtime verifies the manifest's valid signature against the running signed component's publisher before hashing. The manifest is parsed as data and never executed. Required file names, hashes, traversal, symlinks/reparse points, corruption and missing files are checked. Mutable config, identity, logs and databases are protected by ACLs rather than immutable hashes.

Initial deployment must obtain the release from an administrator-trusted distribution channel. Before loading helpers or running binaries, the installer locks source files against writes, authenticates the publisher manifest, verifies hashes and copies the immutable package into an administrator-only staging directory. A repair/update requires a valid manifest from the installed publisher and stages files into an administrator-only directory, revalidates there and invokes the trusted installer. Publisher rotation needs an administrator-approved release deployment. `install.ps1 -AllowUnsigned` is an explicit development opt-in: device protection reports errors and the watchdog refuses trusted restart. It does not bypass integrity for repair packages.

## Hardware and encryption

BitLocker uses `Get-BitLockerVolume`; edition is reported from `Win32_OperatingSystem`. Status includes volume, encryption state/percentage/method, protection, lock state and protector **types only**. The provisioning script requires an elevated administrator to choose `-Escrow ActiveDirectory` or `-Escrow EntraID`. It verifies TPM readiness, preserves already-encrypted or partially encrypted volumes, retains existing protectors, adds a recovery password only if needed, and completes directory escrow before enabling a TPM protector. It encrypts the full previously used volume, preserves organization encryption-method policy, and retains the Windows hardware test. No recovery passwords or full protector objects are logged. Failure retains protectors and does not disable encryption. Provisioning is never an install/update side effect. Escrow success is the Windows cmdlet result; organization administrators must confirm directory key retrieval and recovery before rollout.

TPM uses `Get-Tpm` plus `Win32_Tpm` for specification version, with present/ready/enabled/activated/owned/manufacturer/version signals. There is no automatic provisioning, ownership change or TPM clear. Secure Boot uses `Get-ComputerInfo -Property BiosFirmwareType` and `Confirm-SecureBootUEFI`, distinguishes legacy BIOS, unsupported UEFI, disabled and detection errors, and never modifies firmware. These are cached queries through the absolute inbox Windows PowerShell executable, with a 90-second deadline and bounded output. Slow queries run off the core synchronization loop.

## Authorization, servicing and uninstall

Status IPC uses existing ACL-protected files. No new privileged request endpoint is exposed. Windows administrator elevation/UAC authorizes maintenance; the backend has signed lock/recovery commands, but no maintenance authorization contract. Existing backend commands continue to be validated by their existing verifier.

From an elevated Windows PowerShell session:

```powershell
.\Maintain-Protection.ps1 -Action Begin
# Perform approved diagnostics; SYSTEM/Admin already have maintenance file access.
.\Maintain-Protection.ps1 -Action End
.\Maintain-Protection.ps1 -Action Repair -PackageDir 'C:\TrustedRelease'
.\Maintain-Protection.ps1 -Action Update -PackageDir 'C:\TrustedRelease'
.\Maintain-Protection.ps1 -Action Uninstall
.\Provision-BitLocker.ps1 -Escrow EntraID
```

Begin records a private 30-minute lease and stops watchdog before core; the lease suppresses recovery if watchdog starts unexpectedly. End authenticates the manifest, verifies hashes, reapplies ACLs and starts core before watchdog. ACL relaxation is unnecessary because administrators retain FullControl. The uninstaller stops watchdog before core and retains ProgramData/recovery information. Intune Required assignments can reinstall removed software: retire/exclude the device through your tenant first.

Logs are JSON, five files per component, each approximately 2 MiB; core, watchdog and updater have separate streams. State writes keep the existing atomic publication mechanism. Recovery keys, credentials and tokens must never be passed to tracing. The OS's own BitLocker, TPM, SCM and administrator audit logs supply additional diagnostics.

## Validation and Windows limitations

Rust unit tests cover manifest completeness/path traversal, missing/corrupt files, aggregation, bounded retries, sustained-health reset and log rotation. Existing enrollment/command/recovery/lock tests remain. Windows CI parses all PowerShell scripts and runs state ACL tests, real standard-user delete/overwrite/rename/ACL denial, SYSTEM access, ACL idempotence/repair, and deterministic hardware-provider/provisioning tests. `tests/Test-ProtectionServices.ps1 -DisposableVm` verifies stopped/crashed service recovery on an installed signed release; after actual logout/reboot run with `-AfterReboot`. Real encryption, physical firmware and recovery-key retrieval require an administrator-controlled Windows acceptance machine.

NTFS/SCM cannot protect against an elevated administrator, kernel compromise, offline disk replacement or reimaging. ACLs do not constrain firmware settings. TPM/Secure Boot availability depends on hardware and firmware; BitLocker management depends on Windows edition and organization policy. Authenticode hashes provide application verification, not OS-wide execution enforcement.

The current `install.cmd` preserves WinRE and BCD. Earlier versions disabled recovery; this release does not guess or automatically overwrite historical boot settings. An administrator should restore WinRE with `reagentc /enable`, check `reagentc /info`, and review the historical `C:\bcd-backup` and organization boot policy. Enabling WinRE alone does not undo old BCD changes. No install, repair or update clears TPM, changes firmware/BCD, disables Windows Recovery or removes BitLocker protectors.

## Changed file inventory

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `apps/windows-agent/src/agent/runner.rs`
- `apps/windows-agent/src/agent/service.rs`
- `apps/windows-agent/src/bin/emi-device-updater.rs`
- `apps/windows-agent/src/bin/emi-device-watchdog.rs`
- `apps/windows-agent/src/lib.rs`
- `apps/windows-agent/src/main.rs`
- `apps/windows-agent/src/protection/acl.rs`
- `apps/windows-agent/src/protection/integrity.rs`
- `apps/windows-agent/src/protection/logging.rs`
- `apps/windows-agent/src/protection/mod.rs`
- `apps/windows-agent/src/protection/model.rs`
- `apps/windows-agent/src/protection/repair.rs`
- `apps/windows-agent/src/protection/retry.rs`
- `apps/windows-agent/src/protection/snapshot.rs`
- `apps/windows-agent/src/protection/watchdog.rs`
- `apps/windows-agent/src/protection/windows.rs`
- `apps/windows-agent/src/ui/app.rs`
- `apps/windows-agent/src/ui/mod.rs`
- `apps/windows-agent/src/ui/protection.rs`
- `docs/device-protection.md`
- `docs/security.md`
- `packaging/windows/Get-DeviceProtection.ps1`
- `packaging/windows/Get-SecurityPosture.ps1`
- `packaging/windows/Maintain-Protection.ps1`
- `packaging/windows/Protection-Acl.ps1`
- `packaging/windows/Protection-Integrity.ps1`
- `packaging/windows/Protection-Package.ps1`
- `packaging/windows/Protection-Transaction.ps1`
- `packaging/windows/Provision-BitLocker.ps1`
- `packaging/windows/Set-EmiStateAcl.ps1`
- `packaging/windows/install.cmd`
- `packaging/windows/install.ps1`
- `packaging/windows/tests/Test-ProtectionAcl.ps1`
- `packaging/windows/tests/Test-ProtectionServices.ps1`
- `packaging/windows/tests/Test-SecurityPosture.ps1`
- `packaging/windows/tests/Test-UntrustedRepair.ps1`
- `packaging/windows/uninstall.ps1`
