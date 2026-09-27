# Enterprise anti-theft deployment

This runbook describes a supported, recoverable anti-theft deployment for organization-owned Windows devices. It intentionally separates behavior implemented by this repository from Microsoft-tenant and OEM controls that an operator must configure.

## Security outcome and limits

The target outcome is data protection and automatic restoration of management after a supported reset—not an undeletable program.

| Scenario | Expected protection |
|---|---|
| Agent is stopped or removed by a standard user | Windows ACLs limit modification; Intune Required-app detection offers the package again. |
| Windows Autopilot Reset | Microsoft Entra and Intune association is retained; policy and required applications are reapplied. |
| Clean Windows installation reaches online OOBE | A correctly registered Autopilot device receives the organization's assigned deployment profile and is managed again. |
| SSD is removed | BitLocker makes existing volume data unreadable without recovery material. |
| SSD is formatted or replaced | Existing data is erased; Autopilot can restore management because its registration identifies the device rather than the old disk. |
| Motherboard is replaced, firmware is attacked, or the device stays offline | Management restoration is not guaranteed. Follow the asset-loss and hardware-replacement procedure. |

No Windows agent can prevent a person with physical possession from destroying or erasing storage. Do not disable WinRE, sabotage reset, hide persistence, install a kernel hook, or deny an authorized administrator a recovery path.

## Responsibility boundary

### Implemented in this repository

- Enrollment through the documented Device Agent endpoint using the BIOS serial.
- A LocalSystem service that checks in at startup and resume, then periodically.
- Persistence of the last server-confirmed state across reboot and temporary API outage.
- Validation of command/patch identity, action, expiry, length, and SHA-256 before applying it.
- Fail-closed Ed25519 verification using explicitly provisioned trusted public keys, plus durable version rollback and nonce replay protection.
- `LOCK`, `UNLOCK`, `WARN`, and `RELEASE` state handling and command acknowledgement.
- Refusal of remote `UNINSTALL`; local administrator removal remains available.
- A visible, branded restriction UI and documented administrator/WinRE recovery boundaries.

### Required outside this repository

- Microsoft Entra ID, Intune licensing, automatic MDM enrollment, device groups, role assignments, and conditional-access policy.
- Windows Autopilot device registration and deployment-profile assignment. OEM/reseller registration is preferred for production fleets; manual hardware-hash import is primarily appropriate for controlled onboarding and evaluation.
- Building, uploading, assigning, and versioning an Intune Win32 package.
- BitLocker policy and organizational recovery-key escrow.
- DFCI enrollment and UEFI policy on hardware whose OEM supports it.
- Production Authenticode signing and Defender/App Control allow-listing.
- API-side authorization, administrator audit, command issuance, and any future `LOST`/`RECOVERED` contract.
- API-side generation of the exact versioned Ed25519 signature described below and secure lifecycle management of the matching private key.
- A secure way to re-enroll the same asset after its local bearer token is erased by a clean reinstall or SSD replacement. The current one-time `/api/agent/enroll/` contract rejects a second enrollment once the existing Device Agent is no longer `PENDING`.

The concrete server implementation and test work is tracked in
[`backend-signed-command-checklist.md`](backend-signed-command-checklist.md).

Installing this repository's release package alone does not satisfy the external requirements.

## Current lost-device semantics

The current API action vocabulary is `LOCK`, `UNLOCK`, `WARN`, `RELEASE`, and `UNINSTALL`; it has no distinct `LOST` or `RECOVERED` action. Use these semantics without inventing an undocumented request:

- Issue `LOCK` with a concise, non-sensitive return message to place a reported device in restricted mode.
- Issue `UNLOCK` if the restriction was temporary or erroneous.
- Issue `RELEASE` only when the device is permanently released from management under the organization's asset-disposal policy.
- Do not use `UNINSTALL` as recovery; the agent deliberately rejects it.
- Do not auto-lock merely because check-ins stop. A powered-off, offline, or broken device is not proof of theft.

A future backend revision can add explicit `LOST` and `RECOVERED` states. That change must be versioned across the OpenAPI contract, server, client, audit log, and tests before operators use it.

## Signed command contract

Remote transitions fail closed until deployment provisions a trusted public key and the backend emits a matching signature. Provision the 32-byte Ed25519 public key as standard or unpadded URL-safe base64:

```powershell
emi-device-agent.exe trust-command-key --key-id <nonzero-id> --public-key "<base64-public-key>"
```

`PatchFileResponse.signed_payload` must be the base64 detached Ed25519 signature of compact UTF-8 JSON with fields in this exact order:

```json
{"domain":"emi-command-patch-v1","device_uuid":"<uuid>","patch_uuid":"<uuid>","command_uuid":"<uuid>","version":1,"action":"LOCK","reason":"THEFT","nonce":"<nonce>","command_expires_at":"2026-01-01T00:00:00.000000Z","patch_expires_at":"2026-01-01T00:00:00.000000Z","checksum":"sha256:<lowercase-hex>","size_bytes":123}
```

UUIDs use lowercase hyphenated form. Actions use the documented uppercase enum. Timestamps are UTC RFC 3339 with six fractional digits and `Z`. The checksum is trimmed and lowercased. `signing_key_id` selects the locally provisioned verification key. Unknown keys, invalid signatures, expired commands, metadata changes, version rollback/equal-version substitution, and nonce reuse are rejected and negatively acknowledged where the patch UUID is known.

## Tenant and hardware prerequisites

1. Use supported Windows Pro, Enterprise, or Education devices with TPM 2.0 and Secure Boot.
2. Confirm the device is organization-owned and record asset ID, serial, model, assigned user, and purchase chain.
3. Register it with Windows Autopilot and assign a deployment profile. Seeing a device in Intune is not by itself proof that Autopilot registration and profile assignment are complete.
4. Enable automatic Intune enrollment and target a device group dedicated to this deployment.
5. Verify whether the exact model and purchase channel support DFCI. Treat unsupported hardware as a reduced-assurance tier.
6. Configure BitLocker and escrow recovery material to the organization before handing the device to a user.
7. Keep at least one audited break-glass administrator and preserve WinRE.

Authoritative references:

- [Windows Autopilot requirements](https://learn.microsoft.com/en-us/autopilot/configuration-requirements)
- [Windows Autopilot device registration](https://learn.microsoft.com/en-us/autopilot/registration-overview)
- [Windows Autopilot Reset](https://learn.microsoft.com/en-us/autopilot/windows-autopilot-reset)
- [Intune Win32 app management](https://learn.microsoft.com/en-us/intune/app-management/deployment/win32)
- [DFCI management with Intune](https://learn.microsoft.com/en-us/intune/intune-service/configuration/device-firmware-configuration-interface-windows)
- [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)

## Intune deployment runbook

1. Produce an Authenticode-signed release and verify its published SHA-256 digest. Do not promote an unsigned CI artifact to production.
2. Package the release as an Intune Win32 app. Install in **System** context with the repository's elevated installer and use the matching elevated uninstaller only for authorized retirement.
3. Assign the application as **Required** to the managed device group—not merely Available in Company Portal.
4. Configure requirements for supported architecture and Windows edition.
5. Configure detection to require all of the following:
   - the expected installed release/version;
   - the `EmiDeviceAgent` service exists, uses the expected binary path, and is configured for automatic startup;
   - both installed executables have the expected publisher signature;
   - do not expose or parse the bearer token from `config.json` in detection output.
6. Configure supersedence for upgrades and an explicit exclusion/retirement group. Removing a device must be a deliberate admin action, not a failed detection rule.
7. Use Enrollment Status Page policy when the device must not reach its normal user desktop before the required application and security profiles are installed.
8. Pilot first, then expand by deployment rings. Monitor install status, service health, API check-in age, BitLocker compliance, Secure Boot, and DFCI applicability separately.

Intune detection is eventual remediation, not instantaneous self-defense. Microsoft documents that required-app evaluation can offer a missing application again; operators should not promise uninterrupted enforcement during the interval.

## Reset and recovery runbook

### Supported reset

1. Prefer a remote Windows Autopilot Reset for a managed Microsoft Entra-joined device when its documented prerequisites apply.
2. Confirm reset completion, MDM sync, security-profile application, required-app installation, service startup, enrollment, and fresh API check-in.
3. Keep the device quarantined from sensitive resources through Conditional Access until every required control reports compliant.

### Clean installation or replaced SSD

1. Connect the device to a trusted network during Windows OOBE.
2. Confirm organizational branding/profile appears; if it does not, stop deployment and verify the Autopilot record and profile assignment.
3. Complete Entra/Intune enrollment and verify the required application reinstall sequence.
4. Confirm the agent's backend record is the intended asset. The current one-time enrollment contract requires an authorized backend reset/reissue workflow before this reinstalled agent can obtain a new token. Resolve duplicate/stale enrollment server-side rather than copying tokens from another machine.

### Retirement or ownership transfer

1. Authorize the transfer through the asset-management process.
2. Send the applicable API release action and preserve its audit result.
3. Remove Required-app targeting, retire/wipe the Intune object as policy requires, unlock/remove DFCI policy in the correct documented order, rotate or remove recovery material, and deregister Autopilot only when ownership actually transfers.
4. Run the local uninstaller if the OS is still accessible. Authorized removal must remain possible.

Deleting cloud records in the wrong order can leave firmware settings managed or cause the agent to reinstall. Test and document the tenant-specific sequence before production.

## Acceptance and recovery verification

Run these tests on each supported hardware/edition model before fleet approval:

- **Boot:** service reaches Running without user logon; an enrolled device sends an immediate successful check-in.
- **Offline boot:** the last confirmed state remains visible; reconnection resumes check-in without replacing device identity.
- **Required-app repair:** removal in a controlled test is detected by Intune and the signed current version is reinstalled.
- **Autopilot Reset:** organizational management remains connected and the agent is restored before user handoff.
- **Clean install/new SSD:** online OOBE receives the assigned Autopilot profile and Intune restores the agent.
- **Removed SSD:** encrypted data cannot be mounted without BitLocker recovery material; formatting is treated as destructive erasure, not something the agent can block.
- **DFCI:** only on declared-supported hardware, verify intended boot/UEFI controls and the documented recovery procedure.
- **Lost/recovered:** `LOCK` displays the approved return message; `UNLOCK` restores normal use; every command receives an acknowledgement and audit entry.
- **Break glass:** an authorized administrator and WinRE can recover the machine, and the procedure is logged and periodically exercised.
- **Hardware replacement:** verify that a motherboard replacement follows re-registration/retirement policy and is not assumed to retain the old Autopilot identity.

Record OS build, firmware version, model, test date, result, and operator. A passing VM test is not a substitute for testing every production hardware family.
