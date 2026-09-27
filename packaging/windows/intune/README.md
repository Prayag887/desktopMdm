# Microsoft Intune and Autopilot deployment

These files deploy and monitor the EMI Device Agent through supported Windows management controls. They do not disable Windows Recovery, prevent an authorized administrator from removing software, or make firmware changes.

## Register a company-owned laptop with Windows Autopilot

For production purchases, ask the OEM or reseller to register the devices to your Microsoft tenant. For an existing pilot laptop, run this repository's export helper **on that Windows laptop** from an elevated PowerShell prompt:

```powershell
.\intune\Export-AutopilotHardwareHash.ps1 -OutputPath 'C:\HWID\AutopilotHWID.csv' -GroupTag EMI
```

Create `C:\HWID` first. The script reads the BIOS serial and Windows hardware hash, writes one import-ready ANSI CSV, refuses to overwrite an existing file, and never uploads the hash. The hash is sensitive device identity data; transfer it only to the organization administrator and delete the export after confirming import.

In [Microsoft Intune admin center](https://intune.microsoft.com), open **Devices → Windows → Enrollment → Windows Autopilot → Devices → Import**, upload the CSV, select **Sync**, and verify the serial appears. Registration alone is not enough: verify a deployment profile is assigned to the device before reset or handoff. Manual hash import is suited to pilots and existing devices; OEM/reseller registration is preferred for fleets.

Create a dedicated Entra device group targeting the `EMI` group tag. Assign a Windows Autopilot **user-driven Microsoft Entra join** profile to it with **User account type: Standard**. Configure automatic MDM enrollment for eligible users. Assign an Enrollment Status Page (ESP) to the same deployment scope and require installation of the EMI Win32 app before access to the normal desktop. Keep a separate authorized administrator recovery procedure.

## Apply BitLocker and compliance policies

In **Intune → Endpoint security → Disk encryption**, create a Windows BitLocker profile for the EMI device group. Enable **Require Device Encryption**. Configure operating system drive recovery so **Require device to back up recovery information to Microsoft Entra** is **Yes**; encryption must not complete without organizational recovery-key escrow. For standard-user deployment, use the supported **Allow Standard User Encryption** setting where applicable. Pilot the policy on each hardware model and verify the recovery key is visible in the intended Entra/Intune device record before fleet assignment. Do not put recovery passwords in this app, its logs, or the Autopilot CSV.

Create a Windows compliance policy for the same group requiring BitLocker, Secure Boot, and TPM where supported. Use `Get-EmiCompliance.ps1 -RequireEnrollment -RequireBitLocker -RequireSecureBoot -RequireTpm -ExitNonCompliant` as an additional local readiness check. BitLocker stays enabled after EMI completion; EMI completion changes the app's restriction/assignment, not the customer's disk encryption.

## Build the Win32 package

Place the release executables beside `packaging/windows/install.ps1`, then package the complete `packaging/windows` directory with the Microsoft Win32 Content Prep Tool:

```text
IntuneWinAppUtil.exe -c packaging\windows -s intune\Install-Intune.ps1 -o out
```

Use these Intune Win32 app settings:

| Setting | Value |
|---|---|
| Install behavior | System |
| Install command | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\intune\Install-Intune.ps1 -SkipWingetBootstrap -CommandSigningKeyId <id> -CommandSigningPublicKey "<base64-public-key>"` |
| Uninstall command | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\intune\Uninstall-Intune.ps1` |
| Restart behavior | App install may force a device restart: No |
| Assignment | Required, device group |
| Detection rule | Custom script: `intune\Detect-EmiDeviceAgent.ps1` |
| Run detection as 32-bit | No |

Intune Win32 custom detection scripts do not receive command-line arguments. To enforce a baseline, edit the detection script's parameter defaults before upload and set `MinimumVersion` to the release being deployed. The included detection script requires a completed agent enrollment; create the matching pending device record before assigning the app. An installed but unenrolled copy is not reported as healthy.

**Reset blocker:** The current EMI API documents enrollment as one-time and rejects a second enrollment after the Device Agent leaves `PENDING`. A clean Windows reinstall or SSD replacement loses the local agent token. Autopilot and Intune can restore the binaries, but they cannot restore that token or make this one-time API accept a fresh enrollment. The administrator must use a supported backend workflow to reset/reissue enrollment for the same asset, or the backend must add a secure re-enrollment flow. Until that exists and has been tested, do not claim that this agent automatically resumes control after a clean reinstall. Repeated Intune installation attempts will not fix an enrollment refusal.

The signing key is a public verification key, not a secret. Its numeric ID must match the API patch `signing_key_id`, and the backend must produce the canonical Ed25519 signature documented in `docs/enterprise-antitheft-deployment.md`. Installation fails rather than enabling remote transitions without a valid trust key.

## Remediation and compliance

Deploy `Detect-EmiDeviceAgent.ps1` and `Remediate-EmiDeviceAgent.ps1` as an Intune Remediations package running as SYSTEM in 64-bit PowerShell. Both scripts are standalone because Intune uploads them separately. The remediation only restarts and refreshes an existing trusted installation. If binaries or the service are missing, the Required Win32 app assignment is responsible for reinstalling them.

`Get-EmiCompliance.ps1` produces machine-readable JSON. Optional enforcement switches are:

- `-RequireEnrollment`
- `-RequireBitLocker`
- `-RequireSecureBoot`
- `-RequireTpm`
- `-MinimumVersion <version>`
- `-MaximumHealthAgeMinutes <minutes>`
- `-ExitNonCompliant`

BitLocker recovery keys should be escrowed to Microsoft Entra ID before requiring encryption. Configure BitLocker, Secure Boot, and DFCI with audited Intune policy; these scripts report state and do not silently alter recovery or firmware configuration.

## Autopilot and DFCI prerequisites

Run `Test-AutopilotDfciPrerequisites.ps1` as a read-only inventory script. `-ExitWhenNotReady` returns exit code 1 when local prerequisite evidence is incomplete. A passing result is not a DFCI-support guarantee: validate the exact device model and OEM/CSP Autopilot registration against current Microsoft and manufacturer support documentation.

For reset recovery, register company-owned hardware with Windows Autopilot, use an Enrollment Status Page, and make this Win32 app required. A wiped disk does not retain this app; Autopilot and Intune reinstall it after supported provisioning. The one-time EMI enrollment limitation above must be resolved before the reinstalled agent can check in. BitLocker protects existing data on a removed SSD but cannot prevent an owner of the physical media from erasing it.
