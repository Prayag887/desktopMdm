# Local Windows device hardening

These tools add owner-controlled deployment protections without a cloud MDM service. Run them on the organization-owned Windows PC from a separate owner administrator account, using a trusted release package. They do not make a Windows application undeletable.

The Windows account/encryption tools are manufacturer-independent and target supported Windows 11 x64 PCs, including ASUS, Acer and Dell. Firmware capabilities vary by model. For second-hand stock, start with a clean, trusted Windows installation and current firmware. An activated or unactivated OS status alone does not prove integrity; modified/cracked images cannot provide a trustworthy enforcement baseline.

## Provision a fleet device

Prepare the two local accounts, an owner NTFS USB drive and the ADK ScanState tools as described below and in the reset recovery guide. From elevated 64-bit Windows PowerShell, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Provision.ps1 -EnrolledUser 'Customer' -Harden -RecoveryAdministrator 'DeviceOwner' -OfflineRecoveryKeyDirectory 'E:\DeviceOwnerKeys' -ScanStateDir 'D:\ScanState_amd64'
```

Replace these account names and paths per PC. Hardened provisioning installs the signed agent, verifies owner credentials and reduces daily-user privileges, saves recovery keys and configures encryption, then captures reset recovery. Failures stop subsequent steps and identify that the device is not ready for handoff; completed security changes are retained. The historical `provision.cmd username` invocation remains installation-only. Use the explicit PowerShell command above for hardening.

The agent's existing signed server commands still control payment lock/unlock. These tools neither create a local unlock button nor infer payment status. Hardware hardening does not guarantee uninterrupted payment restriction across a reset: restoring a snapshot can roll back state, and fresh payment decisions still require the existing API.

## Prepare accounts

Create an owner-only local administrator and verify its login before handoff. Keep its credentials with the owner; do not share them with the daily user. The daily account and owner account must both exist and be enabled.

From elevated 64-bit Windows PowerShell, replace the example names:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Harden-LocalAccount.ps1 -DailyUser 'Customer' -RecoveryAdministrator 'DeviceOwner'
```

The command verifies the owner credentials before changes, retains that administrator and makes only the selected local daily account a member of Users. It removes that account from Administrators, Power Users, Print Operators, Backup Operators, Network Configuration Operators, Hyper-V Administrators, Remote Desktop Users and Remote Management Users when present. It rejects the built-in Administrator as a daily user, a disabled/missing owner administrator, and execution from the daily user's own session. Failed changes restore prior memberships where possible. Domain-joined PCs require organization account policy instead. Custom group privileges, directly granted remote logon rights and access to another administrator's credentials still need owner review.

Sign out **every** session of the daily user and close its old processes, then sign in again. Existing access tokens retain earlier privileges until their processes exit. From that standard-user session verify that deleting the installation, stopping either service, modifying the scheduled task and running uninstall all require owner administrator credentials. Verify owner sign-in and authorized recovery still work.

## Protect the OS drive without directory escrow

Use a removable NTFS-formatted USB drive under the owner's control. Formatting is not performed by the tool. Replace the example path with a new folder on that USB drive:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Provision-OfflineBitLocker.ps1 -RecoveryKeyDirectory 'E:\DeviceOwnerKeys'
```

This requires supported BitLocker management, an enabled/ready TPM and Secure Boot. It saves all available recovery-password protectors into a new owner-protected file and verifies the file before starting full-volume TPM-backed encryption. Existing encryption and protectors are retained. A hardware test/reboot may be required. Unsupported or ambiguous states stop provisioning. The JSON file contains real recovery secrets: remove the USB drive, keep it offline with the owner, and maintain another secure recovery copy. No passwords are printed to normal output.

Reboot, then verify the OS volume is `FullyEncrypted`, protection is `On`, and owner recovery material is usable before handoff. BitLocker protects disk contents and offline modification; it cannot prevent erasure or replacement of the disk.

## Restrict firmware boot and configure restoration

For the exact supported model, have the owner set a firmware administrator/supervisor password and use the OEM's documented settings to restrict external USB/network boot and unauthorized boot-order changes. Keep Secure Boot enabled and firmware updated. Use the existing BIOS-password UI where the OEM interface is supported; configure remaining boot controls in firmware. Do not assume these controls exist on every model or that Secure Boot alone prevents another signed OS from booting. Record the model, firmware version and tested boot behavior.

Next, follow [Offline reset recovery](offline-reset-recovery.md) to capture a fresh recovery package after account/encryption configuration and perform both supported offline reset tests. Confirm standard-user memberships, BitLocker protection, agent services, startup task, identity/state and owner recovery again after each reset. Restoration can roll state back; it is not a guarantee of uninterrupted payment enforcement.

Use `-WhatIf` on either new tool to preview its action without changing memberships or encryption. Account credential verification occurs only when applying the account change.

Microsoft references: [Local group membership management](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/remove-localgroupmember?view=powershell-5.1), [BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures).
