# Production hardening and prerequisites

## Ready in the client, not yet deployed to a fleet

- Remote transitions require provisioned Ed25519 command keys and the matching backend contract. TLS/checksum metadata alone does not authorize a transition.
- Version, nonce history, and the full signed-message digest are persisted in the same atomic document as the remote state. Exact retries must match all signed fields. Local UTC and server time both constrain expiry; downloads are rechecked before commit. Administrative clock/state rollback remains outside software-only protection.
- The shared unlock word and the known lab recovery key are removed. Only the provisioned owner recovery public key is accepted; private signing material never goes on managed devices.
- A dedicated service worker validates offline recovery without waiting for the network. Counter and response commit together. The UI cannot write recovery state; missing state and write failures never produce a success receipt.
- Release publishing requires an Authenticode identity, publisher thumbprint verification, and a timestamp. ZIP SHA-256 checksums are published alongside signed binaries.

These changes do not retroactively harden v0.6.31 or existing installations. The backend, signing identity, Microsoft tenant, and Windows hardware acceptance tests are rollout prerequisites.

## Owner recovery key

`packaging/windows/recovery-public-key.hex` contains the new public key. Its private half was generated into an owner-only file on the owner's workstation, outside Git. Back it up in an offline vault before deployment. Losing it requires administrator recovery and public-key rotation; this repository cannot reconstruct it.

The installer uses the bundled public key unless `-RecoveryPublicKeyHex` explicitly overrides it. The service rejects the published lab key. Rotation preserves the counter. Use separate keys for remote commands and offline recovery.

Generate a replacement on an offline Unix workstation:

```sh
cargo run --example keygen -p emi-core -- /secure/owner-recovery.key
cargo run --example mint-unlock -p emi-core -- /secure/owner-recovery.key <local-device-uuid> <next-counter> 15
```

Only the public key and short-lived device-specific tokens may be distributed. Never upload the private file to GitHub secrets, attach it to support tickets, or include it in an installer. The mailbox may be disrupted by a malicious user, so keep administrator recovery available. It is not an anti-DoS channel.

## Backend integration gate

The backend is not present in this repository. Follow `backend-signed-command-checklist.md`, provision its public key with `trust-command-key`, and restart the service after key changes. Never deploy a client without coordinating this contract: unsigned or unknown-key commands are deliberately rejected, including unlock commands. Keep offline/admin recovery working throughout migration.

Required acceptance: actual server-signed LOCK and UNLOCK; changed reason/action/device/expiry/checksum rejected; replay and re-signed equal-version substitution rejected; network loss and service restart preserve state; acknowledgement retries do not repeat an unauthorized transition.

## Obtain and connect a signing identity

No signing identity is currently configured. Choose a certificate/signing provider that supports your organization and jurisdiction. New certificates may require hardware-backed or managed signing; do not assume the provider can export a PFX.

The existing PFX-capable workflow now requires:

- Repository secrets `CODE_SIGN_PFX_BASE64` and `CODE_SIGN_PFX_PASSWORD`.
- Repository variable `CODE_SIGN_CERT_SHA1`: the intended publisher certificate thumbprint (40 hex characters).

Configure those through GitHub's protected secret UI only if your provider permits this signing model. Otherwise integrate the provider's supported managed-signing/OIDC workflow and preserve the signature, publisher, timestamp, and checksum checks. Do not substitute a self-signed certificate for a publicly trusted production identity. Avoid broad Defender exclusions; validate the signed program against organizational policy.

## Fleet setup order (requires an Intune/Entra tenant)

Nothing below has been applied to a tenant. Use a pilot device group and retain a separate recovery administrator before fleet assignment.

1. **Enrollment:** establish the organization tenant/licensing and device ownership; register Autopilot devices and assign the profile, standard-user account type, automatic MDM enrollment, and Enrollment Status Page. Set this app as Required in SYSTEM context. Use the Intune wrapper, which preserves WinRE. `install.cmd` disables WinRE and prevents Autopilot Reset until re-enabled.
2. **BitLocker:** create an endpoint-security disk-encryption profile. Require device encryption and successful Microsoft Entra recovery-key backup before encryption completes. Require Secure Boot/TPM in compliance for supported hardware. Verify the actual escrowed key in the correct device record before handoff; local protection status alone does not prove escrow. [Microsoft policy settings](https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-disk-encryption-settings).
3. **Windows LAPS:** enable LAPS in Entra, create an Account protection → Local admin password solution policy, back up to Entra, choose the authorized recovery account, use a long generated password (for example 20 characters), and configure rotation (for example 30 days and after recovery use). These are proposed deployment values, not guarantees. Validate account-management support for each OS version; policy for a named account does not necessarily create that account. Test authorized password retrieval and rotation before removing any existing administrator access. [Microsoft LAPS deployment](https://learn.microsoft.com/en-us/intune/intune-service/protect/windows-laps-policy), [policy definitions](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings).
4. **App Control:** configure Intune Management Extension as a managed installer, then deploy App Control in **Audit only** to the pilot group. Install the signed agent through Intune, exercise boot, UAC, recovery, BIOS tools, updates, and uninstall, and review Code Integrity logs. Include approved recovery and OEM utilities. Only enforce after the observed application set is approved and rollback is tested. Previously installed apps may need redeployment to gain managed-installer trust. [Microsoft deployment guidance](https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy).
5. **Pilot and expand:** verify BitLocker escrow, LAPS retrieval, service startup, token recovery with network disconnected, signed commands, reinstall enrollment, and App Control rollback on each hardware family. Intune reinstall does not solve the current backend's one-time re-enrollment limitation.

Local tests and CI cannot prove tenant escrow, firmware support, or physical-device recovery. Record those acceptance results before rollout.
