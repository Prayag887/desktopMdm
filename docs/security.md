# Security and deployment boundaries

## Required before production

1. Terminate TLS at a trusted reverse proxy; never enroll over plain HTTP.
2. Replace shared enrollment keys with short-lived, single-device enrollment tokens.
3. Store agent tokens with Windows DPAPI or TPM-backed keys and hash server-side token values.
4. Add named admin accounts, MFA/SSO, CSRF protection, session expiry, and role-based authorization. Basic authentication is only a bootstrap mechanism.
5. Authenticode-sign the agent and installer, pin update signatures, and restrict service/installation ACLs with an enterprise policy.
6. Add rate limits, encrypted backups, retention policy, audit export, alerting, and a formal privacy/consent flow.
7. Obtain legal review before using payment status to limit a financed device; local consumer-credit and privacy laws vary.

## Firmware credentials

BIOS management differs by OEM and model. A production adapter must use the vendor-supported enterprise interface (for example, a supported Dell, HP, or Lenovo management provider), verify model/firmware compatibility, preserve a break-glass recovery secret, and report an auditable result.

Firmware secrets must never be stored or queued as plaintext. The intended command shape contains an encrypted envelope, but this repository intentionally ships without an encryption-key enrollment protocol or adapter. The agent therefore rejects BIOS rotation commands. Add an audited per-device public-key envelope design before enabling the admin control.

## PIN semantics

The `SetManagedLockPin` command stores a verifier for an application-managed restriction screen. It does not alter a Windows account password or Windows Hello PIN. A production lock experience should use Windows Assigned Access, MDM CSPs, or another documented enterprise policy and must preserve emergency access.

