# Backend signed-command implementation checklist

The Windows agent rejects unsigned, expired, altered, replayed, or incorrectly targeted remote transitions. The backend must complete this work before signed device control is enabled in production.

## Key custody and rotation

- Generate an Ed25519 signing key in a managed KMS/HSM or isolated signing service. Never place the private key in the desktop app, API response, source repository, container image, database, or ordinary environment file.
- Assign each public key a nonzero unsigned 64-bit `signing_key_id` and provision its 32-byte public key through the trusted deployment channel.
- Rotate with overlapping keys: deploy the new public key first, sign with its ID after fleet adoption, then retire the old key.
- Restrict signing permission independently from normal API/database administration and audit every signing request.

## Command issuance transaction

- Authorize the administrator and device scope before command creation. Apply step-up authentication to high-impact actions.
- In one database transaction, allocate a strictly increasing per-device patch `version`, cryptographically random single-use `nonce`, command and patch UUIDs, short expirations, action, and approved user-visible reason.
- Prevent concurrent writers from allocating the same version with a row lock, serializable transaction, or atomic database counter.
- Generate final patch bytes first, then calculate their exact length and `sha256:<lowercase-hex>` digest. Do not transform those bytes afterward.
- Build and sign the canonical message below. Store the detached signature as standard base64 in `signed_payload` and return its `signing_key_id`.
- Publish the command and patch only after signing succeeds. A partial or unsigned record must never become current.

## Canonical signed message

Sign compact UTF-8 JSON with no whitespace and fields in this exact order:

```text
domain, device_uuid, patch_uuid, command_uuid, version, action, reason, nonce,
command_expires_at, patch_expires_at, checksum, size_bytes
```

- `domain` is `emi-command-patch-v1`.
- UUIDs are lowercase hyphenated strings and actions are uppercase API enum values.
- Timestamps are UTC RFC 3339 with exactly six fractional digits and trailing `Z`.
- The checksum is trimmed and lowercased before signing.
- JSON strings use standard JSON escaping and numbers are JSON integers.
- Sign these JSON bytes directly with Ed25519; do not hash, base64, or wrap the message first.

The byte-exact fixture is enforced by `canonical_message_is_byte_stable_for_backend_interop` in `apps/windows-agent/src/command_security.rs`.

## Device Agent API behavior

- Check-in returns server time and at most one current `pending_command` for the authenticated device. Never use a client-supplied device UUID as authorization.
- The current-patch endpoint returns the patch whose command UUID and action match the pending command.
- Patch download requires the device token, is scoped to that device/patch, and returns exactly the signed bytes.
- Acknowledgement is idempotent and records success/failure, timestamp, device, patch UUID, and sanitized failure reason.
- An exact acknowledged retry returns the prior outcome. Never reuse a nonce or version for a different command.
- Enforce expiry server-side and device-side, use synchronized UTC, and monitor clock drift.

## Administration and audit

- Expose explicit `LOCK`, `UNLOCK`, `WARN`, and `RELEASE` operations. The agent refuses remote `UNINSTALL`.
- A stolen device uses `LOCK` with reason `THEFT`; recovery uses `UNLOCK`; ownership transfer uses `RELEASE` only after asset approval.
- Keep an append-only audit record with actor, tenant, device, correlation ID, previous state, action, reason, UUIDs, version, key ID, issue/expiry times, and acknowledgement.
- Rate-limit issuance and acknowledgements, alert on repeated verification failures, and never log bearer tokens, private keys, authorization headers, or sensitive free-form messages.

## Required backend tests

- Reproduce the agent's exact canonical bytes and verify a server-produced signature with the provisioned public key.
- Change every signed field individually and confirm verification fails.
- Cover unknown/retired keys, malformed base64, wrong keys, expiry, command/patch mismatch, checksum/size mismatch, rollback, equal-version substitution, nonce reuse, and cross-device replay.
- Test concurrent issuance and prove per-device versions are unique and monotonic.
- Test rollback when signing/storage fails, acknowledgement retries, key overlap/rotation, and devices offline beyond expiry.
- Run an end-to-end Windows test: provision key, enroll, issue signed lock, observe acknowledgement, reboot offline, reconnect, unlock, and verify audit history.

Production rollout is blocked until these backend tests pass and the matching public key is distributed to the intended device ring.
