# Payment-restricted mode — architecture, threat model, and safety boundaries

> Scope: authorized EMI device management on **company-owned** Windows PCs, with
> customer consent captured at enrollment. This document describes a *safe,
> reversible* design and separates a **lab-safe prototype** (in this repo) from
> **production security recommendations** (documented, not implemented here).
>
> Lock state is controlled by the YajTech EMI admin API. The Windows service
> enrolls once, checks in at boot/resume and every 60 seconds, validates pending
> patch metadata/download integrity, persists the last confirmed state, and
> acknowledges application back to the server.

## 1. Goals and non-goals

Goals:

- Show a **branded payment-restriction screen** — explicitly *not* a fake Windows
  BSOD, not a fake crash, not a fake stop code.
- Restrict only the **enrolled standard customer account**.
- Prefer **Microsoft-supported** mechanisms: Assigned Access, Shell Launcher,
  AppLocker, Keyboard Filter (WEKF), CSP/MDM policy, a Windows service.
- Suppress escape shortcuts (Alt+Tab, Alt+F4, Win, Ctrl+Shift+Esc, …) only
  **where officially supported**, while keeping the keyboard usable for
  accessibility, network recovery, payment-reference entry, and admin auth.
- Reversible: automatic release on a signed "payment restored" policy.
- Fail **safe** (release, never trap) on expired / malformed / unverifiable policy.

Non-goals (explicitly forbidden in this design):

- No custom kernel keyboard driver; no modification of keyboard drivers.
- No credential interception; no data destruction.
- No interference with Windows Recovery Environment (WinRE).
- No absolute uninstall prevention against an authorized administrator / WinRE.
- No stealth, no persistence of the restriction against recovery accounts.

## 2. Why "disable the keyboard completely" is rejected

A full keyboard kill directly breaks four stated requirements: recovery-code
entry, technician authentication, accessibility, and payment-reference entry. It
also creates a hard-trap failure mode: if the release path faults, the account is
bricked with no input. That is the irreversible behavior the brief forbids.

Microsoft's supported control is **Keyboard Filter (WEKF)**, which blocks
*specific* key combinations from an allow/block list while ordinary typing keeps
working. The correct primitive is therefore a **scoped filter**, not a global
disable:

- Block: `Alt+Tab`, `Alt+F4`, `LWin`/`RWin`, `Ctrl+Shift+Esc`, `Ctrl+Esc`,
  `Alt+Esc`, `Win+*` hotkeys, `Ctrl+Alt+Del` breakout via Assigned Access.
- Allow: letters, digits, navigation, and the keys needed for the recovery field
  and accessibility tools.

`Ctrl+Alt+Del` (SAS) is handled by Assigned Access kiosk configuration, not by
suppressing the driver.

## 3. Component architecture

```
Enrolled standard user session
  └─ Assigned Access / Shell Launcher  → EMI app is the shell for THAT account
       ├─ AppLocker                     → only the signed EMI binary + recovery
       │                                  tools may launch
       ├─ Keyboard Filter (WEKF)        → block escape combos, ALLOW text keys
       ├─ Payment-restriction screen    → branded, fullscreen, topmost
       └─ Recovery surface (always on)  → recovery-code field + technician auth
                                          (keyboard MUST stay alive here)

Windows service (LocalSystem, separate process)
  ├─ evaluates the signed policy → sets / clears the restriction flag
  ├─ append-only audit log
  ├─ policy version + monotonic counter (rollback protection)
  └─ staging / test-mode flag

Administrator + WinRE accounts → NEVER targeted (exempt by account SID)
```

Restriction decision (pure function, fail-safe):

```
restricted =
    policy.verify(pubkey)            // signature valid
 && policy.not_expired(now)          // time-limited
 && policy.counter > last_seen       // rollback protection
 && policy.state == Unpaid
 && current_account == enrolled_sid  // never admin / recovery
```

Anything else → **released** (fail open to *unrestricted*).

## 4. Threat model

| # | Threat | Mitigation |
|---|--------|-----------|
| 1 | User escapes via Alt+Tab / Win / Task Manager | Keyboard Filter blocklist + Assigned Access single-app kiosk |
| 2 | User uninstalls the app | Program Files ACL + service ownership; an **authorized admin / WinRE can still remove it** (no absolute block) |
| 3 | Attacker forges a "paid" policy | Ed25519 signature verified against an embedded/pinned public key |
| 4 | Replay of an old paid→unpaid policy | Monotonic counter; reject `counter <= last_seen` |
| 5 | User trapped, release path fails | Fail-open; prototype 5-min timeout; offline signed time-limited recovery code; keyboard kept alive for entry |
| 6 | Brute force of the recovery code | Rate limiting + audit + short-lived signed codes |
| 7 | "It intercepts my password" | No credential capture; no keyboard driver; WinRE untouched |
| 8 | Restriction applied to admin / recovery | SID allowlist for exempt accounts; restriction only for enrolled SID |
| 9 | Malformed / truncated policy file | Strict parse; parse failure = released, logged |

## 5. Recovery paths (never remove all of these)

1. **Signed "payment restored" policy** → automatic release.
2. **Offline recovery code**: signed, time-limited, single-use, rate-limited.
   Keyboard stays enabled for entry.
3. **Authenticated technician**: local admin / recovery account is never
   restricted and can exit directly.
4. **WinRE**: untouched — last-resort OS recovery always available.
5. Prototype only: 5-minute safety timeout and explicit Exit button.

## 6. Windows edition requirements

| Feature | Requires |
|---------|----------|
| Assigned Access (kiosk) | Windows Pro/Enterprise/Education (single-app); multi-app kiosk is Enterprise/Education/IoT |
| Shell Launcher | Enterprise / Education / IoT Enterprise |
| Keyboard Filter (WEKF) | Enterprise / Education / IoT Enterprise |
| AppLocker | Enterprise / Education (Pro via MDM CSP) |
| CSP / MDM policy | Any managed edition via MDM |

On **Home / plain Pro** the strong controls (Shell Launcher, Keyboard Filter)
are unavailable. There you get only a topmost fullscreen window, which a
determined user can leave. Tell customers this before enrollment.

## 7. Prototype vs production — hard separation

**Prototype (this repo, lab / VM only):**

- The fullscreen restriction screen is a normal egui window.
- Keyboard suppression is **window-scoped**: the app drains its own key/text
  events while the restriction screen is up, *except* while the recovery field
  has focus. It does **not** and **cannot** block OS-global Alt+Tab / Win — that
  is Keyboard Filter's job.
- Reversible: administrator `UNLOCK`/`RELEASE`, offline recovery token, or local administrator/WinRE recovery.
  Restart always begins unrestricted. Nothing is written to firmware or OS.

**Production (recommended, NOT implemented here):**

- Enforce via Assigned Access + Shell Launcher + Keyboard Filter + AppLocker
  applied to the enrolled SID only, delivered through MDM CSP.
- The restriction flag comes from a code-signed policy verified by the LocalSystem
  service; the UI only reflects it.
- Ship code-signed binaries; keep WinRE and admin accounts exempt.
- Never ship the prototype's window-scoped suppression as the enforcement layer.

## 8. Reference: production Keyboard Filter (do NOT run on a workstation)

For a **lab VM** on Enterprise/IoT, the supported filter is configured via the
`WEKF_PredefinedKey` / `WEKF_CustomKey` WMI classes, e.g.:

```powershell
# LAB VM ONLY. Requires the "Keyboard Filter" optional feature (Enterprise/IoT).
# Enable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter
$common = "root\standardcimv2\embedded"
foreach ($id in "Alt+Tab","Alt+F4","Ctrl+Shift+Esc","Win","Ctrl+Esc") {
  $k = Get-CimInstance -Namespace $common -ClassName WEKF_PredefinedKey `
        -Filter "Id='$id'"
  if ($k) { $k.Enabled = $true; Set-CimInstance -InputObject $k }
}
```

This blocks only those combos; ordinary typing (recovery code, password) still
works. It is reversible by setting `Enabled = $false`. It is documented here as a
production recommendation, not wired into the prototype.

## 9. Provisioning scripts (lab-VM) and edition degradation

`packaging/windows/Set-PaymentRestriction.ps1` / `Remove-PaymentRestriction.ps1`
apply and fully reverse the lockdown for **one enrolled standard account**. They
are `-LabVm`-gated, refuse to target an administrator, refuse unless another
admin account exists as recovery, never touch WinRE, and record every change to
`%PROGRAMDATA%\EmiDeviceAgent\restriction-state.json` for exact rollback.

**"Works on all editions" is impossible** — Assigned Access (Win32), Shell
Launcher, Keyboard Filter and AppLocker are gated to specific editions. The
script degrades gracefully instead of pretending:

| Layer | Home | Pro | Enterprise / Education / IoT |
|-------|------|-----|------------------------------|
| Per-user shell (app replaces Explorer) | ✅ | ✅ | ✅ |
| Disable Task Manager + Fast User Switching | ✅ | ✅ | ✅ |
| Keyboard Filter (WEKF) — block Alt+Tab/Win/… | ❌ | ❌ | ✅ |
| AppLocker exe allowlist | ❌ | ❌ | ✅ |
| Shell Launcher (supported Win32 kiosk) | ❌ | ❌ | ✅ |

On Home/Pro you get the universal base only: strong enough to stop a casual
standard user (no desktop, no Task Manager), but **bypassable via Safe Mode or a
second admin account** — because those editions lack the enforcement features.
The script logs which layers it skipped and why. Only Enterprise-class editions
reach the hard-to-bypass tier, and even there admin/WinRE recovery stays open by
design.

Strengthening the base against Safe Mode / reimage (BitLocker + BIOS password +
disabled USB/PXE boot) is the "disk/boot hardening" tier — documented, not
scripted here, because it can brick a test VM and needs firmware access.

## 10. How to unlock — owner runbook

The normal release path is an administrator `UNLOCK` or `RELEASE` command. Offline owner tokens and local administrator/WinRE access remain emergency recovery paths when API connectivity is unavailable.

### A. Offline signed unlock token (the "only the owner can do it" path)

The device embeds an Ed25519 **public** key (`OWNER_PUBLIC_KEY_HEX` in
`emi-device-ui.rs`). The matching **signing** key lives only with the owner. Only
that key can mint a token the device accepts. Crypto lives in
`crates/emi-core/src/recovery.rs`.

1. Once, offline, generate your keypair and embed the public half:
   ```sh
   cargo run --example keygen -p emi-core
   ```
   Put the printed PUBLIC key into `OWNER_PUBLIC_KEY_HEX`, rebuild, deploy.
   Store the SIGNING key in an offline vault. Never put it on a device.
2. To unlock a specific device, read its **Device ID** from the restriction
   screen, then mint a short-lived token:
   ```sh
   cargo run --example mint-unlock -p emi-core -- \
       <signing-key-hex> <device-id> <counter> <ttl-minutes>
   ```
   `counter` must be greater than any value used before for that device (the
   device stores the last accepted counter in
   `%PROGRAMDATA%\EmiDeviceAgent\unlock-counter.txt` and rejects `<=`).
3. Paste the `EMIU1-…` token into the device's recovery field → **Unlock**.

Verification is fail-safe: wrong key, wrong device, expired, replayed, or
malformed → refused, device stays locked. A leaked token only works on one
device, only until its short expiry, and only once (counter).

### B. Administrator account (the everyday recovery path)

The enrolled account is a **standard** user; an **administrator** account is
never restricted. Sign into the admin account (its own desktop is normal) and run
the teardown, which restores Explorer and removes every layer:

```powershell
.\Remove-PaymentRestriction.ps1 -LabVm
```

### C. Windows Recovery Environment (last resort)

WinRE is never touched. From WinRE you can reach an admin command prompt / reset.
This is the floor that guarantees a device is never permanently bricked.

Keep at least B or C available at all times. Losing the signing key costs you the
convenient path A, not the device.
