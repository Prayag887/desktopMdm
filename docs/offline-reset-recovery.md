# Offline Windows reset recovery

`Provision-OfflineRecovery.ps1` prepares a local Windows push-button reset package. No cloud service is needed to capture or restore the installed application. The agent still uses its existing API for enrollment and new management commands.

Recovery capture is a per-device provisioning step integrated into the updated `install.cmd`. It captures the installed applications and Windows settings baseline, plus explicit agent binaries, ProgramData state, repair cache, service registration and companion task artifacts. It is not an agent-only installer. Prepare a clean organization-owned PC before handing it to a user. The package can contain device credentials and captured state: never reuse it across devices or distribute it as a release artifact.

## Prepare a Windows x64 PC

### Capture during installation

The updated source `install.cmd` automatically prepares Microsoft ScanState and requires successful recovery capture before returning success. Run `install.cmd` as administrator with internet access. If the required ADK components are absent, the installer downloads Microsoft's signed ADK setup and silently installs Deployment Tools and USMT (CEIP disabled, no automatic restart). It then combines the x64 USMT and Windows Setup files in a protected directory under the agent installation. A complete installed ADK is reused. Microsoft ADK remains installed afterward; capture includes the PC application/settings baseline.

For offline deployment, you can still provide a prepared directory:

```cmd
install.cmd -ScanStateDir "D:\ScanState_amd64" -CommandSigningKeyId 1 -CommandSigningPublicKey "SERVER_ED25519_PUBLIC_KEY_BASE64"
```

Replace the public key placeholder with your server's actual deployment public key. Download, signature, ADK setup or capture failures return failure even if the application is already installed; that PC is not ready for handoff. If ADK requests a restart, restart and rerun installation. An existing recovery package must be explicitly archived before recapturing an approved upgrade. Do not distribute packages between PCs.

Direct `Start-EmiInstaller.ps1` and `Provision.ps1` calls retain their existing behavior unless recovery is explicitly requested; `Provision.ps1 -Harden` already captures recovery after its hardening steps. Automatic recovery preparation is included in v0.6.55. Capture completion still records `resetValidated: false` and does not replace the acceptance tests below.

1. Install a signed production agent release normally, with deployment public keys. Verify both services are running and the companion launches at logon.
2. On a technician PC, install the Windows ADK USMT and Deployment Tools. Prepare a matching x64 ScanState directory by copying USMT `amd64` files and Windows Setup `amd64\Sources` files into one directory, following Microsoft's deployment guide below. Include `Config_AppsAndSettings.xml`. Transfer that directory by USB if the target is offline. The script does not download tools.
3. Run `reagentc /info` as administrator and confirm Windows RE is **Enabled**. Preserve existing OEM recovery customizations. Allow enough disk space for a baseline capture.
4. In elevated Windows PowerShell, run from the extracted agent release:

   ```powershell
   .\Provision-OfflineRecovery.ps1 -ScanStateDir 'D:\ScanState_amd64'
   ```

The script checks installed release integrity and service/task presence, adds explicit migration rules, and invokes ScanState without the continue-on-error flag. It publishes `C:\Recovery\Customizations\EmiDeviceAgent.ppkg` only after a successful nonempty capture. The Recovery directory, customization directory and package are restricted to SYSTEM and Administrators; this also tightens inherited permissions on existing OEM recovery assets, without replacing their content. Logs and the SHA-256 capture report stay in a protected staging directory beside it. An existing agent package causes the command to stop; archive it explicitly before replacing it.

Follow the Windows deployment guide's audit-mode/OOBE preparation for factory deployments. Provisioning an already deployed PC requires the same model/build reset tests; merely creating a package is not proof of supported restoration.

## Required reset acceptance test

Use a spare PC or a recoverable VM snapshot. These tests erase application/user state; do not run them on the development workstation.

1. Record Windows build, hardware model, installed agent version, service settings, scheduled task and local device UUID. Keep administrator recovery access and BitLocker recovery keys available.
2. Disconnect networking. Test **Reset this PC → Keep my files → Local reinstall**, with restoration of preinstalled apps enabled when Windows offers that choice. The installer hides the Settings Recovery page, so use the supported Windows RE entry point or have an administrator restore the page policy for testing.
3. After reset, verify the installed release with `Get-DeviceProtection.ps1`, both automatic services, SYSTEM service accounts, the all-users companion task, publisher signatures, state ACLs and administrator recovery. Confirm the companion appears at logon and that captured device identity/state behaves as expected offline.
4. Repeat from a fresh captured baseline using **Remove everything → Local reinstall**, from both Settings and Windows RE where applicable. Test any OEM reset variants you intend to support.
5. Reconnect and verify API check-in. If enrollment was not restored, the current one-time API enrollment contract requires an administrator to reissue/reset enrollment for that asset.
6. Record actual results separately from the capture report; `resetValidated: false` means capture succeeded but restoration has not been tested. Do not claim support for a model/build until these checks pass.

Captured state is a snapshot. A reset can restore an older lock state, token, recovery counter or command replay history. This feature does not establish tamper-resistant continuity of payment restrictions across resets. Validate that risk with the backend before using it for enforcement. Recapture after approved upgrades or enrollment changes; remove obsolete packages on authorized retirement, otherwise a later reset may restore the retired app.

## Limits

Deleting recovery files/partitions, disabling restoration of preinstalled apps, installing an unrelated recovery image, a USB clean install or replacing the SSD can bypass local recovery. This script does not change firmware or disk partitions, disable recovery, or make the app undeletable. An offline restore does not provide fresh server commands.

Microsoft references: [Deploy push-button reset features](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-push-button-reset-features?view=windows-11), [Recovery components](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/recovery-strategy-for-common-customizations?view=windows-11), [USMT XML elements](https://learn.microsoft.com/en-us/windows/deployment/usmt/usmt-xml-elements-library).

Automatic ADK setup references: [ADK downloads and supported Windows versions](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install), [silent ADK installation](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-offline-install), [ScanState file preparation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-pbr-features-using-auto-apply).

GitHub Actions uses Windows Server, which Microsoft USMT does not support. The release test runs the actual installer and ADK setup, verifies ScanState rejects that OS without publishing a package, and checks installed services, upgrade, repair, rollback and uninstall. This is not a successful Windows 11 capture or reset test. [Microsoft USMT requirements](https://learn.microsoft.com/en-us/windows/deployment/usmt/usmt-requirements).
