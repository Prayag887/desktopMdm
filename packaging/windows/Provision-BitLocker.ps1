#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('ActiveDirectory','EntraID')][string]$Escrow)
$ErrorActionPreference = 'Stop'
# No private key, recovery password, or complete BitLocker object is written to output.
$t = Get-Tpm -ErrorAction Stop
if (-not $t.TpmPresent -or -not $t.TpmReady -or -not $t.TpmEnabled) { throw 'TPM must be present, enabled and ready; provisioning did not start' }
$b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
if ($b.VolumeStatus -ne 'FullyDecrypted') {
  # Existing organization configuration is authoritative, including paused encryption.
  Write-Output '{"changed":false,"detail":"Existing encryption configuration preserved; use your organization BitLocker policy to service it"}'
  return
}
if ($b.LockStatus -ne 'Unlocked') { throw 'OS volume must be unlocked' }
$before = @($b.KeyProtector | ForEach-Object { $_.KeyProtectorId })
try {
  $recovery = @($b.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
  if ($recovery.Count -eq 0) {
    $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
    $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $recovery = @($b.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
  }
  if ($recovery.Count -eq 0) { throw 'No recovery password protector available for escrow' }
  foreach ($protector in $recovery) {
    if ($Escrow -eq 'ActiveDirectory') { $null = Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop }
    else { $null = BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop }
  }
  # Full-volume encryption for previously used drives; retain Windows hardware test.
  # Policy-selected encryption method is preserved by leaving EncryptionMethod unset.
  $tpm = @($b.KeyProtector | Where-Object { [string]$_.KeyProtectorType -like 'Tpm*' })
  if ($tpm.Count -gt 0) { throw 'Existing TPM protector on a decrypted volume requires organization review; recovery protectors preserved' }
  $null = Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop
  $after = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $ids = @($after.KeyProtector | ForEach-Object { $_.KeyProtectorId })
  foreach ($id in $before) { if ($ids -notcontains $id) { throw 'An existing protector is missing; administrator investigation required' } }
  if (@($after.KeyProtector | Where-Object { [string]$_.KeyProtectorType -like 'Tpm*' }).Count -eq 0) { throw 'TPM protector verification failed' }
  Write-Output '{"event":"bitlocker_configuration_change","changed":true,"detail":"Recovery escrow completed; BitLocker hardware test may require restart; verify protection after reboot"}'
} catch {
  # Never remove protectors as rollback, never log cmdlet exception text (may contain secrets).
  throw 'BitLocker provisioning failed safely; protectors retained. Review BitLocker event logs and organization policy before retrying.'
}
