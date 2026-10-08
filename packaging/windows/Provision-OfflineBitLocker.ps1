#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param([Parameter(Mandatory=$true)][string]$RecoveryKeyDirectory)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Run in 64-bit Windows PowerShell.' }
$directory = [IO.Path]::GetFullPath($RecoveryKeyDirectory)
if ($directory -notmatch '^([A-Za-z]):\\') { throw 'Recovery keys must be saved to a local removable NTFS drive.' }
$driveLetter = $Matches[1]
if (($driveLetter + ':') -eq $env:SystemDrive) { throw 'Recovery keys cannot be saved on the OS drive.' }
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($driveLetter):'" -ErrorAction Stop
if (-not $disk -or $disk.DriveType -ne 2 -or $disk.FileSystem -ne 'NTFS') { throw 'Use a removable USB drive formatted as NTFS so recovery-key access can be restricted.' }
$ancestor = $directory
while ($ancestor) {
  if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Recovery-key path cannot contain reparse points.' }
  $parent = Split-Path -Parent $ancestor
  if ($parent -eq $ancestor) { break }
  $ancestor = $parent
}
$tpm = Get-Tpm -ErrorAction Stop
if (-not $tpm.TpmPresent -or -not $tpm.TpmReady -or -not $tpm.TpmEnabled) { throw 'TPM must be enabled and ready.' }
if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) { throw 'Enable Secure Boot in supported firmware before provisioning.' }
$volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
if ($volume.LockStatus -ne 'Unlocked' -or $volume.VolumeStatus -notin @('FullyDecrypted','FullyEncrypted','EncryptionInProgress')) { throw 'Unlock the OS volume and resolve paused/decrypting encryption before provisioning.' }
if ($volume.VolumeStatus -eq 'FullyDecrypted' -and @($volume.KeyProtector | Where-Object { [string]$_.KeyProtectorType -like 'Tpm*' }).Count -gt 0) { throw 'An existing TPM protector on a decrypted volume requires administrator review.' }
if (-not $PSCmdlet.ShouldProcess($env:SystemDrive, 'Save recovery keys to the owner USB drive, then enable full-volume BitLocker if decrypted')) { return }
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $directory -AclObject $acl
$recovery = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
if ($recovery.Count -eq 0) {
  $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
  $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $recovery = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
}
if ($recovery.Count -eq 0) { throw 'No recovery password was created; encryption was not started.' }
# CreateNew prevents accidentally overwriting another device's recovery material.
$backup = Join-Path $directory ('BitLocker-' + [Guid]::NewGuid().ToString('N') + '.json')
$keys = @($recovery | ForEach-Object {
  if ($_.RecoveryPassword -notmatch '^\d{6}(-\d{6}){7}$') { throw 'A recovery password is unavailable; encryption was not started.' }
  @{ protectorId=$_.KeyProtectorId; recoveryPassword=$_.RecoveryPassword }
})
$content = @{ computer=$env:COMPUTERNAME; volume=$env:SystemDrive; savedAt=[DateTime]::UtcNow.ToString('o'); keys=$keys } | ConvertTo-Json -Depth 5
$stream = [IO.File]::Open($backup, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($content)
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush($true)
} finally { $stream.Dispose() }
if ([IO.File]::ReadAllText($backup) -ne $content) { throw 'Recovery-key backup verification failed; encryption was not started.' }
# Never print recovery passwords or remove protectors on failure.
$content = $null; $keys = $null; $bytes = $null
if ($volume.VolumeStatus -eq 'FullyDecrypted') { $null = Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop }
$after = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
[ordered]@{ recoveryBackup=$backup; encryptionState=[string]$after.VolumeStatus; protectionStatus=[string]$after.ProtectionStatus; rebootAndVerifyRequired=$true } | ConvertTo-Json
Write-Host 'Remove the recovery USB drive and keep it with the owner. Reboot and verify encryption and protection before handoff.'
