#Requires -Version 5.1
#Requires -RunAsAdministrator
# All hardware/encryption commands are mocked; only an isolated temp folder is used.
$ErrorActionPreference='Stop'
$tool=Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-OfflineBitLocker.ps1'
$temporary=Join-Path $env:TEMP ('EmiOfflineKeyTest-'+[Guid]::NewGuid().ToString('N'))
$originalDrive=$env:SystemDrive
function Assert($condition,$message) { if (-not $condition) { throw $message } }
function Get-CimInstance { [pscustomobject]@{ DriveType=2; FileSystem='NTFS' } }
function Get-Tpm { [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true } }
function Confirm-SecureBootUEFI { return $true }
function Get-BitLockerVolume { return $global:EmiOfflineTestVolume }
function Add-BitLockerKeyProtector {
  $global:EmiOfflineTestAddCalls++
  $global:EmiOfflineTestVolume.KeyProtector=@([pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='{fake-test-id}';RecoveryPassword=$global:EmiOfflineTestPassword})
}
function Enable-BitLocker {
  # Enabling encryption before a usable recovery backup is a regression.
  $files=@(Get-ChildItem -LiteralPath $global:EmiOfflineTestKeyDirectory -Filter '*.json')
  Assert ($files.Count -eq 1) 'Encryption started before recovery backup'
  $saved=Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
  Assert ($saved.keys[0].recoveryPassword -eq $global:EmiOfflineTestPassword) 'Recovery backup is unusable'
  $global:EmiOfflineTestEnableCalls++
  $global:EmiOfflineTestVolume.VolumeStatus='EncryptionInProgress'
}
function Reset-Fixture {
  $global:EmiOfflineTestVolume=[pscustomobject]@{LockStatus='Unlocked';VolumeStatus='FullyDecrypted';ProtectionStatus='Off';KeyProtector=@()}
  $global:EmiOfflineTestPassword='111111-111111-111111-111111-111111-111111-111111-111111'
  $global:EmiOfflineTestEnableCalls=0; $global:EmiOfflineTestAddCalls=0
}
try {
  # Keep the real temp drive writable while treating a different drive as the mocked OS.
  $env:SystemDrive=if ($temporary.StartsWith('Q:',[StringComparison]::OrdinalIgnoreCase)) { 'Z:' } else { 'Q:' }
  Reset-Fixture
  $global:EmiOfflineTestKeyDirectory=Join-Path $temporary 'valid'
  $output=& $tool -RecoveryKeyDirectory $global:EmiOfflineTestKeyDirectory -Confirm:$false | Out-String
  Assert ($global:EmiOfflineTestEnableCalls -eq 1) 'Encryption was not enabled after backup'
  Assert (-not $output.Contains($global:EmiOfflineTestPassword)) 'Recovery secret leaked to output'
  Reset-Fixture
  $global:EmiOfflineTestKeyDirectory=Join-Path $temporary 'dry-run'
  $null=& $tool -RecoveryKeyDirectory $global:EmiOfflineTestKeyDirectory -WhatIf
  Assert ($global:EmiOfflineTestAddCalls -eq 0 -and $global:EmiOfflineTestEnableCalls -eq 0 -and -not (Test-Path $global:EmiOfflineTestKeyDirectory)) 'WhatIf changed device state'
  Reset-Fixture
  $global:EmiOfflineTestPassword='invalid'
  $global:EmiOfflineTestKeyDirectory=Join-Path $temporary 'invalid'
  $failed=$false
  try { $null=& $tool -RecoveryKeyDirectory $global:EmiOfflineTestKeyDirectory -Confirm:$false } catch { $failed=$true }
  Assert ($failed -and $global:EmiOfflineTestEnableCalls -eq 0) 'Encryption started without a usable recovery password'
  Reset-Fixture
  $global:EmiOfflineTestKeyDirectory=Join-Path $temporary 'existing'
  $global:EmiOfflineTestVolume.VolumeStatus='FullyEncrypted'; $global:EmiOfflineTestVolume.ProtectionStatus='On'
  $null=& $tool -RecoveryKeyDirectory $global:EmiOfflineTestKeyDirectory -Confirm:$false
  Assert ($global:EmiOfflineTestEnableCalls -eq 0) 'Existing encryption was reconfigured'
  Write-Output 'Offline BitLocker: backup-before-encryption, no secret output, dry-run, invalid-key rejection and existing encryption preservation passed.'
} finally {
  $env:SystemDrive=$originalDrive
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Variable -Scope Global -Name EmiOfflineTestVolume,EmiOfflineTestPassword,EmiOfflineTestEnableCalls,EmiOfflineTestAddCalls,EmiOfflineTestKeyDirectory -ErrorAction SilentlyContinue
}
