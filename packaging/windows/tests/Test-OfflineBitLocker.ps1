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
function Get-BitLockerVolume { return $script:volume }
function Add-BitLockerKeyProtector {
  $script:addCalls++
  $script:volume.KeyProtector=@([pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='{fake-test-id}';RecoveryPassword=$script:password})
}
function Enable-BitLocker {
  # Enabling encryption before a usable recovery backup is a regression.
  $files=@(Get-ChildItem -LiteralPath $script:keyDirectory -Filter '*.json')
  Assert ($files.Count -eq 1) 'Encryption started before recovery backup'
  $saved=Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
  Assert ($saved.keys[0].recoveryPassword -eq $script:password) 'Recovery backup is unusable'
  $script:enableCalls++
  $script:volume.VolumeStatus='EncryptionInProgress'
}
function Reset-Fixture {
  $script:volume=[pscustomobject]@{LockStatus='Unlocked';VolumeStatus='FullyDecrypted';ProtectionStatus='Off';KeyProtector=@()}
  $script:password='111111-111111-111111-111111-111111-111111-111111-111111'
  $script:enableCalls=0; $script:addCalls=0
}
try {
  # Keep the real temp drive writable while treating a different drive as the mocked OS.
  $env:SystemDrive=if ($temporary.StartsWith('Q:',[StringComparison]::OrdinalIgnoreCase)) { 'Z:' } else { 'Q:' }
  Reset-Fixture
  $script:keyDirectory=Join-Path $temporary 'valid'
  $output=& $tool -RecoveryKeyDirectory $script:keyDirectory -Confirm:$false | Out-String
  Assert ($script:enableCalls -eq 1) 'Encryption was not enabled after backup'
  Assert (-not $output.Contains($script:password)) 'Recovery secret leaked to output'
  Reset-Fixture
  $script:keyDirectory=Join-Path $temporary 'dry-run'
  $null=& $tool -RecoveryKeyDirectory $script:keyDirectory -WhatIf
  Assert ($script:addCalls -eq 0 -and $script:enableCalls -eq 0 -and -not (Test-Path $script:keyDirectory)) 'WhatIf changed device state'
  Reset-Fixture
  $script:password='invalid'
  $script:keyDirectory=Join-Path $temporary 'invalid'
  $failed=$false
  try { $null=& $tool -RecoveryKeyDirectory $script:keyDirectory -Confirm:$false } catch { $failed=$true }
  Assert ($failed -and $script:enableCalls -eq 0) 'Encryption started without a usable recovery password'
  Reset-Fixture
  $script:keyDirectory=Join-Path $temporary 'existing'
  $script:volume.VolumeStatus='FullyEncrypted'; $script:volume.ProtectionStatus='On'
  $null=& $tool -RecoveryKeyDirectory $script:keyDirectory -Confirm:$false
  Assert ($script:enableCalls -eq 0) 'Existing encryption was reconfigured'
  Write-Output 'Offline BitLocker: backup-before-encryption, no secret output, dry-run, invalid-key rejection and existing encryption preservation passed.'
} finally { $env:SystemDrive=$originalDrive; Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
