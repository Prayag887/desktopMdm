# Deterministic provider tests; never change real encryption or firmware.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-SecurityPosture.ps1')
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$script:present=$true; $script:ready=$true; $script:enabled=$true; $script:firmware=2; $script:bootError=$false
function Get-Tpm { [pscustomobject]@{ TpmPresent=$script:present; TpmReady=$script:ready; TpmEnabled=$true; TpmActivated=$true; TpmOwned=$true; ManufacturerIdTxt='Test'; ManufacturerVersion='1' } }
function Get-CimInstance { param($Namespace,$ClassName) if ($ClassName -eq 'Win32_Tpm') { [pscustomobject]@{SpecVersion='2.0'} } else { [pscustomobject]@{Caption='Windows Test'} } }
function Get-ComputerInfo { [pscustomobject]@{BiosFirmwareType=$script:firmware} }
function Confirm-SecureBootUEFI { if ($script:unsupported) { throw [PlatformNotSupportedException]::new('unsupported') }; if ($script:bootError) { throw 'Access denied' }; $script:enabled }
$script:encrypted=$true
function Get-BitLockerVolume { [pscustomobject]@{ VolumeStatus=$(if ($script:encrypted) {'FullyEncrypted'} else {'FullyDecrypted'}); EncryptionPercentage=$(if ($script:encrypted) {100} else {0}); ProtectionStatus=$(if ($script:encrypted) {'On'} else {'Off'}); LockStatus='Unlocked'; EncryptionMethod='XtsAes256'; KeyProtector=@([pscustomobject]@{KeyProtectorType='Tpm';KeyProtectorId='tpm'},[pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='recovery'}) } }
$t=Get-TpmProtectionStatus; Assert ($t.check.state -eq 'PROTECTED' -and $t.specificationVersion -eq '2.0') 'TPM 2.0 detection failed'
$script:present=$false; Assert ((Get-TpmProtectionStatus).check.state -eq 'UNSUPPORTED') 'No TPM detection failed'
$script:present=$true; $script:ready=$false; Assert ((Get-TpmProtectionStatus).check.state -eq 'NEEDS_ATTENTION') 'TPM not ready failed'
$script:ready=$true
Assert ((Get-SecureBootProtectionStatus).enabled -eq $true) 'Enabled Secure Boot failed'
$script:enabled=$false; $b=Get-SecureBootProtectionStatus; Assert ($b.check.state -eq 'NEEDS_ATTENTION' -and $b.supported) 'Disabled Secure Boot failed'
$script:firmware=1; Assert ((Get-SecureBootProtectionStatus).check.detail -eq 'Legacy BIOS') 'Legacy BIOS failed'
$script:firmware=2; $script:bootError=$true; $b=Get-SecureBootProtectionStatus; Assert ($b.check.state -eq 'ERROR' -and $null -eq $b.enabled -and $b.detectionError) 'Detection error collapsed to disabled'
$script:bootError=$false; $script:unsupported=$true
Assert ((Get-SecureBootProtectionStatus).check.state -eq 'UNSUPPORTED') 'UEFI unsupported detection failed'
$script:unsupported=$false
$b=Get-BitLockerProtectionStatus; Assert ($b.check.state -eq 'PROTECTED' -and $b.tpmProtectorPresent -and $b.recoveryProtectorPresent) 'BitLocker protector detection failed'
$script:encrypted=$false; Assert ((Get-BitLockerProtectionStatus).check.state -eq 'NEEDS_ATTENTION') 'Disabled BitLocker failed'
# Any attempt to mutate an existing encrypted machine fails this test.
function Enable-BitLocker { throw 'Unexpected encryption mutation' }
function Add-BitLockerKeyProtector { throw 'Unexpected protector mutation' }
function Remove-BitLockerKeyProtector { throw 'Existing protector removal prohibited' }
function Clear-Tpm { throw 'TPM clear prohibited' }
$script:encrypted=$true
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID
$script:ready=$false
$failed=$false
try { & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID } catch { $failed=$true }
Assert $failed 'Provisioning continued with unready TPM'
Write-Output 'TPM, BitLocker, Secure Boot and preservation checks passed.'

# Fresh provisioning escrows before enabling and preserves all existing protectors.
$script:ready=$true; $script:encrypted=$false; $script:events=@(); $script:extraTpm=$false
function Get-BitLockerVolume { [pscustomobject]@{VolumeStatus='FullyDecrypted';LockStatus='Unlocked'; KeyProtector=@([pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='existing-recovery'}) + $(if($script:extraTpm){@([pscustomobject]@{KeyProtectorType='Tpm';KeyProtectorId='new-tpm'})}else{@()})} }
function BackupToAAD-BitLockerKeyProtector { $script:events += 'escrow'; if ($script:escrowFailure) { throw 'Escrow failed' } }
function Enable-BitLocker { $script:events += 'enable'; $script:extraTpm=$true }
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID
Assert (($script:events -join ',') -eq 'escrow,enable') 'Encryption enabled before escrow'
$script:events=@(); $script:extraTpm=$false; $script:escrowFailure=$true; $failed=$false
try { & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID } catch { $failed=$true }
Assert ($failed -and ($script:events -join ',') -eq 'escrow') 'Encryption enabled after escrow failure'
