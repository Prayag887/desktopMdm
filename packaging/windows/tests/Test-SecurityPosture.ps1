# Deterministic provider tests; never change real encryption or firmware.
$ErrorActionPreference = 'Stop'
# Share one object with mock functions invoked from child script scopes.
$testPostureState = @{}
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-SecurityPosture.ps1')
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$testPostureState.present=$true; $testPostureState.ready=$true; $testPostureState.enabled=$true; $testPostureState.firmware=2; $testPostureState.bootError=$false
function Get-Tpm { [pscustomobject]@{ TpmPresent=$testPostureState.present; TpmReady=$testPostureState.ready; TpmEnabled=$true; TpmActivated=$true; TpmOwned=$true; ManufacturerIdTxt='Test'; ManufacturerVersion='1' } }
function Get-CimInstance { param($Namespace,$ClassName) if ($ClassName -eq 'Win32_Tpm') { [pscustomobject]@{SpecVersion='2.0'} } else { [pscustomobject]@{Caption='Windows Test'} } }
function Get-ComputerInfo { [pscustomobject]@{BiosFirmwareType=$testPostureState.firmware} }
function Confirm-SecureBootUEFI { if ($testPostureState.unsupported) { throw [PlatformNotSupportedException]::new('unsupported') }; if ($testPostureState.bootError) { throw 'Access denied' }; $testPostureState.enabled }
$testPostureState.encrypted=$true
function Get-BitLockerVolume { [pscustomobject]@{ VolumeStatus=$(if ($testPostureState.encrypted) {'FullyEncrypted'} else {'FullyDecrypted'}); EncryptionPercentage=$(if ($testPostureState.encrypted) {100} else {0}); ProtectionStatus=$(if ($testPostureState.encrypted) {'On'} else {'Off'}); LockStatus='Unlocked'; EncryptionMethod='XtsAes256'; KeyProtector=@([pscustomobject]@{KeyProtectorType='Tpm';KeyProtectorId='tpm'},[pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='recovery'}) } }
$t=Get-TpmProtectionStatus; Assert ($t.check.state -eq 'PROTECTED' -and $t.specificationVersion -eq '2.0') 'TPM 2.0 detection failed'
$testPostureState.present=$false; Assert ((Get-TpmProtectionStatus).check.state -eq 'UNSUPPORTED') 'No TPM detection failed'
$testPostureState.present=$true; $testPostureState.ready=$false; Assert ((Get-TpmProtectionStatus).check.state -eq 'NEEDS_ATTENTION') 'TPM not ready failed'
$testPostureState.ready=$true
Assert ((Get-SecureBootProtectionStatus).enabled -eq $true) 'Enabled Secure Boot failed'
$testPostureState.enabled=$false; $b=Get-SecureBootProtectionStatus; Assert ($b.check.state -eq 'NEEDS_ATTENTION' -and $b.supported) 'Disabled Secure Boot failed'
$testPostureState.firmware=1; Assert ((Get-SecureBootProtectionStatus).check.detail -eq 'Legacy BIOS') 'Legacy BIOS failed'
$testPostureState.firmware=2; $testPostureState.bootError=$true; $b=Get-SecureBootProtectionStatus; Assert ($b.check.state -eq 'ERROR' -and $null -eq $b.enabled -and $b.detectionError) 'Detection error collapsed to disabled'
$testPostureState.bootError=$false; $testPostureState.unsupported=$true
Assert ((Get-SecureBootProtectionStatus).check.state -eq 'UNSUPPORTED') 'UEFI unsupported detection failed'
$testPostureState.unsupported=$false
$b=Get-BitLockerProtectionStatus; Assert ($b.check.state -eq 'PROTECTED' -and $b.tpmProtectorPresent -and $b.recoveryProtectorPresent) 'BitLocker protector detection failed'
$testPostureState.encrypted=$false; Assert ((Get-BitLockerProtectionStatus).check.state -eq 'NEEDS_ATTENTION') 'Disabled BitLocker failed'
# Any attempt to mutate an existing encrypted machine fails this test.
function Enable-BitLocker { throw 'Unexpected encryption mutation' }
function Add-BitLockerKeyProtector { throw 'Unexpected protector mutation' }
function Remove-BitLockerKeyProtector { throw 'Existing protector removal prohibited' }
function Clear-Tpm { throw 'TPM clear prohibited' }
$testPostureState.encrypted=$true
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID
$testPostureState.ready=$false
$failed=$false
try { & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID } catch { $failed=$true }
Assert $failed 'Provisioning continued with unready TPM'
Write-Output 'TPM, BitLocker, Secure Boot and preservation checks passed.'

# Fresh provisioning escrows before enabling and preserves all existing protectors.
$testPostureState.ready=$true; $testPostureState.encrypted=$false; $testPostureState.events=@(); $testPostureState.extraTpm=$false
function Get-BitLockerVolume { [pscustomobject]@{VolumeStatus='FullyDecrypted';LockStatus='Unlocked'; KeyProtector=@([pscustomobject]@{KeyProtectorType='RecoveryPassword';KeyProtectorId='existing-recovery'}) + $(if($testPostureState.extraTpm){@([pscustomobject]@{KeyProtectorType='Tpm';KeyProtectorId='new-tpm'})}else{@()})} }
function BackupToAAD-BitLockerKeyProtector { $testPostureState.events += 'escrow'; if ($testPostureState.escrowFailure) { throw 'Escrow failed' } }
function Enable-BitLocker { $testPostureState.events += 'enable'; $testPostureState.extraTpm=$true }
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID
Assert (($testPostureState.events -join ',') -eq 'escrow,enable') 'Encryption enabled before escrow'
$testPostureState.events=@(); $testPostureState.extraTpm=$false; $testPostureState.escrowFailure=$true; $failed=$false
try { & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Provision-BitLocker.ps1') -Escrow EntraID } catch { $failed=$true }
Assert ($failed -and ($testPostureState.events -join ',') -eq 'escrow') 'Encryption enabled after escrow failure'
