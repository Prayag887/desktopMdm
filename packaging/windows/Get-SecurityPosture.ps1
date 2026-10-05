#Requires -Version 5.1
function Get-TpmProtectionStatus {
  $status = [ordered]@{ present=$null; ready=$null; enabled=$null; activated=$null; owned=$null; specificationVersion=$null; manufacturer=$null; manufacturerVersion=$null; check=@{state='ERROR'; detail='TPM detection failed'} }
  try {
    $t = Get-Tpm -ErrorAction Stop
    $status.present = [bool]$t.TpmPresent; $status.ready = [bool]$t.TpmReady
    $status.enabled = [bool]$t.TpmEnabled; $status.activated = [bool]$t.TpmActivated; $status.owned = [bool]$t.TpmOwned
    $status.manufacturer = [string]$t.ManufacturerIdTxt; $status.manufacturerVersion = [string]$t.ManufacturerVersion
    if ($t.TpmPresent) {
      $cim = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
      $status.specificationVersion = [string]$cim.SpecVersion
      $status.check = if ($t.TpmReady -and $t.TpmEnabled) { @{state='PROTECTED';detail='TPM ready'} } else { @{state='NEEDS_ATTENTION';detail='TPM present but not ready/enabled'} }
    } else { $status.check = @{state='UNSUPPORTED';detail='No TPM present'} }
  } catch { $status.check = @{state='ERROR';detail="TPM detection failed ($($_.Exception.HResult))"} }
  [pscustomobject]$status
}
function Get-BitLockerProtectionStatus {
  $status = [ordered]@{ supported=$null; windowsEdition=$null; volume=$env:SystemDrive; encryptionState=$null; encryptionPercentage=$null; protectionEnabled=$null; lockState=$null; encryptionMethod=$null; keyProtectorTypes=@(); tpmProtectorPresent=$false; recoveryProtectorPresent=$false; check=@{state='ERROR';detail='BitLocker detection failed'} }
  try {
    $status.windowsEdition = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
      $status.supported=$false; $status.check=@{state='UNSUPPORTED';detail='BitLocker management unavailable on this Windows edition'}
    } else {
      $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
      $status.supported=$true; $status.encryptionState=[string]$b.VolumeStatus
      $status.encryptionPercentage=[int]$b.EncryptionPercentage; $status.protectionEnabled=([string]$b.ProtectionStatus -eq 'On')
      $status.lockState=[string]$b.LockStatus; $status.encryptionMethod=[string]$b.EncryptionMethod
      $status.keyProtectorTypes=@($b.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
      $status.tpmProtectorPresent=(@($status.keyProtectorTypes | Where-Object { $_ -like 'Tpm*' }).Count -gt 0)
      $status.recoveryProtectorPresent=($status.keyProtectorTypes -contains 'RecoveryPassword' -or $status.keyProtectorTypes -contains 'RecoveryKey')
      $status.check = if ($status.protectionEnabled -and $b.VolumeStatus -eq 'FullyEncrypted') { @{state='PROTECTED';detail='OS drive encrypted and protected'} } elseif ($b.VolumeStatus -eq 'EncryptionInProgress') { @{state='PARTIALLY_PROTECTED';detail='Encryption in progress; verify after completion'} } else { @{state='NEEDS_ATTENTION';detail='OS drive not fully encrypted/protected; administrator action required'} }
    }
  } catch { $status.check=@{state='ERROR';detail="BitLocker detection failed ($($_.Exception.HResult))"} }
  [pscustomobject]$status
}
function Get-SecureBootProtectionStatus {
  $status = [ordered]@{ uefi=$null; supported=$null; enabled=$null; detectionError=$null; check=@{state='ERROR';detail='Unable to determine Secure Boot'} }
  try {
    # Windows reports firmware type independently of Secure Boot query success.
    $firmware = [int](Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType
    if ($firmware -eq 1) { $status.uefi=$false; $status.supported=$false; $status.check=@{state='UNSUPPORTED';detail='Legacy BIOS'} }
    elseif ($firmware -eq 2) {
      $status.uefi=$true
      try {
        $status.enabled=[bool](Confirm-SecureBootUEFI -ErrorAction Stop); $status.supported=$true
        $status.check = if ($status.enabled) { @{state='PROTECTED';detail='Secure Boot enabled'} } else { @{state='NEEDS_ATTENTION';detail='Secure Boot disabled'} }
      } catch {
        $exception=$_.Exception
        while ($exception.InnerException) { $exception=$exception.InnerException }
        if ($exception -is [PlatformNotSupportedException] -or $exception -is [NotSupportedException] -or $_.CategoryInfo.Category -eq 'NotImplemented' -or $exception.HResult -eq -2147024846) {
          $status.supported=$false; $status.check=@{state='UNSUPPORTED';detail='Secure Boot unsupported on this UEFI platform'}
        } else { throw }
      }
    } else { throw 'Unknown firmware type' }
  } catch { $status.detectionError="Secure Boot detection failed ($($_.Exception.HResult))"; $status.check=@{state='ERROR';detail=$status.detectionError} }
  [pscustomobject]$status
}
