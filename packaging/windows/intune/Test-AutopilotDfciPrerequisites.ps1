#Requires -Version 5.1
[CmdletBinding()]
param([switch]$ExitWhenNotReady)

$ErrorActionPreference = 'Stop'

function Try-Command([scriptblock]$Command) {
  try { return & $Command }
  catch { return $null }
}

$computer = Try-Command { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
$bios = Try-Command { Get-CimInstance Win32_BIOS -ErrorAction Stop }
$os = Try-Command { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
$tpm = Try-Command { Get-Tpm -ErrorAction Stop }
$tpmCim = Try-Command { Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop }
$secureBoot = Try-Command { Confirm-SecureBootUEFI -ErrorAction Stop }
$firmwareType = Try-Command { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType }
$autopilotMarker = Test-Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot'
$mdmEnrollment = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
  Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID -eq 'MS DM Server' }).Count -gt 0

$azureAdJoined = $false
try {
  $dsreg = (& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null) -join "`n"
  $azureAdJoined = $dsreg -match 'AzureAdJoined\s*:\s*YES'
}
catch {}

$prerequisites = [ordered]@{
  Windows10OrNewer = ($null -ne $os -and [version]$os.Version -ge [version]'10.0')
  UefiBoot = ($firmwareType -eq 2)
  SecureBoot = ($secureBoot -eq $true)
  Tpm20Present = ($null -ne $tpm -and $tpm.TpmPresent -and $null -ne $tpmCim -and ([string]$tpmCim.SpecVersion -match '(^|,)\s*2\.0(,|$)'))
  TpmReady = ($null -ne $tpm -and $tpm.TpmReady)
  AutopilotEvidencePresent = $autopilotMarker
  MdmEnrollmentPresent = $mdmEnrollment
  MicrosoftEntraJoined = $azureAdJoined
}

# DFCI eligibility ultimately depends on the OEM model, CSP registration, and
# Microsoft/OEM support data. This read-only check deliberately does not claim
# eligibility or write firmware settings.
$report = [ordered]@{
  SchemaVersion = 1
  CheckedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
  Manufacturer = if ($computer) { $computer.Manufacturer } else { $null }
  Model = if ($computer) { $computer.Model } else { $null }
  BiosSerial = if ($bios) { $bios.SerialNumber } else { $null }
  BiosVersion = if ($bios) { $bios.SMBIOSBIOSVersion } else { $null }
  Prerequisites = $prerequisites
  DfciEligibility = 'Verify this exact model and OEM/CSP Autopilot registration with Microsoft and the hardware vendor.'
  ReadOnly = $true
}
$report | ConvertTo-Json -Depth 6

$ready = $prerequisites.Windows10OrNewer -and $prerequisites.UefiBoot -and $prerequisites.SecureBoot -and `
  $prerequisites.Tpm20Present -and $prerequisites.TpmReady -and $prerequisites.AutopilotEvidencePresent -and `
  $prerequisites.MdmEnrollmentPresent -and $prerequisites.MicrosoftEntraJoined
if ($ExitWhenNotReady -and -not $ready) { exit 1 }
exit 0
