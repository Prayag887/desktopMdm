#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [string]$DataDir = "$env:ProgramData\EmiDeviceAgent",
  [string]$MinimumVersion = '',
  [ValidateRange(1, 1440)][int]$MaximumHealthAgeMinutes = 15,
  [switch]$RequireEnrollment,
  [switch]$RequireBitLocker,
  [switch]$RequireSecureBoot,
  [switch]$RequireTpm,
  [switch]$ExitNonCompliant
)

$ErrorActionPreference = 'Stop'

function Read-JsonFile([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  try { return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
  catch { return $null }
}

function Get-SecureBootState {
  try { return [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
  catch { return $null }
}

function Get-TpmState {
  try {
    $tpm = Get-Tpm -ErrorAction Stop
    return [ordered]@{ Present = [bool]$tpm.TpmPresent; Ready = [bool]$tpm.TpmReady; Enabled = [bool]$tpm.TpmEnabled }
  }
  catch { return [ordered]@{ Present = $false; Ready = $false; Enabled = $false; Error = $_.Exception.Message } }
}

function Get-BitLockerState {
  try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    return [ordered]@{
      ProtectionOn = ($volume.ProtectionStatus -eq 'On')
      VolumeStatus = [string]$volume.VolumeStatus
      EncryptionMethod = [string]$volume.EncryptionMethod
    }
  }
  catch { return [ordered]@{ ProtectionOn = $false; Error = $_.Exception.Message } }
}

$agentPath = Join-Path $InstallDir 'emi-device-agent.exe'
$configPath = Join-Path $DataDir 'config.json'
$healthPath = Join-Path $DataDir 'health.json'
$config = Read-JsonFile $configPath
$health = Read-JsonFile $healthPath
$service = Get-Service -Name 'EmiDeviceAgent' -ErrorAction SilentlyContinue

$installedVersion = $null
if (Test-Path -LiteralPath $agentPath -PathType Leaf) {
  try {
    $versionOutput = (& $agentPath --version 2>$null) -join ' '
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(\d+\.\d+\.\d+)') { throw 'unrecognized version output' }
    $installedVersion = $Matches[1]
  }
  catch { $installedVersion = $null }
}
$versionCompliant = [bool]$installedVersion
if ($versionCompliant -and $MinimumVersion) {
  try { $versionCompliant = ([version]$installedVersion -ge [version]$MinimumVersion) }
  catch { $versionCompliant = $false }
}

$configValid = ($null -ne $config -and [bool]$config.device_id -and [bool]$config.api_base)
$enrolled = ($configValid -and [bool]$config.agent_token -and [bool]$config.remote_device_id)
$commandTrustConfigured = ($configValid -and $null -ne $config.trusted_command_signing_keys -and $config.trusted_command_signing_keys.PSObject.Properties.Count -gt 0)
$healthFresh = $false
if ($null -ne $health -and [bool]$health.observed_at -and [bool]$health.agent_version) {
  try {
    $observed = [DateTimeOffset]::Parse([string]$health.observed_at).ToUniversalTime()
    $healthFresh = $observed -ge [DateTimeOffset]::UtcNow.AddMinutes(-$MaximumHealthAgeMinutes)
  }
  catch { $healthFresh = $false }
}

$secureBoot = Get-SecureBootState
$tpm = Get-TpmState
$bitLocker = Get-BitLockerState
$checks = [ordered]@{
  AgentBinary = (Test-Path -LiteralPath $agentPath -PathType Leaf)
  AgentVersion = $versionCompliant
  ServiceInstalled = ($null -ne $service)
  ServiceRunning = ($null -ne $service -and $service.Status -eq 'Running')
  ServiceAutomatic = $false
  Configuration = $configValid
  CommandTrust = $commandTrustConfigured
  Enrollment = ((-not $RequireEnrollment) -or $enrolled)
  HealthFresh = $healthFresh
  BitLocker = ((-not $RequireBitLocker) -or [bool]($bitLocker.ProtectionOn))
  SecureBoot = ((-not $RequireSecureBoot) -or ($secureBoot -eq $true))
  Tpm = ((-not $RequireTpm) -or ([bool]($tpm.Present) -and [bool]($tpm.Ready) -and [bool]($tpm.Enabled)))
}
if ($null -ne $service) {
  try {
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='EmiDeviceAgent'" -ErrorAction Stop
    $checks.ServiceAutomatic = ($serviceInfo.StartMode -eq 'Auto')
  }
  catch { $checks.ServiceAutomatic = $false }
}

$compliant = -not ($checks.Values -contains $false)
$report = [ordered]@{
  SchemaVersion = 1
  Compliant = $compliant
  CheckedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
  InstalledVersion = $installedVersion
  MinimumVersion = $MinimumVersion
  Enrolled = $enrolled
  Checks = $checks
  Security = [ordered]@{ BitLocker = $bitLocker; SecureBoot = $secureBoot; Tpm = $tpm }
}
$report | ConvertTo-Json -Depth 8 -Compress
if ($ExitNonCompliant -and -not $compliant) { exit 1 }
exit 0
