#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [string]$MinimumVersion = '',
  [ValidateRange(1, 1440)][int]$MaximumHealthAgeMinutes = 15,
  [switch]$RequireEnrollment
)

$ErrorActionPreference = 'Stop'
$agent = Join-Path $InstallDir 'emi-device-agent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
  throw 'The agent payload is absent. Assign the Intune Win32 app as Required so Intune can reinstall it.'
}

$service = Get-Service -Name 'EmiDeviceAgent' -ErrorAction SilentlyContinue
if ($null -eq $service) {
  throw 'The service is absent. Use the Required Win32 app assignment to reinstall; remediation does not create an unverified service.'
}

Set-Service -Name 'EmiDeviceAgent' -StartupType Automatic
if ($service.Status -ne 'Running') { Start-Service -Name 'EmiDeviceAgent' }

# These commands repair local metadata and refresh health without changing
# firmware, recovery settings, BitLocker policy, or the administrator's state.
& $agent init
if ($LASTEXITCODE -ne 0) { throw "Agent initialization failed with exit code $LASTEXITCODE." }
if ($RequireEnrollment) {
  & $agent enroll
  if ($LASTEXITCODE -ne 0) { Write-Warning 'Enrollment is still pending on the administration server.' }
}
& $agent run --once
if ($LASTEXITCODE -ne 0) { throw "Health refresh failed with exit code $LASTEXITCODE." }

$versionOutput = (& $agent --version 2>$null) -join ' '
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(\d+\.\d+\.\d+)') {
  throw 'Installed agent version could not be read.'
}
$installedVersion = $Matches[1]
if ($MinimumVersion -and ([version]$installedVersion -lt [version]$MinimumVersion)) {
  throw "Installed version $installedVersion is below required version $MinimumVersion; assign the updated Win32 app."
}
$healthPath = "$env:ProgramData\EmiDeviceAgent\health.json"
try {
  $health = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json -ErrorAction Stop
  $observed = [DateTimeOffset]::Parse([string]$health.observed_at).ToUniversalTime()
  if ($observed -lt [DateTimeOffset]::UtcNow.AddMinutes(-$MaximumHealthAgeMinutes)) { throw 'health is stale' }
}
catch { throw "Health verification failed after remediation: $($_.Exception.Message)" }
Write-Output 'Remediated: service is automatic and running; local configuration and health were refreshed.'
exit 0
