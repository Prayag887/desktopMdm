#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$MinimumVersion = '',
  [ValidateRange(1, 1440)][int]$MaximumHealthAgeMinutes = 15,
  [switch]$RequireEnrollment = $true
)

$ErrorActionPreference = 'Stop'
$agent = "$env:ProgramFiles\EmiDeviceAgent\emi-device-agent.exe"
$configPath = "$env:ProgramData\EmiDeviceAgent\config.json"
$healthPath = "$env:ProgramData\EmiDeviceAgent\health.json"
$failures = [System.Collections.Generic.List[string]]::new()

if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { $failures.Add('agent binary missing') }
else {
  try {
    $versionOutput = (& $agent --version 2>$null) -join ' '
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(\d+\.\d+\.\d+)') { throw 'unrecognized version output' }
    $version = $Matches[1]
    if ($MinimumVersion -and ([version]$version -lt [version]$MinimumVersion)) { $failures.Add("version $version is below $MinimumVersion") }
  }
  catch { $failures.Add('agent version unreadable') }
}
$service = Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue
if ($null -eq $service) { $failures.Add('service missing') }
elseif ($service.Status -ne 'Running') { $failures.Add('service not running') }
else {
  try {
    if ((Get-CimInstance Win32_Service -Filter "Name='EmiDeviceAgent'").StartMode -ne 'Auto') { $failures.Add('service is not automatic') }
  }
  catch { $failures.Add('service startup mode unreadable') }
}
try { $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -ErrorAction Stop }
catch { $config = $null }
if ($null -eq $config -or -not $config.device_id -or -not $config.api_base) { $failures.Add('configuration invalid') }
else {
  if ($RequireEnrollment -and (-not $config.agent_token -or -not $config.remote_device_id)) { $failures.Add('enrollment incomplete') }
  if ($null -eq $config.trusted_command_signing_keys -or $config.trusted_command_signing_keys.PSObject.Properties.Count -eq 0) {
    $failures.Add('trusted command signing key missing')
  }
}
try {
  $health = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json -ErrorAction Stop
  $observed = [DateTimeOffset]::Parse([string]$health.observed_at).ToUniversalTime()
  if (-not $health.agent_version -or $observed -lt [DateTimeOffset]::UtcNow.AddMinutes(-$MaximumHealthAgeMinutes)) { throw 'stale' }
}
catch { $failures.Add('health missing, invalid, or stale') }

if ($failures.Count -gt 0) {
  Write-Output ('Noncompliant: ' + ($failures -join '; '))
  exit 1
}
Write-Output 'Compliant: EMI Device Agent is installed, running, configured, and healthy.'
exit 0
