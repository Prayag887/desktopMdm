#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Acl.ps1')
. (Join-Path $PSScriptRoot 'Get-SecurityPosture.ps1')
. (Join-Path $PSScriptRoot 'Set-EmiStateAcl.ps1')
function Get-ServiceProtectionStatus([string]$Name, [string]$Executable, [string]$Argument) {
  try {
    $s = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $s) { return @{state='NEEDS_ATTENTION';detail="$Name is not registered"} }
    $expected = '"' + (Join-Path $PSScriptRoot $Executable) + '" ' + $Argument
    if ($s.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or $s.StartMode -ne 'Auto' -or $s.PathName -ne $expected) { return @{state='NEEDS_ATTENTION';detail="$Name registration differs from expected LocalSystem/Automatic/quoted path"} }
    if ($s.State -eq 'Running') { return @{state='PROTECTED';detail="$Name running as LocalSystem, automatic startup"} }
    return @{state='NEEDS_ATTENTION';detail="$Name state: $($s.State)"}
  } catch { return @{state='ERROR';detail="Cannot query $Name"} }
}
$watchdogCheck = Get-ServiceProtectionStatus EmiDeviceWatchdog 'emi-device-watchdog.exe' service
$watchdogState = Join-Path $env:ProgramData 'EmiDeviceAgent\watchdog-status.json'
if (Test-Path -LiteralPath $watchdogState) {
  try {
    $w = Get-Content -LiteralPath $watchdogState -Raw | ConvertFrom-Json
    if (-not $w.healthy -or -not $w.integrityVerified -or $w.recoveryExhausted -or ([DateTime]::UtcNow - [DateTime]$w.observedAt).TotalSeconds -gt 180) { $watchdogCheck = @{state='NEEDS_ATTENTION'; detail=$w.detail} }
  } catch { $watchdogCheck = @{state='ERROR'; detail='Watchdog diagnostics unreadable'} }
} else { $watchdogCheck = @{state='NEEDS_ATTENTION'; detail='Waiting for watchdog verification'} }
$acl = Verify-ProtectionAcl $PSScriptRoot
$stateAcl = Test-EmiStateAcl (Join-Path $env:ProgramData 'EmiDeviceAgent')
$aclCheck = if ($acl.verified -and $stateAcl.verified) { @{state='PROTECTED';detail=$acl.strategy} } else { @{state='NEEDS_ATTENTION';detail="ACL mismatch: $(@($acl.failures) + @($stateAcl.failures) -join ', ')"} }
[ordered]@{
  aclProtection=$aclCheck
  coreService=(Get-ServiceProtectionStatus EmiDeviceAgent 'emi-device-agent.exe' service)
  watchdog=$watchdogCheck
  integrity=@{state='ERROR';detail='Caller must verify trusted manifest'}
  bitLocker=(Get-BitLockerProtectionStatus)
  tpm=(Get-TpmProtectionStatus)
  secureBoot=(Get-SecureBootProtectionStatus)
  lastVerifiedAt=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 8 -Compress
