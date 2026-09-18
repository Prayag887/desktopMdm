#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [switch]$SkipWingetBootstrap,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent"
)
$ErrorActionPreference = 'Stop'
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$programFilesPrefix = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $InstallDir.StartsWith($programFilesPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'InstallDir must be a child directory under Program Files' }

$exe = Join-Path $PSScriptRoot 'emi-device-agent.exe'
$uiExe = Join-Path $PSScriptRoot 'emi-device-ui.exe'
if (-not (Test-Path $exe)) { throw 'emi-device-agent.exe must be beside install.ps1' }
if (-not (Test-Path $uiExe)) { throw 'emi-device-ui.exe must be beside install.ps1' }

$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'

# --- Defender exclusions (best-effort) ---------------------------------------
# The app is behaviour-flagged (keyboard hook, shell lock); on a device you own,
# exclude it so Defender does not quarantine it or block the install. On a fleet,
# push the same exclusion via MDM.
foreach ($x in $InstallDir, $dataDir) { try { Add-MpPreference -ExclusionPath $x -ErrorAction SilentlyContinue } catch {} }
foreach ($p in 'emi-device-ui.exe', 'emi-device-agent.exe') { try { Add-MpPreference -ExclusionProcess $p -ErrorAction SilentlyContinue } catch {} }

# --- Stop and REMOVE any previous instance so files are not locked -----------
Get-Process -Name 'emi-device-ui', 'emi-device-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  Stop-Service EmiDeviceAgent -Force -ErrorAction SilentlyContinue
  sc.exe delete EmiDeviceAgent | Out-Null   # delete, not just stop: it auto-restarts and re-locks its config
}
Start-Sleep -Seconds 1

# --- Clear any stale, over-restricted ProgramData state ----------------------
# A prior install may have left config.json with ACLs the agent cannot read;
# reset ownership/inheritance so `init` starts clean.
if (Test-Path $dataDir) {
  takeown /f $dataDir /r /d y 2>$null | Out-Null
  icacls $dataDir /reset /t /c 2>$null | Out-Null
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe (Join-Path $InstallDir 'emi-device-agent.exe') -Force
Copy-Item $uiExe (Join-Path $InstallDir 'emi-device-ui.exe') -Force
$agent = Join-Path $InstallDir 'emi-device-agent.exe'

if (-not $SkipWingetBootstrap) {
  & $agent bootstrap
  if ($LASTEXITCODE -ne 0) { Write-Warning "WinGet bootstrap failed (exit $LASTEXITCODE); continuing without it." }
}

& $agent init
if ($LASTEXITCODE -ne 0) { throw "Local device initialization failed (exit $LASTEXITCODE)" }
& $agent run --once
if ($LASTEXITCODE -ne 0) { Write-Warning "Initial health snapshot failed (exit $LASTEXITCODE); continuing." }

# Tamper hardening: SYSTEM/Administrators full, standard users read-only.
icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T | Out-Null

# --- Health service (optional) via New-Service -------------------------------
# New-Service handles the spaced binary path that sc.exe rejects (exit 1639).
# The lock does not need the service, so a failure here is non-fatal.
try {
  New-Service -Name EmiDeviceAgent -BinaryPathName ('"' + $agent + '" service') -StartupType Automatic `
    -DisplayName 'EMI Device Agent' -Description 'Standalone desktop companion and local device health' -ErrorAction Stop | Out-Null
  sc.exe failure EmiDeviceAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
  Start-Service EmiDeviceAgent -ErrorAction SilentlyContinue
}
catch { Write-Warning "Health service setup skipped: $_" }

# --- Auto-start for EVERY account at login -----------------------------------
$uiPath = Join-Path $InstallDir 'emi-device-ui.exe'
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
$shortcutPath = Join-Path $startup 'EMI Device.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $uiPath
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = 'EMI desktop companion'
$shortcut.Save()

# All-users logon scheduled task (fires for every account incl. admins; unlike
# the StartUp folder it cannot be skipped with Shift). Unlock any session with
# the on-screen word.
$lockAction = New-ScheduledTaskAction -Execute $uiPath
$lockTrigger = New-ScheduledTaskTrigger -AtLogOn
$lockPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-1-0'
$lockSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'EmiDeviceLockAll' -Action $lockAction -Trigger $lockTrigger -Principal $lockPrincipal -Settings $lockSettings -Force | Out-Null

Start-Process $uiPath
Write-Host 'EMI desktop companion installed and set to auto-launch on every login.' -ForegroundColor Green
