#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [switch]$SkipWingetBootstrap,
  [switch]$SkipUiLaunch,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [UInt64]$CommandSigningKeyId = 0,
  [string]$CommandSigningPublicKey = '',
  [string]$RecoveryPublicKeyHex = ''
)
$ErrorActionPreference = 'Stop'
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$programFilesPrefix = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $InstallDir.StartsWith($programFilesPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'InstallDir must be a child directory under Program Files' }

$exe = Join-Path $PSScriptRoot 'emi-device-agent.exe'
$uiExe = Join-Path $PSScriptRoot 'emi-device-ui.exe'
if (-not (Test-Path $exe)) { throw 'emi-device-agent.exe must be beside install.ps1' }
if (-not (Test-Path $uiExe)) { throw 'emi-device-ui.exe must be beside install.ps1' }

# Fail before modifying an existing installation if Windows cannot load the
# binary (for example, an old dynamically-linked build missing VCRUNTIME140).
$versionOutput = & $exe --version 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "The packaged device agent could not start (exit $LASTEXITCODE): $($versionOutput -join [Environment]::NewLine)"
}

$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'
if ([string]::IsNullOrWhiteSpace($RecoveryPublicKeyHex)) {
  $bundledRecoveryKey = Join-Path $PSScriptRoot 'recovery-public-key.hex'
  if (Test-Path -LiteralPath $bundledRecoveryKey -PathType Leaf) {
    $RecoveryPublicKeyHex = (Get-Content -LiteralPath $bundledRecoveryKey -Raw).Trim()
  }
}
if ($RecoveryPublicKeyHex -and ($RecoveryPublicKeyHex -notmatch '^[A-Fa-f0-9]{64}$' -or $RecoveryPublicKeyHex -eq 'ac1473ba71d2cd322163ccc8a8f64e1226cfcb815bfc270cbe7417f16d8ae7ba')) {
  throw 'A non-lab 32-byte recovery public key is required.'
}
if (($CommandSigningKeyId -eq 0) -ne ([string]::IsNullOrWhiteSpace($CommandSigningPublicKey))) {
  throw 'CommandSigningKeyId and CommandSigningPublicKey must be supplied together; key ID must be nonzero.'
}

# Validate Ed25519 material before stopping or changing an existing installation.
$keyCheckArgs = @('validate-public-keys')
if ($CommandSigningPublicKey) { $keyCheckArgs += @('--command-public-key', $CommandSigningPublicKey) }
if ($RecoveryPublicKeyHex) { $keyCheckArgs += @('--recovery-public-key-hex', $RecoveryPublicKeyHex) }
& $exe @keyCheckArgs
if ($LASTEXITCODE -ne 0) { throw 'Invalid deployment public keys; installation was not modified.' }

# --- Stop and REMOVE any previous instance so files are not locked -----------
Get-Process -Name 'emi-device-ui', 'emi-device-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  Stop-Service EmiDeviceAgent -Force -ErrorAction SilentlyContinue
  sc.exe delete EmiDeviceAgent | Out-Null   # delete, not just stop: it auto-restarts and re-locks its config
}
Start-Sleep -Seconds 1

# Establish exact ACLs before writing credentials or exposing the recovery mailbox.
# Do not use icacls /reset: it can temporarily expose existing bearer tokens.
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
. (Join-Path $PSScriptRoot 'Set-EmiStateAcl.ps1')
Set-EmiAcl $dataDir
Get-ChildItem -LiteralPath $dataDir -Force | ForEach-Object {
  if ($_.PSIsContainer) { throw 'Unexpected directory in agent state; inspect it before upgrading.' }
  Set-EmiAcl $_.FullName -Private:($_.Name -like 'config*')
}
$mailbox = Join-Path $dataDir 'recovery-request.json'
[IO.File]::WriteAllText($mailbox, '')
Set-EmiAcl $mailbox -Mailbox $true

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe (Join-Path $InstallDir 'emi-device-agent.exe') -Force
Copy-Item $uiExe (Join-Path $InstallDir 'emi-device-ui.exe') -Force
foreach ($scriptName in 'Install-BiosAdapter.ps1', 'Manage-BiosPassword.ps1', 'Set-PaymentRestriction.ps1', 'Remove-PaymentRestriction.ps1') {
  $scriptPath = Join-Path $PSScriptRoot $scriptName
  if (Test-Path -LiteralPath $scriptPath) {
    Copy-Item $scriptPath (Join-Path $InstallDir $scriptName) -Force
  }
}
$agent = Join-Path $InstallDir 'emi-device-agent.exe'

if (-not $SkipWingetBootstrap) {
  & $agent bootstrap
  if ($LASTEXITCODE -ne 0) { Write-Warning "WinGet bootstrap failed (exit $LASTEXITCODE); continuing without it." }
}

$initOutput = & $agent init 2>&1
$initExit = $LASTEXITCODE
if ($initExit -ne 0) {
  throw "Local device initialization failed (exit $initExit): $($initOutput -join [Environment]::NewLine)"
}
if ($CommandSigningKeyId -ne 0) {
  $trustOutput = & $agent trust-command-key --key-id $CommandSigningKeyId --public-key $CommandSigningPublicKey 2>&1
  $trustExit = $LASTEXITCODE
  if ($trustExit -ne 0) {
    throw "Command signing key configuration failed (exit $trustExit): $($trustOutput -join [Environment]::NewLine)"
  }
}
if (-not [string]::IsNullOrWhiteSpace($RecoveryPublicKeyHex)) {
  & $agent trust-recovery-key --public-key-hex $RecoveryPublicKeyHex
  if ($LASTEXITCODE -ne 0) { throw 'Recovery public-key provisioning failed.' }
} elseif (-not (Test-Path -LiteralPath (Join-Path $dataDir 'recovery-state.json'))) {
  Write-Warning 'Offline token recovery is not provisioned. Keep the administrator recovery account available.'
}
& $agent enroll
if ($LASTEXITCODE -ne 0) {
  Write-Warning 'Enrollment is pending. Create a PENDING Device Agent for this BIOS serial in the admin panel; the service retries every five minutes.'
}
& $agent run --once
if ($LASTEXITCODE -ne 0) { Write-Warning "Initial health snapshot failed (exit $LASTEXITCODE); continuing." }

# State replacements inherit read-only access; config temporaries are protected
# by the agent before any credentials are written. The mailbox is the sole
# user-writable file and does not grant users delete/replace/ACL rights.
Set-EmiAcl (Join-Path $dataDir 'config.json') -Private $true

# --- Automatic boot service --------------------------------------------------
# New-Service handles the spaced binary path that sc.exe rejects (exit 1639).
# This service is authoritative: it starts during boot, enrolls if necessary,
# checks in immediately when enrolled, and continues checking every 60 seconds.
try {
  New-Service -Name EmiDeviceAgent -BinaryPathName ('"' + $agent + '" service') -StartupType Automatic `
    -DisplayName 'EMI Device Agent' -Description 'EMI administrator control, lock-state synchronization, and device health' -ErrorAction Stop | Out-Null
  sc.exe failure EmiDeviceAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
  sc.exe failureflag EmiDeviceAgent 1 | Out-Null
  Start-Service EmiDeviceAgent -ErrorAction Stop
  $service = Get-Service EmiDeviceAgent -ErrorAction Stop
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
  if ($service.Status -ne 'Running') { throw "service state is $($service.Status)" }
}
catch { throw "Automatic EMI service installation failed: $_" }

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
# the StartUp folder it cannot be skipped with Shift). Recovery tokens are
# verified by the service; administrator sign-in remains available.
$lockAction = New-ScheduledTaskAction -Execute $uiPath
$lockTrigger = New-ScheduledTaskTrigger -AtLogOn
$lockPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-1-0'
$lockSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName 'EmiDeviceLockAll' -Action $lockAction -Trigger $lockTrigger -Principal $lockPrincipal -Settings $lockSettings -Force | Out-Null

Write-Host 'EMI agent service installed; desktop companion is set to auto-launch on login.' -ForegroundColor Green
if (-not $SkipUiLaunch) {
  . (Join-Path $PSScriptRoot 'Start-EmiCompanion.ps1')
  [void](Start-EmiCompanion -UiPath $uiPath)
}
# Optional bootstrap/enrollment/interactive-launch failures do not override the
# verified service installation. Mandatory failures above still throw.
exit 0
