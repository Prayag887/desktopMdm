#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [switch]$SkipWingetBootstrap,
  [switch]$AllowUnsigned,
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

$watchdogExe = Join-Path $PSScriptRoot 'RepairWatchdog.exe'
$updaterExe = Join-Path $PSScriptRoot 'emi-device-updater.exe'
if (-not (Test-Path -LiteralPath $updaterExe)) { throw 'Updater binary missing from package' }
if (-not (Test-Path -LiteralPath $watchdogExe)) { throw 'Watchdog binary missing from package' }
if ([Environment]::OSVersion.Version.Major -lt 10 -or -not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw '64-bit Windows 10 or later is required' }
# Authenticate and stage immutable artifacts before loading package helpers or running binaries.
$packageRoot=$PSScriptRoot
$temporaryPackage=''
if (-not $AllowUnsigned) {
  $handles=@()
  try {
    foreach ($path in @($exe, (Join-Path $PSScriptRoot 'protection-manifest.ps1'))) {
      $handles += [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    $agentSignature=Get-AuthenticodeSignature -LiteralPath $exe
    $manifestPath=Join-Path $PSScriptRoot 'protection-manifest.ps1'
    $manifestSignature=Get-AuthenticodeSignature -LiteralPath $manifestPath
    if ((Get-Item -LiteralPath $manifestPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Manifest reparse point rejected' }
    if ($agentSignature.Status -ne 'Valid' -or $manifestSignature.Status -ne 'Valid' -or $agentSignature.SignerCertificate.Thumbprint -ne $manifestSignature.SignerCertificate.Thumbprint) { throw 'Package publisher authentication failed' }
    $line=Get-Content -LiteralPath $manifestPath -TotalCount 1
    if (-not $line.StartsWith('# EMI-MANIFEST ')) { throw 'Invalid signed manifest' }
    $manifest=$line.Substring(15) | ConvertFrom-Json
    $temporaryPackage=Join-Path $env:ProgramData ('EmiProtectionStage-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $temporaryPackage | Out-Null
    $stageAcl=[Security.AccessControl.DirectorySecurity]::new()
    $stageAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $temporaryPackage -AclObject $stageAcl
    foreach ($entry in $manifest.PSObject.Properties) {
      if ($entry.Name -match '[/\\:]' -or $entry.Name -in @('.','..') -or $entry.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Unsafe signed manifest entry' }
      $path=Join-Path $PSScriptRoot $entry.Name
      if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package reparse point rejected' }
      if ($path -ne $exe) { $handles += [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
      if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value) { throw "Package hash mismatch: $($entry.Name)" }
      Copy-Item -LiteralPath $path -Destination (Join-Path $temporaryPackage $entry.Name)
    }
    Copy-Item -LiteralPath $manifestPath -Destination $temporaryPackage
    $packageRoot=$temporaryPackage
  } catch {
    if ($temporaryPackage) { Remove-Item -LiteralPath $temporaryPackage -Recurse -Force -ErrorAction SilentlyContinue }
    throw
  } finally { foreach ($handle in $handles) { $handle.Dispose() } }
}
try {
$exe=Join-Path $packageRoot 'emi-device-agent.exe'
$uiExe=Join-Path $packageRoot 'emi-device-ui.exe'
$watchdogExe=Join-Path $packageRoot 'RepairWatchdog.exe'
$updaterExe=Join-Path $packageRoot 'emi-device-updater.exe'
. (Join-Path $packageRoot 'Protection-Integrity.ps1')
. (Join-Path $packageRoot 'Protection-Acl.ps1')
. (Join-Path $packageRoot 'Set-EmiStateAcl.ps1')
. (Join-Path $packageRoot 'Protection-Transaction.ps1')
. (Join-Path $packageRoot 'Protection-Service.ps1')
. (Join-Path $packageRoot 'Protection-Package.ps1')
. (Join-Path $packageRoot 'Get-SecurityPosture.ps1')
if (-not $AllowUnsigned) {
  $packageCheck = Test-ProtectionIntegrity $packageRoot
  if (-not $packageCheck.verified) { throw "Package integrity failed: $($packageCheck.failures -join ', ')" }
} else { Write-Warning 'Unsigned development package: trusted integrity and watchdog restart will be unavailable.' }
$preflight = @{ tpm=Get-TpmProtectionStatus; bitLocker=Get-BitLockerProtectionStatus; secureBoot=Get-SecureBootProtectionStatus; architecture=$env:PROCESSOR_ARCHITECTURE }

# Fail before modifying an existing installation if Windows cannot load the
# binary (for example, an old dynamically-linked build missing VCRUNTIME140).
$versionOutput = & $exe --version 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "The packaged device agent could not start (exit $LASTEXITCODE): $($versionOutput -join [Environment]::NewLine)"
}

$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'
if ([string]::IsNullOrWhiteSpace($RecoveryPublicKeyHex)) {
  $bundledRecoveryKey = Join-Path $packageRoot 'recovery-public-key.hex'
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

# Snapshot before stopping the existing service. No boot/firmware policy is modified.
$transaction = Start-ProtectionTransaction $InstallDir $dataDir
try {
Stop-Service EmiDeviceWatchdog -ErrorAction SilentlyContinue
Stop-Service EmiDeviceAgent -ErrorAction SilentlyContinue
Get-Process -Name 'emi-device-ui' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $InstallDir 'emi-device-ui.exe') } | Stop-Process -Force

# Establish exact ACLs before writing credentials or exposing the recovery mailbox.
# Do not use icacls /reset: it can temporarily expose existing bearer tokens.
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
. (Join-Path $packageRoot 'Set-EmiStateAcl.ps1')
Set-EmiAcl $dataDir
Get-ChildItem -LiteralPath $dataDir -Force | ForEach-Object {
  if ($_.Name -like '.tmp*') { return }
  if ($_.PSIsContainer) { throw 'Unexpected directory in agent state; inspect it before upgrading.' }
  Set-EmiAcl $_.FullName -Private:($_.Name -like 'config*' -or $_.Name -in @('maintenance.json','repair-source.json'))
}
$mailbox = Join-Path $dataDir 'recovery-request.json'
[IO.File]::WriteAllText($mailbox, '')
Set-EmiAcl $mailbox -Mailbox $true

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-ProtectionPackage $packageRoot $InstallDir ([bool]$AllowUnsigned)
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
foreach ($registration in @(@('EmiDeviceAgent', $agent), @('EmiDeviceWatchdog', (Join-Path $InstallDir 'RepairWatchdog.exe')))) {
  $name=$registration[0]; $binary=$registration[1]
  $displayName=if ($name -eq 'EmiDeviceWatchdog') { 'RepairWatchdog' } else { $name }
  $binaryPath='"' + $binary + '" service'
  if (Get-Service $name -ErrorAction SilentlyContinue) {
    Set-ProtectionServiceConfiguration $name $binaryPath 'Automatic' $displayName
  } else { New-Service -Name $name -BinaryPathName $binaryPath -StartupType Automatic -DisplayName $displayName | Out-Null }
  & "$env:SystemRoot\System32\sc.exe" failure $name reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Recovery configuration failed: $name" }
  & "$env:SystemRoot\System32\sc.exe" failureflag $name 1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Recovery flag configuration failed: $name" }
}
Apply-ProtectionAcl $InstallDir (Join-Path $transaction.Backup 'installation-acls.json') | Out-Null
if (-not $AllowUnsigned) {
  $installedCheck=Test-ProtectionIntegrity $InstallDir
  if (-not $installedCheck.verified) { throw 'Installed file integrity failed' }
}
if (-not $AllowUnsigned) { Initialize-ProtectionRepairCache $packageRoot $dataDir $packageCheck.publisher }
Remove-Item -LiteralPath (Join-Path $dataDir 'maintenance.json') -ErrorAction SilentlyContinue
foreach ($name in 'EmiDeviceAgent','EmiDeviceWatchdog') {
  Start-Service $name -ErrorAction Stop
  $service=Get-Service $name
  $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
}
$finalStatus = & (Join-Path $InstallDir 'Get-DeviceProtection.ps1') | ConvertFrom-Json
$finalStatus.integrity = if ($AllowUnsigned) { @{state='ERROR';detail='Unsigned development installation'} } else { @{state='PROTECTED';detail='Signed manifest and SHA-256 verified'} }
[IO.File]::WriteAllText((Join-Path $dataDir 'installation-report.json'), (@{ at=[DateTime]::UtcNow.ToString('o'); preflight=$preflight; final=$finalStatus; unsigned=[bool]$AllowUnsigned; backup=$transaction.Backup } | ConvertTo-Json -Depth 12))
Set-EmiAcl (Join-Path $dataDir 'installation-report.json')

# --- Auto-start for EVERY account at login -----------------------------------
$uiPath = Join-Path $InstallDir 'emi-device-ui.exe'
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
$shortcutPath = Join-Path $startup 'EMI Device.lnk'
# Older installers also created a StartUp-folder shortcut. It races the
# scheduled task at every logon and can create two windows before the named
# mutex settles on a busy post-reboot system. Keep one authoritative logon
# trigger and remove the legacy duplicate during upgrades.
Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue

# All-users logon scheduled task (fires for every account incl. admins; unlike
# the StartUp folder it cannot be skipped with Shift). Recovery tokens are
# verified by the service; administrator sign-in remains available.
$lockAction = New-ScheduledTaskAction -Execute $uiPath
$lockTrigger = New-ScheduledTaskTrigger -AtLogOn
$lockPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-1-0'
$lockSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'EmiDeviceLockAll' -Action $lockAction -Trigger $lockTrigger -Principal $lockPrincipal -Settings $lockSettings -Force | Out-Null

# Earlier releases disabled Explorer right-click menus; restore the original
# policy on upgrade.
Remove-EmiExplorerContextPolicy $dataDir
Disable-EmiSignInPowerPolicy $dataDir
Enable-EmiRecoveryPagePolicy $dataDir
Write-Host 'Recovery page hidden in Windows Settings. Close and reopen Settings to apply.' -ForegroundColor Green
Write-Host 'Sign-in screen power button disabled.' -ForegroundColor Green

} catch {
  $installationError = $_
  try { Undo-ProtectionTransaction $transaction } catch { Write-Warning "Rollback incomplete; administrator recovery backup: $($transaction.Backup)" }
  throw $installationError
}
Write-Host 'EMI agent service installed; desktop companion is set to auto-launch once at login.' -ForegroundColor Green
if (-not $SkipUiLaunch) {
  . (Join-Path $packageRoot 'Start-EmiCompanion.ps1')
  [void](Start-EmiCompanion -UiPath $uiPath)
}
# Optional bootstrap/enrollment/interactive-launch failures do not override the
# verified service installation. Mandatory failures above still throw.
exit 0

} finally {
  if ($temporaryPackage) { Remove-Item -LiteralPath $temporaryPackage -Recurse -Force -ErrorAction SilentlyContinue }
}
