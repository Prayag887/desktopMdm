#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ScanStateDir,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT' -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or [Environment]::OSVersion.Version.Major -lt 10) { throw 'Windows 10 or later, x64, is required.' }
$ScanStateDir = (Resolve-Path -LiteralPath $ScanStateDir).Path
$scanState = Join-Path $ScanStateDir 'scanstate.exe'
$config = Join-Path $ScanStateDir 'Config_AppsAndSettings.xml'
foreach ($path in @($scanState, $config)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required ADK file missing: $path. Prepare USMT and Windows Setup files as described in the offline recovery guide." }
}
$scanSignature = Get-AuthenticodeSignature -LiteralPath $scanState
if ($scanSignature.Status -ne 'Valid') { throw 'ScanState must have a valid Authenticode signature.' }
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
$agentSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $InstallDir 'emi-device-agent.exe')
$helper = Join-Path $InstallDir 'Protection-Integrity.ps1'
$manifestPath = Join-Path $InstallDir 'protection-manifest.ps1'
$manifestSignature = Get-AuthenticodeSignature -LiteralPath $manifestPath
if ($agentSignature.Status -ne 'Valid' -or $manifestSignature.Status -ne 'Valid' -or
    $agentSignature.SignerCertificate.Thumbprint -ne $manifestSignature.SignerCertificate.Thumbprint) { throw 'A signed, trusted agent installation is required.' }
# Release scripts are authenticated by the signed manifest, not individual signatures.
$header = Get-Content -LiteralPath $manifestPath -TotalCount 1
if (-not $header.StartsWith('# EMI-MANIFEST ')) { throw 'Invalid signed manifest.' }
$manifest = $header.Substring(15) | ConvertFrom-Json
$helperHash = $manifest.PSObject.Properties['Protection-Integrity.ps1']
if (-not $helperHash -or $helperHash.Value -notmatch '^[a-fA-F0-9]{64}$' -or
    (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ne $helperHash.Value) { throw 'Integrity helper does not match the signed manifest.' }
foreach ($path in @($InstallDir, $helper, $manifestPath)) {
  if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Installation reparse point rejected: $path" }
}
. $helper
if (-not (Test-ProtectionIntegrity $InstallDir).verified) { throw 'Installed release integrity verification failed.' }
foreach ($name in @('EmiDeviceAgent','EmiDeviceWatchdog')) {
  $service = Get-Service -Name $name -ErrorAction Stop
  if ($service.Status -ne 'Running') { throw "$name must be running before capture." }
  $registration = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
  $binary = if ($name -eq 'EmiDeviceAgent') { 'emi-device-agent.exe' } else { 'RepairWatchdog.exe' }
  $expectedPath = '"' + (Join-Path $InstallDir $binary) + '" service'
  if ($registration.StartMode -ne 'Auto' -or $registration.StartName -ne 'LocalSystem' -or $registration.PathName -ne $expectedPath) { throw "Invalid service account, startup mode or executable: $name" }
}
$task = Get-ScheduledTask -TaskName 'EmiDeviceLockAll' -ErrorAction Stop
if ($task.State -eq 'Disabled' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne (Join-Path $InstallDir 'emi-device-ui.exe')) { throw 'The companion logon task is disabled or has an unexpected action.' }
& "$env:SystemRoot\System32\reagentc.exe" /info
if ($LASTEXITCODE -ne 0) { throw 'Windows recovery configuration could not be queried.' }

$recovery = Join-Path $env:SystemDrive 'Recovery'
$destination = Join-Path $recovery 'Customizations'
$package = Join-Path $destination 'EmiDeviceAgent.ppkg'
# Reject redirected recovery paths before writing an elevated capture containing state.
foreach ($path in @($recovery, $destination)) {
  if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Recovery reparse point rejected: $path" }
}
if (Test-Path -LiteralPath $package) { throw 'EmiDeviceAgent.ppkg already exists. Archive/remove that package explicitly before capturing a replacement.' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
# Protect the parent too: a writable parent can allow deletion of protected files.
$destinationAcl = [Security.AccessControl.DirectorySecurity]::new()
$destinationAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $recovery -AclObject $destinationAcl
Set-Acl -LiteralPath $destination -AclObject $destinationAcl
$stage = Join-Path $destination ('EmiCapture-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $stage -AclObject $acl
$stagedPackage = Join-Path $stage 'EmiDeviceAgent.ppkg'
$log = Join-Path $stage 'ScanState.log'
$migration = Join-Path $stage 'EmiDeviceAgent.xml'
# Add custom service/state artifacts to the ADK's application/settings capture.
$patterns = @(
  @('File', "$InstallDir\* [*]"),
  @('File', "$env:ProgramData\EmiDeviceAgent\* [*]"),
  @('File', "$env:ProgramData\RepairWatchdog\* [*]"),
  @('File', "$env:SystemRoot\System32\Tasks [EmiDeviceLockAll]"),
  @('Registry', 'HKLM\SYSTEM\CurrentControlSet\Services\EmiDeviceAgent\* [*]'),
  @('Registry', 'HKLM\SYSTEM\CurrentControlSet\Services\EmiDeviceWatchdog\* [*]')
)
$taskCache = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
try {
  $tree = $registry.OpenSubKey("$taskCache\Tree\EmiDeviceLockAll")
  if (-not $tree) { throw 'Companion task cache entry is missing.' }
  try { $rawTaskId = $tree.GetValue('Id') } finally { $tree.Dispose() }
  . (Join-Path $InstallDir 'Recovery-TaskId.ps1')
  $taskId = ConvertTo-EmiRecoveryTaskId $rawTaskId
  $patterns += ,@('Registry', "HKLM\$taskCache\Tree\EmiDeviceLockAll\* [*]")
  $patterns += ,@('Registry', "HKLM\$taskCache\Tasks\$taskId\* [*]")
  foreach ($bucket in @('Plain','Logon','Boot','Maintenance')) {
    $entry = $registry.OpenSubKey("$taskCache\$bucket\$taskId")
    if ($entry) { $entry.Dispose(); $patterns += ,@('Registry', "HKLM\$taskCache\$bucket\$taskId\* [*]") }
  }
} finally { $registry.Dispose() }
$xmlPatterns = ($patterns | ForEach-Object {
  '<pattern type="' + $_[0] + '">' + [Security.SecurityElement]::Escape($_[1]) + '</pattern>'
}) -join "`r`n"
$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<migration urlid="https://yajtech.com/migration/emi-offline-recovery/v1">
  <component type="Application" context="System">
    <displayName>EMI Device Agent recovery</displayName>
    <role role="Settings"><rules><include><objectSet>
$xmlPatterns
    </objectSet></include></rules></role>
  </component>
</migration>
"@
[IO.File]::WriteAllText($migration, $xml, [Text.UTF8Encoding]::new($false))
Write-Warning 'This captures the PC application/settings baseline and device-specific agent state. Keep the package on this device; do not distribute it to other PCs.'
# No /c: capture errors must fail instead of publishing an incomplete package.
& $scanState /apps "/config:$config" "/i:$migration" /ppkg $stagedPackage /v:13 "/l:$log"
$captureExit = $LASTEXITCODE
if ($captureExit -ne 0) { throw "ScanState failed (exit $captureExit). Diagnostic files retained in $stage; no recovery package published." }
if (-not (Test-Path -LiteralPath $stagedPackage -PathType Leaf) -or (Get-Item -LiteralPath $stagedPackage).Length -eq 0) { throw "ScanState produced no package. Diagnostics: $stage" }
$fileAcl = [Security.AccessControl.FileSecurity]::new()
$fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
Set-Acl -LiteralPath $stagedPackage -AclObject $fileAcl
# Same-volume move publishes only a completed package and preserves its protected ACL.
[IO.File]::Move($stagedPackage, $package)
$report = @{ capturedAt=[DateTime]::UtcNow.ToString('o'); package=$package; sha256=(Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash; resetValidated=$false }
[IO.File]::WriteAllText((Join-Path $stage 'capture-report.json'), ($report | ConvertTo-Json))
Write-Host "Local recovery package prepared: $package" -ForegroundColor Green
Write-Host "Capture report and logs: $stage"
Write-Host 'Reset restoration is not validated yet. Follow docs/offline-reset-recovery.md on a test PC before deployment.'
