#Requires -Version 5
<#
.SYNOPSIS
  One-shot device provisioning for administrator-controlled EMI locking.

.DESCRIPTION
  Meant to be launched by provision.cmd (which sets -ExecutionPolicy Bypass).
  Self-elevates if not already admin. It installs and enrolls the agent; lock
  state is then controlled exclusively by commands from the admin API.

.PARAMETER EnrolledUser
  Retained for command-line compatibility. The API-managed UI launches for all
  users and does not apply a local lock during provisioning.

.PARAMETER WithWinget
  Also bootstrap WinGet during install (off by default).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$EnrolledUser,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [switch]$WithWinget,
  [switch]$SkipUiLaunch,
  [switch]$Harden,
  [string]$RecoveryAdministrator = '',
  [string]$OfflineRecoveryKeyDirectory = '',
  [string]$ScanStateDir = ''
)
$ErrorActionPreference = 'Stop'
if ($Harden) {
  if (-not $RecoveryAdministrator -or -not $OfflineRecoveryKeyDirectory -or -not $ScanStateDir) { throw 'Harden requires RecoveryAdministrator, OfflineRecoveryKeyDirectory and ScanStateDir.' }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $administrator = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
  if (-not $administrator -or -not [Environment]::Is64BitProcess) { throw 'Run hardened provisioning from elevated 64-bit Windows PowerShell.' }
} elseif ($RecoveryAdministrator -or $OfflineRecoveryKeyDirectory -or $ScanStateDir) { throw 'Hardening options require -Harden; no hardening settings were applied.' }

$options=@()
if (-not $WithWinget) { $options += '-SkipWingetBootstrap' }
if ($SkipUiLaunch) { $options += '-SkipUiLaunch' }
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Start-EmiInstaller.ps1') -InstallDir $InstallDir @options
$result=$LASTEXITCODE
if ($result -eq 0 -and $Harden) {
  # Separate processes preserve mandatory script failures and isolate native exit codes.
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'Harden-LocalAccount.ps1') -DailyUser $EnrolledUser -RecoveryAdministrator $RecoveryAdministrator
  if ($LASTEXITCODE -ne 0) { throw 'Installation succeeded but account hardening failed. Device is not ready for handoff.' }
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'Provision-OfflineBitLocker.ps1') -RecoveryKeyDirectory $OfflineRecoveryKeyDirectory
  if ($LASTEXITCODE -ne 0) { throw 'Installation/account hardening completed but offline encryption provisioning failed. Device is not ready for handoff.' }
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'Provision-OfflineRecovery.ps1') -ScanStateDir $ScanStateDir -InstallDir $InstallDir
  if ($LASTEXITCODE -ne 0) { throw 'Installation/account/encryption provisioning completed but reset recovery capture failed. Device is not ready for handoff.' }
  Write-Warning 'Provisioning steps completed. Device handoff still requires sign-out/reboot, completed encryption, firmware boot-control verification and offline reset acceptance tests.'
}
if ($result -eq 0) { Write-Host "Provisioned '$EnrolledUser'. Use the admin panel to issue LOCK or UNLOCK." -ForegroundColor Green }
exit $result
