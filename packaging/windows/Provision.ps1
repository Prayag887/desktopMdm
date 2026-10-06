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
  [switch]$SkipUiLaunch
)
$ErrorActionPreference = 'Stop'

$options=@()
if (-not $WithWinget) { $options += '-SkipWingetBootstrap' }
if ($SkipUiLaunch) { $options += '-SkipUiLaunch' }
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Start-EmiInstaller.ps1') -InstallDir $InstallDir @options
$result=$LASTEXITCODE
if ($result -eq 0) { Write-Host "Provisioned '$EnrolledUser'. Use the admin panel to issue LOCK or UNLOCK." -ForegroundColor Green }
exit $result
