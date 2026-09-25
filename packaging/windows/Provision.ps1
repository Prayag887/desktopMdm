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
  [switch]$WithWinget
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  # Relaunch elevated with the same arguments. (No-op under SYSTEM/RMM.)
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
    '-EnrolledUser', "`"$EnrolledUser`"", '-InstallDir', "`"$InstallDir`""
  )
  return
}

$here = Split-Path -Parent $PSCommandPath

$installArgs = @{ InstallDir = $InstallDir }
if (-not $WithWinget) { $installArgs['SkipWingetBootstrap'] = $true }
& (Join-Path $here 'install.ps1') @installArgs

Write-Host "Provisioned '$EnrolledUser'. Use the admin panel to issue LOCK or UNLOCK." -ForegroundColor Green
