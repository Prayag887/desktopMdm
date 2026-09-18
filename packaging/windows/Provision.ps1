#Requires -Version 5
<#
.SYNOPSIS
  One-shot device provisioning: install the agent and apply the payment
  restriction so the enrolled account boots into the lock on every login.

.DESCRIPTION
  Meant to be launched by provision.cmd (which sets -ExecutionPolicy Bypass).
  Self-elevates if not already admin. Under an RMM/MDM that runs as SYSTEM it is
  already elevated and runs straight through. WinGet bootstrap is skipped by
  default (it is only needed later for OEM firmware tooling) so a missing/failed
  WinGet never blocks provisioning.

.PARAMETER EnrolledUser
  The local standard account to lock (SAM name). Must not be an administrator.

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

& (Join-Path $here 'Set-PaymentRestriction.ps1') `
  -EnrolledUser $EnrolledUser `
  -AppPath (Join-Path $InstallDir 'emi-device-ui.exe') `
  -LabVm

Write-Host "Provisioned '$EnrolledUser'. That account boots into the lock on next login." -ForegroundColor Green
