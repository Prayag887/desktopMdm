#Requires -Version 5.1
[CmdletBinding()]
param([switch]$SkipWingetBootstrap, [switch]$SkipUiLaunch, [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent")
$ErrorActionPreference = 'Stop'
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $administrator = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $options = @()
  if ($SkipWingetBootstrap) { $options += '-SkipWingetBootstrap' }
  if ($SkipUiLaunch) { $options += '-SkipUiLaunch' }
  if (-not $administrator) {
    # -File keeps apostrophes and other path characters out of PowerShell code.
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-InstallDir',('"'+$InstallDir+'"')) + $options
    $child = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru -ErrorAction Stop
    exit $child.ExitCode
  }
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Install-PublisherTrust.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'Publisher trust failed; application installation was not started.' }
  # Isolate install.ps1's exit in its own process and preserve the installer result.
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install.ps1') -InstallDir $InstallDir @options
  exit $LASTEXITCODE
} catch {
  Write-Error -Message $_.Exception.Message -ErrorAction Continue
  exit 1
}
