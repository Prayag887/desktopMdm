#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent")
$ErrorActionPreference = 'Stop'
$resolvedInstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$programFilesPrefix = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $resolvedInstallDir.StartsWith($programFilesPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'InstallDir must be a child directory under Program Files' }
if (-not (Test-Path (Join-Path $resolvedInstallDir 'emi-device-agent.exe'))) { throw 'InstallDir does not contain the EMI Device Agent; nothing was removed' }
Get-Process -Name 'emi-device-ui' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $resolvedInstallDir 'emi-device-ui.exe') } | Stop-Process -Force
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  Stop-Service EmiDeviceAgent -Force
  sc.exe delete EmiDeviceAgent | Out-Null
}
Remove-Item $resolvedInstallDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EMI Device.lnk" -Force -ErrorAction SilentlyContinue
Write-Host 'Desktop companion removed. Local device data remains in ProgramData for recovery.'
