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
function Assert-NativeExit([string]$Operation) {
  if ($LASTEXITCODE -ne 0) { throw "$Operation failed (exit $LASTEXITCODE)" }
}
$exe = Join-Path $PSScriptRoot 'emi-device-agent.exe'
$uiExe = Join-Path $PSScriptRoot 'emi-device-ui.exe'
if (-not (Test-Path $exe)) { throw 'emi-device-agent.exe must be beside install.ps1' }
if (-not (Test-Path $uiExe)) { throw 'emi-device-ui.exe must be beside install.ps1' }
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) { Stop-Service EmiDeviceAgent -Force }
Get-Process -Name 'emi-device-ui' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $InstallDir 'emi-device-ui.exe') } | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe (Join-Path $InstallDir 'emi-device-agent.exe') -Force
Copy-Item $uiExe (Join-Path $InstallDir 'emi-device-ui.exe') -Force
$agent = Join-Path $InstallDir 'emi-device-agent.exe'
if (-not $SkipWingetBootstrap) {
  & $agent bootstrap
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "WinGet bootstrap failed (exit $LASTEXITCODE); continuing without it."
  }
}
& $agent init
Assert-NativeExit 'Local device initialization'
& $agent run --once
Assert-NativeExit 'Initial local health snapshot'
$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'
icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T | Out-Null
Assert-NativeExit 'Agent state permissions'
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  sc.exe config EmiDeviceAgent binPath= "`"$agent`" service" start= auto | Out-Null
} else {
  sc.exe create EmiDeviceAgent binPath= "`"$agent`" service" start= auto DisplayName= "EMI Device Agent" | Out-Null
}
Assert-NativeExit 'Windows service setup'
sc.exe description EmiDeviceAgent "Standalone desktop companion and local device health" | Out-Null
Assert-NativeExit 'Windows service description'
sc.exe failure EmiDeviceAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Assert-NativeExit 'Windows service recovery'
Start-Service EmiDeviceAgent
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
$shortcutPath = Join-Path $startup 'EMI Device.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $InstallDir 'emi-device-ui.exe'
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = 'Standalone EMI desktop companion'
$shortcut.Save()
Start-Process (Join-Path $InstallDir 'emi-device-ui.exe')
Write-Host 'EMI desktop companion installed. No server or enrollment required.' -ForegroundColor Green
