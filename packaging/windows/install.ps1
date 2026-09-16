#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$EnrollmentKey,
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
& $agent bootstrap
Assert-NativeExit 'WinGet bootstrap'
& $agent enroll --server $Server --enrollment-key $EnrollmentKey
Assert-NativeExit 'Device enrollment'
$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'
icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T | Out-Null
Assert-NativeExit 'Agent state permissions'
$configPath = Join-Path $dataDir 'config.json'
icacls.exe $configPath /inheritance:r /remove:g '*S-1-5-32-545' '*S-1-5-11' '*S-1-1-0' | Out-Null
Assert-NativeExit 'Private agent credentials permissions'
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  sc.exe config EmiDeviceAgent binPath= "`"$agent`" service" start= auto | Out-Null
} else {
  sc.exe create EmiDeviceAgent binPath= "`"$agent`" service" start= auto DisplayName= "EMI Device Agent" | Out-Null
}
Assert-NativeExit 'Windows service setup'
sc.exe description EmiDeviceAgent "Authorized payment-plan device management and health agent" | Out-Null
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
$shortcut.Description = 'EMI device status and payment notifications'
$shortcut.Save()
Start-Process (Join-Path $InstallDir 'emi-device-ui.exe')
Write-Host 'EMI Device Agent and desktop UI installed and enrolled.' -ForegroundColor Green
