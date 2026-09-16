#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$EnrollmentKey,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent"
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'emi-device-agent.exe'
$uiExe = Join-Path $PSScriptRoot 'emi-device-ui.exe'
if (-not (Test-Path $exe)) { throw 'emi-device-agent.exe must be beside install.ps1' }
if (-not (Test-Path $uiExe)) { throw 'emi-device-ui.exe must be beside install.ps1' }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe (Join-Path $InstallDir 'emi-device-agent.exe') -Force
Copy-Item $uiExe (Join-Path $InstallDir 'emi-device-ui.exe') -Force
$agent = Join-Path $InstallDir 'emi-device-agent.exe'
& $agent bootstrap
& $agent enroll --server $Server --enrollment-key $EnrollmentKey
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) { Stop-Service EmiDeviceAgent -Force; sc.exe delete EmiDeviceAgent | Out-Null }
sc.exe create EmiDeviceAgent binPath= "`"$agent`" service" start= auto DisplayName= "EMI Device Agent" | Out-Null
sc.exe description EmiDeviceAgent "Authorized payment-plan device management and health agent" | Out-Null
sc.exe failure EmiDeviceAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
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
