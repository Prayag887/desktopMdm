#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$EnrollmentKey,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent"
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'emi-device-agent.exe'
if (-not (Test-Path $exe)) { throw 'emi-device-agent.exe must be beside install.ps1' }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exe (Join-Path $InstallDir 'emi-device-agent.exe') -Force
$agent = Join-Path $InstallDir 'emi-device-agent.exe'
& $agent bootstrap
& $agent enroll --server $Server --enrollment-key $EnrollmentKey
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) { Stop-Service EmiDeviceAgent -Force; sc.exe delete EmiDeviceAgent | Out-Null }
sc.exe create EmiDeviceAgent binPath= "`"$agent`" service" start= auto DisplayName= "EMI Device Agent" | Out-Null
sc.exe description EmiDeviceAgent "Authorized payment-plan device management and health agent" | Out-Null
sc.exe failure EmiDeviceAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service EmiDeviceAgent
Write-Host 'EMI Device Agent installed and enrolled.' -ForegroundColor Green
