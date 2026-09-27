#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-EmiCompanion.ps1')
$script:launchFailure = $false
$script:launchPath = ''
function Start-Process {
  [CmdletBinding()]
  param([string]$FilePath)
  $script:launchPath = $FilePath
  if ($script:launchFailure) {
    throw [ComponentModel.Win32Exception]::new(1223)
  }
}
$path = 'C:\Program Files\EmiDeviceAgent\emi-device-ui.exe'
if (-not (Start-EmiCompanion -UiPath $path)) { throw 'Successful launch was not reported' }
if ($script:launchPath -ne $path) { throw 'Spaced UI path was not passed intact' }
$script:launchFailure = $true
$warnings = @()
$result = Start-EmiCompanion -UiPath $path -WarningVariable warnings -WarningAction SilentlyContinue
if ($result -ne $false) { throw 'Canceled launch must return false without throwing' }
if (($warnings -join ' ') -notmatch 'service is installed') { throw 'Warning must explain partial launch outcome' }
Write-Output 'Successful launch and Windows cancellation handling verified.'
