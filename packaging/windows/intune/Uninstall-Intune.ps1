#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$PayloadRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent"
)

$ErrorActionPreference = 'Stop'
$uninstaller = Join-Path $PayloadRoot 'uninstall.ps1'
if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
  throw "uninstall.ps1 was not found in payload root '$PayloadRoot'."
}
& $uninstaller -InstallDir $InstallDir
exit $LASTEXITCODE
