#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$PayloadRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [switch]$SkipWingetBootstrap,
  [Parameter(Mandatory = $true)][UInt64]$CommandSigningKeyId,
  [Parameter(Mandatory = $true)][string]$CommandSigningPublicKey
)

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PayloadRoot 'install.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
  throw "install.ps1 was not found in payload root '$PayloadRoot'. Package the complete packaging/windows directory."
}
& $installer -InstallDir $InstallDir -SkipWingetBootstrap:$SkipWingetBootstrap `
  -CommandSigningKeyId $CommandSigningKeyId -CommandSigningPublicKey $CommandSigningPublicKey
exit $LASTEXITCODE
