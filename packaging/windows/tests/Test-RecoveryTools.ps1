#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Recovery-Tools.ps1')
$global:EmiRecoveryFixture = @{ root=(Join-Path $env:TEMP ('EmiRecoveryTest-' + [Guid]::NewGuid().ToString('N'))); signed=$true; exitCode=0; downloads=0; starts=0 }
function Invoke-WebRequest { param($Uri,$OutFile,[switch]$UseBasicParsing,$ErrorAction) $global:EmiRecoveryFixture.downloads++; [IO.File]::WriteAllText($OutFile,'fixture') }
function Get-AuthenticodeSignature { param($LiteralPath) @{ Status=$(if ($global:EmiRecoveryFixture.signed) { 'Valid' } else { 'NotSigned' }); SignerCertificate=@{Subject='CN=Microsoft Windows, O=Microsoft Corporation, C=US'} } }
function New-TestAdk {
  $root = Join-Path $global:EmiRecoveryFixture.root 'ADK'
  foreach ($part in @('User State Migration Tool\amd64','Windows Setup\amd64\Sources')) { New-Item -ItemType Directory -Path (Join-Path $root $part) -Force | Out-Null }
  [IO.File]::WriteAllText((Join-Path $root 'User State Migration Tool\amd64\scanstate.exe'),'fixture')
  [IO.File]::WriteAllText((Join-Path $root 'Windows Setup\amd64\Sources\Config_AppsAndSettings.xml'),'<fixture/>')
}
function Start-Process { param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru,$ErrorAction) $global:EmiRecoveryFixture.starts++; if ($global:EmiRecoveryFixture.exitCode -eq 0) { New-TestAdk }; @{ExitCode=$global:EmiRecoveryFixture.exitCode} }
function Assert-Fails { param([scriptblock]$Action,[string]$Expected) try { & $Action | Out-Null } catch { if ($_.Exception.Message -like "*$Expected*") { return }; throw }; throw "Expected failure: $Expected" }
try {
  New-Item -ItemType Directory -Path $global:EmiRecoveryFixture.root | Out-Null
  $adk = Join-Path $global:EmiRecoveryFixture.root 'ADK'
  $prepared = Initialize-EmiRecoveryTools -InstallDir $global:EmiRecoveryFixture.root -AdkRoot $adk
  if (-not (Test-Path (Join-Path $prepared 'Config_AppsAndSettings.xml')) -or $global:EmiRecoveryFixture.starts -ne 1) { throw 'Automatic preparation did not complete.' }
  Initialize-EmiRecoveryTools -InstallDir $global:EmiRecoveryFixture.root -AdkRoot $adk | Out-Null
  if ($global:EmiRecoveryFixture.downloads -ne 1) { throw 'Ready ADK should be reused without downloading.' }
  Remove-Item -LiteralPath $adk -Recurse -Force
  $global:EmiRecoveryFixture.signed = $false
  Assert-Fails { Initialize-EmiRecoveryTools -InstallDir $global:EmiRecoveryFixture.root -AdkRoot $adk } 'refusing to execute'
  if ($global:EmiRecoveryFixture.starts -ne 1) { throw 'Unsigned installer was executed.' }
  $global:EmiRecoveryFixture.signed = $true
  $global:EmiRecoveryFixture.exitCode = 1603
  Assert-Fails { Initialize-EmiRecoveryTools -InstallDir $global:EmiRecoveryFixture.root -AdkRoot $adk } 'exit code 1603'
  $global:EmiRecoveryFixture.exitCode = 3010
  Assert-Fails { Initialize-EmiRecoveryTools -InstallDir $global:EmiRecoveryFixture.root -AdkRoot $adk } 'requires a restart'
  Write-Host 'Recovery bootstrap tests passed (mocked downloads and ADK setup).'
} finally {
  Remove-Item -LiteralPath $global:EmiRecoveryFixture.root -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Variable EmiRecoveryFixture -Scope Global
}
