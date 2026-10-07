#Requires -Version 5.1
[CmdletBinding()]
param(
  [switch]$SkipWingetBootstrap,
  [switch]$SkipUiLaunch,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [UInt64]$CommandSigningKeyId = 0,
  [string]$CommandSigningPublicKey = '',
  [string]$RecoveryPublicKeyHex = '',
  [switch]$RequireOfflineRecovery,
  [string]$ScanStateDir = ''
)
$ErrorActionPreference = 'Stop'
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $administrator = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $recoveryOptions = @()
  if ($RequireOfflineRecovery) {
    if ($ScanStateDir) {
      $ScanStateDir = (Resolve-Path -LiteralPath $ScanStateDir).Path
      if ($ScanStateDir.Contains('"')) { throw 'Invalid ScanState path.' }
      foreach ($file in @('scanstate.exe', 'Config_AppsAndSettings.xml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $ScanStateDir $file) -PathType Leaf)) { throw "Recovery capture requires prepared Microsoft ADK tools: missing $file in $ScanStateDir." }
      }
    }
    if (Test-Path -LiteralPath (Join-Path $env:SystemDrive 'Recovery\Customizations\EmiDeviceAgent.ppkg')) { throw 'Archive the existing agent recovery package explicitly before installing and capturing a replacement.' }
    $recoveryOptions = @('-RequireOfflineRecovery')
    if ($ScanStateDir) { $recoveryOptions += @('-ScanStateDir',('"'+$ScanStateDir+'"')) }
  } elseif ($ScanStateDir) { throw 'ScanStateDir requires RequireOfflineRecovery.' }
  $options = @()
  if ($SkipWingetBootstrap) { $options += '-SkipWingetBootstrap' }
  if ($SkipUiLaunch) { $options += '-SkipUiLaunch' }
  if (($CommandSigningKeyId -eq 0) -ne ([string]::IsNullOrWhiteSpace($CommandSigningPublicKey))) { throw 'Command signing key ID and public key must be supplied together.' }
  if ($CommandSigningPublicKey) {
    if ($CommandSigningPublicKey -notmatch '^[A-Za-z0-9+/=_-]+$') { throw 'Command signing public key must be base64 without whitespace.' }
    $options += @('-CommandSigningKeyId', $CommandSigningKeyId.ToString(), '-CommandSigningPublicKey', $CommandSigningPublicKey)
  }
  if ($RecoveryPublicKeyHex) {
    if ($RecoveryPublicKeyHex -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Recovery public key must contain 64 hexadecimal characters.' }
    $options += @('-RecoveryPublicKeyHex', $RecoveryPublicKeyHex)
  }
  if (-not $administrator) {
    # -File keeps apostrophes and other path characters out of PowerShell code.
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-InstallDir',('"'+$InstallDir+'"')) + $options + $recoveryOptions
    $child = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru -ErrorAction Stop
    exit $child.ExitCode
  }
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Install-PublisherTrust.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'Publisher trust failed; application installation was not started.' }
  # Isolate install.ps1's exit in its own process and preserve the installer result.
  & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install.ps1') -InstallDir $InstallDir @options
  $installExit = $LASTEXITCODE
  if ($installExit -ne 0) { exit $installExit }
  if ($RequireOfflineRecovery) {
    if (-not $ScanStateDir) {
      . (Join-Path $InstallDir 'Protection-Integrity.ps1')
      if (-not (Test-ProtectionIntegrity $InstallDir).verified) { throw 'Installed release integrity failed; recovery tool preparation was not started.' }
      . (Join-Path $InstallDir 'Recovery-Tools.ps1')
      $ScanStateDir = Initialize-EmiRecoveryTools -InstallDir $InstallDir
    }
    & $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'Provision-OfflineRecovery.ps1') -InstallDir $InstallDir -ScanStateDir $ScanStateDir
    if ($LASTEXITCODE -ne 0) { throw 'Application installed, but recovery capture FAILED. This PC is not ready for handoff. Review capture diagnostics and retry.' }
  }
  exit 0
} catch {
  Write-Error -Message $_.Exception.Message -ErrorAction Continue
  exit 1
}
