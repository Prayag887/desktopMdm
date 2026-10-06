#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
  [ValidateSet('Begin','End','Repair','Update','Uninstall')][string]$Action,
  [string]$InstallDir = "$env:ProgramFiles\EmiDeviceAgent",
  [string]$PackageDir = ''
)
$ErrorActionPreference = 'Stop'
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$prefix = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $InstallDir.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'InstallDir must be under Program Files' }
. (Join-Path $PSScriptRoot 'Protection-Integrity.ps1')
. (Join-Path $PSScriptRoot 'Protection-Acl.ps1')
. (Join-Path $PSScriptRoot 'Set-EmiStateAcl.ps1')
$dataDir = Join-Path $env:ProgramData 'EmiDeviceAgent'
$lease = Join-Path $dataDir 'maintenance.json'
[pscustomobject]@{ event='authorized_maintenance'; action=$Action; at=[DateTime]::UtcNow.ToString('o'); user=[Security.Principal.WindowsIdentity]::GetCurrent().Name } | ConvertTo-Json -Compress
if ($Action -in @('Update','Repair')) {
  if (-not $PackageDir) { throw 'A trusted extracted release package is required' }
  $publisher = Get-AuthenticodeSignature (Join-Path $InstallDir 'RepairWatchdog.exe')
  if ($publisher.Status -ne 'Valid') { throw 'Installed publisher unavailable; recover with an administrator-verified release and install.ps1' }
  $result = Test-ProtectionIntegrity $PackageDir $publisher.SignerCertificate.Thumbprint
  if (-not $result.verified) { throw "Untrusted repair package: $($result.failures -join ', ')" }
  # Stage into a private directory to remove user-writable package TOCTOU.
  $stage = Join-Path $env:ProgramData ('EmiProtectionStage-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $stage | Out-Null
  Set-EmiAcl $stage -Private $true
  try {
    Get-ProtectionItems $PackageDir | Out-Null
    Copy-Item -Path (Join-Path $PackageDir '*') -Destination $stage -Recurse -Force
    Get-ProtectionItems $stage | ForEach-Object { Set-EmiAcl $_.FullName -Private $true }
    $verified = Test-ProtectionIntegrity $stage $publisher.SignerCertificate.Thumbprint
    if (-not $verified.verified) { throw 'Staged repair package failed verification' }
    & (Join-Path $stage 'install.ps1') -InstallDir $InstallDir -SkipWingetBootstrap -SkipUiLaunch
    if ($LASTEXITCODE -ne 0) { throw 'Repair/update installation failed' }
  } finally { Remove-Item -LiteralPath $stage -Recurse -Force }
  return
}
if ($Action -eq 'Uninstall') { & (Join-Path $InstallDir 'uninstall.ps1') -InstallDir $InstallDir; return }
if ($Action -eq 'Begin') {
  [IO.File]::WriteAllText($lease, (@{expiresAt=[DateTime]::UtcNow.AddMinutes(30).ToString('o')} | ConvertTo-Json))
  Set-EmiAcl $lease -Private $true
  Stop-Service EmiDeviceWatchdog -ErrorAction Stop
  Stop-Service EmiDeviceAgent -ErrorAction Stop
} elseif ($Action -eq 'End') {
  $result = Test-ProtectionIntegrity $InstallDir
  if (-not $result.verified) { throw 'Integrity verification failed; services remain stopped' }
  Apply-ProtectionAcl $InstallDir | Out-Null
  Remove-Item -LiteralPath $lease -Force -ErrorAction SilentlyContinue
  Start-Service EmiDeviceAgent
  Start-Service EmiDeviceWatchdog
} else { throw 'Specify a maintenance Action' }
