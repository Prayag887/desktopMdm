#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$installer=Join-Path $root 'Install-PublisherTrust.ps1'
$first=& $installer | ConvertFrom-Json
$second=& $installer | ConvertFrom-Json
if (@($second.addedStores).Count -ne 0 -or $first.thumbprint -ne $second.thumbprint) { throw 'Publisher trust installation is not idempotent' }
foreach ($name in @('Root','TrustedPublisher')) {
  if (-not (Test-Path "Cert:\LocalMachine\$name\$($second.thumbprint)")) { throw "Publisher trust missing from $name" }
}
$wrong=Join-Path ([IO.Path]::GetTempPath()) ('emi-wrong-certificate-'+[Guid]::NewGuid()+'.cer')
try {
  [IO.File]::WriteAllBytes($wrong, [byte[]]@(1,2,3))
  $failed=$false
  try { & $installer -CertificatePath $wrong | Out-Null } catch { $failed=$true }
  if (-not $failed) { throw 'A substituted certificate was accepted' }
} finally { Remove-Item -LiteralPath $wrong -Force -ErrorAction SilentlyContinue }
Write-Output 'Pinned public certificate, LocalMachine trust, idempotence and substitution rejection verified.'
