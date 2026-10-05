# Signature verification must fail before any untrusted installer code runs.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Protection-Integrity.ps1')
$directory=Join-Path ([IO.Path]::GetTempPath()) ('emi-untrusted-'+[Guid]::NewGuid())
try {
  New-Item -ItemType Directory $directory | Out-Null
  '# EMI-MANIFEST {}' | Set-Content (Join-Path $directory 'protection-manifest.ps1')
  $failed=$false
  try { Test-ProtectionIntegrity $directory ('a'*40) | Out-Null } catch { $failed=$true }
  if (-not $failed) { throw 'Untrusted repair manifest accepted' }
  Write-Output 'Unsigned repair manifest rejected before loading executable code.'
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
