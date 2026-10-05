#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param([string]$CertificatePath = (Join-Path $PSScriptRoot 'emi-publisher.cer'))
$ErrorActionPreference='Stop'
# This is the single administrator-approved private publisher, not an arbitrary root import.
$expectedSha256='DA2234BEDB50A8FBA21ADE3AECD4BFE1343E86D5C97ADF68FEBCD5DE2F2D8861'
$bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($CertificatePath))
$hasher=[Security.Cryptography.SHA256]::Create()
try { $digest=([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','') } finally { $hasher.Dispose() }
if ($digest -ne $expectedSha256) { throw 'Publisher certificate fingerprint mismatch; no certificate was imported' }
$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
$added=@()
try {
  if ($certificate.HasPrivateKey) { throw 'Only the public publisher certificate may be distributed' }
  if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Publisher certificate is outside its validity period; check the system clock' }
  $eku=@($certificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })
  if ($eku.Count -ne 1 -or $eku[0].EnhancedKeyUsages.Count -ne 1 -or $eku[0].EnhancedKeyUsages[0].Value -ne '1.3.6.1.5.5.7.3.3') { throw 'Publisher certificate must be restricted to code signing' }
  $constraints=@($certificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] })
  if ($constraints.Count -ne 1 -or $constraints[0].CertificateAuthority) { throw 'Publisher certificate must not be a certificate authority' }
  foreach ($name in @('Root','TrustedPublisher')) {
    $store=[Security.Cryptography.X509Certificates.X509Store]::new($name, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
      $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
      $matches=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $certificate.Thumbprint, $false)
      if ($matches.Count -eq 0) { $store.Add($certificate); $added += $name }
      $verified=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $certificate.Thumbprint, $false)
      if ($verified.Count -eq 0) { throw "Publisher certificate trust verification failed in $name" }
    } finally { $store.Close() }
  }
  [pscustomobject]@{event='private_publisher_trusted'; thumbprint=$certificate.Thumbprint; addedStores=$added; expiresAt=$certificate.NotAfter.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress
} catch {
  foreach ($name in $added) {
    $store=[Security.Cryptography.X509Certificates.X509Store]::new($name, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try { $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); $store.Remove($certificate) } finally { $store.Close() }
  }
  throw
} finally { $certificate.Dispose() }
