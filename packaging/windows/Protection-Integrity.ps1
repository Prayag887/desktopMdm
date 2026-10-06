#Requires -Version 5.1
# The manifest is a signed comment containing JSON. Never execute its content.
function Test-ProtectionIntegrity([string]$InstallDir, [string]$PublisherThumbprint = '') {
  $root = Get-Item -LiteralPath $InstallDir -Force
  if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation root is a reparse point' }
  $manifestPath = Join-Path $InstallDir 'protection-manifest.ps1'
  $manifestSignature = Get-AuthenticodeSignature -LiteralPath $manifestPath
  if (-not $PublisherThumbprint) {
    $agentSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $InstallDir 'emi-device-agent.exe')
    if ($agentSignature.Status -ne 'Valid') { throw 'Core agent publisher signature is invalid' }
    $PublisherThumbprint = $agentSignature.SignerCertificate.Thumbprint
  }
  if ($manifestSignature.Status -ne 'Valid' -or $manifestSignature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) { throw 'Untrusted integrity manifest publisher' }
  $line = Get-Content -LiteralPath $manifestPath -TotalCount 1
  if (-not $line.StartsWith('# EMI-MANIFEST ')) { throw 'Invalid manifest header' }
  $manifest = $line.Substring(15) | ConvertFrom-Json
  $required = @('emi-device-agent.exe', 'emi-device-ui.exe', 'emi-device-watchdog.exe', 'emi-device-updater.exe', 'Get-DeviceProtection.ps1', 'Protection-Acl.ps1', 'Protection-Integrity.ps1', 'Get-SecurityPosture.ps1', 'Provision-BitLocker.ps1', 'Maintain-Protection.ps1', 'Set-EmiStateAcl.ps1', 'Protection-Transaction.ps1', 'Protection-Service.ps1', 'Start-EmiInstaller.ps1', 'Protection-Package.ps1', 'Install-PublisherTrust.ps1', 'emi-publisher.cer', 'install.ps1', 'uninstall.ps1')
  foreach ($name in $required) { if (-not $manifest.PSObject.Properties[$name]) { throw "Manifest omits $name" } }
  $failures = @()
  foreach ($entry in $manifest.PSObject.Properties) {
    if ($entry.Name -match '[/\\:]' -or $entry.Name -in @('.', '..') -or $entry.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid manifest entry' }
    $path = Join-Path $InstallDir $entry.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $failures += "$($entry.Name): missing"; continue }
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $failures += "$($entry.Name): reparse point"; continue }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value) { $failures += "$($entry.Name): SHA-256 mismatch" }
  }
  [pscustomobject]@{ verified = ($failures.Count -eq 0); failures = $failures; publisher = $PublisherThumbprint }
}
