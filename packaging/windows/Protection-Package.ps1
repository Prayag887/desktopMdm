#Requires -Version 5.1
# Install/copy only immutable release artifacts. No mutable credentials or device state.
function Copy-ProtectionPackage([string]$Source, [string]$Destination, [bool]$Unsigned = $false) {
  New-Item -ItemType Directory -Force $Destination | Out-Null
  $manifestPath=Join-Path $Source 'protection-manifest.ps1'
  if (Test-Path -LiteralPath $manifestPath) {
    $line=Get-Content -LiteralPath $manifestPath -TotalCount 1
    if (-not $line.StartsWith('# EMI-MANIFEST ')) { throw 'Invalid package manifest' }
    $manifest=$line.Substring(15) | ConvertFrom-Json
    foreach ($entry in $manifest.PSObject.Properties) {
      if ($entry.Name -match '[/\\:]' -or $entry.Name -in @('.','..')) { throw 'Unsafe package entry' }
      Copy-Item -LiteralPath (Join-Path $Source $entry.Name) -Destination (Join-Path $Destination $entry.Name) -Force
    }
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $Destination 'protection-manifest.ps1') -Force
  } elseif ($Unsigned) {
    Get-ChildItem -LiteralPath $Source -File | Where-Object { $_.Extension -in @('.exe','.ps1','.cmd','.hex') } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name) -Force }
  } else { throw 'Signed package manifest required' }
}
function Initialize-ProtectionRepairCache([string]$Source, [string]$DataDir, [string]$Publisher) {
  $cacheRoot=Join-Path $env:ProgramData 'EmiDeviceAgentRepair'
  New-Item -ItemType Directory -Force $cacheRoot | Out-Null
  Apply-ProtectionAcl $cacheRoot | Out-Null
  $packageId=(Get-FileHash (Join-Path $Source 'protection-manifest.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
  $cache=Join-Path $cacheRoot $packageId
  if (-not (Test-Path -LiteralPath $cache)) {
    New-Item -ItemType Directory $cache | Out-Null
    Apply-ProtectionAcl $cache | Out-Null
    Copy-ProtectionPackage $Source $cache
  }
  Apply-ProtectionAcl $cacheRoot | Out-Null
  $result=Test-ProtectionIntegrity $cache $Publisher
  if (-not $result.verified) { throw 'Trusted repair cache verification failed' }
  $sourceFile=Join-Path $DataDir 'repair-source.json'
  [IO.File]::WriteAllText($sourceFile, (@{package=$cache} | ConvertTo-Json))
  Set-EmiAcl $sourceFile -Private $true
}
