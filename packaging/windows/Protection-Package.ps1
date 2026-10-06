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
    Get-ChildItem -LiteralPath $Source -File | Where-Object { $_.Extension -in @('.exe','.ps1','.cmd','.hex','.cer') } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name) -Force }
  } else { throw 'Signed package manifest required' }
}
function Initialize-ProtectionRepairCache([string]$Source, [string]$DataDir, [string]$Publisher) {
  $cacheRoot=Join-Path $env:ProgramData 'RepairWatchdog'
  New-Item -ItemType Directory -Force $cacheRoot | Out-Null
  Apply-ProtectionAcl $cacheRoot | Out-Null
  $packageId=(Get-FileHash (Join-Path $Source 'protection-manifest.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
  $cache=Join-Path $cacheRoot $packageId
  $existing=if (Test-Path -LiteralPath $cache) { Test-ProtectionIntegrity $cache $Publisher } else { $null }
  if (-not $existing -or -not $existing.verified) {
    $stage=Join-Path $cacheRoot ('stage-'+[Guid]::NewGuid().ToString('N'))
    try {
      New-Item -ItemType Directory $stage | Out-Null
      Apply-ProtectionAcl $stage | Out-Null
      Copy-ProtectionPackage $Source $stage
      if (-not (Test-ProtectionIntegrity $stage $Publisher).verified) { throw 'Staged repair backup verification failed' }
      if (Test-Path -LiteralPath $cache) { Get-ProtectionItems $cache | Out-Null; Remove-Item -LiteralPath $cache -Recurse -Force }
      [IO.Directory]::Move($stage,$cache)
    } finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force } }
  }
  Apply-ProtectionAcl $cacheRoot | Out-Null
  $result=Test-ProtectionIntegrity $cache $Publisher
  if (-not $result.verified) { throw 'Trusted repair cache verification failed' }
  $sourceFile=Join-Path $DataDir 'repair-source.json'
  [IO.File]::WriteAllText($sourceFile, (@{package=$cache} | ConvertTo-Json))
  Set-EmiAcl $sourceFile -Private $true
  Write-Host "Verified RepairWatchdog backup installed at: $cache" -ForegroundColor Green
}
