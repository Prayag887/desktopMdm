#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'Explorer-ContextPolicy.ps1')
. (Join-Path $root 'Set-EmiStateAcl.ps1')
$original=Get-EmiExplorerPolicyState
$data=Join-Path $env:ProgramData ('EmiExplorerTest-'+[Guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory $data | Out-Null
  Set-EmiAcl $data -Private $true
  foreach ($before in @([pscustomobject]@{present=$false;kind='DWord';value=0},[pscustomobject]@{present=$true;kind='DWord';value=0},[pscustomobject]@{present=$true;kind='DWord';value=1})) {
    Set-EmiExplorerPolicyState $before
    Enable-EmiExplorerContextPolicy $data
    if ((Get-EmiExplorerPolicyState).value -ne 1) { throw 'Policy was not enabled' }
    $backup=Get-Content (Join-Path $data 'config.explorer-policy.json') -Raw
    Enable-EmiExplorerContextPolicy $data
    if ((Get-Content (Join-Path $data 'config.explorer-policy.json') -Raw) -ne $backup) { throw 'Upgrade replaced baseline' }
    Remove-EmiExplorerContextPolicy $data
    if ((Get-EmiExplorerPolicyState | ConvertTo-Json -Compress) -ne ($before | ConvertTo-Json -Compress)) { throw 'Previous policy was not restored' }
  }
  Set-EmiExplorerPolicyState ([pscustomobject]@{present=$false;kind='DWord';value=0})
  Enable-EmiExplorerContextPolicy $data
  Set-EmiExplorerPolicyState ([pscustomobject]@{present=$true;kind='DWord';value=0})
  Remove-EmiExplorerContextPolicy $data
  if ((Get-EmiExplorerPolicyState).value -ne 0) { throw 'Administrator policy change was overwritten' }
  Write-Output 'Explorer policy enable, upgrade idempotence, absent/existing baseline restoration and external changes verified.'
} finally {
  Set-EmiExplorerPolicyState $original
  Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue
}
