#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'Recovery-PagePolicy.ps1')
. (Join-Path $root 'Set-EmiStateAcl.ps1')
$original=Get-EmiRecoveryPagePolicyState
$data=Join-Path $env:ProgramData ('EmiRecoveryPageTest-'+[Guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory $data | Out-Null
  Set-EmiAcl $data -Private $true
  $cases=@(
    @{present=$false;value=0;expected='hide:recovery'},
    @{present=$true;value='';expected='hide:recovery'},
    @{present=$true;value='hide:recovery';expected='hide:recovery'},
    @{present=$true;value='hide:about;network-proxy';expected='hide:about;network-proxy;recovery'},
    @{present=$true;value='showonly:about;recovery';expected='showonly:about'},
    @{present=$true;value='showonly:about';expected='showonly:about'},
    @{present=$true;value='showonly:recovery';expected='showonly:'}
  )
  foreach ($case in $cases) {
    $before=[pscustomobject]@{present=$case.present;kind=if ($case.present) { 'String' } else { 'DWord' };value=$case.value}
    Set-EmiRecoveryPagePolicyState $before
    Enable-EmiRecoveryPagePolicy $data
    $actual=Get-EmiRecoveryPagePolicyState
    if ($actual.kind -ne 'String' -or $actual.value -ne $case.expected) { throw 'Recovery visibility merge failed' }
    Enable-EmiRecoveryPagePolicy $data
    if ((Get-EmiRecoveryPagePolicyState).value -ne $case.expected) { throw 'Repeated install changed visibility policy' }
    Remove-EmiRecoveryPagePolicy $data
    if ((Get-EmiRecoveryPagePolicyState | ConvertTo-Json -Compress) -ne ($before | ConvertTo-Json -Compress)) { throw 'Original visibility policy was not restored' }
  }
  Set-EmiRecoveryPagePolicyState ([pscustomobject]@{present=$false;kind='DWord';value=0})
  Enable-EmiRecoveryPagePolicy $data
  Set-EmiRecoveryPagePolicyState ([pscustomobject]@{present=$true;kind='String';value='hide:about'})
  Remove-EmiRecoveryPagePolicy $data
  if ((Get-EmiRecoveryPagePolicyState).value -ne 'hide:about') { throw 'External administrator policy was overwritten' }
  Write-Output 'Recovery page hiding, existing hide/showonly restrictions, upgrade idempotence, baseline restoration and external changes verified.'
} finally {
  Set-EmiRecoveryPagePolicyState $original
  Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue
}
