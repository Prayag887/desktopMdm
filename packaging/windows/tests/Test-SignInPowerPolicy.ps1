#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'SignIn-PowerPolicy.ps1')
. (Join-Path $root 'Set-EmiStateAcl.ps1')
$original=Get-EmiSignInPowerPolicyState
$data=Join-Path $env:ProgramData ('EmiSignInPowerTest-'+[Guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory $data | Out-Null
  Set-EmiAcl $data -Private $true
  foreach ($before in @([pscustomobject]@{present=$false;kind='DWord';value=0},[pscustomobject]@{present=$true;kind='DWord';value=0},[pscustomobject]@{present=$true;kind='DWord';value=1})) {
    Set-EmiSignInPowerPolicyState $before
    Disable-EmiSignInPowerPolicy $data
    if ((Get-EmiSignInPowerPolicyState).value -ne 0) { throw 'Sign-in shutdown was not disabled' }
    $backup=Get-Content (Join-Path $data 'config.signin-power-policy.json') -Raw
    Disable-EmiSignInPowerPolicy $data
    if ((Get-Content (Join-Path $data 'config.signin-power-policy.json') -Raw) -ne $backup) { throw 'Upgrade replaced baseline' }
    Remove-EmiSignInPowerPolicy $data
    if ((Get-EmiSignInPowerPolicyState | ConvertTo-Json -Compress) -ne ($before | ConvertTo-Json -Compress)) { throw 'Previous policy was not restored' }
  }
  Set-EmiSignInPowerPolicyState ([pscustomobject]@{present=$false;kind='DWord';value=0})
  Disable-EmiSignInPowerPolicy $data
  Set-EmiSignInPowerPolicyState ([pscustomobject]@{present=$true;kind='DWord';value=1})
  Remove-EmiSignInPowerPolicy $data
  if ((Get-EmiSignInPowerPolicyState).value -ne 1) { throw 'Administrator policy change was overwritten' }
  Write-Output 'Sign-in power policy disable, upgrade idempotence, absent/existing baseline restoration and external changes verified.'
} finally {
  Set-EmiSignInPowerPolicyState $original
  Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue
}
