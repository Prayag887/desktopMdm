#Requires -Version 5.1
# Sign-in screen shutdown policy; preserve the pre-install value across upgrades.
function Get-EmiSignInPowerPolicyState {
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\System')
    try {
      if ($key -and $key.GetValueNames() -contains 'ShutdownWithoutLogon') {
        return [pscustomobject]@{present=$true;kind=$key.GetValueKind('ShutdownWithoutLogon').ToString();value=$key.GetValue('ShutdownWithoutLogon',$null,'DoNotExpandEnvironmentNames')}
      }
      [pscustomobject]@{present=$false;kind='DWord';value=0}
    } finally { if ($key) { $key.Dispose() } }
  } finally { $root.Dispose() }
}
function Set-EmiSignInPowerPolicyState($State) {
  if ($null -eq $State -or $State.present -isnot [bool] -or $State.kind -notin @('DWord','QWord','Binary','MultiString','String','ExpandString','None')) { throw 'Invalid sign-in power policy backup' }
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\System')
    try {
      if ($State.present) {
        $value=switch ($State.kind) {
          DWord { [int]$State.value }; QWord { [long]$State.value }
          None { ,[byte[]]$State.value }; Binary { ,[byte[]]$State.value }; MultiString { ,[string[]]$State.value }
          String { [string]$State.value }; ExpandString { [string]$State.value }
          default { throw 'Unsupported previous sign-in power policy value type' }
        }
        $key.SetValue('ShutdownWithoutLogon',$value,[Microsoft.Win32.RegistryValueKind]$State.kind)
      } else { $key.DeleteValue('ShutdownWithoutLogon',$false) }
    } finally { $key.Dispose() }
  } finally { $root.Dispose() }
}
function Disable-EmiSignInPowerPolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.signin-power-policy.json'
  if (-not (Test-Path -LiteralPath $backup)) {
    $previous=Get-EmiSignInPowerPolicyState
    $temporary=Join-Path $DataDir ('.tmp-signin-power-policy-'+[Guid]::NewGuid().ToString('N'))
    try {
      [IO.File]::WriteAllText($temporary,'')
      Set-EmiAcl $temporary -Private $true
      [IO.File]::WriteAllText($temporary,($previous | ConvertTo-Json -Depth 5 -Compress))
      [IO.File]::Move($temporary,$backup)
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  } else {
    $previous=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    if ($null -eq $previous -or $previous.present -isnot [bool]) { throw 'Invalid sign-in power policy backup' }
  }
  Set-EmiSignInPowerPolicyState ([pscustomobject]@{present=$true;kind='DWord';value=0})
  $state=Get-EmiSignInPowerPolicyState
  if (-not $state.present -or $state.kind -ne 'DWord' -or $state.value -ne 0) { throw 'Sign-in power policy verification failed' }
}
function Remove-EmiSignInPowerPolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.signin-power-policy.json'
  if (Test-Path -LiteralPath $backup) {
    $previous=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    $current=Get-EmiSignInPowerPolicyState
    # Preserve a different policy applied subsequently by an administrator or GPO.
    if ($current.present -and $current.kind -eq 'DWord' -and $current.value -eq 0) { Set-EmiSignInPowerPolicyState $previous }
    Remove-Item -LiteralPath $backup -Force
  }
}
