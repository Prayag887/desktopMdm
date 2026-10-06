#Requires -Version 5.1
# Recovery page visibility policy; preserve the pre-install value across upgrades.
function Get-EmiRecoveryPagePolicyState {
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')
    try {
      if ($key -and $key.GetValueNames() -contains 'SettingsPageVisibility') {
        return [pscustomobject]@{present=$true;kind=$key.GetValueKind('SettingsPageVisibility').ToString();value=$key.GetValue('SettingsPageVisibility',$null,'DoNotExpandEnvironmentNames')}
      }
      [pscustomobject]@{present=$false;kind='DWord';value=0}
    } finally { if ($key) { $key.Dispose() } }
  } finally { $root.Dispose() }
}
function Set-EmiRecoveryPagePolicyState($State) {
  if ($null -eq $State -or $State.present -isnot [bool] -or $State.kind -notin @('DWord','QWord','Binary','MultiString','String','ExpandString','None')) { throw 'Invalid Settings page policy backup' }
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')
    try {
      if ($State.present) {
        $value=switch ($State.kind) {
          DWord { [int]$State.value }; QWord { [long]$State.value }
          None { ,[byte[]]$State.value }; Binary { ,[byte[]]$State.value }; MultiString { ,[string[]]$State.value }
          String { [string]$State.value }; ExpandString { [string]$State.value }
          default { throw 'Unsupported previous Settings page policy value type' }
        }
        $key.SetValue('SettingsPageVisibility',$value,[Microsoft.Win32.RegistryValueKind]$State.kind)
      } else { $key.DeleteValue('SettingsPageVisibility',$false) }
    } finally { $key.Dispose() }
  } finally { $root.Dispose() }
}
function Get-EmiRecoveryHiddenValue($State) {
  if (-not $State.present -or [string]::IsNullOrWhiteSpace([string]$State.value)) { return 'hide:recovery' }
  if ($State.kind -ne 'String') { throw 'SettingsPageVisibility must be a string' }
  $value=[string]$State.value
  if ($value -match '^hide:(.*)$') {
    $pages=@($Matches[1].Split(';') | Where-Object { $_ })
    if ($pages -notcontains 'recovery') { $pages+='recovery' }
    return 'hide:'+($pages -join ';')
  }
  if ($value -match '^showonly:(.*)$') {
    $pages=@($Matches[1].Split(';') | Where-Object { $_ -and $_ -ne 'recovery' })
    return 'showonly:'+($pages -join ';')
  }
  throw 'Unrecognized SettingsPageVisibility policy; existing restrictions were preserved'
}
function Enable-EmiRecoveryPagePolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.recovery-page-policy.json'
  $current=Get-EmiRecoveryPagePolicyState
  $applied=Get-EmiRecoveryHiddenValue $current
  $previous=$current
  if (Test-Path -LiteralPath $backup) {
    $saved=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    if ($null -eq $saved.previous -or $saved.previous.present -isnot [bool] -or $saved.applied -isnot [string]) { throw 'Invalid Settings page policy backup' }
    $previous=$saved.previous
  }
  $temporary=Join-Path $DataDir ('.tmp-recovery-page-policy-'+[Guid]::NewGuid().ToString('N'))
  $replaced=$temporary+'.previous'
  try {
    [IO.File]::WriteAllText($temporary,'')
    Set-EmiAcl $temporary -Private $true
    [IO.File]::WriteAllText($temporary,(@{previous=$previous;applied=$applied} | ConvertTo-Json -Depth 5 -Compress))
    if (Test-Path -LiteralPath $backup) { [IO.File]::Replace($temporary,$backup,$replaced) }
    else { [IO.File]::Move($temporary,$backup) }
  } finally { Remove-Item -LiteralPath $temporary,$replaced -Force -ErrorAction SilentlyContinue }
  Set-EmiRecoveryPagePolicyState ([pscustomobject]@{present=$true;kind='String';value=$applied})
  $actual=Get-EmiRecoveryPagePolicyState
  if (-not $actual.present -or $actual.kind -ne 'String' -or $actual.value -ne $applied) { throw 'Recovery page visibility verification failed' }
}
function Remove-EmiRecoveryPagePolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.recovery-page-policy.json'
  if (Test-Path -LiteralPath $backup) {
    $saved=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    $current=Get-EmiRecoveryPagePolicyState
    if ($current.present -and $current.kind -eq 'String' -and $current.value -eq $saved.applied) { Set-EmiRecoveryPagePolicyState $saved.previous }
    Remove-Item -LiteralPath $backup -Force
  }
}
