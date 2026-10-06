#Requires -Version 5.1
# Machine-wide Explorer menu policy; preserve the pre-install value across upgrades.
function Get-EmiExplorerPolicyState {
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')
    try {
      if ($key -and $key.GetValueNames() -contains 'NoViewContextMenu') {
        return [pscustomobject]@{present=$true;kind=$key.GetValueKind('NoViewContextMenu').ToString();value=$key.GetValue('NoViewContextMenu',$null,'DoNotExpandEnvironmentNames')}
      }
      [pscustomobject]@{present=$false;kind='DWord';value=0}
    } finally { if ($key) { $key.Dispose() } }
  } finally { $root.Dispose() }
}
function Set-EmiExplorerPolicyState($State) {
  if ($null -eq $State -or $State.present -isnot [bool] -or $State.kind -notin @('DWord','QWord','Binary','MultiString','String','ExpandString','None')) { throw 'Invalid Explorer policy backup' }
  $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
  try {
    $key=$root.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer')
    try {
      if ($State.present) {
        $value=switch ($State.kind) {
          DWord { [int]$State.value }; QWord { [long]$State.value }
          None { ,[byte[]]$State.value }; Binary { ,[byte[]]$State.value }; MultiString { ,[string[]]$State.value }
          String { [string]$State.value }; ExpandString { [string]$State.value }
          default { throw 'Unsupported previous Explorer policy value type' }
        }
        $key.SetValue('NoViewContextMenu',$value,[Microsoft.Win32.RegistryValueKind]$State.kind)
      } else { $key.DeleteValue('NoViewContextMenu',$false) }
    } finally { $key.Dispose() }
  } finally { $root.Dispose() }
}
function Enable-EmiExplorerContextPolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.explorer-policy.json'
  if (-not (Test-Path -LiteralPath $backup)) {
    $previous=Get-EmiExplorerPolicyState
    $temporary=Join-Path $DataDir ('.tmp-explorer-policy-'+[Guid]::NewGuid().ToString('N'))
    try {
      [IO.File]::WriteAllText($temporary,'')
      Set-EmiAcl $temporary -Private $true
      [IO.File]::WriteAllText($temporary,($previous | ConvertTo-Json -Depth 5 -Compress))
      [IO.File]::Move($temporary,$backup)
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  } else {
    $previous=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    if ($null -eq $previous -or $previous.present -isnot [bool]) { throw 'Invalid Explorer policy backup' }
  }
  Set-EmiExplorerPolicyState ([pscustomobject]@{present=$true;kind='DWord';value=1})
  $state=Get-EmiExplorerPolicyState
  if (-not $state.present -or $state.kind -ne 'DWord' -or $state.value -ne 1) { throw 'Explorer context-menu policy verification failed' }
}
function Remove-EmiExplorerContextPolicy([string]$DataDir) {
  $backup=Join-Path $DataDir 'config.explorer-policy.json'
  if (Test-Path -LiteralPath $backup) {
    $previous=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    $current=Get-EmiExplorerPolicyState
    # Preserve a different policy applied subsequently by an administrator or GPO.
    if ($current.present -and $current.kind -eq 'DWord' -and $current.value -eq 1) { Set-EmiExplorerPolicyState $previous }
    Remove-Item -LiteralPath $backup -Force
  }
}
