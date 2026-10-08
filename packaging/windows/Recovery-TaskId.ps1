function ConvertTo-EmiRecoveryTaskId {
  param([Parameter(Mandatory=$true)]$Value)
  $guid = [Guid]::Empty
  if ($Value -is [byte[]] -and $Value.Length -eq 16) {
    $guid = [Guid]::new([byte[]]$Value)
  } elseif (-not [Guid]::TryParse(([string]$Value).Trim().Trim([char]0), [ref]$guid)) {
    throw "Invalid companion task ID (registry type $($Value.GetType().FullName))."
  }
  if ($guid -eq [Guid]::Empty) { throw 'Empty companion task ID.' }
  return $guid.ToString('B')
}
