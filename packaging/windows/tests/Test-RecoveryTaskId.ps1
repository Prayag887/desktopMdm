$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Recovery-TaskId.ps1')
$guid = [Guid]::NewGuid()
foreach ($value in @($guid.ToString('B'), $guid.ToString('D'), (' ' + $guid.ToString('B') + [char]0), $guid)) {
  if ((ConvertTo-EmiRecoveryTaskId $value) -ne $guid.ToString('B')) { throw 'Task ID normalization failed.' }
}
if ((ConvertTo-EmiRecoveryTaskId ($guid.ToByteArray())) -ne $guid.ToString('B')) { throw 'Binary task ID normalization failed.' }
foreach ($value in @('not-a-guid', [Guid]::Empty.ToString('B'))) {
  $failed = $false
  try { ConvertTo-EmiRecoveryTaskId $value | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'Invalid task ID was accepted.' }
}
Write-Host 'Recovery task ID normalization passed.'
