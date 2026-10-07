#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'StandardUser-Policy.ps1')
function Assert($condition, $message) { if (-not $condition) { throw $message } }
function Reset-Fixture {
  $script:daily = [pscustomobject]@{ Name='Daily'; Enabled=$true; SID=[pscustomobject]@{ Value='S-1-5-21-1-1001' } }
  $script:owner = [pscustomobject]@{ Name='Owner'; Enabled=$true; SID=[pscustomobject]@{ Value='S-1-5-21-1-1002' } }
  $script:groups = @{}
  foreach ($sid in @('S-1-5-32-544','S-1-5-32-545','S-1-5-32-551','S-1-5-32-555','S-1-5-32-580')) { $script:groups[$sid]=[pscustomobject]@{Name=$sid; SID=$sid} }
  $script:members = @{ 'S-1-5-32-544'=@($script:daily,$script:owner); 'S-1-5-32-545'=@(); 'S-1-5-32-551'=@($script:daily); 'S-1-5-32-555'=@($script:daily); 'S-1-5-32-580'=@($script:daily) }
  $script:failGroup = ''
  $script:changes = 0
}
function Get-LocalUser($Name) { if ($Name -eq 'Daily') { return $script:daily }; if ($Name -eq 'Owner') { return $script:owner }; throw 'Unknown local user' }
function Get-LocalGroup($SID) { return $script:groups[$SID] }
function Get-LocalGroupMember($Group) { return $script:members[$Group.SID] }
function Add-LocalGroupMember($Group, $Member) { $script:members[$Group.SID] += $Member; $script:changes++ }
function Remove-LocalGroupMember($Group, $Member) {
  if ($Group.SID -eq $script:failGroup) { throw 'Simulated removal failure' }
  $script:members[$Group.SID] = @($script:members[$Group.SID] | Where-Object { $_.SID.Value -ne $Member.SID.Value })
  $script:changes++
}
Reset-Fixture
$result = Set-EmiStandardUser Daily Owner $script:owner.SID.Value
Assert ($result.removedGroups.Count -eq 4) 'Privileged/remote access groups were not removed'
Assert (@($script:members['S-1-5-32-544']).Count -eq 1 -and $script:members['S-1-5-32-544'][0].Name -eq 'Owner') 'Owner admin was not preserved'
Assert ($script:members['S-1-5-32-545'][0].Name -eq 'Daily') 'Standard Users membership missing'
$before = $script:changes
$null = Set-EmiStandardUser Daily Owner $script:owner.SID.Value
Assert ($script:changes -eq $before) 'Repeated application is not idempotent'
foreach ($scenario in @('SameAccount','DisabledOwner','MissingOwnerAdmin','CurrentDaily','BuiltInAdmin')) {
  Reset-Fixture
  $ownerName='Owner'; $current=$script:owner.SID.Value
  switch ($scenario) {
    SameAccount { $ownerName='Daily' }
    DisabledOwner { $script:owner.Enabled=$false }
    MissingOwnerAdmin { $script:members['S-1-5-32-544']=@($script:daily) }
    CurrentDaily { $current=$script:daily.SID.Value }
    BuiltInAdmin { $script:daily.SID.Value='S-1-5-21-1-500' }
  }
  $rejected=$false
  try { $null=Set-EmiStandardUser Daily $ownerName $current } catch { $rejected=$true }
  Assert $rejected "Unsafe scenario accepted: $scenario"
  Assert ($script:changes -eq 0) "Unsafe scenario changed memberships: $scenario"
}
Reset-Fixture
$script:failGroup='S-1-5-32-551'
$failed=$false
try { $null=Set-EmiStandardUser Daily Owner $script:owner.SID.Value } catch { $failed=$true }
Assert $failed 'Removal failure was swallowed'
Assert (@($script:members['S-1-5-32-544'] | Where-Object { $_.Name -eq 'Daily' }).Count -eq 1) 'Rollback did not restore daily admin membership'
Assert (@($script:members['S-1-5-32-545']).Count -eq 0) 'Rollback did not restore original Users membership'
Write-Output 'Standard account hardening: owner preservation, unsafe-account rejection, idempotence and partial-failure rollback passed.'
