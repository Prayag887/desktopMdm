#Requires -Version 5.1
# Local accounts only. Never delete accounts or change their passwords.
function Set-EmiStandardUser([string]$DailyUser, [string]$RecoveryAdministrator, [string]$CurrentUserSid) {
  $users = @(Get-LocalUser -Name $DailyUser -ErrorAction Stop)
  $owners = @(Get-LocalUser -Name $RecoveryAdministrator -ErrorAction Stop)
  if ($users.Count -ne 1 -or $owners.Count -ne 1 -or $users[0].Name -ne $DailyUser -or $owners[0].Name -ne $RecoveryAdministrator) { throw 'Specify exact, distinct local account names; wildcard matches are not supported.' }
  $user = $users[0]
  $owner = $owners[0]
  if (-not $user.Enabled -or -not $owner.Enabled) { throw 'Both named local accounts must be enabled.' }
  if ($user.SID.Value -eq $owner.SID.Value) { throw 'Daily user and owner administrator must be separate accounts.' }
  if ($user.SID.Value -eq $CurrentUserSid) { throw 'Run hardening from the separate owner administrator account, not the daily user.' }
  if ($user.SID.Value -match '-500$') { throw 'The built-in Administrator cannot be the daily user.' }
  $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
  $admins = @(Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop)
  if ($admins.SID.Value -notcontains $owner.SID.Value) { throw 'The owner recovery account must already belong to Administrators.' }
  $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545' -ErrorAction Stop
  # Resolve every membership before making any change. Fail on unreadable groups.
  $removals = @()
  foreach ($sid in @('S-1-5-32-544','S-1-5-32-547','S-1-5-32-550','S-1-5-32-551','S-1-5-32-556','S-1-5-32-578')) {
    $group = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
    if ($group -and @((Get-LocalGroupMember -Group $group -ErrorAction Stop) | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count -gt 0) { $removals += $group }
  }
  $wasUser = @((Get-LocalGroupMember -Group $usersGroup -ErrorAction Stop) | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count -gt 0
  $removed = @()
  $addedUser = $false
  try {
    if (-not $wasUser) {
      Add-LocalGroupMember -Group $usersGroup -Member $user -ErrorAction Stop
      $addedUser = $true
    }
    foreach ($group in $removals) {
      # Keep the owner account enabled and administrative throughout provisioning.
      $ownerNow = Get-LocalUser -Name $RecoveryAdministrator -ErrorAction Stop
      if (-not $ownerNow.Enabled -or @((Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop) | Where-Object { $_.SID.Value -eq $owner.SID.Value }).Count -ne 1) { throw 'Owner administrator access changed; hardening stopped.' }
      Remove-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
      $removed += $group
    }
    foreach ($group in $removals) {
      if (@((Get-LocalGroupMember -Group $group -ErrorAction Stop) | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count -gt 0) { throw 'Privileged membership removal did not persist.' }
    }
    if (@((Get-LocalGroupMember -Group $usersGroup -ErrorAction Stop) | Where-Object { $_.SID.Value -eq $user.SID.Value }).Count -ne 1) { throw 'Standard Users membership did not persist.' }
  } catch {
    $failure = $_
    $rollbackFailed = $false
    foreach ($group in $removed) {
      try { Add-LocalGroupMember -Group $group -Member $user -ErrorAction Stop } catch { $rollbackFailed = $true }
    }
    if ($addedUser) {
      try { Remove-LocalGroupMember -Group $usersGroup -Member $user -ErrorAction Stop } catch { $rollbackFailed = $true }
    }
    if ($rollbackFailed) { throw 'Account hardening failed and membership rollback was incomplete. Use the preserved owner administrator to inspect memberships.' }
    throw $failure
  }
  [pscustomobject]@{ dailyUser=$user.Name; ownerAdministrator=$owner.Name; removedGroups=@($removed | ForEach-Object { $_.Name }); signOutRequired=$true }
}
