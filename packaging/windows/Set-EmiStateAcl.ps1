#Requires -Version 5.1
# Shared with the Windows ACL integration checks.
function Get-EmiStateAcl([string]$Path, [bool]$Private = $false, [bool]$Mailbox = $false) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not allowed in agent state: $Path" }
  $acl = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $inherit = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', $inherit, 'None', 'Allow'))
  }
  if (-not $Private) {
    $rights = if ($Mailbox) { [Security.AccessControl.FileSystemRights]'Read,Write' } else { [Security.AccessControl.FileSystemRights]'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $rights, $inherit, 'None', 'Allow'))
  }
  return $acl
}

function Set-EmiAcl([string]$Path, [bool]$Private = $false, [bool]$Mailbox = $false) {
  Set-Acl -LiteralPath $Path -AclObject (Get-EmiStateAcl $Path $Private $Mailbox) -ErrorAction Stop
}
function Test-EmiStateAcl([string]$Directory) {
  $failures=@()
  foreach ($item in @(Get-Item -LiteralPath $Directory -Force) + @(Get-ChildItem -LiteralPath $Directory -Force)) {
    # Atomic private writes use unnamed .tmp* files. Never widen their ACLs.
    if ($item.Name -like '.tmp*') { continue }
    if ($item.PSIsContainer -and $item.FullName -ne $Directory) { throw 'Unexpected subdirectory in agent state' }
    $expected=Get-EmiStateAcl $item.FullName ($item.Name -like 'config*' -or $item.Name -in @('maintenance.json','repair-source.json')) ($item.Name -eq 'recovery-request.json')
    $actual=Get-Acl -LiteralPath $item.FullName
    $owner=$actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $valid=$owner -in @('S-1-5-18','S-1-5-32-544')
    $actualRights=@{}; $expectedRights=@{}
    foreach ($rule in $actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne 'Allow') { $valid=$false; continue }
      $sid=$rule.IdentityReference.Value
      $actualRights[$sid]=[int64]$actualRights[$sid] -bor [int64]$rule.FileSystemRights
    }
    foreach ($rule in $expected.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) { $expectedRights[$rule.IdentityReference.Value]=[int64]$rule.FileSystemRights }
    foreach ($sid in @($actualRights.Keys) + @($expectedRights.Keys)) {
      if (-not $actualRights.ContainsKey($sid) -or -not $expectedRights.ContainsKey($sid) -or $actualRights[$sid] -ne $expectedRights[$sid]) { $valid=$false }
    }
    if (-not $valid) { $failures += $item.Name }
  }
  [pscustomobject]@{verified=($failures.Count -eq 0); failures=$failures}
}
function Repair-EmiStateAcl([string]$Directory) {
  Set-EmiAcl $Directory
  foreach ($item in Get-ChildItem -LiteralPath $Directory -Force) {
    if ($item.Name -like '.tmp*') { continue }
    if ($item.PSIsContainer) { throw 'Unexpected subdirectory in agent state' }
    Set-EmiAcl $item.FullName ($item.Name -like 'config*' -or $item.Name -in @('maintenance.json','repair-source.json')) ($item.Name -eq 'recovery-request.json')
  }
  $result=Test-EmiStateAcl $Directory
  if (-not $result.verified) { throw 'State ACL repair verification failed' }
}
