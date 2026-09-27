#Requires -Version 5.1
# Shared with the Windows ACL integration checks.
function Set-EmiAcl([string]$Path, [bool]$Private = $false, [bool]$Mailbox = $false) {
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
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}
