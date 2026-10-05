#Requires -Version 5.1
# Exact native .NET ACLs, no deny entries. Installation tree only; state uses Set-EmiStateAcl.
function Get-ProtectionAcl([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point rejected: $Path" }
  $acl = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $inherit = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($sid in 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545') {
    $rights = if ($sid -eq 'S-1-5-32-545') { 'ReadAndExecute' } else { 'FullControl' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, $inherit, 'None', 'Allow'))
  }
  return $acl
}
function Get-ProtectionItems([string]$Path) {
  $ancestor = Get-Item -LiteralPath $Path -Force
  while ($ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point ancestor rejected: $($ancestor.FullName)" }
    $parent = Split-Path -Parent $ancestor.FullName
    if (-not $parent -or $parent -eq $ancestor.FullName) { break }
    $ancestor = Get-Item -LiteralPath $parent -Force
  }
  $root = Get-Item -LiteralPath $Path -Force
  if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point rejected: $Path" }
  $root
  if ($root.PSIsContainer) {
    # Walk manually so junctions are rejected before recursion.
    foreach ($child in Get-ChildItem -LiteralPath $Path -Force) { Get-ProtectionItems $child.FullName }
  }
}
function Verify-ProtectionAcl([string]$Path) {
  $failures = @()
  foreach ($item in Get-ProtectionItems $Path) {
    $expected = Get-ProtectionAcl $item.FullName
    $actual = Get-Acl -LiteralPath $item.FullName
    $sections = [Security.AccessControl.AccessControlSections]'Access,Owner'
    if ($actual.GetSecurityDescriptorSddlForm($sections) -ne $expected.GetSecurityDescriptorSddlForm($sections)) { $failures += $item.FullName }
  }
  [pscustomobject]@{ path = $Path; verified = ($failures.Count -eq 0); failures = $failures; strategy = 'SYSTEM/Admin FullControl; Users ReadAndExecute; protected DACL; Admin owner' }
}
function Apply-ProtectionAcl([string]$Path, [string]$BackupPath) {
  $items = @(Get-ProtectionItems $Path) # preflight all reparse points before modifying anything
  if ($BackupPath -and -not (Test-Path -LiteralPath $BackupPath)) {
    $backup = @($items | ForEach-Object { [pscustomobject]@{ path = $_.FullName; sddl = (Get-Acl -LiteralPath $_.FullName).Sddl } })
    [IO.File]::WriteAllText($BackupPath, (ConvertTo-Json -InputObject $backup -Depth 4))
  }
  foreach ($item in $items) { Set-Acl -LiteralPath $item.FullName -AclObject (Get-ProtectionAcl $item.FullName) -ErrorAction Stop }
  $result = Verify-ProtectionAcl $Path
  if (-not $result.verified) { throw "ACL verification failed: $($result.failures -join ', ')" }
  $result
}
function Repair-ProtectionAcl([string]$Path, [string]$BackupPath) { Apply-ProtectionAcl $Path $BackupPath }
