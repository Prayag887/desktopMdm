#Requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$AgentPath)
$ErrorActionPreference = 'Stop'
$AgentPath = (Resolve-Path -LiteralPath $AgentPath).Path
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Set-EmiStateAcl.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('emi-acl-' + [guid]::NewGuid())
$previousProgramData = $env:PROGRAMDATA
try {
  $directory = Join-Path $testRoot 'EmiDeviceAgent'
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  Set-EmiAcl $directory
  $mailbox = Join-Path $directory 'recovery-request.json'
  [IO.File]::WriteAllText($mailbox, '')
  Set-EmiAcl $mailbox -Mailbox $true
  $env:PROGRAMDATA = $testRoot
  & $AgentPath init
  if ($LASTEXITCODE -ne 0) { throw 'agent initialization failed' }
  & $AgentPath init
  if ($LASTEXITCODE -ne 0) { throw 'atomic config replacement failed' }
  $configRules = (Get-Acl (Join-Path $directory 'config.json')).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  foreach ($rule in $configRules) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin 'S-1-5-18','S-1-5-32-544') { throw 'Private config exposed to an unexpected principal' }
  }
  $key = (Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'recovery-public-key.hex') -Raw).Trim()
  & $AgentPath trust-recovery-key --public-key-hex $key
  if ($LASTEXITCODE -ne 0) { throw 'recovery key provisioning failed' }
  $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
  foreach ($name in 'recovery-state.json', 'ui-config.json') {
    $rules = (Get-Acl (Join-Path $directory $name)).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $readable = $false
    foreach ($rule in $rules | Where-Object { $_.IdentityReference -eq $users -and $_.AccessControlType -eq 'Allow' }) {
      $dangerous = [Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership'
      if ($rule.FileSystemRights -band $dangerous) { throw "$name is writable by standard users" }
      $readable = [bool]($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)
    }
    if (-not $readable) { throw "$name is not readable by the UI" }
  }
  $mailboxRules = (Get-Acl $mailbox).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  $userRule = @($mailboxRules | Where-Object { $_.IdentityReference -eq $users -and $_.AccessControlType -eq 'Allow' })
  if ($userRule.Count -ne 1 -or -not ($userRule[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData)) { throw 'Mailbox not writable' }
  if ($userRule[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]'Delete,ChangePermissions,TakeOwnership') { throw 'Mailbox replacement rights exposed' }
  Write-Output 'Config privacy, atomic replacement, recovery-state read-only access, and mailbox rights verified.'
} finally {
  $env:PROGRAMDATA = $previousProgramData
  if (Test-Path $testRoot) { Remove-Item -LiteralPath $testRoot -Force -Recurse }
}
