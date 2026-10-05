#Requires -RunAsAdministrator
# Real standard-user and SYSTEM access probes, confined to a disposable test directory.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Protection-Acl.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Set-EmiStateAcl.ps1')
$id=[Guid]::NewGuid().ToString('N').Substring(0,8)
$name='EmiAcl'+$id
$root=Join-Path $env:ProgramData ('EmiAclTest-'+$id)
$task='EmiAclSystem-'+$id
try {
  New-Item -ItemType Directory $root | Out-Null
  Set-EmiAcl $root
  $program=Join-Path $root 'program'; New-Item -ItemType Directory $program | Out-Null
  $binary=Join-Path $program 'agent.exe'; [IO.File]::WriteAllText($binary,'protected')
  $result=Apply-ProtectionAcl $program
  if (-not $result.verified) { throw 'Apply failed' }
  $sddl=(Get-Acl $binary).Sddl
  Apply-ProtectionAcl $program | Out-Null
  if ((Get-Acl $binary).Sddl -ne $sddl) { throw 'ACL application is not idempotent' }
  $acl=Get-Acl $binary
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Write','Allow'))
  Set-Acl $binary $acl
  if ((Verify-ProtectionAcl $program).verified) { throw 'Tampered ACL was accepted' }
  Repair-ProtectionAcl $program | Out-Null
  $acl=Get-Acl $binary
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
  Set-Acl $binary $acl
  if ((Verify-ProtectionAcl $program).verified) { throw 'Unexpected owner was accepted' }
  Repair-ProtectionAcl $program | Out-Null
  $acl=Get-Acl $program
  $acl.SetAccessRuleProtection($false,$true)
  Set-Acl $program $acl
  if ((Verify-ProtectionAcl $program).verified) { throw 'Unprotected DACL was accepted' }
  Repair-ProtectionAcl $program | Out-Null
  $output=Join-Path $root 'result.json'; [IO.File]::WriteAllText($output,''); Set-EmiAcl $output -Mailbox $true
  $password=ConvertTo-SecureString ('A!a9'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
  New-LocalUser -Name $name -Password $password -AccountNeverExpires | Out-Null
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
  $credential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name",$password)
  $probe=@'
$ErrorActionPreference='Stop'
$p='BINARY'; $r='OUTPUT'; $denied=@()
if ([IO.File]::ReadAllText($p) -ne 'protected') { exit 10 }
foreach($action in @('overwrite','delete','rename','acl')) {
  try {
    switch($action) {
      overwrite { [IO.File]::WriteAllText($p,'bad') }
      delete { Remove-Item -LiteralPath $p -Force }
      rename { Rename-Item -LiteralPath $p -NewName 'bad.exe' }
      acl { $a=Get-Acl $p; $a.SetAccessRuleProtection($false,$true); Set-Acl $p $a }
    }
  } catch { $denied += $action }
}
[IO.File]::WriteAllText($r,($denied | ConvertTo-Json -Compress))
'@
  $probe=$probe.Replace('BINARY',$binary.Replace("'","''")).Replace('OUTPUT',$output.Replace("'","''"))
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
  $child=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -Credential $credential -Wait -PassThru
  if ($child.ExitCode -ne 0) { throw 'Standard user cannot read protected executable or test did not execute' }
  $denied=@(Get-Content $output -Raw | ConvertFrom-Json)
  if ($denied.Count -ne 4 -or [IO.File]::ReadAllText($binary) -ne 'protected') { throw 'Standard user changed protected file' }
  $systemProbe="[IO.File]::WriteAllText('$output',[IO.File]::ReadAllText('$binary'))"
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($systemProbe))
  $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -EncodedCommand $encoded"
  Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
  Start-ScheduledTask $task
  $deadline=[DateTime]::UtcNow.AddSeconds(30)
  while ((Get-Content $output -Raw) -ne 'protected' -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
  if ((Get-Content $output -Raw) -ne 'protected') { throw 'SYSTEM could not access protected resources' }
  Write-Output 'Standard-user delete/replace/rename/ACL denial, SYSTEM access and ACL repair verified.'
} finally {
  Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
