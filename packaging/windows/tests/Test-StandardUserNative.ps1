#Requires -Version 5.1
#Requires -RunAsAdministrator
# Disposable Windows CI runner: create and remove only random test-owned accounts.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'StandardUser-Policy.ps1')
$suffix=[Guid]::NewGuid().ToString('N').Substring(0,10)
$dailyName='EmiTestD'+$suffix
$ownerName='EmiTestO'+$suffix
$password='Emi!'+[Guid]::NewGuid().ToString('N')+'9aA!'
$secure=ConvertTo-SecureString $password -AsPlainText -Force
$created=@()
function Assert($condition,$message) { if (-not $condition) { throw $message } }
try {
  foreach ($name in @($dailyName,$ownerName)) {
    $account=New-LocalUser -Name $name -Password $secure -Description 'Temporary EMI hardening CI test' -ErrorAction Stop
    $created+=$account
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $account -ErrorAction Stop
  }
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $context=[DirectoryServices.AccountManagement.PrincipalContext]::new([DirectoryServices.AccountManagement.ContextType]::Machine,$env:COMPUTERNAME)
  try { Assert ($context.ValidateCredentials($ownerName,$password)) 'Native owner credential verification failed' }
  finally { $context.Dispose(); $password=$null }
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try { $result=Set-EmiStandardUser $dailyName $ownerName $identity.User.Value }
  finally { $identity.Dispose() }
  $adminSids=@((Get-LocalGroupMember -SID 'S-1-5-32-544').SID.Value)
  Assert ($adminSids -contains $created[1].SID.Value) 'Real owner administrator membership lost'
  Assert ($adminSids -notcontains $created[0].SID.Value) 'Real daily account remains an administrator'
  $userSids=@((Get-LocalGroupMember -SID 'S-1-5-32-545').SID.Value)
  Assert ($userSids -contains $created[0].SID.Value) 'Real daily account lacks Users membership'
  Assert $result.signOutRequired 'Token refresh requirement missing'
  Write-Output 'Native Windows local credentials and account membership hardening passed.'
} finally {
  foreach ($account in $created) { Remove-LocalUser -SID $account.SID -ErrorAction Stop }
}
