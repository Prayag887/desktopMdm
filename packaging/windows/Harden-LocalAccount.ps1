#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][string]$DailyUser,
  [Parameter(Mandatory=$true)][string]$RecoveryAdministrator
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess -or $env:OS -ne 'Windows_NT') { throw 'Run in 64-bit Windows PowerShell.' }
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if ($computer.PartOfDomain) { throw 'This tool is for local accounts on standalone PCs. Manage domain accounts with organization policy.' }
$uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
if ($uac.EnableLUA -ne 1) { throw 'Enable UAC and reboot before account hardening.' }
if ($PSCmdlet.ShouldProcess($DailyUser, 'Remove privileged local group memberships and retain the separate owner administrator')) {
  # Verify actual owner credentials before removing the daily user's admin rights.
  $credential = Get-Credential -UserName "$env:COMPUTERNAME\$RecoveryAdministrator" -Message 'Verify the separate owner administrator login. Credentials are not saved.'
  if (-not $credential -or $credential.UserName -notin @($RecoveryAdministrator, "$env:COMPUTERNAME\$RecoveryAdministrator", ".\$RecoveryAdministrator")) { throw 'Credentials must belong to the named local owner administrator.' }
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $context = [DirectoryServices.AccountManagement.PrincipalContext]::new([DirectoryServices.AccountManagement.ContextType]::Machine, $env:COMPUTERNAME)
  try {
    if (-not $context.ValidateCredentials($RecoveryAdministrator, $credential.GetNetworkCredential().Password)) { throw 'Owner administrator credentials could not be verified; no memberships changed.' }
  } finally { $context.Dispose(); $credential = $null }
  . (Join-Path $PSScriptRoot 'StandardUser-Policy.ps1')
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $result = Set-EmiStandardUser $DailyUser $RecoveryAdministrator $identity.User.Value }
  finally { $identity.Dispose() }
  $result | ConvertTo-Json -Depth 4
  Write-Warning 'Sign out all sessions of the daily user, then sign in again. Existing processes keep their old access tokens until they exit.'
}
