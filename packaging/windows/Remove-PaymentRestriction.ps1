#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Reverses Set-PaymentRestriction.ps1 exactly, using the recorded state file.

.DESCRIPTION
  Reads restriction-state.json and undoes each applied layer:
    * per-user-shell           -> restore Shell = explorer.exe
    * disable-taskmgr          -> remove DisableTaskMgr / DisableChangePassword
    * hide-fast-user-switching -> remove HideFastUserSwitching
    * keyboard-filter          -> disable WEKF predefined keys
    * applocker                -> restore the backed-up local policy

  Safe to run repeatedly. If the state file is missing it restores the shell to
  explorer.exe for the named user as a best-effort recovery.

.PARAMETER LabVm
  Required safety acknowledgement.

.PARAMETER EnrolledUser
  Optional. Only needed for best-effort recovery when the state file is absent.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$LabVm,
  [string]$EnrolledUser,
  [string]$StateDir = "$env:ProgramData\EmiDeviceAgent"
)

$ErrorActionPreference = 'Stop'
if (-not $LabVm) { throw 'Refusing to run without -LabVm.' }

$statePath = Join-Path $StateDir 'restriction-state.json'
$auditPath = Join-Path $StateDir 'restriction-audit.log'

$state = $null
if (Test-Path $statePath) {
  $state = Get-Content $statePath -Raw | ConvertFrom-Json
  $EnrolledUser = $state.enrolled_user
}
elseif (-not $EnrolledUser) {
  throw "No state file at $statePath. Pass -EnrolledUser for best-effort recovery."
}

$sid = (Get-LocalUser -Name $EnrolledUser).SID.Value
$userRoot = "Registry::HKEY_USERS\$sid"
$hiveLoaded = $false
if (-not (Test-Path $userRoot)) {
  $profilePath = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath
  $ntuser = Join-Path $profilePath 'NTUSER.DAT'
  & reg.exe load "HKU\$sid" "$ntuser" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not load user hive: $ntuser" }
  $hiveLoaded = $true
}

function Remove-UserValue([string]$subPath, [string]$name) {
  $key = "$userRoot\$subPath"
  if (Test-Path $key) { Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue }
}

$layers = if ($state) { $state.layers } else { @('per-user-shell') }

try {
  if ($PSCmdlet.ShouldProcess($EnrolledUser, 'Remove payment restriction')) {
    $winlogon = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $policySystem = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    if ($layers -contains 'shell-launcher') {
      # Disable Shell Launcher and drop the enrolled user's custom shell so the
      # account returns to the default Explorer desktop.
      try {
        $shellLauncher = [wmiclass]"\\localhost\root\standardcimv2\embedded:WESL_UserSetting"
        $shellLauncher.RemoveCustomShell($sid) | Out-Null
        $shellLauncher.SetEnabled($false) | Out-Null
        Write-Host '  restored: Shell Launcher disabled'
      }
      catch { Write-Warning "  Shell Launcher teardown failed: $_" }
    }
    if ($layers -contains 'per-user-shell') {
      # Restore the standard Explorer shell for this account.
      $key = "$userRoot\$winlogon"
      if (Test-Path $key) { New-ItemProperty -Path $key -Name 'Shell' -Value 'explorer.exe' -PropertyType String -Force | Out-Null }
      Write-Host '  restored: per-user-shell -> explorer.exe'
    }
    if ($layers -contains 'disable-taskmgr') {
      Remove-UserValue $policySystem 'DisableTaskMgr'
      Remove-UserValue $policySystem 'DisableChangePassword'
      Write-Host '  restored: Task Manager'
    }
    if ($layers -contains 'hide-fast-user-switching') {
      Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'HideFastUserSwitching' -ErrorAction SilentlyContinue
      Write-Host '  restored: Fast User Switching'
    }
    if ($layers -contains 'keyboard-filter') {
      $ns = 'root\standardcimv2\embedded'
      foreach ($id in 'Alt+Tab', 'Alt+F4', 'Alt+Esc', 'Ctrl+Esc', 'Ctrl+Shift+Esc', 'Win', 'Win+L') {
        $k = Get-CimInstance -Namespace $ns -ClassName WEKF_PredefinedKey -Filter "Id='$id'" -ErrorAction SilentlyContinue
        if ($k) { $k.Enabled = $false; Set-CimInstance -InputObject $k }
      }
      Write-Host '  restored: Keyboard Filter (keys unblocked)'
    }
    if ($layers -contains 'applocker') {
      $backup = if ($state) { $state.applocker_backup } else { Join-Path $StateDir 'applocker-backup.xml' }
      if ($backup -and (Test-Path $backup)) {
        Set-AppLockerPolicy -XmlPolicy $backup -ErrorAction SilentlyContinue
        Write-Host '  restored: AppLocker policy from backup'
      }
    }
  }
}
finally {
  if ($hiveLoaded) {
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    & reg.exe unload "HKU\$sid" | Out-Null
  }
}

if (Test-Path $statePath) { Remove-Item $statePath -Force }
$line = '{0} REMOVE user={1}' -f (Get-Date).ToUniversalTime().ToString('o'), $EnrolledUser
Add-Content -Path $auditPath -Value $line

Write-Host ''
Write-Host "Payment restriction removed for $EnrolledUser." -ForegroundColor Green
Write-Host 'Sign the user out and back in (or reboot) for the shell change to apply.' -ForegroundColor Cyan
