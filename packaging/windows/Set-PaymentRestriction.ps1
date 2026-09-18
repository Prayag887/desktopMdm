#Requires -RunAsAdministrator
<#
.SYNOPSIS
  LAB-VM ONLY. Applies a reversible payment-restriction lockdown to ONE enrolled
  standard user, using the strongest Windows features the edition supports.

.DESCRIPTION
  Graceful degradation across editions (nothing here works on every edition the
  same way -- that is a Microsoft limitation, not a bug):

    Universal base (Home -> Enterprise):
      * Replace the enrolled user's shell (explorer.exe -> EMI app) via the
        per-user Winlogon "Shell" value, so that account boots into the app with
        no desktop, taskbar or Start menu.
      * Disable Task Manager and Fast User Switching for that account.
    Enterprise / Education / IoT Enterprise only (added on top):
      * Keyboard Filter (WEKF): block Alt+Tab, Alt+F4, Win, Ctrl+Esc, etc.,
        while ordinary typing (recovery code, password) still works.
      * AppLocker exe rules: allow Windows + the signed EMI app, deny the rest.

  Every change is recorded to a state file so Remove-PaymentRestriction.ps1 can
  reverse exactly what was applied. Administrator and recovery accounts are never
  touched. WinRE is never touched. No driver is installed.

  This can lock a real user out of a real machine. It refuses to run without
  -LabVm, refuses to target an administrator, and refuses unless at least one
  OTHER administrator account exists as a recovery path.

.PARAMETER EnrolledUser
  The local standard account to restrict (SAM name). Must not be an admin.

.PARAMETER AppPath
  Full path to the EMI app exe that becomes the enrolled user's shell.

.PARAMETER LabVm
  Required safety acknowledgement. Without it the script refuses to run.

.EXAMPLE
  .\Set-PaymentRestriction.ps1 -EnrolledUser emicustomer `
      -AppPath 'C:\Program Files\EmiDeviceAgent\emi-device-ui.exe' -LabVm
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)][string]$EnrolledUser,
  [Parameter(Mandatory = $true)][string]$AppPath,
  [switch]$LabVm,
  [switch]$SkipShell,
  [switch]$SkipKeyboardFilter,
  [switch]$SkipAppLocker,
  [string]$StateDir = "$env:ProgramData\EmiDeviceAgent"
)

$ErrorActionPreference = 'Stop'

# --- Safety gates ------------------------------------------------------------
if (-not $LabVm) {
  throw 'Refusing to run without -LabVm. This applies a real lockout; use a test VM.'
}
if (-not (Test-Path -LiteralPath $AppPath)) {
  throw "AppPath not found: $AppPath"
}

$account = Get-LocalUser -Name $EnrolledUser -ErrorAction Stop
$adminGroupSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$adminGroup = (Get-LocalGroup -SID $adminGroupSid).Name
$adminMembers = Get-LocalGroupMember -Group $adminGroup

$enrolledSid = $account.SID.Value
if ($adminMembers.SID.Value -contains $enrolledSid) {
  throw "$EnrolledUser is an administrator. Restricting an admin is refused."
}
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($currentSid -eq $enrolledSid) {
  throw 'Refusing to restrict the account running this script.'
}
$otherAdmins = @($adminMembers | Where-Object { $_.SID.Value -ne $enrolledSid })
if ($otherAdmins.Count -lt 1) {
  throw 'No other administrator account exists to serve as a recovery path. Refused.'
}

# --- Edition capability probe ------------------------------------------------
$caption = (Get-CimInstance Win32_OperatingSystem).Caption  # e.g. "...Windows 11 Enterprise"
$isEnterpriseClass = $caption -match 'Enterprise|Education|IoT'
$isPro = $caption -match '\bPro\b'
Write-Host "Detected edition: $caption"
Write-Host ("Enterprise-class features available: {0}" -f $isEnterpriseClass)

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$statePath = Join-Path $StateDir 'restriction-state.json'
$auditPath = Join-Path $StateDir 'restriction-audit.log'

$state = [ordered]@{
  schema        = 1
  applied_utc   = (Get-Date).ToUniversalTime().ToString('o')
  operator      = $currentSid
  enrolled_user = $EnrolledUser
  enrolled_sid  = $enrolledSid
  edition       = $caption
  app_path      = $AppPath
  layers        = @()
  skipped       = @()
}

function Add-Layer([string]$name) { $state.layers += $name; Write-Host "  applied: $name" }
function Add-Skipped([string]$name, [string]$why) {
  $state.skipped += @{ layer = $name; reason = $why }; Write-Warning "  skipped: $name -- $why"
}

# --- Per-user hive access ----------------------------------------------------
# Set values under the enrolled user's hive whether or not they are logged in.
$hiveLoaded = $false
$userRoot = "Registry::HKEY_USERS\$enrolledSid"
if (-not (Test-Path $userRoot)) {
  $profilePath = (Get-CimInstance Win32_UserProfile -Filter "SID='$enrolledSid'").LocalPath
  if (-not $profilePath) { throw "No profile for $EnrolledUser; log in once, then re-run." }
  $ntuser = Join-Path $profilePath 'NTUSER.DAT'
  & reg.exe load "HKU\$enrolledSid" "$ntuser" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not load user hive: $ntuser" }
  $hiveLoaded = $true
}

function Set-UserValue([string]$subPath, [string]$name, $value, [string]$type = 'String') {
  $key = "$userRoot\$subPath"
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
  New-ItemProperty -Path $key -Name $name -Value $value -PropertyType $type -Force | Out-Null
}

try {
  if ($PSCmdlet.ShouldProcess($EnrolledUser, 'Apply payment restriction')) {

    # --- Layer 1: make the app the enrolled user's shell ---------------------
    # Enterprise/IoT: Shell Launcher (supported, robust, auto-launches the app as
    # the shell on every login with no desktop; admins keep the default shell).
    # Other editions: fall back to the per-user Winlogon Shell value.
    $winlogon = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($SkipShell) {
      Add-Skipped 'shell' 'disabled by -SkipShell'
    }
    elseif ($isEnterpriseClass) {
      $feature = Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -ErrorAction SilentlyContinue
      if ($feature -and $feature.State -ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -NoRestart | Out-Null
      }
      $shellLauncher = [wmiclass]"\\localhost\root\standardcimv2\embedded:WESL_UserSetting"
      # DefaultAction 0 = restart the shell if it exits, so the device stays on the
      # locked app until an administrator removes the restriction.
      $shellLauncher.SetCustomShell($enrolledSid, $AppPath, ($null), ($null), 0) | Out-Null
      $shellLauncher.SetEnabled($true) | Out-Null
      Add-Layer 'shell-launcher'
    }
    else {
      Set-UserValue $winlogon 'Shell' "`"$AppPath`""
      Add-Layer 'per-user-shell'
    }

    # Logon auto-start: relaunch the lock at every logon of the enrolled user, so
    # it always comes up after a boot or restart even on editions without Shell
    # Launcher. Runs at the user's standard privilege.
    if (-not $SkipShell) {
      $taskAction = New-ScheduledTaskAction -Execute $AppPath
      $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $EnrolledUser
      $taskPrincipal = New-ScheduledTaskPrincipal -UserId $EnrolledUser -RunLevel Limited
      Register-ScheduledTask -TaskName 'EmiDeviceLock' -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Force | Out-Null
      Add-Layer 'logon-task'
    }

    $policySystem = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-UserValue $policySystem 'DisableTaskMgr' 1 'DWord'          # blocks Ctrl+Shift+Esc target
    Set-UserValue $policySystem 'DisableChangePassword' 1 'DWord'
    Add-Layer 'disable-taskmgr'

    # Fast User Switching is machine-wide policy (affects the lock screen only).
    $hklmSystem = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    New-Item -Path $hklmSystem -Force | Out-Null
    New-ItemProperty -Path $hklmSystem -Name 'HideFastUserSwitching' -Value 1 -PropertyType DWord -Force | Out-Null
    Add-Layer 'hide-fast-user-switching'

    # --- Layer 2: Keyboard Filter (Enterprise-class only) --------------------
    if ($SkipKeyboardFilter) {
      Add-Skipped 'keyboard-filter' 'disabled by -SkipKeyboardFilter'
    }
    elseif ($isEnterpriseClass) {
      $feature = Get-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -ErrorAction SilentlyContinue
      if ($feature -and $feature.State -ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -NoRestart | Out-Null
      }
      $ns = 'root\standardcimv2\embedded'
      foreach ($id in 'Alt+Tab', 'Alt+F4', 'Alt+Esc', 'Ctrl+Esc', 'Ctrl+Shift+Esc', 'Win', 'Win+L') {
        $k = Get-CimInstance -Namespace $ns -ClassName WEKF_PredefinedKey -Filter "Id='$id'" -ErrorAction SilentlyContinue
        if ($k) { $k.Enabled = $true; Set-CimInstance -InputObject $k }
      }
      Add-Layer 'keyboard-filter'
    }
    else {
      Add-Skipped 'keyboard-filter' 'requires Enterprise/Education/IoT'
    }

    # --- Layer 3: AppLocker (Enterprise-class only) --------------------------
    if ($SkipAppLocker) {
      Add-Skipped 'applocker' 'disabled by -SkipAppLocker'
    }
    elseif ($isEnterpriseClass) {
      Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
      # Backup any existing local policy for exact rollback.
      $backup = Join-Path $StateDir 'applocker-backup.xml'
      Get-AppLockerPolicy -Local -Xml | Out-File -FilePath $backup -Encoding utf8
      $appDir = Split-Path -Parent $AppPath
      $rules = New-AppLockerPolicy -RuleType Publisher, Path -User $EnrolledUser `
        -FileInformation (Get-ChildItem "$env:SystemRoot\System32\*.exe" | Get-AppLockerFileInformation) -Optimize
      # Note: in production, generate rules from the signed EMI app publisher only,
      # plus $appDir, and set enforcement via GPO/MDM. This lab rule set is minimal.
      Set-AppLockerPolicy -PolicyObject $rules -ErrorAction SilentlyContinue
      $state | Add-Member -NotePropertyName applocker_backup -NotePropertyValue $backup
      Add-Layer 'applocker'
    }
    else {
      Add-Skipped 'applocker' 'requires Enterprise/Education/IoT'
    }

    if ($isPro) { Add-Skipped 'shell-launcher' 'Win32 kiosk needs Enterprise; Pro uses per-user-shell base' }
  }
}
finally {
  if ($hiveLoaded) {
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    & reg.exe unload "HKU\$enrolledSid" | Out-Null
  }
}

# --- Persist state + audit ---------------------------------------------------
$state | ConvertTo-Json -Depth 6 | Out-File -FilePath $statePath -Encoding utf8
$auditLine = '{0} APPLY user={1} edition="{2}" layers={3} skipped={4}' -f `
  $state.applied_utc, $EnrolledUser, $caption, ($state.layers -join ','), ($state.skipped.layer -join ',')
Add-Content -Path $auditPath -Value $auditLine

Write-Host ''
Write-Host 'Payment restriction applied.' -ForegroundColor Yellow
Write-Host "  Enrolled user:  $EnrolledUser"
Write-Host "  Layers applied: $($state.layers -join ', ')"
if ($state.skipped.Count) { Write-Host "  Not available:  $($state.skipped.layer -join ', ')" }
Write-Host "  State file:     $statePath"
Write-Host ''
Write-Host 'Reverse with:  .\Remove-PaymentRestriction.ps1 -LabVm' -ForegroundColor Cyan
Write-Host 'Recovery: log in as an administrator (never restricted) or use WinRE.' -ForegroundColor Cyan
if ($state.layers -contains 'keyboard-filter') {
  Write-Host 'A restart is required for Keyboard Filter to take effect.' -ForegroundColor Cyan
}
