#Requires -RunAsAdministrator
# Disposable GitHub Windows runner only: install, upgrade, rollback, uninstall.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackagePath)
$ErrorActionPreference='Stop'
$install=Join-Path $env:ProgramFiles 'EmiDeviceAgent'
$data=Join-Path $env:ProgramData 'EmiDeviceAgent'
if ((Test-Path $install) -or (Test-Path $data) -or (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue)) { throw 'Installer test requires a clean disposable runner' }
$package=Join-Path $env:RUNNER_TEMP "EMI install test's package"
Copy-Item -LiteralPath $PackagePath -Destination $package -Recurse
. (Join-Path $package 'Explorer-ContextPolicy.ps1')
. (Join-Path $package 'SignIn-PowerPolicy.ps1')
$originalExplorerPolicy=Get-EmiExplorerPolicyState
$originalSignInPowerPolicy=Get-EmiSignInPowerPolicyState
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
try {
  New-NetFirewallRule -DisplayName 'EMI installer test isolation' -Direction Outbound -Program (Join-Path $install 'emi-device-agent.exe') -Action Block | Out-Null
  # Seed only local identity and an unreachable loopback API: no production API calls.
  & (Join-Path $package 'emi-device-agent.exe') init
  if ($LASTEXITCODE -ne 0) { throw 'Test identity initialization failed' }
  $configPath=Join-Path $data 'config.json'
  $config=Get-Content $configPath -Raw | ConvertFrom-Json
  $identity=$config.device_id
  $config.api_base='https://127.0.0.1:9'
  [IO.File]::WriteAllText($configPath,($config | ConvertTo-Json -Depth 8))
  foreach ($attempt in 1,2,3) {
    if ($attempt -eq 1) {
      # Exercise the actual .cmd; NUL answers its final pause on the CI runner.
      $command='""' + (Join-Path $package 'install.cmd') + '" -SkipWingetBootstrap -SkipUiLaunch <NUL"'
      $start=[Diagnostics.ProcessStartInfo]::new()
      $start.FileName=Join-Path $env:SystemRoot 'System32\cmd.exe'
      $start.UseShellExecute=$false
      $start.Arguments='/d /s /c '+$command
      $child=[Diagnostics.Process]::Start($start)
      try { $child.WaitForExit(); $exitCode=$child.ExitCode } finally { $child.Dispose() }
    } elseif ($attempt -eq 3) {
      & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'Provision.ps1') -EnrolledUser InstallerTest -SkipUiLaunch
      $exitCode=$LASTEXITCODE
    } else {
      & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'Start-EmiInstaller.ps1') -SkipWingetBootstrap -SkipUiLaunch
      $exitCode=$LASTEXITCODE
    }
    $powerPolicy=Get-EmiSignInPowerPolicyState
    if (-not $powerPolicy.present -or $powerPolicy.kind -ne 'DWord' -or $powerPolicy.value -ne 0) { throw 'Sign-in power button policy was not disabled' }
    $explorerPolicy=Get-EmiExplorerPolicyState
    if (-not $explorerPolicy.present -or $explorerPolicy.value -ne 1) { throw 'Machine-wide Explorer menus were not disabled' }
    $shell=New-Object -ComObject Shell.Application
    try { if ($shell.IsRestricted('Explorer','NoViewContextMenu') -ne 1) { throw 'Windows shell did not recognize the Explorer policy' } } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    if ($exitCode -ne 0) { throw "Installer attempt $attempt failed" }
    foreach ($name in 'EmiDeviceAgent','EmiDeviceWatchdog') {
      if ((Get-Service $name).Status -ne 'Running') { throw "$name not running after install" }
      $binary=if ($name -eq 'EmiDeviceAgent') { 'emi-device-agent.exe' } else { 'RepairWatchdog.exe' }
      $expected='"'+(Join-Path $install $binary)+'" service'
      $registration=Get-CimInstance Win32_Service -Filter "Name='$name'"
      if ($registration.StartMode -ne 'Auto' -or $registration.StartName -ne 'LocalSystem') { throw "$name will not start as SYSTEM at boot" }
      if ($name -eq 'EmiDeviceWatchdog' -and $registration.DisplayName -ne 'RepairWatchdog') { throw 'Watchdog display name incorrect' }
      if ($registration.PathName -ne $expected) { throw "$name has an incorrectly quoted binary path" }
    }
    $repairSource=Get-Content (Join-Path $data 'repair-source.json') -Raw | ConvertFrom-Json
    $cacheRoot=Join-Path $env:ProgramData 'RepairWatchdog'
    if ([IO.Path]::GetDirectoryName($repairSource.package) -ne $cacheRoot -or -not (Test-Path (Join-Path $repairSource.package 'RepairWatchdog.exe'))) { throw 'Verified repair backup missing after installer' }
    if ((Get-Content $configPath -Raw | ConvertFrom-Json).device_id -ne $identity) { throw 'Reinstall replaced device identity' }
    if (-not (Get-ScheduledTask -TaskName EmiDeviceLockAll)) { throw 'Logon task missing' }
    if ($attempt -eq 1) { Remove-Item -LiteralPath (Join-Path $repairSource.package 'emi-device-ui.exe') -Force }
  }
  # Restart only the monitor to force its initial integrity check after deletion.
  Stop-Service EmiDeviceWatchdog
  Stop-Service EmiDeviceAgent
  $missing=Join-Path $install 'emi-device-ui.exe'
  Remove-Item -LiteralPath $missing -Force
  Start-Service EmiDeviceWatchdog
  $deadline=[DateTime]::UtcNow.AddMinutes(4)
  do {
    Start-Sleep -Seconds 3
    $recovered=(Test-Path $missing) -and ((Get-Service EmiDeviceAgent).Status -eq 'Running') -and ((Get-Service EmiDeviceWatchdog).Status -eq 'Running')
  } until ($recovered -or [DateTime]::UtcNow -ge $deadline)
  if (-not $recovered) { throw 'Watchdog did not restore deleted installation file' }
  if ((Get-FileHash $missing).Hash -ne (Get-FileHash (Join-Path $package 'emi-device-ui.exe')).Hash) { throw 'Restored file differs from signed release' }
  Write-Output 'RepairWatchdog backup, automatic SYSTEM boot configuration and actual deleted-file recovery verified.'
  # Force an error after transaction snapshot; existing services/state must recover.
  $unexpected=Join-Path $data 'unexpected-test-directory'
  New-Item -ItemType Directory $unexpected | Out-Null
  & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'install.ps1') -SkipWingetBootstrap -SkipUiLaunch
  if ($LASTEXITCODE -eq 0) { throw 'Unexpected state directory was accepted' }
  foreach ($name in 'EmiDeviceAgent','EmiDeviceWatchdog') {
    if ((Get-Service $name).Status -ne 'Running') { throw "$name not restored by rollback" }
  }
  if ((Get-Content $configPath -Raw | ConvertFrom-Json).device_id -ne $identity) { throw 'Rollback lost device identity' }
  if ((Get-EmiSignInPowerPolicyState).value -ne 0) { throw 'Rollback lost sign-in power policy' }
  if ((Get-EmiExplorerPolicyState).value -ne 1) { throw 'Rollback lost installed Explorer policy' }
  Remove-Item -LiteralPath $unexpected -Recurse -Force
  & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'uninstall.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'Uninstall failed' }
  if ((Get-EmiExplorerPolicyState | ConvertTo-Json -Compress) -ne ($originalExplorerPolicy | ConvertTo-Json -Compress)) { throw 'Uninstall did not restore Explorer policy' }
  if ((Get-EmiSignInPowerPolicyState | ConvertTo-Json -Compress) -ne ($originalSignInPowerPolicy | ConvertTo-Json -Compress)) { throw 'Uninstall did not restore sign-in power policy' }
  if ((Test-Path $install) -or (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) -or (Get-Service EmiDeviceWatchdog -ErrorAction SilentlyContinue) -or (Get-ScheduledTask EmiDeviceLockAll -ErrorAction SilentlyContinue)) { throw 'Uninstall left program/services/task behind' }
  if ((Get-Content $configPath -Raw | ConvertFrom-Json).device_id -ne $identity) { throw 'Uninstall lost recovery data' }
  Write-Output 'Signed install from spaced/apostrophe path, reinstall, failure rollback and uninstall verified.'
} finally {
  if (Test-Path (Join-Path $install 'emi-device-agent.exe')) { & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $package 'uninstall.ps1') }
  Set-EmiExplorerPolicyState $originalExplorerPolicy
  Set-EmiSignInPowerPolicyState $originalSignInPowerPolicy
  Remove-NetFirewallRule -DisplayName 'EMI installer test isolation' -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $package -Recurse -Force -ErrorAction SilentlyContinue
}
