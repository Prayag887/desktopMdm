#Requires -RunAsAdministrator
# Run only in a disposable Windows VM with a signed package already installed.
[CmdletBinding()]
param([switch]$DisposableVm, [switch]$AfterReboot, [string]$InstallDir="$env:ProgramFiles\EmiDeviceAgent")
$ErrorActionPreference='Stop'
if (-not $DisposableVm) { throw 'Explicit -DisposableVm is required: this test deliberately stops/crashes the installed core service' }
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Protection-Integrity.ps1')
$check=Test-ProtectionIntegrity $InstallDir
if (-not $check.verified) { throw 'A trusted signed installation is required' }
foreach ($name in 'EmiDeviceAgent','EmiDeviceWatchdog') {
  $s=Get-CimInstance Win32_Service -Filter "Name='$name'"
  if ($s.State -ne 'Running' -or $s.StartMode -ne 'Auto' -or $s.StartName -ne 'LocalSystem') { throw "Invalid service startup/account: $name" }
}
if ($AfterReboot) { Write-Output 'Both services running after reboot without needing the desktop UI'; return }
try {
  Stop-Service EmiDeviceAgent
  $deadline=[DateTime]::UtcNow.AddSeconds(120)
  do { Start-Sleep -Seconds 1; $s=Get-Service EmiDeviceAgent } while ($s.Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
  if ($s.Status -ne 'Running') { throw 'Watchdog did not restore stopped core service' }
  $core=Get-CimInstance Win32_Service -Filter "Name='EmiDeviceAgent'"
  Stop-Process -Id $core.ProcessId -Force
  $deadline=[DateTime]::UtcNow.AddSeconds(120)
  do { Start-Sleep -Seconds 1; $core=Get-CimInstance Win32_Service -Filter "Name='EmiDeviceAgent'" } while (($core.State -ne 'Running' -or $core.ProcessId -eq 0) -and [DateTime]::UtcNow -lt $deadline)
  if ($core.State -ne 'Running') { throw 'SCM/watchdog recovery failed after crash' }
  $pidAfter=$core.ProcessId
  Start-Sleep -Seconds 30
  $core=Get-CimInstance Win32_Service -Filter "Name='EmiDeviceAgent'"
  if ($core.ProcessId -ne $pidAfter) { throw 'Core restarted again after successful recovery' }
  Write-Output 'Stopped-service and crash recovery verified. Log out/reboot the VM and run -AfterReboot for startup acceptance.'
} finally { Start-Service EmiDeviceAgent -ErrorAction SilentlyContinue; Start-Service EmiDeviceWatchdog -ErrorAction SilentlyContinue }
