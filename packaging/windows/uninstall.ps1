#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
if (Get-Service EmiDeviceAgent -ErrorAction SilentlyContinue) {
  Stop-Service EmiDeviceAgent -Force
  sc.exe delete EmiDeviceAgent | Out-Null
}
Remove-Item "$env:ProgramFiles\EmiDeviceAgent" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EMI Device.lnk" -Force -ErrorAction SilentlyContinue
Write-Host 'Agent removed. Enrollment data remains in ProgramData for audit/recovery.'
