#Requires -Version 5.1
# Configure existing SCM registrations without native command-line quote rewriting.
function Set-ProtectionServiceConfiguration([string]$Name, [string]$BinaryPath, [string]$StartMode) {
  $service=Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
  if (-not $service) { throw "Service is missing: $Name" }
  $result=Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$BinaryPath;StartMode=$StartMode;StartName='LocalSystem'} -ErrorAction Stop
  if ($result.ReturnValue -ne 0) { throw "Service configuration failed: $Name (Windows result $($result.ReturnValue))" }
}
