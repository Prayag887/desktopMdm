#Requires -Version 5.1
# Windows service configuration and bounded lifecycle operations.
function Set-ProtectionServiceConfiguration([string]$Name, [string]$BinaryPath, [string]$StartMode, [string]$DisplayName = '') {
  $service=Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
  if (-not $service) { throw "Service is missing: $Name" }
  $arguments=@{PathName=$BinaryPath;StartMode=$StartMode;StartName='LocalSystem'}
  if ($DisplayName) { $arguments.DisplayName=$DisplayName }
  $result=Invoke-CimMethod -InputObject $service -MethodName Change -Arguments $arguments -ErrorAction Stop
  if ($result.ReturnValue -ne 0) { throw "Service configuration failed: $Name (Windows result $($result.ReturnValue))" }
}

# Stop only after pending startup/shutdown settles; tolerate a concurrent clean exit.
function Stop-ProtectionService([string]$Name) {
  $service=Get-Service $Name -ErrorAction SilentlyContinue
  if (-not $service) { return }
  $deadline=[DateTime]::UtcNow.AddSeconds(120)
  try {
    while ([DateTime]::UtcNow -lt $deadline) {
      $service.Refresh()
      if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) { return }
      if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::StopPending) {
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,($deadline-[DateTime]::UtcNow))
        return
      }
      if ($service.CanStop -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::StartPending) {
        $stopAccepted=$false
        try { $service.Stop(); $stopAccepted=$true }
        catch {
          $stopError=$_
          $service.Refresh()
          if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) { return }
          $native=$stopError.Exception.GetBaseException()
          if ($native -isnot [ComponentModel.Win32Exception] -or $native.NativeErrorCode -notin @(1061,1062)) { throw $stopError }
        }
        if ($stopAccepted) {
          $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,($deadline-[DateTime]::UtcNow))
          return
        }
      }
      Start-Sleep -Milliseconds 250
    }
    throw "Timed out stopping service: $Name"
  } finally { $service.Dispose() }
}
