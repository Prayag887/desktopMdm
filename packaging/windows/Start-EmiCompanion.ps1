#Requires -Version 5.1
function Start-EmiCompanion {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$UiPath)

  # Launching the interactive companion is optional after service installation.
  # A canceled Windows launch/security prompt must not turn that into failure.
  try {
    Start-Process -FilePath $UiPath -ErrorAction Stop | Out-Null
    return $true
  }
  catch {
    Write-Warning "The agent service is installed, but Windows could not open the desktop companion: $($_.Exception.Message)"
    Write-Warning "Try opening '$UiPath' manually in your desktop session. If Windows blocks it, review the Windows security message with your administrator."
    return $false
  }
}
