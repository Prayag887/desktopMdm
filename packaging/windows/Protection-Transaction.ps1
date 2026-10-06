#Requires -Version 5.1
# Capture program/state files and service registration before changing the installation.
. (Join-Path $PSScriptRoot 'Protection-Service.ps1')
. (Join-Path $PSScriptRoot 'Explorer-ContextPolicy.ps1')
function Start-ProtectionTransaction([string]$InstallDir, [string]$DataDir) {
  $backup = Join-Path $env:ProgramData ('EmiProtectionBackup-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $backup -ErrorAction Stop | Out-Null
  Set-EmiAcl $backup -Private $true
  $services = @()
  foreach ($name in 'EmiDeviceAgent','EmiDeviceWatchdog') {
    $s = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($s) { $services += [pscustomobject]@{ Name=$name; PathName=$s.PathName; StartMode=$s.StartMode; StartName=$s.StartName; WasRunning=($s.State -eq 'Running'); DisplayName=$s.DisplayName } }
  }
  foreach ($s in $services) { if ($s.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) { throw 'Cannot transactionally service a non-LocalSystem installation' } }
  $explorerPolicy = Get-EmiExplorerPolicyState
  $task = Get-ScheduledTask -TaskName EmiDeviceLockAll -ErrorAction SilentlyContinue
  if ($task) { Export-ScheduledTask -TaskName EmiDeviceLockAll | Set-Content (Join-Path $backup 'task.xml') }
  try {
  foreach ($name in 'EmiDeviceWatchdog','EmiDeviceAgent') { Stop-ProtectionService $name }
  $aclBackup = @()
  foreach ($pair in @(@($InstallDir,'program'), @($DataDir,'state'))) {
    if (Test-Path -LiteralPath $pair[0]) {
      $items = @(Get-ProtectionItems $pair[0])
      $aclBackup += @($items | ForEach-Object { [pscustomobject]@{path=$_.FullName;sddl=(Get-Acl -LiteralPath $_.FullName).Sddl} })
      Copy-Item -LiteralPath $pair[0] -Destination (Join-Path $backup $pair[1]) -Recurse -Force
      # Credential backups must not inherit the source's UI-readable ACL.
      Get-ProtectionItems (Join-Path $backup $pair[1]) | ForEach-Object { Set-EmiAcl $_.FullName -Private $true }
    }
  }
  [IO.File]::WriteAllText((Join-Path $backup 'acls.json'), (ConvertTo-Json -InputObject $aclBackup -Depth 4))
  [pscustomobject]@{ Backup=$backup; Services=$services; InstallDir=$InstallDir; DataDir=$DataDir; ExplorerPolicy=$explorerPolicy }
  } catch {
    foreach ($s in $services) { if ($s.WasRunning) { Start-Service $s.Name -ErrorAction SilentlyContinue } }
    throw
  }
}
function Undo-ProtectionTransaction($Transaction) {
  Set-EmiExplorerPolicyState $Transaction.ExplorerPolicy
  foreach ($name in 'EmiDeviceWatchdog','EmiDeviceAgent') {
    Stop-ProtectionService $name
    if ($name -notin @($Transaction.Services | ForEach-Object { $_.Name }) -and (Get-Service $name -ErrorAction SilentlyContinue)) {
      & "$env:SystemRoot\System32\sc.exe" delete $name | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Could not remove new service $name" }
    }
  }
  foreach ($pair in @(@($Transaction.InstallDir,'program'), @($Transaction.DataDir,'state'))) {
    if (Test-Path -LiteralPath $pair[0]) { Get-ProtectionItems $pair[0] | Out-Null; Remove-Item -LiteralPath $pair[0] -Recurse -Force }
    $saved = Join-Path $Transaction.Backup $pair[1]
    if (Test-Path -LiteralPath $saved) { Copy-Item -LiteralPath $saved -Destination $pair[0] -Recurse -Force }
  }
  foreach ($entry in (Get-Content (Join-Path $Transaction.Backup 'acls.json') -Raw | ConvertFrom-Json)) {
    $item = Get-Item -LiteralPath $entry.path -Force
    $acl = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetSecurityDescriptorSddlForm($entry.sddl)
    Set-Acl -LiteralPath $entry.path -AclObject $acl
  }
  foreach ($s in $Transaction.Services) {
    $startup = if ($s.StartMode -eq 'Auto') { 'Automatic' } elseif ($s.StartMode -eq 'Disabled') { 'Disabled' } else { 'Manual' }
    if (Get-Service $s.Name -ErrorAction SilentlyContinue) {
      $mode = if ($s.StartMode -eq 'Auto') { 'Automatic' } elseif ($s.StartMode -eq 'Disabled') { 'Disabled' } else { 'Manual' }
      Set-ProtectionServiceConfiguration $s.Name $s.PathName $mode
    } else { New-Service -Name $s.Name -BinaryPathName $s.PathName -DisplayName $s.DisplayName -StartupType $startup | Out-Null }
    & "$env:SystemRoot\System32\sc.exe" failure $s.Name reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
    if ($s.WasRunning) { Start-Service $s.Name }
  }
  Unregister-ScheduledTask -TaskName EmiDeviceLockAll -Confirm:$false -ErrorAction SilentlyContinue
  if (Test-Path (Join-Path $Transaction.Backup 'task.xml')) { Register-ScheduledTask -TaskName EmiDeviceLockAll -Xml (Get-Content (Join-Path $Transaction.Backup 'task.xml') -Raw) | Out-Null }
}

function Stop-ProtectionService([string]$Name) {
  $service=Get-Service $Name -ErrorAction SilentlyContinue
  if ($service) {
    try {
      Stop-Service $Name -ErrorAction Stop
      $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(120))
    } finally { $service.Dispose() }
  }
}
