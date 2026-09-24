#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Dell', 'HP', 'Lenovo', 'Asus')][string]$Provider,
  [Parameter(Mandatory)][string]$SecretPath,
  [Parameter(Mandatory)][string]$ProgressPath
)
$ErrorActionPreference = 'Stop'

function Write-BiosProgress([int]$Percent, [string]$Message) {
  Set-Content -LiteralPath $ProgressPath -Value ("{0}|{1}" -f $Percent, $Message) -Encoding UTF8
}

function Resolve-Tool([string[]]$Candidates, [string]$Name) {
  $path = $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $path) { throw "$Name is not installed. Install the OEM adapter first." }
  return $path
}

function Assert-LenovoResult($Result, [string]$Step) {
  $value = if ($null -ne $Result.return) { $Result.return } else { $Result.ReturnValue }
  if ($value -and $value -ne 'Success' -and $value -ne 0) {
    throw "Lenovo firmware rejected '$Step': $value"
  }
}

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$resolvedSecret = [IO.Path]::GetFullPath($SecretPath)
$resolvedProgress = [IO.Path]::GetFullPath($ProgressPath)
if (-not $resolvedSecret.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($resolvedSecret)).StartsWith('emi-bios-secrets-') -or
    -not $resolvedProgress.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($resolvedProgress)).StartsWith('emi-bios-progress-')) {
  throw 'The protected credential file is outside the expected temporary directory.'
}

$current = $null
$new = $null
$asusPasswordFile = $null
try {
  Write-BiosProgress 10 'Unlocking protected credentials'
  $payload = Get-Content -LiteralPath $resolvedSecret -Raw | ConvertFrom-Json
  if ($payload.current) {
    $currentBytes = [Security.Cryptography.ProtectedData]::Unprotect(
      [Convert]::FromBase64String($payload.current), $null,
      [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $current = [Text.Encoding]::UTF8.GetString($currentBytes)
  }
  $newBytes = [Security.Cryptography.ProtectedData]::Unprotect(
    [Convert]::FromBase64String($payload.new), $null,
    [Security.Cryptography.DataProtectionScope]::LocalMachine)
  $new = [Text.Encoding]::UTF8.GetString($newBytes)
  if ([string]::IsNullOrEmpty($new)) { throw 'The new BIOS password cannot be empty.' }

  Write-BiosProgress 35 "Validating $Provider firmware interface"
  switch ($Provider) {
    'Dell' {
      $tool = Resolve-Tool @(
        "${env:ProgramFiles(x86)}\Dell\Command Configure\X86_64\cctk.exe",
        "$env:ProgramFiles\Dell\Command Configure\X86_64\cctk.exe"
      ) 'Dell Command | Configure'
      Write-BiosProgress 65 'Applying Dell BIOS administrator password'
      $arguments = @("--setuppwd=$new")
      if ($current) { $arguments += "--valsetuppwd=$current" }
      & $tool @arguments | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Dell firmware command failed with exit code $LASTEXITCODE" }
    }
    'HP' {
      Import-Module HP.ClientManagement -Force -ErrorAction Stop
      $passwordIsSet = Get-HPBIOSSetupPasswordIsSet
      if ($passwordIsSet -and -not $current) { throw 'The current BIOS password is required.' }
      Write-BiosProgress 65 'Applying HP BIOS setup password'
      if ($passwordIsSet) {
        Set-HPBIOSSetupPassword -NewPassword $new -Password $current -ErrorAction Stop
      }
      else {
        Set-HPBIOSSetupPassword -NewPassword $new -ErrorAction Stop
      }
    }
    'Lenovo' {
      $state = (Get-WmiObject -Namespace root\wmi -Class Lenovo_BiosPasswordSettings -ErrorAction Stop).PasswordState
      if (($state -band 2) -eq 0) {
        throw 'Lenovo only allows the first supervisor password to be created in UEFI setup. Create it there once, then this app can change it.'
      }
      if (-not $current) { throw 'The current Lenovo supervisor password is required.' }
      if ($current.Contains(';') -or $new.Contains(';')) {
        throw 'This Lenovo WMI interface cannot safely pass a semicolon in a password.'
      }
      Write-BiosProgress 65 'Changing Lenovo supervisor password'
      $opcode = Get-WmiObject -Namespace root\wmi -Class Lenovo_WmiOpcodeInterface -ErrorAction SilentlyContinue
      if ($opcode) {
        $isMobile = (Get-CimInstance Win32_ComputerSystem).PCSystemType -eq 2
        if (-not $isMobile) { Assert-LenovoResult ($opcode.WmiOpcodeInterface("WmiOpcodePasswordAdmin:$current;")) 'authenticate' }
        Assert-LenovoResult ($opcode.WmiOpcodeInterface('WmiOpcodePasswordType:pap;')) 'select password type'
        Assert-LenovoResult ($opcode.WmiOpcodeInterface("WmiOpcodePasswordCurrent01:$current;")) 'validate current password'
        Assert-LenovoResult ($opcode.WmiOpcodeInterface("WmiOpcodePasswordNew01:$new;")) 'set new password'
        Assert-LenovoResult ($opcode.WmiOpcodeInterface('WmiOpcodePasswordSetUpdate')) 'commit password'
      }
      else {
        if ($current.Contains(',') -or $new.Contains(',')) { throw 'This legacy Lenovo WMI interface cannot safely pass a comma in a password.' }
        $legacy = Get-WmiObject -Namespace root\wmi -Class Lenovo_SetBiosPassword -ErrorAction Stop
        Assert-LenovoResult ($legacy.SetBiosPassword("pap,$current,$new,ascii,us;")) 'change password'
      }
    }
    'Asus' {
      $tool = Resolve-Tool @(
        "$env:ProgramFiles\ASUS\ASUS BIOS Config Tool\act.exe",
        "$env:ProgramFiles\ASUS\ACT\act.exe",
        "${env:ProgramFiles(x86)}\ASUS\ASUS BIOS Config Tool\act.exe",
        "${env:ProgramFiles(x86)}\ASUS\ACT\act.exe"
      ) 'ASUS BIOS Configuration Tool'
      Write-BiosProgress 65 'Applying ASUS BIOS administrator password'
      if ($current) {
        & $tool --renewpwd $new --pwd $current --quiet
      }
      else {
        $asusPasswordFile = Join-Path $env:TEMP ("emi-asus-password-{0}.bin" -f [guid]::NewGuid())
        & $tool --newpwd $new --output $asusPasswordFile --quiet
      }
      if ($LASTEXITCODE -ne 0) { throw "ASUS firmware command failed with exit code $LASTEXITCODE" }
    }
  }
  Write-BiosProgress 100 'BIOS password updated successfully'
}
catch {
  Write-BiosProgress 0 'Firmware rejected the change; verify the current password and model support'
  throw
}
finally {
  Remove-Item -LiteralPath $resolvedSecret -Force -ErrorAction SilentlyContinue
  if ($asusPasswordFile) { Remove-Item -LiteralPath $asusPasswordFile -Force -ErrorAction SilentlyContinue }
  $current = $null
  $new = $null
  if ($currentBytes) { [Array]::Clear($currentBytes, 0, $currentBytes.Length) }
  if ($newBytes) { [Array]::Clear($newBytes, 0, $newBytes.Length) }
}
