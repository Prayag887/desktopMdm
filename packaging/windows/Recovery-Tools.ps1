# Microsoft ADK bootstrap for an elevated, integrity-verified installation.
function Initialize-EmiRecoveryTools {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$InstallDir,
        [string]$AdkRoot = (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit'))
  $ErrorActionPreference = 'Stop'
  $usmt = Join-Path $AdkRoot 'User State Migration Tool\amd64'
  $setupSources = Join-Path $AdkRoot 'Windows Setup\amd64\Sources'
  $destination = Join-Path $InstallDir ('RecoveryTools-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  Set-Acl -LiteralPath $destination -AclObject $acl
  if (-not (Test-Path -LiteralPath (Join-Path $usmt 'scanstate.exe')) -or
      -not (Test-Path -LiteralPath (Join-Path $setupSources 'Config_AppsAndSettings.xml'))) {
    Write-Host 'Downloading and installing Microsoft ADK recovery tools. Internet access is required; this can take several minutes.'
    $installer = Join-Path $destination 'adksetup.exe'
    $oldProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
      [Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -UseBasicParsing -Uri 'https://go.microsoft.com/fwlink/?linkid=2289980' -OutFile $installer -ErrorAction Stop
    } finally { [Net.ServicePointManager]::SecurityProtocol = $oldProtocol }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
      throw 'ADK setup is not validly signed by Microsoft; refusing to execute it.'
    }
    $process = Start-Process -FilePath $installer -ArgumentList @('/quiet','/norestart','/ceip','off','/features','OptionId.DeploymentTools','OptionId.UserStateMigrationTool') -Wait -PassThru -ErrorAction Stop
    if ($process.ExitCode -eq 3010) { throw 'Microsoft ADK requires a restart. Restart Windows and rerun install.cmd; recovery capture has not completed.' }
    if ($process.ExitCode -ne 0) { throw "Microsoft ADK installation failed with exit code $($process.ExitCode). Recovery capture has not completed." }
    Remove-Item -LiteralPath $installer -Force
  }
  foreach ($source in @($usmt, $setupSources)) {
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Microsoft ADK recovery component missing after setup: $source" }
    # Microsoft's preparation order: USMT first, Windows Setup files second.
    Get-ChildItem -LiteralPath $source -File | Copy-Item -Destination $destination -Force -ErrorAction Stop
  }
  foreach ($file in @('scanstate.exe','Config_AppsAndSettings.xml')) {
    if (-not (Test-Path -LiteralPath (Join-Path $destination $file) -PathType Leaf)) { throw "Prepared recovery tools are incomplete: $file" }
  }
  $scanSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $destination 'scanstate.exe')
  if ($scanSignature.Status -ne 'Valid' -or $scanSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { throw 'Prepared ScanState is not validly signed by Microsoft.' }
  return $destination
}
