#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Dell', 'HP')][string]$Provider,
  [Parameter(Mandatory)][string]$ProgressPath
)
$ErrorActionPreference = 'Stop'

function Write-InstallProgress([int]$Percent, [string]$Message) {
  Set-Content -LiteralPath $ProgressPath -Value ("{0}|{1}" -f $Percent, $Message) -Encoding UTF8
}

try {
  Write-InstallProgress 5 'Waiting for administrator approval'
  if ($Provider -eq 'Dell') {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
      Write-InstallProgress 15 'Downloading Microsoft App Installer'
      $bundle = Join-Path $env:TEMP 'emi-winget-bootstrap.msixbundle'
      try {
        Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile $bundle -UseBasicParsing
        Write-InstallProgress 45 'Installing Microsoft App Installer'
        Add-AppxPackage -Path $bundle
      }
      finally {
        Remove-Item -LiteralPath $bundle -Force -ErrorAction SilentlyContinue
      }
    }
    Write-InstallProgress 60 'Downloading Dell Command | Configure'
    & winget.exe install --id Dell.CommandConfigure -e --accept-source-agreements --accept-package-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw "Dell adapter installation failed with exit code $LASTEXITCODE" }
    Write-InstallProgress 95 'Verifying Dell adapter'
  }
  else {
    Write-InstallProgress 20 'Preparing PowerShell Gallery'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-InstallProgress 40 'Downloading HP Client Management Script Library'
    Install-Module -Name HPCMSL -Repository PSGallery -Force -AcceptLicense -Scope AllUsers
    Write-InstallProgress 95 'Verifying HP adapter'
    Import-Module HP.ClientManagement -Force -ErrorAction Stop
  }
  Write-InstallProgress 100 'OEM adapter installed'
}
catch {
  Write-InstallProgress 0 'OEM adapter installation failed'
  throw
}
