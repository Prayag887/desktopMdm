#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$OutputPath,
  [string]$GroupTag = 'EMI'
)

$ErrorActionPreference = 'Stop'

# Intune's Autopilot CSV importer accepts ANSI text with these exact,
# case-sensitive headings and no quotation marks or extra columns.
function Assert-CsvField([string]$Name, [string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[,\r\n"]' -or $Value -match '[^\x20-\x7E]') {
    throw "$Name cannot be represented in an Autopilot import CSV. Check the device firmware value."
  }
}

$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
$serial = [string]$bios.SerialNumber
Assert-CsvField 'BIOS serial number' $serial

$hardware = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
  -ClassName MDM_DevDetail_Ext01 `
  -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction Stop
$hash = [string]$hardware.DeviceHardwareData
if ([string]::IsNullOrWhiteSpace($hash) -or $hash -notmatch '^[A-Za-z0-9+/=]+$') {
  throw 'Windows did not provide a valid Autopilot hardware hash.'
}
Assert-CsvField 'Group tag' $GroupTag

$destination = [System.IO.Path]::GetFullPath($OutputPath)
$parent = [System.IO.Path]::GetDirectoryName($destination)
if (-not [System.IO.Directory]::Exists($parent)) {
  throw "Output directory does not exist: $parent"
}
if ([System.IO.File]::Exists($destination)) {
  throw "Output file already exists: $destination"
}

$header = 'Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User'
$row = "$serial,,$hash,$GroupTag,"
$contents = "$header`r`n$row`r`n"
$encoding = [System.Text.Encoding]::GetEncoding(1252)
$bytes = $encoding.GetBytes($contents)
$stream = [System.IO.File]::Open($destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
try { $stream.Write($bytes, 0, $bytes.Length) }
finally { $stream.Dispose() }

Write-Output "Autopilot import CSV saved to $destination for serial $serial. Treat the file as sensitive and remove it after confirmed import."
