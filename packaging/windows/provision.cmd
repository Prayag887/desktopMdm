@echo off
setlocal
rem One-shot EMI provisioning entry point. Bypasses the PowerShell execution
rem policy and hands off to Provision.ps1, which self-elevates and installs +
rem applies the payment restriction for the given enrolled account.
rem
rem Usage:  provision.cmd <enrolled-standard-account>
rem Example: provision.cmd emicustomer

if "%~1"=="" (
  echo Usage: provision.cmd ^<enrolled-standard-account^>
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Provision.ps1" -EnrolledUser "%~1"
exit /b %errorlevel%
