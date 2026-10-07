@echo off
setlocal
rem Rebuild native module paths when launched from PowerShell 7 or automation.
set "PSModulePath="
rem The launcher checks the Windows token and handles UAC independently of services.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-EmiInstaller.ps1" -RequireOfflineRecovery %*
set "INSTALL_EXIT=%ERRORLEVEL%"
echo.
if not "%INSTALL_EXIT%"=="0" (
  echo Installation FAILED with exit code %INSTALL_EXIT%.
  echo Review the error shown above. Some components may already be installed.
) else (
  echo Installation and recovery capture completed. Actual reset restoration still requires validation.
)
pause
exit /b %INSTALL_EXIT%
