@echo off
rem The launcher checks the Windows token and handles UAC independently of services.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-EmiInstaller.ps1"
set "INSTALL_EXIT=%ERRORLEVEL%"
echo.
if not "%INSTALL_EXIT%"=="0" (
  echo Installation FAILED with exit code %INSTALL_EXIT%.
  echo Review the error shown above. Some components may already be installed.
) else (
  echo Installation completed. Windows Recovery, boot configuration, and firmware were preserved.
)
pause
exit /b %INSTALL_EXIT%
