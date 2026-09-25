@echo off
rem One-click EMI installer. Double-click this file. It self-elevates (UAC) and
rem runs install.ps1 with the execution-policy bypass, so nobody has to open
rem PowerShell or type anything.

net session >nul 2>&1
if %errorlevel% neq 0 (
  rem Not elevated yet: relaunch this .cmd as administrator.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "INSTALL_EXIT=%ERRORLEVEL%"
echo.
if not "%INSTALL_EXIT%"=="0" (
  echo Installation FAILED with exit code %INSTALL_EXIT%.
  echo Review the error shown above. Nothing has been reported as installed.
  pause
  exit /b %INSTALL_EXIT%
)
echo Installation completed successfully. You can close this window.
pause
exit /b 0
