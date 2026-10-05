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

rem Trust only the pinned public code-signing certificate; UAC authorizes this device change.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-PublisherTrust.ps1"
if errorlevel 1 (
  echo Publisher certificate installation FAILED. Application installation was not started.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "INSTALL_EXIT=%ERRORLEVEL%"
echo.
if not "%INSTALL_EXIT%"=="0" (
  echo Installation FAILED with exit code %INSTALL_EXIT%.
  echo Review the error shown above. Some components may already be installed.
  pause
  exit /b %INSTALL_EXIT%
)
echo Installation completed. Windows Recovery, boot configuration, and firmware were preserved.
pause
exit /b 0
