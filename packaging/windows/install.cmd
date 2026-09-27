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
  echo Review the error shown above. Some components may already be installed.
  pause
  exit /b %INSTALL_EXIT%
)
rem Configure recovery only after the agent installer has succeeded.
echo Disabling Windows Recovery Environment...
reagentc /disable
set "RECOVERY_EXIT=%ERRORLEVEL%"
reagentc /info
set "RECOVERY_INFO_EXIT=%ERRORLEVEL%"
if not "%RECOVERY_EXIT%"=="0" (
  echo Agent installed, but disabling Windows RE FAILED with exit code %RECOVERY_EXIT%.
  pause
  exit /b %RECOVERY_EXIT%
)
if not "%RECOVERY_INFO_EXIT%"=="0" (
  echo Agent installed, but querying Windows RE FAILED with exit code %RECOVERY_INFO_EXIT%.
  pause
  exit /b %RECOVERY_INFO_EXIT%
)
echo Installation completed successfully. Windows RE has been disabled.
echo An administrator can restore Windows RE with: reagentc /enable
pause
exit /b 0
