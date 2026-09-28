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
:: 1. Back up BCD first
bcdedit /export C:\bcd-backup
if errorlevel 1 goto :bcd_failed

:: 2. Disable Windows Recovery Environment
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
:: 3. Disable boot recovery
bcdedit /set {current} recoveryenabled No
if errorlevel 1 goto :bcd_failed
bcdedit /set {default} recoveryenabled No
if errorlevel 1 goto :bcd_failed

:: 4. Prevent failed boots from automatically entering recovery
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
if errorlevel 1 goto :bcd_failed
bcdedit /set {default} bootstatuspolicy IgnoreAllFailures
if errorlevel 1 goto :bcd_failed

:: 5. Disable shutdown without logging on
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
 /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f
if errorlevel 1 goto :registry_failed

echo Installation completed successfully. Windows RE and automatic boot recovery have been disabled.
echo Shutdown without logging on has been disabled.
echo BCD backup: C:\bcd-backup
echo An administrator can restore Windows RE with: reagentc /enable
pause
exit /b 0

:bcd_failed
set "BCD_EXIT=%ERRORLEVEL%"
echo Agent installed, but BCD configuration FAILED with exit code %BCD_EXIT%.
echo Review the error above. Recovery configuration may be incomplete.
pause
exit /b %BCD_EXIT%

:registry_failed
set "REGISTRY_EXIT=%ERRORLEVEL%"
echo Agent installed, but setting ShutdownWithoutLogon FAILED with exit code %REGISTRY_EXIT%.
echo Review the error above. Recovery settings have already been applied.
pause
exit /b %REGISTRY_EXIT%
