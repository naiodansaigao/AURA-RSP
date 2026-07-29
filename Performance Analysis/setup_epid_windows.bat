@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_epid_windows.ps1"
if errorlevel 1 (
  echo [ERROR] Intel EPID setup failed.
  exit /b 1
)
echo Intel EPID setup completed.
