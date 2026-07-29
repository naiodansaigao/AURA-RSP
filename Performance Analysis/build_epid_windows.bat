@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_epid_windows.ps1"
if errorlevel 1 (
  echo [ERROR] Intel EPID build failed. See logs\epid_build.log.
  exit /b 1
)
echo Intel EPID build completed.
