@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_epid_benchmark_windows.ps1" -Warmup 1000 -Iterations 10000
if errorlevel 1 (
  echo [ERROR] Intel EPID benchmark failed. See logs\epid_benchmark.log.
  exit /b 1
)
echo Intel EPID benchmark completed.
