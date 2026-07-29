@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Environment not found. Run setup_windows.bat first.
    pause
    exit /b 1
)

rem Change this value to the actual encrypted Profile package size in bytes.
set PROFILE_BYTES=65536

rem Each primitive is measured exactly 10,000 times after 1,000 warm-up calls.
set ITERATIONS=10000
set WARMUP=1000
set MAC_BYTES=128
set CPU_INDEX=0
set OUTPUT_PREFIX=aura_rsp_windows

echo ============================================================
echo AURA-RSP + genuine Intel EPID native Windows benchmark
echo Profile bytes : %PROFILE_BYTES%
echo Iterations    : %ITERATIONS%
echo Warm-up       : %WARMUP%
echo CPU           : %CPU_INDEX%
echo ============================================================

echo [1/2] Measuring genuine DAA with direct EpidSign/EpidVerify calls...
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0run_epid_benchmark_windows.ps1" ^
  -Warmup %WARMUP% ^
  -Iterations %ITERATIONS%
if errorlevel 1 (
    echo.
    echo [ERROR] Native Intel EPID benchmark failed.
    exit /b 1
)

echo [2/2] Measuring remaining primitives and calculating schemes...
".venv\Scripts\python.exe" crypto_operation_benchmark_windows.py ^
  --iterations %ITERATIONS% ^
  --warmup %WARMUP% ^
  --payload-bytes %PROFILE_BYTES% ^
  --mac-bytes %MAC_BYTES% ^
  --cpu %CPU_INDEX% ^
  --daa-results epid_daa_results.json ^
  --output-prefix %OUTPUT_PREFIX% > "logs\python_benchmark.log" 2>&1

set PYTHON_BENCHMARK_EXIT=%ERRORLEVEL%
type "logs\python_benchmark.log"

if not "%PYTHON_BENCHMARK_EXIT%"=="0" (
    echo.
    echo [ERROR] Benchmark failed.
    exit /b %PYTHON_BENCHMARK_EXIT%
)

echo.
echo Generated:
echo   %OUTPUT_PREFIX%_operations.csv
echo   %OUTPUT_PREFIX%_schemes.csv
echo   %OUTPUT_PREFIX%.json
echo   epid_daa_results.json
echo   logs\epid_benchmark.log
echo   logs\python_benchmark.log
