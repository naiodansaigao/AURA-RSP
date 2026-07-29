@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo AURA-RSP Windows benchmark environment setup
echo ============================================================

where py >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python Launcher "py" was not found.
    echo Install 64-bit Python 3.12 from python.org and select:
    echo   Add python.exe to PATH
    echo   Install launcher for all users
    pause
    exit /b 1
)

py -3.12 -c "import struct; assert struct.calcsize('P') == 8; print('Python 3.12 x64 detected')" 
if errorlevel 1 (
    echo [ERROR] 64-bit Python 3.12 is required.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating virtual environment...
    py -3.12 -m venv .venv
    if errorlevel 1 goto :failed
) else (
    echo [1/3] Existing virtual environment found.
)

echo [2/3] Updating pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :failed

echo [3/3] Installing benchmark dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements_windows.txt
if errorlevel 1 goto :failed

echo.
echo Testing imports...
".venv\Scripts\python.exe" -c "import pyblst, cryptography, nacl, pqcrypto, oblivious, rbcl; print('All required packages loaded successfully.')"
if errorlevel 1 goto :failed

echo.
echo Setup completed successfully.
echo Run run_benchmark_windows.bat next.
pause
exit /b 0

:failed
echo.
echo [ERROR] Setup failed. Copy the complete error message and keep this window open.
pause
exit /b 1
