[CmdletBinding()]
param(
    [string]$MsysRoot = "C:\msys64",
    [string]$DriveLetter = "R"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Logs = Join-Path $ProjectRoot "logs"
$LogPath = Join-Path $Logs "epid_build.log"
$BuildRelative = "build\epid-sdk-ucrt64"
$Cmake = Join-Path $MsysRoot "ucrt64\bin\cmake.exe"
$UcrtBin = Join-Path $MsysRoot "ucrt64\bin"
$Drive = "$DriveLetter`:"

if (-not (Test-Path $Cmake)) {
    throw "UCRT64 CMake not found. Run setup_epid_windows.ps1 first."
}
if (Test-Path "$Drive\") {
    throw "Drive $Drive is already in use; choose another -DriveLetter."
}
New-Item -ItemType Directory -Force $Logs | Out-Null
if (Test-Path $LogPath) { Remove-Item -LiteralPath $LogPath -Force }

try {
    & subst.exe $Drive $ProjectRoot
    if ($LASTEXITCODE -ne 0) { throw "Cannot map ASCII build drive $Drive." }
    $env:PATH = "$UcrtBin;$env:PATH"
    $Source = "$Drive/third_party/epid-sdk"
    $Build = "$Drive/$($BuildRelative -replace '\\','/')"
    $Benchmark = "$Drive/native_epid_benchmark"

    "Intel EPID SDK native Windows build" | Tee-Object -FilePath $LogPath
    "Timestamp: $(Get-Date -Format o)" | Tee-Object -FilePath $LogPath -Append
    "Source commit: 389426ff4ba2286d2e133bec29d178427d434d8c" |
        Tee-Object -FilePath $LogPath -Append
    & (Join-Path $UcrtBin "gcc.exe") --version 2>&1 |
        Tee-Object -FilePath $LogPath -Append
    & $Cmake --version 2>&1 | Tee-Object -FilePath $LogPath -Append
    & (Join-Path $UcrtBin "ninja.exe") --version 2>&1 |
        Tee-Object -FilePath $LogPath -Append

    # CMake emits deprecation diagnostics on stderr even when configuration
    # succeeds. PowerShell 7 must not promote those native warning lines into
    # terminating NativeCommandError records.
    $SavedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $Cmake -S $Source -B $Build -G Ninja `
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DAURA_EPID_BENCHMARK_DIR=$Benchmark" 2>&1 |
        Tee-Object -FilePath $LogPath -Append
    $ConfigureExitCode = $LASTEXITCODE
    $ErrorActionPreference = $SavedErrorPreference
    if ($ConfigureExitCode -ne 0) { throw "Intel EPID CMake configuration failed." }

    $ErrorActionPreference = "Continue"
    & $Cmake --build $Build --target aura_epid_benchmark --parallel 4 2>&1 |
        Tee-Object -FilePath $LogPath -Append
    $BuildExitCode = $LASTEXITCODE
    $ErrorActionPreference = $SavedErrorPreference
    if ($BuildExitCode -ne 0) { throw "Intel EPID native benchmark build failed." }

    $Executable = Join-Path $ProjectRoot "$BuildRelative\aura_epid_benchmark\aura_epid_benchmark.exe"
    if (-not (Test-Path $Executable)) {
        throw "Expected native benchmark was not generated: $Executable"
    }
    "Build status: OK" | Tee-Object -FilePath $LogPath -Append
    Write-Host "Native benchmark: $Executable"
    Write-Host "Build log: $LogPath"
} finally {
    & subst.exe $Drive /D 2>$null
}
