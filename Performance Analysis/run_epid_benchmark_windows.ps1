[CmdletBinding()]
param(
    [int]$Warmup = 1000,
    [int]$Iterations = 10000,
    [string]$DriveLetter = "R"
)

$ErrorActionPreference = "Stop"
if ($Warmup -le 0 -or $Iterations -le 0) {
    throw "Warmup and Iterations must both be positive."
}
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Logs = Join-Path $ProjectRoot "logs"
$LogPath = Join-Path $Logs "epid_benchmark.log"
$ResultPath = Join-Path $ProjectRoot "epid_daa_results.json"
$Executable = Join-Path $ProjectRoot "build\epid-sdk-ucrt64\aura_epid_benchmark\aura_epid_benchmark.exe"
$Drive = "$DriveLetter`:"

if (-not (Test-Path $Executable)) {
    throw "Native benchmark not found. Run build_epid_windows.ps1 first."
}
if (Test-Path "$Drive\") {
    throw "Drive $Drive is already in use; choose another -DriveLetter."
}
New-Item -ItemType Directory -Force $Logs | Out-Null
if (Test-Path $LogPath) { Remove-Item -LiteralPath $LogPath -Force }

try {
    & subst.exe $Drive $ProjectRoot
    if ($LASTEXITCODE -ne 0) { throw "Cannot map ASCII benchmark drive $Drive." }
    $MappedExecutable = "$Drive\build\epid-sdk-ucrt64\aura_epid_benchmark\aura_epid_benchmark.exe"
    $DataDir = "$Drive\third_party\epid-sdk\example\split_data"
    $MappedResult = "$Drive\epid_daa_results.json"

    & $MappedExecutable `
        --data-dir $DataDir `
        --output $MappedResult `
        --warmup $Warmup `
        --iterations $Iterations 2>&1 |
        Tee-Object -FilePath $LogPath
    if ($LASTEXITCODE -ne 0) { throw "Native Intel EPID benchmark failed." }
    if (-not (Test-Path $ResultPath)) {
        throw "Native Intel EPID result JSON was not generated."
    }
    Write-Host "Native DAA result: $ResultPath"
    Write-Host "Runtime log: $LogPath"
} finally {
    & subst.exe $Drive /D 2>$null
}
