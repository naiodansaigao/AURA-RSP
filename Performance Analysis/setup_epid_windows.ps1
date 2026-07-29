[CmdletBinding()]
param(
    [string]$MsysRoot = "C:\msys64",
    [switch]$SkipSystemUpdate
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SdkRoot = Join-Path $ProjectRoot "third_party\epid-sdk"
$PatchPath = Join-Path $ProjectRoot "patches\intel-epid-sdk-ucrt64.patch"
$Commit = "389426ff4ba2286d2e133bec29d178427d434d8c"
$Repository = "https://github.com/Intel-EPID-SDK/epid-sdk.git"
$InstallerName = "msys2-x86_64-20260611.exe"
$InstallerUrl = "https://github.com/msys2/msys2-installer/releases/download/2026-06-11/$InstallerName"
$InstallerPath = Join-Path $env:TEMP $InstallerName

if (-not (Test-Path (Join-Path $MsysRoot "usr\bin\bash.exe"))) {
    Write-Host "[1/4] Downloading signed MSYS2 2026-06-11 installer..."
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
    $Signature = Get-AuthenticodeSignature -LiteralPath $InstallerPath
    if ($Signature.Status -ne "Valid") {
        throw "MSYS2 installer signature is not valid: $($Signature.Status)"
    }
    Write-Host "      Authenticode signer: $($Signature.SignerCertificate.Subject)"
    Start-Process -FilePath $InstallerPath -ArgumentList @(
        "in", "--confirm-command", "--accept-messages",
        "--root", ($MsysRoot -replace "\\", "/")
    ) -Wait -NoNewWindow
} else {
    Write-Host "[1/4] Existing MSYS2 installation found at $MsysRoot"
}

$Bash = Join-Path $MsysRoot "usr\bin\bash.exe"
if (-not $SkipSystemUpdate) {
    Write-Host "[2/4] Updating MSYS2 package databases and base packages..."
    & $Bash -lc "pacman -Syu --noconfirm"
    if ($LASTEXITCODE -ne 0) { throw "First pacman update failed." }
    & $Bash -lc "pacman -Syu --noconfirm"
    if ($LASTEXITCODE -ne 0) { throw "Second pacman update failed." }
} else {
    Write-Host "[2/4] MSYS2 system update skipped by request."
}

Write-Host "[3/4] Installing UCRT64 GCC, CMake and Ninja..."
& $Bash -lc "pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja"
if ($LASTEXITCODE -ne 0) { throw "UCRT64 toolchain installation failed." }

Write-Host "[4/4] Fetching Intel EPID SDK at the fixed commit..."
if (-not (Test-Path (Join-Path $SdkRoot ".git"))) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $SdkRoot) | Out-Null
    git clone $Repository $SdkRoot
    if ($LASTEXITCODE -ne 0) { throw "Intel EPID SDK clone failed." }
}
$SafeArg = "safe.directory=$($SdkRoot -replace '\\','/')"
git -c $SafeArg -C $SdkRoot fetch --tags origin
if ($LASTEXITCODE -ne 0) { throw "Intel EPID SDK fetch failed." }
git -c $SafeArg -C $SdkRoot checkout --detach $Commit
if ($LASTEXITCODE -ne 0) { throw "Cannot checkout fixed Intel EPID commit." }
$ActualCommit = (git -c $SafeArg -C $SdkRoot rev-parse HEAD).Trim()
if ($ActualCommit -ne $Commit) {
    throw "Intel EPID commit mismatch: $ActualCommit"
}

git -c $SafeArg -C $SdkRoot apply --check $PatchPath 2>$null
if ($LASTEXITCODE -eq 0) {
    git -c $SafeArg -C $SdkRoot apply $PatchPath
    if ($LASTEXITCODE -ne 0) { throw "UCRT64 compatibility patch failed." }
} else {
    git -c $SafeArg -C $SdkRoot apply --reverse --check $PatchPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Intel EPID source is neither clean nor already patched."
    }
    Write-Host "      UCRT64 compatibility patch is already applied."
}

$UcrtBin = Join-Path $MsysRoot "ucrt64\bin"
& (Join-Path $UcrtBin "gcc.exe") --version | Select-Object -First 1
& (Join-Path $UcrtBin "cmake.exe") --version | Select-Object -First 1
& (Join-Path $UcrtBin "ninja.exe") --version
Write-Host "Intel EPID SDK setup completed at commit $Commit."
