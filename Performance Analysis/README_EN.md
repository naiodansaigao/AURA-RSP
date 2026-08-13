# AURA-RSP Native Windows Benchmark

This benchmark runs natively on Windows 10/11 without WSL2, a Linux virtual
machine, or Docker.

## 1. Install Python

Install **64-bit Python 3.12.x**. During installation, we recommend selecting:

- Add python.exe to PATH
- Install launcher for all users

After installation, open PowerShell or Command Prompt and run:

```powershell
py -3.12 --version
py -3.12 -c "import struct; print(struct.calcsize('P') * 8)"
```

The second command should output `64`.

## 2. Place the Files in One Directory

We recommend creating the following directory:

```text
D:\AURA-RSP-Benchmark
```

At a minimum, the directory must contain:

```text
crypto_operation_benchmark_windows.py
requirements_windows.txt
setup_windows.bat
run_benchmark_windows.bat
```

## 3. Install the Python Dependencies

Double-click:

```text
setup_windows.bat
```

The script will:

1. Verify that 64-bit Python 3.12 is installed.
2. Create a `.venv` virtual environment.
3. Install the precompiled cryptographic libraries for Windows.
4. Test all required imports.

You do not need to activate the virtual environment in PowerShell or modify
the PowerShell execution policy.

## 4. Install and Build the Genuine Intel EPID 2.0 Implementation

Run the following scripts in order:

```text
setup_epid_windows.bat
build_epid_windows.bat
```

The first script installs the MSYS2 UCRT64 toolchain, downloads the official
Intel open-source repository, checks out commit
`389426ff4ba2286d2e133bec29d178427d434d8c`, and applies a patch limited to
Windows build compatibility. The second script builds the SDK as local static
libraries and links the native `aura_epid_benchmark.exe` executable. The
complete build log is saved to `logs\epid_build.log`.

The benchmark uses the official test material supplied in the SDK's
`example\split_data` directory: the Group A public key, the member0 private
key, the CA certificate, and the officially signed empty GroupRL, PrivRL, and
SigRL. It directly invokes `EpidSign` and `EpidVerify`; process startup for
`signmsg.exe` or `verifysig.exe` is not included in the measurements.

## 5. Set the Profile Size

Open `run_benchmark_windows.bat` in a text editor and locate:

```bat
set PROFILE_BYTES=65536
```

Replace `65536` with the actual size, in bytes, of the encrypted Profile
package used in your experiment.

## 6. Run the Benchmark

Double-click:

```text
run_benchmark_windows.bat
```

The genuine DAA signing and verification operations are each warmed up for
1,000 iterations and then measured over 10,000 iterations. Key and revocation
list authentication, context creation, pairing precomputation, and buffer
allocation are completed before timing begins. `T_DG` includes only one
`EpidSign` call, while `T_DV` includes only one `EpidVerify` call on a
previously generated valid quote. The remaining cryptographic operations use
the same warm-up and measurement counts.

The benchmark generates:

```text
aura_rsp_windows_operations.csv
aura_rsp_windows_schemes.csv
aura_rsp_windows.json
epid_daa_results.json
logs\epid_build.log
logs\epid_benchmark.log
logs\python_benchmark.log
```

The official result snapshot committed to this repository is stored in
`results\`. When the benchmark is run again, the latest results are generated
in the repository root. After verification, they can be copied to `results\`
as a new published snapshot.

- `operations.csv`: the average execution time of each `T_*` primitive.
- `schemes.csv`: the total execution time of each scheme, calculated using the
  formulas in the comparison table.
- `json`: CPU, Windows, Python, and library versions, together with the raw
  results and calculation formulas.

## 7. Measurement Methodology for Genuine DAA in Di5Guise

Di5Guise uses a genuine DAA model at the protocol-design level, instantiated
with Intel EPID 2.0:

```text
2T_DH + T_PE + T_PD + T_S + T_V + T_DG + T_DV + 2T_AE + 2T_AD
```

The EPID parameters use a 256-bit Barreto-Naehrig pairing-friendly curve with
embedding degree 12 and a target security level of 128 bits. The official test
GID specifies SHA-256. The basename is set to `NULL, 0`, enabling random-base
mode so that signatures are anonymous and unlinkable. The official zero-entry
GroupRL, PrivRL, and SigRL are used. VerifierRL is not applicable in
random-base mode. The message length is fixed at 32 bytes.

Each online `EpidSign` call consumes exactly one single-use pre-signature
generated in advance by `EpidAddPreSigs`. For every measurement sample, the
program calls `EpidAddPreSigs(member, 1)` outside the `T_DG` timing window and
confirms that the pool size is one. It then times one `EpidSign` call and
confirms that the pool size returns to zero. The pre-signature generation cost
is recorded separately in the native JSON output and log using a matching
single-operation timing interval; it is not included in the Di5Guise online
formula. `T_DG` and `T_DV` are not replaced with Ed25519, ECDSA, BBS+, or a
simulated loop.

## 8. Recommendations for Stable Measurements

- Connect the laptop to AC power.
- Set the Windows power mode to **Best performance**.
- Close browsers, antivirus scans, and other resource-intensive background
  applications.
- Measure all primitives on the same computer with the same dependency set.
- For a formal experiment, run the complete benchmark three times and retain
  all three JSON files.
- In the paper, report the CPU model, Windows version, Python version, library
  versions, Profile size, and iteration count.
