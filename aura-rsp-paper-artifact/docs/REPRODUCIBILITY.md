# Reproducibility guide

## 1. Environment

The reference environment is WSL2 Ubuntu 24.04 with Python 3.12. The scripts
create isolated virtual environments under:

```text
$HOME/.venvs/rsp-baseline
$HOME/.venvs/aura-rsp
```

No virtual environment is stored in the Git repository.

## 2. Install

```bash
bash scripts/setup_wsl.sh
```

The command installs system packages, Standard RSP Python dependencies, AURA
dependencies, and the ML-KEM dependency used only by Experiment 09.

Vendored upstream source snapshots are already present. The pinned commits are
recorded in `rsp-baseline/VERSIONS.md`.

## 3. Standard RSP baseline

```bash
bash rsp-baseline/scripts/run_all.sh
```

Expected markers:

```text
SOFTWARE_RSP_BASELINE_PASS
INSTALL_NOTIFICATION_PASS
TLS_VERIFY_OK
RSP_BASELINE_ALL_PASS
```

The baseline runs osmo-smdpp and the pySim software eUICC/LPA download path.
OpenEUICC/lpac sources are provided for the implementation route and optional
hardware/Android integration, but the reproducible headless demo uses pySim.

## 4. AURA-RSP

```bash
bash aura-rsp/scripts/run_all.sh
```

Expected markers:

```text
AURA_CRYPTO_SELFTEST_PASS
AURA_RSP_DOWNLOAD_PASS
AURA_PROFILE_DOWNLOAD_EVIDENCE_OK
AURA_RSP_ALL_PASS
```

Runtime keys, SQLite databases, downloaded Profiles, and logs are generated
locally and are intentionally excluded from the public artifact.

## 5. Performance comparison

Keep the Standard SM-DP+ running, then execute:

```bash
bash scripts/run_benchmark.sh 10
```

The comparison uses the same 12,207-byte Profile. Service startup and offline
ticket issuance are excluded; TLS and the complete online download path are
included.

## 6. Security experiments

```bash
bash scripts/run_all_experiments.sh
```

Each experiment resets its own state and writes into its own `results/latest/`.
Recorded results shipped with this artifact are evidence snapshots, not a
substitute for rerunning the code.

Experiment 13:

```bash
bash experiments/experiment-13-out-of-scope-secret-compromise/run_demo.sh \
  --backend production
```

Use the production backend for BBS+ evidence. The portable fallback is clearly
labelled and must not be cited as a BBS+ implementation result.

## 7. Verification

```bash
python3 scripts/verify_artifact.py
sha256sum -c MANIFEST.sha256
```

The verifier checks directory completeness, Python syntax, JSON parsing,
experiment entry points, dependency manifests, and the absence of generated
runtime secrets outside the explicitly vendored pySim test fixtures.

