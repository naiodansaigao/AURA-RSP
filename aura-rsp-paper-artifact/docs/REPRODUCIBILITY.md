# Reproducibility Guide

## Recommended environment

- Windows 11 with WSL2;
- Ubuntu 24.04;
- Python 3.12;
- at least 4 CPU cores and 8 GiB RAM for the large matrix/load experiments.

## Clean setup

```bash
bash ./scripts/setup_wsl.sh
python3 ./scripts/verify_artifact.py
```

The setup script creates the virtual environment under `~/.venvs/pysim-aura-integration`. Generated keys and databases remain inside ignored runtime directories.

## Protocol demos

```bash
bash ./scripts/run_standard.sh
bash ./scripts/run_aura.sh
bash ./scripts/run_benchmark.sh 10
```

The paper-facing benchmark excludes service startup, uses an untimed warm-up, alternates client order, installs identical Profile bytes and asserts a common Profile SHA-256 digest. Do not mix its values with `benchmark_online.sh`, which uses a narrower online-protocol boundary.

## Experiments

```bash
bash ./scripts/run_experiment.sh 1
bash ./scripts/run_all_experiments.sh
```

Each experiment writes its own `results/latest/` directory. The runner stops immediately if an experiment exits non-zero. Fixed seeds and experiment-specific configuration are stored in each `config.json`.

## Reference results

`reference-results/` is a compact snapshot from the verified local runs. It is included for paper audit, not as a substitute for rerunning the code. Large raw JSONL/CSV logs are intentionally omitted from the GitHub artifact.
