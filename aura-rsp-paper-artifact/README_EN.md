# AURA-RSP pySim/osmo-smdpp Research Artifact

This repository contains the reproducible research prototype used in the paper's experiments. It does not consist of three unrelated simulators. Instead, it provides two operating modes within a shared Osmocom pySim/osmo-smdpp codebase:

- **Standard RSP**: the original ES9+ workflow, a software eUICC/LPA, Bound Profile Package download, and installation notification;
- **AURA-RSP**: anonymous credentials and operation tickets, a Privacy Relay, conditional tracing, Profile Binding, session-key binding, and complete lifecycle operations, implemented using the same SM-DP+, Profiles, host, and Python environment as Standard RSP;
- **13 independent experiments**: all experiments use the integrated codebase as their backend and do not depend on the previous standalone AURA-RSP simulation directory.

## Repository Structure

```text
.
├── pysim-aura-integration/   # Shared source code for Standard RSP and AURA-RSP
├── experiments/              # 13 independent experiments
├── reference-results/        # Validated summaries, assertions, and paper figures (large raw logs excluded)
├── scripts/                  # Setup, execution, acceptance, and manifest utilities
├── docs/                     # Architecture, experiment index, security scope, and reproduction guide
├── COPYING                   # GPL-2.0 license applicable to the pySim-derived code
└── MANIFEST.sha256           # Integrity manifest for the released artifact
```

## Quick Reproduction on WSL2 Ubuntu

Enter this directory from WSL2:

```bash
cd /path/to/aura-rsp-pysim-artifact
```

Install the dependencies and generate Standard RSP and AURA-RSP key material for **local testing only**:

```bash
bash ./scripts/setup_wsl.sh
```

Run Standard RSP:

```bash
bash ./scripts/run_standard.sh
```

Run AURA-RSP:

```bash
bash ./scripts/run_aura.sh
```

Run a 10-iteration comparison using the process-level timing boundary adopted in the paper:

```bash
bash ./scripts/run_benchmark.sh 10
```

Run a single experiment (Experiment 5, for example):

```bash
bash ./scripts/run_experiment.sh 5
```

Run all 13 experiments:

```bash
bash ./scripts/run_all_experiments.sh
```

Run the static validation checks for the artifact:

```bash
python3 ./scripts/verify_artifact.py
```

## Expected Success Markers

- Standard RSP: `STANDARD_PYSIM_INTEGRATION_ALL_PASS`
- AURA-RSP: `AURA_PYSIM_INTEGRATION_ALL_PASS`
- 13 experiments: the `status` field in each experiment's `results/latest/summary.json` contains its success marker. The successful attacks in Experiment 12C and Experiment 13 demonstrate explicitly defined threat-model boundaries and are not in-scope protocol security failures.

## Results and Sensitive Runtime Material

The `reference-results/` directory contains only the summaries, machine-readable assertions, and compact figures or tables needed for the paper. The following runtime-generated materials are excluded through `.gitignore`:

- test private keys, anonymous credentials, tickets, and tracing databases;
- SQLite databases, service PID files, network logs, and software-eUICC output;
- large per-request raw experiment data.

After cloning the repository, run `scripts/setup_wsl.sh` to generate the required test material locally. All certificates are intended exclusively for research testing and must not be used in a production mobile network.

## Research Scope

This is a research-grade, software-only prototype. It does not claim GSMA SGP.22/SGP.23 certification and does not replace a physical eUICC, a production EUM, SM-DS, or commercial GSMA PKI. See [docs/SECURITY_SCOPE.md](docs/SECURITY_SCOPE.md) and [docs/EXPERIMENT_INDEX.md](docs/EXPERIMENT_INDEX.md) for the detailed threat model and interpretation of the experiments.

## License and Citation

The integrated code is derived from Osmocom pySim. The upstream baseline commit is documented in `pysim-aura-integration/UPSTREAM.md`. The relevant code is distributed under GPL-2.0, whose full text is provided in `COPYING`. Before publishing the repository, the authors should add and confirm the appropriate personal or institutional copyright notices for the newly authored AURA-RSP and experiment files, complete `CITATION.cff.example`, and rename it to `CITATION.cff`.
