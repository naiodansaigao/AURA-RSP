# Packaging and Validation Report

Status: **PASS**

## Included

- one shared `pysim-aura-integration` source tree containing Standard RSP and AURA-RSP modes;
- 13 independent experiment code directories;
- 13 compact reference-result directories, all reporting `PASS`;
- WSL setup, single-protocol, benchmark, single-experiment, all-experiment and acceptance runners;
- architecture, threat-model, dependency and reproducibility documentation;
- upstream GPL-2.0 license and provenance.

## Static validation

- 454 files checked before creation of `MANIFEST.sha256`;
- 165 Python files compiled successfully;
- 48 JSON files parsed successfully;
- 46 shell scripts passed LF/CRLF validation and WSL `bash -n` syntax checks;
- zero generated PEM files and zero private-key PEM markers;
- zero SQLite/database, log, PID, bytecode or cache artifacts;
- zero files larger than 10 MiB;
- no local absolute research-workspace path remains in text artifacts.

## Runtime validation in WSL2

- Standard RSP integrated download and notification: `STANDARD_PYSIM_INTEGRATION_ALL_PASS`;
- AURA-RSP integrated Profile download: `AURA_PYSIM_INTEGRATION_ALL_PASS`;
- representative relocated experiment smoke tests: Experiments 1, 7, 10 and 13 all returned `PASS`;
- generated certificates, runtime databases, logs, Profile outputs and smoke-test outputs were removed after validation.

## Intentionally excluded

- old standalone AURA-RSP implementation and old paper-artifact copy;
- duplicate historical `rsp-baseline` tree (Standard mode is already present in the shared integration tree);
- generated test private-key files, tickets, credentials, trace databases and service state;
- large per-request raw JSONL/CSV logs and build/cache directories;
- large upstream unit-test fixture tree not required by the paper artifact.

The test-certificate generator contains public deterministic GSMA-style test-vector scalars. They are intentionally non-secret and must never be used in production.
