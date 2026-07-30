# Dependencies

## Standard RSP

- Ubuntu build tools, OpenSSL, PC/SC, libcurl, Java 17;
- Python packages pinned in `rsp-baseline/requirements-rsp.lock`;
- vendored OpenEUICC, lpac, and pySim/osmo-smdpp snapshots;
- optional Android SDK for OpenEUICC APK builds.

## AURA-RSP

- Python 3.12;
- `py-ecc==8.0.0`;
- `cryptography==49.0.0`;
- `requests==2.34.2`;
- all transitive versions pinned in `aura-rsp/requirements-aura.lock`.

## Experiment 09

- `kyber-py==1.2.0`, pinned separately in
  `experiments/experiment-09-capability-downgrade/requirements-experiment9.lock`.

The artifact does not vendor Python wheels, system packages, virtual
environments, Android build outputs, or generated APKs.

