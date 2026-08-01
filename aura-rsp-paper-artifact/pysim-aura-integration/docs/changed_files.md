# Integration change inventory

The source-only audit compares this tree with pySim commit
`25e43e1540144be9026a2733bc3a4271b8fa7d25`. Runtime keys, logs, generated PKI,
benchmark output, caches and Git metadata are excluded.

Core modified files:

- `osmo-smdpp.py`: startup mode, AURA route wiring, shared Profile repository;
- `contrib/es9p_client.py`: local test resolver, shared install evidence, and
  a one-process download-plus-notification command;
- `setup.py`: optional AURA dependency group and package registration;
- `README.md`, `.gitignore`: integration entry point and secret/output hygiene.

Shared additions:

- `pySim/esim/profile_store.py`
- `pySim/esim/software_euicc.py`
- `pySim/esim/measurement.py`

AURA additions are isolated under `pySim/esim/aura/`. Reproduction and
acceptance entry points are under `integration-scripts/`; design, mapping and
methodology documents are under `docs/`.

Generate the machine-readable diff statistic with:

```bash
python ./integration-scripts/source_audit.py \
  --baseline ../rsp-baseline/third_party/pysim \
  --integration . \
  --output results/source-diff-stat.json
```
