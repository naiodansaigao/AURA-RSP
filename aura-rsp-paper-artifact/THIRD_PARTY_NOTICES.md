# Third-party notices

This artifact vendors clean source snapshots of the following upstream projects
to make the Standard RSP baseline reproducible. Build directories, Git history,
virtual environments, and generated APKs are not included.

| Component | Upstream | Pinned commit | License evidence |
|---|---|---|---|
| OpenEUICC | https://github.com/estkme-group/openeuicc | `2a85b8dad6000eea9dd622a468b7558e79933b2a` | `rsp-baseline/third_party/openeuicc/LICENSE` (GPL-3.0 text) |
| lpac | https://github.com/estkme-group/lpac | `3ff35594ec15062a3ed10c3da1c26eb0a13390b8` | License files are retained in each lpac component; AGPL-3.0 and LGPL-2.1 texts are present |
| pySim / osmo-smdpp | https://gitea.osmocom.org/sim-card/pysim | `25e43e1540144be9026a2733bc3a4271b8fa7d25` | `rsp-baseline/third_party/pysim/COPYING` (GPL-2.0 text) |

Python and system dependencies are not copied into this repository. Their pinned
package versions are listed in:

- `rsp-baseline/requirements-rsp.lock`
- `aura-rsp/requirements-aura.lock`
- `experiments/experiment-09-capability-downgrade/requirements-experiment9.lock`

The repository owner is responsible for checking all upstream notices and
license obligations before public distribution.

