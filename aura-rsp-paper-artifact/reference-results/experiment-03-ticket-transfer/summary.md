# Experiment 3 Results

Status: **PASS**

- Devices: 50
- Rounds: 10
- Legal controls per configuration: 500
- Cross-device attacks per configuration: 24500
- Total matrix records: 100000

| Configuration | Legal acceptance | Transfer proof generation | Transfer authentication | Profile delivery |
|---|---:|---:|---:|---:|
| AURA-RSP | 1.000 | 0.000 | 0.000 | 0.000 |
| AURA-RSP w/o secret binding | 1.000 | 1.000 | 1.000 | 1.000 |
| Standard RSP (EID pre-bound) | 1.000 | N/A | 0.000 | 0.000 |
| Standard RSP (unbound code) | 1.000 | N/A | 1.000 | 1.000 |

Full AURA-RSP accepted every owner control and rejected all 24,500 cross-device transfers before Profile delivery. The experiment-only no-secret-binding ablation accepted all transfers, isolating the contribution of the shared hidden witness x.

Concurrency latency is the prewarmed multi-process production proof-verifier CPU path, not HTTP round-trip latency. Pool startup and warmup are reported separately and excluded from online batches. Honest non-owner clients fail locally; forced invalid server submissions are measured only as defense-in-depth.
