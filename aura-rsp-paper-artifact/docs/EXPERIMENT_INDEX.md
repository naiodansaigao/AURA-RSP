# Experiment index

| ID | Independent demo | Main property |
|---:|---|---|
| 01 | `experiment-01-shared-smdpp-linkability` | Shared SM-DP+ cross-Profile linkability |
| 02 | `experiment-02-collusion-log-leakage` | MNO/Reseller–SM-DP+ collusion and log leakage |
| 03 | `experiment-03-ticket-transfer` | Stolen ticket transfer across legitimate devices |
| 04 | `experiment-04-double-spend-tracing` | Replay-safe ticket spending and conditional tracing |
| 05 | `experiment-05-malicious-smdpp-framing` | Malicious SM-DP+ framing resistance |
| 06 | `experiment-06-lifecycle-resilience` | Lifecycle replay, fork control, and delete recovery |
| 07 | `experiment-07-cross-server-transplant` | Cross-server transcript transplant |
| 08 | `experiment-08-profile-operation-transplant` | Cross-Profile and cross-operation transplant |
| 09 | `experiment-09-capability-downgrade` | Hybrid/classical capability downgrade |
| 10 | `experiment-10-profile-ciphertext-integrity` | Ciphertext tamper, replay, and plaintext substitution |
| 11 | `experiment-11-illegal-reinstall` | Illegal and valid lifecycle reinstall |
| 12 | `experiment-12-pr-source-address-privacy` | PR source-address protection and collusion boundary |
| 13 | `experiment-13-out-of-scope-secret-compromise` | Root key, endpoint secret, and trace DB compromise |

Each directory contains:

- an independent `demo.py`;
- fixed `config.json`;
- one-command `run_demo.sh`;
- a Chinese README;
- `results/latest/` containing the recorded machine-readable evidence, with
  generated private keys and runtime databases removed from the public artifact.

Run one experiment:

```bash
bash experiments/<experiment-directory>/run_demo.sh
```

Run all:

```bash
bash scripts/run_all_experiments.sh
```

