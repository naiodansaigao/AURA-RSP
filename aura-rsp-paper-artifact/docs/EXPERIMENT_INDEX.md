# Experiment Index

| No. | Directory | Main question | Expected conclusion |
|---:|---|---|---|
| 1 | `experiment-01-shared-smdpp-linkability` | Can a shared SM-DP+ link Profiles to the same eUICC? | Standard is linkable through stable identifiers; AURA approaches random pairwise linkage. |
| 2 | `experiment-02-collusion-log-leakage` | What history is recovered after collusion/log leakage? | AURA limits the radius to order/Profile lifecycle instead of device-wide history. |
| 3 | `experiment-03-ticket-transfer` | Can a stolen ticket be used by another valid device? | Secret binding gives non-transferability without revealing EID. |
| 4 | `experiment-04-double-spend-tracing` | Can replay be separated from true double spending? | Exact replay is idempotent; distinct valid transcripts trigger tracing. |
| 5 | `experiment-05-malicious-smdpp-framing` | Can a malicious server induce a second response and frame a device? | LocalTicketLog and context comparison prevent a second distinct valid response. |
| 6 | `experiment-06-lifecycle-resilience` | Are state replay, forks and delete message loss recoverable? | Authenticated state chain rejects replay/forks and supports idempotent recovery. |
| 7 | `experiment-07-cross-server-transplant` | Can authentication be moved to another SM-DP+? | Server/context binding rejects all tested transplantation. |
| 8 | `experiment-08-profile-operation-transplant` | Can authorization be moved across Profile or operation? | `pid_h` and `op` binding prevent reuse as a generic device pass. |
| 9 | `experiment-09-capability-downgrade` | Can Hybrid negotiation be downgraded or spliced? | Transcript binding rejects MITM modification; `require_hybrid` enforces device policy. |
| 10 | `experiment-10-profile-ciphertext-integrity` | Can encrypted or plaintext Profile content be replaced? | AEAD/session binding and post-decryption `H(P)=pid_h` prevent installation. |
| 11 | `experiment-11-illegal-reinstall` | Can reinstall bypass tombstone and chain continuity? | Only legal tombstone-to-installed reinstall with original lifecycle values succeeds. |
| 12 | `experiment-12-pr-source-address-privacy` | How much IP linkage does a shared PR remove? | Shared PR reduces SM-DP+-only IP linkage; PR collusion is an expected boundary. |
| 13 | `experiment-13-out-of-scope-secret-compromise` | Which guarantees fail after trust-root/endpoint compromise? | Outcomes are labelled expected out-of-scope compromise, not protocol failures. |

Every directory is standalone at the experiment level: it has its own `README.md`, `config.json`, `demo.py` and `run_demo.sh`, and writes only to its own results directory.
