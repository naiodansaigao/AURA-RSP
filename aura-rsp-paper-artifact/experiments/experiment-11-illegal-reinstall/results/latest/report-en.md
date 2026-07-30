# Experiment 11: Illegal Reinstall

- Experiment status: **PASS**
- Illegal subtests rejected: 8/8
- Machine assertions: 23/23

## Scenario results

| Scenario | Predecessor | Outcome | Reason | State changed | Profile installed |
|---|---|---|---|---:|---:|
| Reinstall directly from installed | installed | REJECT | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| Reinstall directly from enabled | enabled | REJECT | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| Reinstall directly from disabled | disabled | REJECT | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| Wrong lph from tombstone | tombstone | REJECT | `AUTHORIZATION_LPH_MISMATCH` | 0 | 0 |
| New salt_p | tombstone | REJECT | `REINSTALL_SALT_MISMATCH` | 0 | 0 |
| Old ticket | tombstone | REJECT | `TICKET_EXPIRED` | 0 | 0 |
| Replay old ReinstallReceipt | enabled | REJECT | `STALE_RECEIPT_REPLAY` | 0 | 0 |
| Tamper ctr or last_hash | tombstone | REJECT | `COUNTER_MISMATCH;LAST_HASH_MISMATCH` | 0 | 0 |
| Legal tombstone to installed | tombstone | ACCEPT | `ACCEPTED` | 1 | 1 |

## Conclusion

All eight illegal Reinstall subtests were rejected with zero unauthorized business executions. The counter/last_hash subtest contains two independent tamper attempts, both state-preserving.
The legal control continues the same lph/salt_p from tombstone, uses a fresh ticket, session, and Bind_t, decrypts and verifies the Profile with AES-GCM, then atomically reaches installed through a valid HMAC receipt, continuous counter, and predecessor hash.

## Boundary

The Standard baseline has no callable Reinstall state-chain interface, so it is reported as `UNSUPPORTED`, not as vulnerable.
