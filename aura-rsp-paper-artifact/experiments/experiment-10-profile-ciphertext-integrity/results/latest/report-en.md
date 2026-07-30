# Experiment 10: Profile Ciphertext Tamper, Replay, and Plaintext Replacement

- Experiment status: **PASS**
- Security properties: 3/3
- Machine assertions: 17/17
- 10A and 10B: all rejected, with no installation or receipt
- 10C fixed client: wrong Profile rejected by the order pid_h check before installation and receipt

## Scenario results

| Scenario | Signature | AEAD | Order pid_h | Install | Receipt | Outcome |
|---|---:|---:|---:|---:|---:|---|
| Honest Session A | PASS | PASS | PASS | 1 | 1 | ACCEPT |
| Honest Session B | PASS | PASS | PASS | 1 | 1 | ACCEPT |
| 10A Ciphertext byte flip | FAIL | FAIL | N/C | 0 | 0 | REJECT / `INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` |
| 10A Cipher flip + white-box resign | PASS | FAIL | N/C | 0 | 0 | REJECT / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10A Tag flip + white-box resign | PASS | FAIL | N/C | 0 | 0 | REJECT / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10B Replay whole A package to B | FAIL | FAIL | N/C | 0 | 0 | REJECT / `CTX_K_MISMATCH` |
| 10B A ciphertext in B + resign | PASS | FAIL | N/C | 0 | 0 | REJECT / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10C Fixed client / wrong Profile | PASS | PASS | FAIL | 0 | 0 | REJECT / `PROFILE_ORDER_DIGEST_MISMATCH` |
| 10C Remove pid_h check / negative control | PASS | PASS | N/C | 1 | 1 | ACCEPT |
| MNO + SM-DP+ joint authorization | PASS | PASS | PASS | 1 | 1 | ACCEPT |

## 10C fix validation

The malicious SM-DP+ still encrypts Profile-B with the valid current session key and supplies Profile-B's own digest in the AAD and valid server signature. The signature, ctx_K, AEAD, and server-declared digest checks therefore all pass.
The fixed client then compares `H(Profile-B)` with the order commitment `ticket.pid_h = H(Profile-A)` and rejects with `PROFILE_ORDER_DIGEST_MISMATCH` before any file write or receipt.
The negative control with the order check deliberately removed still accepts, installs, and receipts Profile-B, confirming that the new check—not a broken attack fixture—causes the rejection.

## Boundary

If the MNO and SM-DP+ jointly place Profile-B's digest in the order, the order commitment and delivered plaintext agree, so the fixed check also passes. This remains a business authorization trust boundary.
