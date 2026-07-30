# Experiment 9: Capability Downgrade Results

- Status: **PASS**
- Network MITM attacks: 7/7 rejected
- Attack-path Profile deliveries: 0
- Machine assertions: 18/18

## Scenario results

| Scenario | Type | Result | Stage/reason | Profile delivered |
|---|---|---|---|---:|
| Tamper capability offer | Network MITM | REJECT | `capability_transcript / CAPABILITY_TRANSCRIPT_MISMATCH` | 0 |
| Tamper signed selection | Network MITM | REJECT | `server_authentication / INVALID_SERVER_AUTH_SIGNATURE` | 0 |
| Remove ML-KEM public key | Network MITM | REJECT | `client_key_exchange_signature / INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE` | 0 |
| Delete ML-KEM ciphertext | Network MITM | REJECT | `mlkem_server_material / MISSING_MLKEM_CIPHERTEXT` | 0 |
| Replace ML-KEM ciphertext | Network MITM | REJECT | `ctx_k_binding / MLKEM_CIPHERTEXT_HASH_MISMATCH` | 0 |
| Splice Classical ephemeral | Network MITM | REJECT | `server_key_exchange_signature / INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` | 0 |
| Relabel Hybrid as Classical | Network MITM | REJECT | `server_key_exchange_signature / INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` | 0 |
| Legitimate Classical / allow | Legitimate server policy | ACCEPT | `CLASSICAL_ALLOWED_BY_DEVICE_POLICY` | 1 |
| Legitimate Classical / require Hybrid | Legitimate server policy | REJECT | `device_policy / HYBRID_REQUIRED` | 0 |

## Conclusion and scope

No network mutation, material deletion, ciphertext replacement, or cross-mode splice established an attacker session key or delivered a Profile.
When a legitimately signing server selected Classical, a device that allowed Classical accepted it, while a device requiring Hybrid rejected with `HYBRID_REQUIRED` before Profile Binding and key establishment.
ML-KEM uses the real ML-KEM-768 implementation in `kyber-py 1.2.0`, which is educational and not constant-time. The current AURA port 9443 prototype remains Classical-only; this is an independent capability-layer extension.

## Machine assertions

18/18 PASS
