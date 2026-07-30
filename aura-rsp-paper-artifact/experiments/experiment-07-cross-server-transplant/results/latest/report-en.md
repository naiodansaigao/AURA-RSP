# Experiment 7: Cross-Server Transplant

| Protocol | Scenario | Result | Rejection reason | Bind_t/BPP |
|---|---|---|---|---|
| AURA-RSP | direct_replay_to_server_b | rejected | UNKNOWN_TRANSACTION | not generated/not reached |
| AURA-RSP | modify_sid | rejected | INVALID_OR_EXPIRED_TICKET | not generated/not reached |
| AURA-RSP | modify_server_oid | rejected | INVALID_TAU_AUTH | not generated/not reached |
| AURA-RSP | modify_praddr | rejected | INVALID_OR_EXPIRED_TICKET | not generated/not reached |
| AURA-RSP | replace_target_address_only | rejected | SERVER_AUTH_SIGNATURE_MISMATCH | not generated/not reached |
| AURA-RSP | modify_cap | rejected | INVALID_TAU_AUTH | not generated/not reached |
| AURA-RSP | modify_transaction_nonce | rejected | INVALID_TAU_AUTH | not generated/not reached |
| Standard RSP | direct_replay_to_server_b | rejected | TRANSACTION_ID_UNKNOWN | not generated/not reached |
| Standard RSP | replace_outer_transaction_id | rejected | SERVER_CHALLENGE_MISMATCH | not generated/not reached |
| Standard RSP | modify_signed_server_address | rejected | EUICC_SIGNATURE_INVALID | not generated/not reached |
| Standard RSP | replace_target_address_only | rejected | TLS_HOSTNAME_MISMATCH | not generated/not reached |

Machine assertions: 13/13 passed.

Conclusion: AURA-RSP rejects cross-server transplantation through the target server's local session, unified context, ticket, one-time signature, and anonymous proof without exposing a stable device identity. The Standard control also rejects transplantation; this is a security regression test, not a Standard RSP vulnerability.
