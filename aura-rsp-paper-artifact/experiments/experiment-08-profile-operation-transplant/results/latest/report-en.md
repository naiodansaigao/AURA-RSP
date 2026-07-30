# Experiment 8: Profile and Operation Transplant

| Protocol | Scenario | Result | Rejection stage | Reason |
|---|---|---|---|---|
| AURA-RSP | profile_pid_h_plain_mutation | rejected | one_time_context_signature | INVALID_TAU_AUTH |
| AURA-RSP | profile_pid_h_resigned_envelope | rejected | anonymous_proof | INVALID_PI_AUTH |
| AURA-RSP | profile_a_bind_t_to_profile_b_session | rejected | profile_binding | BIND_T_MISMATCH |
| AURA-RSP | operation_download_to_delete | rejected | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| AURA-RSP | operation_download_to_reinstall | rejected | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| AURA-RSP | operation_download_to_enable | rejected | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| Standard RSP | modify_profile_hash_keep_binding_signature | rejected | bpp_signature | BPP_BINDING_SIGNATURE_INVALID |
| Standard RSP | profile_a_binding_to_profile_b_transaction | rejected | transaction_binding | SIGNED_TRANSACTION_MISMATCH |
| Standard RSP | replace_outer_and_signed_transaction | rejected | bpp_signature | BPP_BINDING_SIGNATURE_INVALID |

Machine assertions: 14/14 passed.

Conclusion: AURA-RSP anonymous authentication is bound to the Profile, operation, authentication transcript, and key session; it is not a generic device pass. The Standard control also rejects Profile transplantation, so this is a security regression test rather than a Standard vulnerability.
