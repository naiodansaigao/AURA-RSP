# Experiment 13: Out-of-Scope Key and Endpoint Compromise

- Status: **PASS**
- Classification: `EXPECTED OUT-OF-SCOPE COMPROMISE`
- Issuer backend: `aura_production_bbs_plus`
- Machine assertions: 20/20

| Compromised asset | Alone sufficient | Effect observed | Classification |
|---|---:|---:|---|
| eUICC long-term secret x | no | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| Ticket witnesses eta,d | no | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| EUM issuing private key | yes | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| MNO ticket issuing key | yes | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| SM-DP+ signing/binding keys | yes | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| EUM tracing database | yes | yes | `EXPECTED OUT-OF-SCOPE COMPROMISE` |

## Interpretation

`x` and `eta,d` are hidden witnesses, not issuer signing keys. Their standalone
disclosure cannot forge EUM or MNO signatures. Endpoint cloning succeeds only
when the attacker also copies the matching issued credentials, ticket, `k`, and
other holder state.

EUM, MNO, and SM-DP+ private-key compromise respectively breaks credential
unforgeability, ticket unforgeability, and server/Profile-Binding authenticity.
Tracing-database disclosure exposes the test `k -> EID` map but grants no signing
capability.

This run used the production AURA BBS+ issuance and verification path.

## Conclusion

These observations delimit the assumptions under which AURA's claims apply;
they are not evidence that AURA remains secure after root trust or an honest
endpoint is compromised.
