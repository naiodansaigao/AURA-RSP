# Security and threat-model scope

## In scope

- Stable EID/certificate/public-key linkability visible to a shared SM-DP+.
- MNO/Reseller and SM-DP+ log analysis or collusion.
- Stolen activation material and AURA operation tickets used by another honest
  eUICC.
- Exact replay, true ticket double spending, and conditional EUM tracing.
- Active SM-DP+ manipulation of transaction context.
- Cross-server, cross-Profile, cross-operation, and cross-session transplant.
- Capability downgrade and mode-splicing attacks.
- Profile ciphertext modification, replay, and malicious plaintext substitution.
- Lifecycle replay, fork, illegal reinstall, and delete recovery under loss.
- Source-address observation at SM-DP+ and PR–SM-DP+ collusion as a privacy
  boundary experiment.

## Outside the claimed guarantee

- Compromise of the EUM credential-issuing key.
- Compromise of the MNO ticket-issuing key.
- Compromise of SM-DP+ authentication or Profile Binding private keys.
- Compromise of GSMA root keys.
- Extraction of honest eUICC internal secrets or complete holder state.
- Disclosure of the EUM trace database.
- Pure message-blocking denial of service.
- A jointly malicious MNO and SM-DP+ defining an unauthorized Profile digest as
  the authorized order itself.
- PR and SM-DP+ collusion, or a global observer simultaneously seeing ingress
  and egress traffic, for source-address anonymity.

Experiment 13 intentionally demonstrates several of these failures and labels
them `EXPECTED OUT-OF-SCOPE COMPROMISE`. Experiment 12C labels PR–SM-DP+
collusion `EXPECTED_BOUNDARY_FAILURE`.

Standard RSP security controls that already reject tampered or transplanted
messages are treated as regression controls. The main privacy comparison is the
stable device identity exposed in normal Standard RSP authentication and logs.

