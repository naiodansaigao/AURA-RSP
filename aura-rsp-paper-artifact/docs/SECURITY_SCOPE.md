# Security and Threat-Model Scope

The experiments distinguish three categories:

1. **Privacy comparison:** Standard RSP normally exposes stable device authentication identifiers to the shared SM-DP+, while AURA-RSP limits visibility to the current order/Profile lifecycle.
2. **Security regression:** message, Profile, operation, server and session transplantation must be rejected by both a correct Standard RSP implementation and AURA-RSP. These are not described as Standard RSP vulnerabilities.
3. **Expected boundaries:** PR–SM-DP+ collusion/global traffic observation and compromise of root signing keys or honest eUICC secrets are outside AURA-RSP's guarantee.

In-scope adversaries may analyze or leak MNO/Reseller and SM-DP+ logs, collude across service roles, replay/tamper/transpose protocol messages, or operate a malicious but correctly keyed SM-DP+ within the experiment definition.

The following compromises are explicitly out of scope: EUM signing key, MNO ticket signing key, SM-DP+ signing key, GSMA root key, honest eUICC long-term secret, and confidentiality of the EUM tracing database. Pure message-blocking denial of service is not counted as a confidentiality or authentication failure.

Experiment 12C and Experiment 13 therefore report `EXPECTED ...` outcomes. Their purpose is to make the protection boundary explicit rather than to claim that the protocol should resist those compromises.
