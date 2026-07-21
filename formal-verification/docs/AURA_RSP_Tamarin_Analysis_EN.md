# AURA-RSP Tamarin Formal Verification: Complete Model and Lemma Analysis

This document provides a file-by-file, rule-by-rule, and lemma-by-lemma analysis of the six AURA-RSP Tamarin models. It is intended for direct inclusion in the GitHub repository. The analysis follows the `.spthy` source code and explains the meaning of every lemma, its dependent events, the attacks it excludes, its modeling boundary, and the correct interpretation of a verified result.

## 1. Verification Scope and Overall Result

The six models contain **41 lemmas**:

- **7 executability (`exists-trace`) lemmas**, which demonstrate honest completion traces and prevent vacuous security results;
- **34 universal (`all-traces`) security lemmas**, covering authentication, authorization, context binding, secrecy, replay handling, conditional tracing, key establishment, and secure delivery.

All 41 lemmas were successfully verified by Tamarin. The recommended logical reading order is:

1. `aura_rsp_server_auth_scheme.spthy`: server authentication;
2. `aura_rsp_anon_ticket_auth_scheme.spthy`: credentials, tickets, and anonymous client authentication;
3. `aura_rsp_profile_binding_scheme.spthy`: Profile Binding;
4. `aura_rsp_trace_scheme.spthy`: conditional tracing after abnormal ticket reuse;
5. `aura_rsp_hybrid_scheme.spthy`: classic/hybrid key establishment;
6. `aura_rsp_download_scheme.spthy`: encrypted Profile delivery and installation confirmation.

Conditional tracing is an exceptional branch after anonymous authentication rather than a mandatory stage of the normal download path.

## 2. Modeling Assumptions and Boundaries

- BBS+ blind issuance, randomized proof of signature possession, and the joint NIZK are modeled as ideal unforgeable proof objects. Tamarin verifies protocol composition rather than reproving BBS+ unforgeability, blindness, or zero knowledge.
- `nullifier(eta)`, `profile_handle(pidh,salt_p,x)`, and `trace_response(d,k,gamma)` symbolically represent the relevant algebraic relations.
- Finite-field tracing extraction is represented by an ideal extraction rule enabled only by two distinct valid responses.
- ML-KEM is represented by an ideal encapsulation/decapsulation equation; its computational security is assumed.
- Credential and ticket expiration are represented by abstract validity facts rather than an explicit clock.
- PR forwarding and traffic correlation are not modeled. `PRaddr` remains bound as an order, signature, and transaction-context field.
- Enable, disable, delete, commit-delete, tombstone, and reinstall are outside the current models.
- A secrecy lemma is not equivalent to observational unlinkability across transactions.

## 3. Main Protocol-to-Model Mapping

| Protocol object | Tamarin representation | Meaning |
|---|---|---|
| $k=H_{tr}(EID\|r_{tr})$ | `h(<'trace-index',eid,rtr>)` | EUM tracing index |
| $\nu=g_\nu^\eta$ | `nullifier(eta)` | Ticket-stable double-spend detector |
| $lph=H_{lph}(pid_h\|salt_p)^x$ | `profile_handle(pidh,salt_p,x)` | Profile-local lifecycle handle |
| $c=d+\gamma k$ | `trace_response(d,k,Gamma)` | Conditional tracing response |
| $\gamma=H(ctx_t)$ | `h(<'gamma',Ctx>)` | Transaction challenge |
| $\tau_{auth}$ | `sign(h(<'auth',Ctx,Gamma,Resp>),skT)` | One-time transaction signature |
| $Bind_t$ | `sign(CtxB,skSp)` | SM-DP+ Profile-Binding signature |
| $K,K_{enc},K_{mac}$ | `kdf`, `kenc`, `kmac` | Master and domain-separated keys |
| AEAD Profile ciphertext | `aead(profile,Kenc,CtxK)` | Profile ciphertext bound to $ctx_K$ |
| Installation-receipt tag | `mac(Data,Kmac)` | Installation-state authenticity |

## 4. Interpreting Tamarin Results

- `verified` means that no trace violating the lemma was found under the current symbolic model and assumptions.
- `exists-trace verified` means that at least one reachable trace contains the target event.
- `all-traces verified` means that every reachable trace satisfies the first-order property.
- A result covers only the events and parameters explicitly quantified by its lemma; a secrecy result must not be overstated as complete anonymity or unlinkability.

## 5. Server Authentication and Capability-Transcript Binding

- **File:** `aura_rsp_server_auth_scheme.spthy`
- **Theory:** `AURA_RSP_Server_Auth_Scheme_V6`
- **Number of lemmas:** 4

This model corresponds to the server-authentication stage and directly represents
$\sigma_S^{auth}=\mathrm{Sig}_{SK_{Sa}}(I_t\|N_S\|N_U\|sid\|serverOID\|PRaddr\|cap)$.
The device emits `DeviceAcceptedServer` only after signature verification.

**Modeling boundary:** This model instantiates the hybrid capability transcript. Agreement between classic and hybrid modes is verified in the separate key-establishment model. PR forwarding is not modeled, while $PRaddr$ remains bound to the order and server signature.

### Rule Flow

| Rule | Role |
|---|---|
| `Setup_Server` | Generates the SM-DP+ server-authentication key pair and publishes the verification key. |
| `Create_Download_Order` | Creates a download order binding $I_{ac}$, $sid$, $pid_h$, $exp$, and $PRaddr$. |
| `Device_Send_Server_Authentication_Request` | The device generates $N_U$ and sends the order, routing field, and capability set. |
| `Server_Send_Authentication_Response` | The SM-DP+ generates $I_t$ and $N_S$ and signs the complete server-authentication context. |
| `Device_Accept_Authenticated_Server` | The device emits an acceptance event only after verifying the server signature. |

### Lemma-by-Lemma Analysis

#### 1. `exists_server_authentication`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_server_authentication:
exists-trace
  "Ex eid Iac sid It #i.
     ServerAuthenticationComplete(eid,Iac,sid,It) @ #i"
```

- **Formal meaning:** Shows that at least one trace completes server authentication.
- **Security effect:** It rules out vacuous proofs caused by an unreachable server-authentication branch and confirms that order creation, request, response, signature verification, and acceptance can occur in sequence.
- **Interpretation boundary:** This lemma is not itself an attack-resistance property; it provides the reachability basis for the universal lemmas.
- **Verification result:** `verified`

#### 2. `server_authentication_agreement`

- **Type:** Authentication agreement
- **Source definition:**

```tamarin
lemma server_authentication_agreement:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> (Ex #j.
            ServerAuthSent(Iac,sid,It,NS,NU,
                           serverOID,PRaddr,Cap) @ #j
          & #j < #i)"
```

- **Formal meaning:** Whenever the device accepts a server-authentication context, the SM-DP+ must previously have sent exactly the same context.
- **Security effect:** It binds $I_{ac}$, $sid$, $I_t$, $N_S$, $N_U$, $serverOID$, $PRaddr$, and $Cap$, excluding server impersonation, nonce substitution, transaction transplant, and cross-session replay of a signed response.
- **Interpretation boundary:** This is non-injective agreement: it establishes a matching send event but does not require distinct accepts to map to distinct sends.
- **Verification result:** `verified`

#### 3. `server_authentication_order_binding`

- **Type:** Order binding
- **Source definition:**

```tamarin
lemma server_authentication_order_binding:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> (Ex pidh exp #j.
            OrderCreated(Iac,sid,pidh,'download',exp,PRaddr) @ #j
          & #j < #i)"
```

- **Formal meaning:** A device acceptance must be preceded by creation of the same download order.
- **Security effect:** It prevents a server-authentication result from being used outside the order described by $I_{ac}$, $sid$, $pid_h$, $exp$, and $PRaddr$.
- **Interpretation boundary:** It proves correspondence with the order event and does not model a real business database or physical time.
- **Verification result:** `verified`

#### 4. `capability_transcript_binding`

- **Type:** Capability binding
- **Source definition:**

```tamarin
lemma capability_transcript_binding:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> Cap = capability('caps-hybrid','hybrid')"
```

- **Formal meaning:** The capability transcript accepted by the device must equal the hybrid transcript instantiated in this model.
- **Security effect:** It prevents substitution of the capability result inside the server-authentication response.
- **Interpretation boundary:** This file fixes the hybrid instance; two-mode agreement and cross-mode rejection are covered by the hybrid model.
- **Verification result:** `verified`

## 6. Anonymous Credential, One-Time Ticket, and Anonymous Client Authentication

- **File:** `aura_rsp_anon_ticket_auth_scheme(1).spthy`
- **Theory:** `AURA_RSP_Anon_Ticket_Auth_Scheme_V6`
- **Number of lemmas:** 14

This model covers offline credential issuance, the one-time operation ticket, the authenticated
server-session input, and anonymous client authentication. The relations are retained as
`nullifier(eta)`, `profile_handle(pidh,salt_p,x)`, and `trace_response(d,k,Gamma)`.
`ValidAnonProof` represents the joint proof of both BBS+ signatures, the common hidden $x$,
and the $\nu$, $lph$, and $c$ relations.

**Modeling boundary:** BBS+ blind issuance and the joint randomized zero-knowledge proof are idealized by issuer state and the private fact `ValidAnonProof`. Credential and ticket expiration are represented by abstract validity facts rather than an explicit physical clock.

### Rule Flow

| Rule | Role |
|---|---|
| `Create_Order_Context` | Creates the public order context carried by the ticket. |
| `Offline_Register_And_Issue_Credential` | Registers the device and creates the credential state containing the same $x$, $k$, and $cred_{exp}$. |
| `Issue_One_Time_Operation_Ticket` | Issues a one-time ticket for the current order with hidden $x$, $\eta$, and $d$. |
| `Establish_Authenticated_Server_Session` | Abstracts the preceding server-authentication stage and establishes $I_t$, $N_S$, $N_U$, and $cap$. |
| `Device_Generate_Anonymous_Authentication` | Constructs $\nu$, $lph$, $ctx_t$, $\gamma$, $c$, $\tau_{auth}$, and the idealized $\Pi_{auth}$. |
| `Server_Accept_Fresh_Anonymous_Authentication` | Verifies the proof, temporary signature, and validity facts, and consumes the unused nullifier. |
| `Server_Process_Exact_Replay` | Handles an exact retransmission of an already accepted authentication message idempotently. |

### Lemma-by-Lemma Analysis

#### 1. `exists_anonymous_authentication`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_anonymous_authentication:
exists-trace
  "Ex eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i"
```

- **Formal meaning:** Shows a successful trace containing credential issuance, ticket issuance, server session establishment, joint proof generation, temporary signing, and fresh-nullifier acceptance.
- **Security effect:** It confirms that the anonymous-authentication branch is reachable and prevents later properties from holding only because the server can never accept.
- **Interpretation boundary:** It does not by itself state a security guarantee.
- **Verification result:** `verified`

#### 2. `anonymous_authentication_soundness`

- **Type:** Anonymous-authentication soundness
- **Source definition:**

```tamarin
lemma anonymous_authentication_soundness:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp #c.
            CredentialIssued(eid,x,k,cred_exp) @ #c & #c < #i)
       & (Ex eta d #t.
            TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #t < #i)"
```

- **Formal meaning:** An SM-DP+ acceptance necessarily corresponds to an earlier EUM credential issuance and an earlier MNO/Reseller ticket issuance.
- **Security effect:** It excludes authentication without a valid credential, without a ticket for the current order, or through an attacker-created `ValidAnonProof`.
- **Interpretation boundary:** It relies on the ideal unforgeability abstraction of BBS+ and the joint NIZK and does not reprove the underlying BBS+ security.
- **Verification result:** `verified`

#### 3. `ticket_non_transferability`

- **Type:** Ticket non-transferability
- **Source definition:**

```tamarin
lemma ticket_non_transferability:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp eta d #c #t.
            CredentialIssued(eid,x,k,cred_exp) @ #c
          & TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #c < #i & #t < #i)"
```

- **Formal meaning:** The matching credential and ticket issuance events must contain the same hidden secret $x$.
- **Security effect:** It prevents combining device A's credential with device B's ticket or transferring a stolen ticket to another legitimate device.
- **Interpretation boundary:** The guarantee assumes that the eUICC secret $x$ remains secret and that the joint proof is sound.
- **Verification result:** `verified`

#### 4. `minimal_authorization_context_binding`

- **Type:** Minimal-authorization context binding
- **Source definition:**

```tamarin
lemma minimal_authorization_context_binding:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex eta d #t.
            TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #t < #i)"
```

- **Formal meaning:** An accepted authentication must correspond to a ticket issued over exactly the same public order fields.
- **Security effect:** It binds $I_{ac}$, $sid$, $pid_h$, $op$, $exp$, and $PRaddr$, excluding cross-order, cross-server, cross-Profile, cross-operation, and cross-route ticket use.
- **Interpretation boundary:** `exp` is a signed and checked field; passage of time is represented by abstract validity facts.
- **Verification result:** `verified`

#### 5. `authentication_signature_is_verified`

- **Type:** Temporary authentication-signature verification
- **Source definition:**

```tamarin
lemma authentication_signature_is_verified:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex Gamma Resp.
            AuthenticationSignatureVerified(VkT,Ctx,Gamma,Resp) @ #i)"
```

- **Formal meaning:** Every anonymous-authentication acceptance is accompanied by successful verification of $\tau_{auth}$.
- **Security effect:** It binds $vk_t$, $ctx_t$, $\gamma$, and $c$, excluding response substitution or use of a mismatching temporary public key.
- **Interpretation boundary:** The verification event occurs at the same rule time as acceptance, meaning that verification is a necessary acceptance condition.
- **Verification result:** `verified`

#### 6. `accepted_authentication_uses_valid_credential_and_ticket`

- **Type:** Validity checking
- **Source definition:**

```tamarin
lemma accepted_authentication_uses_valid_credential_and_ticket:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp #c.
            CredentialValidityEstablished(eid,cred_exp) @ #c
          & #c < #i)
       & (Ex #t. TicketValidityEstablished(Iac,exp) @ #t
          & #t < #i)"
```

- **Formal meaning:** Credential-validity and ticket-validity facts must have been established before authentication is accepted.
- **Security effect:** It excludes an expired or revoked credential/ticket from directly reaching the acceptance rule in the symbolic model.
- **Interpretation boundary:** This is an abstract validity check rather than an analysis of wall-clock time, revocation-distribution delay, or clock synchronization.
- **Verification result:** `verified`

#### 7. `profile_handle_bound_to_credential_secret`

- **Type:** Profile-handle binding
- **Source definition:**

```tamarin
lemma profile_handle_bound_to_credential_secret:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex #j.
            DeviceAuthGenerated(eid,x,k,Iac,sid,pidh,op,exp,
                                PRaddr,Nf,Lph,opid,VkT,Ctx) @ #j
          & #j < #i)"
```

- **Formal meaning:** The accepted $lph$ must originate from a prior device-authentication generation event linked to the same $x$, $pid_h$, and transaction context.
- **Security effect:** It prevents another device from claiming the target Profile-lifecycle handle and prevents substitution of a handle from a different Profile.
- **Interpretation boundary:** The discrete-log relation is represented ideally by `profile_handle(pidh,salt_p,x)`.
- **Verification result:** `verified`

#### 8. `nullifier_single_business_acceptance`

- **Type:** One-time business execution
- **Source definition:**

```tamarin
lemma nullifier_single_business_acceptance:
"All Nf Ctx1 Ctx2 #i #j.
     BusinessAccepted(Nf,Ctx1) @ #i
   & BusinessAccepted(Nf,Ctx2) @ #j
     ==> #i = #j"
```

- **Formal meaning:** Two `BusinessAccepted` events under the same nullifier must be the same event.
- **Security effect:** It ensures that one ticket triggers at most one real business acceptance even under concurrent replay and message reordering.
- **Interpretation boundary:** It does not prohibit idempotent processing of an identical message; replay handling is modeled separately.
- **Verification result:** `verified`

#### 9. `exact_replay_is_idempotent`

- **Type:** Exact-replay idempotence
- **Source definition:**

```tamarin
lemma exact_replay_is_idempotent:
"All Nf Ctx #i.
     ExactReplayProcessed(Nf,Ctx) @ #i
     ==> not (Ex Ctx2 #j.
                BusinessAccepted(Nf,Ctx2) @ #j & #i < #j)"
```

- **Formal meaning:** After an exact replay is processed, no later new business acceptance can occur for the same nullifier.
- **Security effect:** It separates network retransmission from a new business execution, preventing packet-loss recovery from causing duplicate downloads or duplicate state changes.
- **Interpretation boundary:** It applies to the identical `Mauth`; a different valid reuse of the same ticket is analyzed in the tracing model.
- **Verification result:** `verified`

#### 10. `eid_secrecy`

- **Type:** EID secrecy
- **Source definition:**

```tamarin
lemma eid_secrecy:
"All eid #i.
     SecretEID(eid) @ #i ==> not (Ex #j. K(eid) @ #j)"
```

- **Formal meaning:** The adversary cannot derive the EID.
- **Security effect:** It verifies that online messages and model state do not reveal the real device identity to the network adversary.
- **Interpretation boundary:** It is not observational unlinkability and does not analyze external metadata.
- **Verification result:** `verified`

#### 11. `x_secrecy`

- **Type:** Long-term-secret secrecy
- **Source definition:**

```tamarin
lemma x_secrecy:
"All x #i.
     SecretX(x) @ #i ==> not (Ex #j. K(x) @ #j)"
```

- **Formal meaning:** The adversary cannot derive the eUICC's long-term anonymous secret $x$.
- **Security effect:** It protects credential-ticket non-transferability and the secret exponent used in $lph$.
- **Interpretation boundary:** It excludes direct extraction after eUICC hardware compromise.
- **Verification result:** `verified`

#### 12. `eta_secrecy`

- **Type:** Ticket-randomness secrecy
- **Source definition:**

```tamarin
lemma eta_secrecy:
"All eta #i.
     SecretEta(eta) @ #i ==> not (Ex #j. K(eta) @ #j)"
```

- **Formal meaning:** The adversary cannot recover $\eta$ from the public nullifier.
- **Security effect:** It preserves nullifier randomness across tickets and protects the exponent secret.
- **Interpretation boundary:** It relies on the ideal one-way abstraction of `nullifier/1`.
- **Verification result:** `verified`

#### 13. `d_secrecy`

- **Type:** Tracing-offset secrecy
- **Source definition:**

```tamarin
lemma d_secrecy:
"All d #i.
     SecretD(d) @ #i ==> not (Ex #j. K(d) @ #j)"
```

- **Formal meaning:** The adversary cannot obtain the ticket-fixed tracing offset $d$.
- **Security effect:** It ensures that one value $c=d+\gamma k$ does not directly expose the tracing index $k$.
- **Interpretation boundary:** This lemma proves that $d$ is not disclosed; single-response non-traceability is additionally supported by the tracing model.
- **Verification result:** `verified`

#### 14. `temporary_signing_key_secrecy`

- **Type:** One-time private-key secrecy
- **Source definition:**

```tamarin
lemma temporary_signing_key_secrecy:
"All skT #i.
     SecretTemporarySigningKey(skT) @ #i
     ==> not (Ex #j. K(skT) @ #j)"
```

- **Formal meaning:** The adversary cannot obtain $sk_t$.
- **Security effect:** It prevents forgery of $\tau_{auth}$ and later device-side key-establishment signatures.
- **Interpretation boundary:** It does not model direct compromise of temporary-key storage inside the eUICC.
- **Verification result:** `verified`

## 7. Transaction-Bound Profile Binding

- **File:** `aura_rsp_profile_binding_scheme.spthy`
- **Theory:** `AURA_RSP_Profile_Binding_Scheme_V6`
- **Number of lemmas:** 4

This model directly represents
$th_{auth}=H(\text{"auth-transcript"}\|ctx_t\|H(M_U^{auth}))$,
$ctx_{bind}=H(\text{"bind"}\|ctx_t\|th_{auth})$, and
$Bind_t=\mathrm{Sig}_{SK_{Sp}}(ctx_{bind})$.

**Modeling boundary:** The anonymous-authentication and Profile-Binding models are verified compositionally. This file does not repeat credential and ticket processing; instead, it starts from an already accepted anonymous-authentication context.

### Rule Flow

| Rule | Role |
|---|---|
| `Setup_Profile_Binding_Key` | Generates the SM-DP+ Profile-Binding signing key. |
| `Establish_Accepted_Anonymous_Context` | Introduces the already accepted complete $ctx_t$ and $M_U^{auth}$ as the module input. |
| `Server_Create_Profile_Binding` | Computes $th_{auth}$ and $ctx_{bind}$ and generates $Bind_t$. |
| `Device_Accept_Profile_Binding` | The device accepts the binding result only after verifying $Bind_t$. |

### Lemma-by-Lemma Analysis

#### 1. `exists_profile_binding`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_profile_binding:
exists-trace
  "Ex eid sid Ctx Bind #i.
     BoundProtocolComplete(eid,sid,Ctx,Bind) @ #i"
```

- **Formal meaning:** Shows that after anonymous authentication is accepted, the server can generate $Bind_t$ and the device can verify it.
- **Security effect:** It confirms that the Profile-Binding module is reachable.
- **Interpretation boundary:** It does not by itself state binding security.
- **Verification result:** `verified`

#### 2. `profile_binding_agreement`

- **Type:** Profile-Binding agreement
- **Source definition:**

```tamarin
lemma profile_binding_agreement:
"All eid sid serverOID Order Ctx CtxB Bind #i.
     DeviceAcceptedBinding(eid,sid,serverOID,Order,Ctx,CtxB,Bind) @ #i
     ==> (Ex #j.
            ServerCreatedBinding(sid,serverOID,Order,Ctx,CtxB,Bind) @ #j
          & #j < #i)"
```

- **Formal meaning:** Every binding accepted by the device must match an earlier server creation event with the same `Order`, $Ctx$, $CtxB$, and `Bind`.
- **Security effect:** It excludes forgery of $Bind_t$, substitution of the binding digest, and injection of a binding not created by the server.
- **Interpretation boundary:** It relies on ideal digital-signature and hash security.
- **Verification result:** `verified`

#### 3. `binding_uses_accepted_anonymous_context`

- **Type:** Dependence on accepted anonymous authentication
- **Source definition:**

```tamarin
lemma binding_uses_accepted_anonymous_context:
"All eid sid serverOID Order Ctx CtxB Bind #i.
     DeviceAcceptedBinding(eid,sid,serverOID,Order,Ctx,CtxB,Bind) @ #i
     ==> (Ex Iac pidh lph nu VkT Cap #j.
            AnonymousAuthenticationAccepted(eid,sid,Iac,pidh,Ctx,
                                            lph,nu,VkT,Cap) @ #j
          & #j < #i)"
```

- **Formal meaning:** Before a device accepts $Bind_t$, there must be an anonymous-authentication acceptance event for the same device, server, order, and $ctx_t$.
- **Security effect:** It prevents the server path from bypassing credential/ticket verification and creating an acceptable binding for an arbitrary context.
- **Interpretation boundary:** Because the verification is compositional, the anonymous-authentication event is introduced as an input abstraction in this file.
- **Verification result:** `verified`

#### 4. `binding_cannot_cross_contexts`

- **Type:** Cross-context non-transferability
- **Source definition:**

```tamarin
lemma binding_cannot_cross_contexts:
"All eid1 eid2 sid serverOID Order1 Order2 Ctx1 Ctx2
       CtxB1 CtxB2 Bind #i #j.
     DeviceAcceptedBinding(eid1,sid,serverOID,Order1,Ctx1,CtxB1,Bind) @ #i
   & DeviceAcceptedBinding(eid2,sid,serverOID,Order2,Ctx2,CtxB2,Bind) @ #j
     ==> Ctx1 = Ctx2 & Order1 = Order2"
```

- **Formal meaning:** If the same `Bind` is accepted twice, both accepts must use the same $Ctx$ and `Order`.
- **Security effect:** It excludes reuse of one binding across different orders, Profiles, or authentication transcripts.
- **Interpretation boundary:** It permits legitimate retransmission of the same binding message but not a change in its semantic context.
- **Verification result:** `verified`

## 8. Conditional Traceability and Non-Frameability

- **File:** `aura_rsp_trace_scheme.spthy`
- **Theory:** `AURA_RSP_Trace_Scheme_V6`
- **Number of lemmas:** 6

This model analyzes conditional tracing after reuse of the same ticket. The first response is cached;
an identical message is treated as a replay; and the server can create `TraceEvidence` only after
a second valid response with a distinct challenge.

**Modeling boundary:** The finite-field extraction formula $k=(c-c')(\gamma-\gamma')^{-1}$ is represented by an ideal extraction rule that can be enabled only after two distinct valid responses under the same $\nu$ exist.

### Rule Flow

| Rule | Role |
|---|---|
| `Register_Device` | Creates the credential record and the tracing map $k\mapsto EID$. |
| `Issue_Ticket` | Generates $\eta$, $d$, and $\nu$ fixed to the same ticket. |
| `Device_First_Valid_Response` | Generates and caches the first complete valid response for the ticket. |
| `Device_Return_Cached_Response` | Returns only the cached message for the same operation instance. |
| `Device_Reuse_Ticket_For_New_Operation` | Models reuse of the same ticket under a new $opid$ and transaction context. |
| `Server_Accept_First_Response` | Accepts the first valid response and records the used nullifier. |
| `Server_Process_Exact_Replay` | Recognizes an identical message as an exact replay. |
| `Server_Detect_Double_Spend` | Creates tracing evidence only when the second response is valid and uses a distinct challenge. |
| `EUM_Resolve` | The EUM resolves the EID by looking up the recovered $k$ in the tracing map. |

### Lemma-by-Lemma Analysis

#### 1. `exists_conditional_trace`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_conditional_trace:
exists-trace
  "Ex eid Nu k #i. ConditionalTraceComplete(eid,Nu,k) @ #i"
```

- **Formal meaning:** Shows that after one ticket produces two distinct valid responses under different operation instances, the server can create tracing evidence and the EUM can resolve the identity.
- **Security effect:** It confirms that the conditional-tracing path is reachable rather than only proving non-traceability conditions.
- **Interpretation boundary:** The trace models malicious or policy-violating ticket reuse; normal honest execution does not necessarily trigger tracing.
- **Verification result:** `verified`

#### 2. `tracing_requires_two_distinct_valid_responses`

- **Type:** Two-response tracing condition
- **Source definition:**

```tamarin
lemma tracing_requires_two_distinct_valid_responses:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> (Ex opid1 opid2 Ctx1 Ctx2 G1 G2 C1 C2 #j #m.
            ServerAcceptedValidResponse(Nu,opid1,Ctx1,G1,C1,k,M1) @ #j
          & ServerAcceptedValidResponse(Nu,opid2,Ctx2,G2,C2,k,M2) @ #m
          & #j < #i & #m < #i
          & not (G1 = G2))"
```

- **Formal meaning:** Every identity resolution must be supported by two server-accepted valid responses with distinct challenges.
- **Security effect:** It ensures that one server transcript is insufficient for tracing and that evidence arises from genuine double use of the same nullifier.
- **Interpretation boundary:** Finite-field extraction is idealized; the lemma verifies the protocol conditions under which extraction can be enabled.
- **Verification result:** `verified`

#### 3. `trace_resolves_issued_device`

- **Type:** Correct tracing resolution
- **Source definition:**

```tamarin
lemma trace_resolves_issued_device:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> (Ex x cred_exp #j.
            CredentialIssued(eid,x,k,cred_exp) @ #j & #j < #i)"
```

- **Formal meaning:** The resolved EID must correspond to the same tracing index $k$ recorded by the EUM when the credential was issued.
- **Security effect:** It prevents tracing from resolving to an unregistered device or mapping device A's evidence to device B.
- **Interpretation boundary:** It assumes that the EUM `TraceMap` is complete and uncompromised.
- **Verification result:** `verified`

#### 4. `same_opid_is_non_frameable`

- **Type:** Non-frameability under the same operation identifier
- **Source definition:**

```tamarin
lemma same_opid_is_non_frameable:
"All eid Nu opid Ctx1 Ctx2 G1 G2 C1 C2 k M1 M2 #i #j.
     DeviceValidResponse(eid,Nu,opid,Ctx1,G1,C1,k,M1) @ #i
   & DeviceValidResponse(eid,Nu,opid,Ctx2,G2,C2,k,M2) @ #j
     ==> Ctx1 = Ctx2 & M1 = M2"
```

- **Formal meaning:** If an honest device produces two valid responses for the same $\nu$ and `opid`, their contexts and complete messages must be identical.
- **Security effect:** It prevents a malicious server from changing nonces, challenges, or capability context under the same operation instance to induce two extractable responses.
- **Interpretation boundary:** A genuinely new operation may use a new `opid`; illicit ticket reuse under a new identifier remains traceable.
- **Verification result:** `verified`

#### 5. `exact_replay_does_not_create_trace`

- **Type:** Exact replay does not trigger tracing
- **Source definition:**

```tamarin
lemma exact_replay_does_not_create_trace:
"All Nu opid Ctx Msg #i.
     ExactReplayProcessed(Nu,opid,Ctx,Msg) @ #i
     ==> not (Ex eid k #j.
                IdentityResolved(eid,Nu,k,Msg,Msg) @ #j)"
```

- **Formal meaning:** A message classified as an exact replay cannot cause identity resolution using the pair `(Msg,Msg)`.
- **Security effect:** It prevents network duplication, timeout recovery, or attacker copying of one message from being misclassified as double spending.
- **Interpretation boundary:** It does not protect two distinct valid double-spend responses, which are intentionally traceable.
- **Verification result:** `verified`

#### 6. `no_trace_from_single_accepted_response`

- **Type:** No tracing from one response
- **Source definition:**

```tamarin
lemma no_trace_from_single_accepted_response:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> not (M1 = M2)"
```

- **Formal meaning:** The two messages used in every identity-resolution event must be distinct.
- **Security effect:** It ensures that copying a single accepted response cannot satisfy the tracing condition.
- **Interpretation boundary:** Together with the distinct-challenge lemma, it establishes that tracing requires two genuinely different valid transcripts.
- **Verification result:** `verified`

## 9. Classic/Hybrid Authenticated Key Establishment

- **File:** `aura_rsp_hybrid_scheme.spthy`
- **Theory:** `AURA_RSP_Hybrid_Scheme_V6`
- **Number of lemmas:** 7

This model contains both the classic ECDHE branch and the ECDHE+ML-KEM hybrid branch.
The capability transcript is inserted into $ctx_t$ and bound by $Bind_t$; device and server
key-establishment signatures cover the ECDHE/KEM materials required by the protocol.

**Modeling boundary:** ML-KEM is modeled using `kem_enc/kem_dec` and an ideal decapsulation equation; its computational security is not reproved in Tamarin. The selected mode is included in $ctx_t$ and bound by $Bind_t$.

### Rule Flow

| Rule | Role |
|---|---|
| `Setup` | Generates the server Profile-Binding/key-establishment signing key. |
| `Create_Unselected_Bound_Context` | Creates a bound context before classic or hybrid mode is selected. |
| `Select_Classic_Bound_Context` | Places the classic capability transcript in $ctx_t$ and signs it to produce $Bind_t$. |
| `Select_Hybrid_Bound_Context` | Places the hybrid capability transcript in $ctx_t$ and signs it to produce $Bind_t$. |
| `Device_Send_Classic_KA` | Sends the ECDHE public key and a classic request authenticated by $sk_t$. |
| `Server_Accept_Classic_KA` | Verifies the request, generates $Q_S$, and derives the classic session key. |
| `Device_Accept_Classic_KA` | Verifies the server signature and derives the same classic key. |
| `Device_Send_Hybrid_KA` | Sends both the ECDHE public key and the ML-KEM public key. |
| `Server_Accept_Hybrid_KA` | Performs ECDHE and KEM encapsulation and derives the hybrid key. |
| `Device_Accept_Hybrid_KA` | Decapsulates the KEM ciphertext and derives the same hybrid key. |

### Lemma-by-Lemma Analysis

#### 1. `exists_classic_key_agreement`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_classic_key_agreement:
exists-trace
  "Ex eid sid Iac CtxK K #i.
     ClassicComplete(eid,sid,Iac,CtxK,K) @ #i"
```

- **Formal meaning:** Shows that the classic ECDHE path can complete and emit `ClassicComplete`.
- **Security effect:** It confirms reachability of mode selection, signature verification, and key derivation.
- **Interpretation boundary:** It does not by itself state key security.
- **Verification result:** `verified`

#### 2. `exists_hybrid_key_agreement`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_hybrid_key_agreement:
exists-trace
  "Ex eid sid Iac CtxK K #i.
     HybridComplete(eid,sid,Iac,CtxK,K) @ #i"
```

- **Formal meaning:** Shows that the ECDHE+ML-KEM hybrid path can complete and emit `HybridComplete`.
- **Security effect:** It confirms reachability of KEM public-key handling, ciphertext generation, decapsulation, and hybrid KDF processing.
- **Interpretation boundary:** It does not reprove ML-KEM computational security.
- **Verification result:** `verified`

#### 3. `key_agreement_mode_and_transcript_agreement`

- **Type:** Mode and transcript agreement
- **Source definition:**

```tamarin
lemma key_agreement_mode_and_transcript_agreement:
"All eid sid Iac mode Cap CtxK K QU QS PkPQ CtPQ #i.
     DeviceDerived(eid,sid,Iac,mode,Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #i
     ==> (Ex #j.
            ServerDerived(sid,Iac,mode,Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #j
          & #j < #i)"
```

- **Formal meaning:** Whenever the device derives a key, the server must previously have derived the same result under the same mode, capability transcript, $ctx_K$, key, and all key-establishment materials.
- **Security effect:** It excludes public-key substitution, KEM-ciphertext replacement, cross-session response replay, unknown-key share, and mixing of mode-specific materials.
- **Interpretation boundary:** This is device-to-server agreement; server acceptance of the device request is enforced by signature verification in the rules.
- **Verification result:** `verified`

#### 4. `hybrid_acceptance_requires_hybrid_capability_transcript`

- **Type:** Hybrid capability consistency
- **Source definition:**

```tamarin
lemma hybrid_acceptance_requires_hybrid_capability_transcript:
"All eid sid Iac Cap CtxK K QU QS PkPQ CtPQ #i.
     DeviceDerived(eid,sid,Iac,'hybrid',Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #i
     ==> Cap = cap_transcript('caps-hybrid','hybrid')"
```

- **Formal meaning:** A device can accept a hybrid key only when the bound capability transcript explicitly selects hybrid.
- **Security effect:** It prevents PQ material from being injected under a classic capability context or a hybrid result from being transplanted from another context.
- **Interpretation boundary:** The negotiation policy is abstracted as `cap_transcript`; UI or external policy errors are not modeled.
- **Verification result:** `verified`

#### 5. `classic_acceptance_requires_classic_capability_transcript`

- **Type:** Classic capability consistency
- **Source definition:**

```tamarin
lemma classic_acceptance_requires_classic_capability_transcript:
"All eid sid Iac Cap CtxK K QU QS #i.
     DeviceDerived(eid,sid,Iac,'classic',Cap,CtxK,K,QU,QS,
                   'none','none') @ #i
     ==> Cap = cap_transcript('caps-classic','classic')"
```

- **Formal meaning:** A device can accept a classic key only when the transcript explicitly selects classic and the PQ fields are `none`.
- **Security effect:** It prevents a hybrid context from being silently interpreted as classic and rules out leftover PQ material.
- **Interpretation boundary:** It does not decide whether policy should prefer hybrid; it verifies consistency with the selected mode.
- **Verification result:** `verified`

#### 6. `no_cross_mode_key_acceptance`

- **Type:** No cross-mode acceptance
- **Source definition:**

```tamarin
lemma no_cross_mode_key_acceptance:
"All eid sid Iac Cap1 Cap2 CtxK1 CtxK2 K1 K2
       QU1 QU2 QS1 QS2 P1 P2 C1 C2 #i #j.
     DeviceDerived(eid,sid,Iac,'classic',Cap1,CtxK1,K1,
                   QU1,QS1,P1,C1) @ #i
   & DeviceDerived(eid,sid,Iac,'hybrid',Cap2,CtxK2,K2,
                   QU2,QS2,P2,C2) @ #j
     ==> F"
```

- **Formal meaning:** The same device, server, and order cannot produce both classic and hybrid device-key-acceptance events.
- **Security effect:** It excludes splicing signatures, key materials, or contexts from two modes into dual acceptance.
- **Interpretation boundary:** The property is also supported structurally by the one-time mode-selection state in the model.
- **Verification result:** `verified`

#### 7. `key_secrecy`

- **Type:** Key secrecy
- **Source definition:**

```tamarin
lemma key_secrecy:
"All key #i.
     SecretKAKey(key) @ #i
     ==> not (Ex #j. K(key) @ #j)"
```

- **Formal meaning:** The adversary cannot derive any marked $K$, $K_{enc}$, or $K_{mac}$.
- **Security effect:** It protects the classic and hybrid session keys and their domain-separated subkeys.
- **Interpretation boundary:** It excludes endpoint compromise, RNG failure, and computational attacks on the underlying DH or KEM.
- **Verification result:** `verified`

## 10. Encrypted Profile Delivery and Installation Confirmation

- **File:** `aura_rsp_download_scheme.spthy`
- **Theory:** `AURA_RSP_Download_Scheme_V6`
- **Number of lemmas:** 6

Starting from an accepted $ctx_t$ and $Bind_t$, this model verifies classic ECDHE,
domain-separated keys, AEAD Profile delivery, device installation, and `InstallReceipt` authenticity.

**Modeling boundary:** This model verifies the classic ECDHE path for the initial download. Hybrid key establishment itself is verified in the separate hybrid model. Enable, disable, delete, commit-delete, and reinstall are outside this file.

### Rule Flow

| Rule | Role |
|---|---|
| `Setup` | Creates the server signing key. |
| `Establish_Bound_Download_Context` | Abstracts preceding authentication and Profile Binding and creates the download context and Profile plaintext. |
| `Device_Send_KA` | Sends the ECDHE public key signed by $sk_t$. |
| `Server_Accept_KA` | Verifies the device signature and derives $K$, $K_{enc}$, and $K_{mac}$. |
| `Device_Accept_KA` | Verifies the server signature and derives the same keys. |
| `Server_Send_Profile` | AEAD-encrypts the Profile using $K_{enc}$ and $ctx_K$. |
| `Device_Install_Profile` | After correct decryption, generates an installation receipt bound to $Bind_t$ and the ciphertext hash. |
| `Server_Accept_InstallReceipt` | Verifies the MAC and creates the installed-state record. |

### Lemma-by-Lemma Analysis

#### 1. `exists_complete_download`

- **Type:** Executability
- **Source definition:**

```tamarin
lemma exists_complete_download:
exists-trace
  "Ex sid Iac pidh Lph Rid #i.
     DownloadComplete(sid,Iac,pidh,Lph,Rid) @ #i"
```

- **Formal meaning:** Shows a complete trace through bound context, ECDHE, encrypted delivery, decryption, installation, receipt verification, and installed-state creation.
- **Security effect:** It excludes vacuous confidentiality or receipt-authenticity proofs caused by an unreachable installation path.
- **Interpretation boundary:** It covers only the initial download-to-installed transition.
- **Verification result:** `verified`

#### 2. `key_agreement_device_to_server`

- **Type:** Download-stage key agreement
- **Source definition:**

```tamarin
lemma key_agreement_device_to_server:
"All eid sid Iac CtxK K QU QS #i.
     DeviceKeyDerived(eid,sid,Iac,CtxK,K,QU,QS) @ #i
     ==> (Ex #j.
            ServerKeyDerived(sid,Iac,CtxK,K,QU,QS) @ #j
          & #j < #i)"
```

- **Formal meaning:** Whenever the device derives a key, the server must previously have derived the same $K$ under the same $I_{ac}$, $ctx_K$, $Q_U$, and $Q_S$.
- **Security effect:** It excludes acceptance of an attacker-generated server public key, cross-session key response, or a key under a different transcript.
- **Interpretation boundary:** This file verifies the classic download path; hybrid mode and material agreement are covered by the separate hybrid model.
- **Verification result:** `verified`

#### 3. `installation_receipt_authenticity`

- **Type:** Installation-receipt authenticity
- **Source definition:**

```tamarin
lemma installation_receipt_authenticity:
"All sid Iac pidh Lph BindHash Rid #i.
     InstallReceiptAccepted(sid,Iac,pidh,Lph,BindHash,Rid) @ #i
     ==> (Ex eid profile CtxK #j.
            ProfileInstalled(eid,sid,Iac,pidh,profile,Lph,BindHash,CtxK) @ #j
          & #j < #i)"
```

- **Formal meaning:** Before the server accepts a receipt, a device must previously have successfully decrypted and installed the same Profile under the same $lph$, `BindHash`, and $ctx_K$.
- **Security effect:** It prevents an adversary from creating an installed server state without a corresponding Profile installation.
- **Interpretation boundary:** It relies on secrecy of $K_{mac}$ and on the installation rule firing only after successful AEAD decryption.
- **Verification result:** `verified`

#### 4. `installation_receipt_is_bound_to_profile_binding`

- **Type:** Receipt binding to Profile Binding
- **Source definition:**

```tamarin
lemma installation_receipt_is_bound_to_profile_binding:
"All sid Iac pidh Lph BindHash Rid #i.
     InstallReceiptAccepted(sid,Iac,pidh,Lph,BindHash,Rid) @ #i
     ==> (Ex eid profile CtxK #j.
            ProfileInstalled(eid,sid,Iac,pidh,profile,Lph,BindHash,CtxK) @ #j
          & #j < #i)"
```

- **Formal meaning:** An accepted receipt must correspond to a device installation event carrying the same `BindHash`.
- **Security effect:** It is intended to prevent moving a receipt across different Profile Bindings or transactions.
- **Interpretation boundary:** The current quantified formula is identical to `installation_receipt_authenticity`, so both formally prove the same correspondence property. A future refinement could explicitly relate the lemma to `BoundDownloadContext`.
- **Verification result:** `verified`

#### 5. `profile_confidentiality`

- **Type:** Profile confidentiality
- **Source definition:**

```tamarin
lemma profile_confidentiality:
"All profile #i.
     SecretProfile(profile) @ #i
     ==> not (Ex #j. K(profile) @ #j)"
```

- **Formal meaning:** The adversary cannot derive the Profile plaintext.
- **Security effect:** It ensures that the public channel exposes only an AEAD ciphertext protected by $K_{enc}$ and $ctx_K$.
- **Interpretation boundary:** It does not analyze length leakage, traffic patterns, or local disclosure after installation.
- **Verification result:** `verified`

#### 6. `session_key_secrecy`

- **Type:** Download-session key secrecy
- **Source definition:**

```tamarin
lemma session_key_secrecy:
"All key #i.
     SecretSessionKey(key) @ #i
     ==> not (Ex #j. K(key) @ #j)"
```

- **Formal meaning:** The adversary cannot derive $K$, $K_{enc}$, or $K_{mac}$.
- **Security effect:** It protects both the Profile-encryption key and the installation-receipt MAC key.
- **Interpretation boundary:** It relies on ideal ECDHE, KDF, signature, AEAD/MAC security and uncompromised endpoints.
- **Verification result:** `verified`

## 11. Compositional Relationship Among the Six Models

The `.spthy` files are independent Tamarin theories and do not import each other's state facts at runtime. They form a compositional verification through consistent protocol fields and module-entry abstractions:

1. The server-authentication model proves that the device accepts only an SM-DP+ response matching the order and capability transcript.
2. The anonymous-authentication model starts from an established server session and verifies the credential, ticket, common $x$, $\tau_{auth}$, nullifier, and one-time business execution.
3. The Profile-Binding model starts from an accepted anonymous-authentication transcript and proves that $Bind_t$ cannot be separated from that transcript.
4. The hybrid model starts from an accepted $ctx_t$ and $Bind_t$ and verifies mode and key-material agreement.
5. The download model starts from a bound context and verifies the classic delivery path, Profile confidentiality, and installation receipt.
6. The tracing model independently analyzes abnormal reuse of the same ticket, exact replay, and EUM identity resolution.

The paper should therefore state that six modular models jointly verify the core AURA-RSP flow, rather than claiming that all stages are merged into one monolithic end-to-end theory.

## 12. Lemma Coverage Matrix

| Security objective | Main lemmas |
|---|---|
| Server authentication | `server_authentication_agreement`, `server_authentication_order_binding`, `capability_transcript_binding` |
| Anonymous legitimacy | `anonymous_authentication_soundness`, `accepted_authentication_uses_valid_credential_and_ticket` |
| Ticket non-transferability | `ticket_non_transferability` |
| Minimal authorization | `minimal_authorization_context_binding` |
| Temporary authentication signature | `authentication_signature_is_verified` |
| One-time nullifier use | `nullifier_single_business_acceptance`, `exact_replay_is_idempotent` |
| Secret protection | `eid_secrecy`, `x_secrecy`, `eta_secrecy`, `d_secrecy`, `temporary_signing_key_secrecy` |
| Profile Binding | `profile_binding_agreement`, `binding_uses_accepted_anonymous_context`, `binding_cannot_cross_contexts` |
| Conditional tracing | `tracing_requires_two_distinct_valid_responses`, `trace_resolves_issued_device` |
| Non-frameability and replay distinction | `same_opid_is_non_frameable`, `exact_replay_does_not_create_trace`, `no_trace_from_single_accepted_response` |
| Mode and KA transcript agreement | `key_agreement_mode_and_transcript_agreement`, `hybrid_acceptance_requires_hybrid_capability_transcript`, `classic_acceptance_requires_classic_capability_transcript`, `no_cross_mode_key_acceptance` |
| Session-key secrecy | `key_secrecy`, `session_key_secrecy` |
| Profile confidentiality | `profile_confidentiality` |
| Installation-receipt authenticity | `installation_receipt_authenticity`, `installation_receipt_is_bound_to_profile_binding` |

## 13. Reproduction Commands

Single-threaded execution is recommended on memory-constrained virtual machines:

```bash
tamarin-prover "aura_rsp_server_auth_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_anon_ticket_auth_scheme(1).spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_profile_binding_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_trace_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_hybrid_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_download_scheme.spthy" --prove +RTS -N1 -RTS
```

Each executability lemma can also be run first, followed by all security lemmas. If Tamarin reports any well-formedness warning, the corresponding `verified` output must not be treated as a final proof result until variable binding, capitalization, or action-fact errors are corrected.

## 14. Known Opportunities for Refinement

1. `installation_receipt_authenticity` and `installation_receipt_is_bound_to_profile_binding` currently have identical quantified formulas and therefore formally establish the same correspondence. A future version can strengthen the second lemma by explicitly requiring an earlier `BoundDownloadContext` or `ServerCreatedBinding` event.
2. A strict cross-transaction unlinkability claim requires an observational-equivalence or diff-equivalence model and cannot be derived solely from secrecy lemmas.
3. A separate Profile-lifecycle state-machine model is required to cover the full paper scheme.
4. A real authenticated PR path would require explicit PR-forwarding facts; the current models verify only binding of the `PRaddr` field.

## 15. Conclusion

Under ideal-cryptography assumptions, the six models verify server authentication, anonymous legitimacy, ticket non-transferability, minimal authorization, temporary transaction signatures, one-time nullifier use, exact-replay idempotence, secret protection, strong Profile Binding, conditional traceability, non-frameability, classic/hybrid mode agreement, session-key secrecy, Profile confidentiality, and installation-receipt authenticity. All seven executability lemmas and all 34 security lemmas were verified.
