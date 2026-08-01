# AURA-RSP integration design and as-built plan

## Goal and boundary

The fork provides mutually exclusive `standard` and `aura` startup modes in
one pySim/osmo-smdpp source tree. It implements Profile Download only. It does
not claim production SGP.22 compliance and does not implement the AURA
lifecycle operations or a production GSMA PKI.

The original `rsp-baseline`, standalone `aura-rsp`, and 13 experiment
directories remain separate regression artifacts. Integration code is confined
to `pysim-aura-integration`.

## Existing Standard call chain

```text
contrib/es9p_client.py::Es9pClient
  -> pySim.esim.es9p.Es9pApiClient
  -> POST /gsma/rsp2/es9plus/*
  -> osmo-smdpp.py::SmDppHttpServer
  -> pySim.esim.rsp.RspSessionState / RspSessionStore
  -> pySim.esim.es8p.BoundProfilePackage
  -> software eUICC BPP decode and install_profile()
  -> handleNotification
```

The four Standard stages are `initiateAuthentication`,
`authenticateClient`, `getBoundProfilePackage`, and `handleNotification`.

## Integration points

1. `osmo-smdpp.py` adds `--rsp-mode standard|aura`; the default is Standard.
2. AURA routes are registered by the same Klein/Twisted HTTPS application.
3. HTTP handlers only decode, select mode, call `AuraService`, map typed errors,
   and encode the response.
4. Standard and AURA read byte-identical input through
   `pySim.esim.profile_store.ProfileRepository`.
5. Both call `pySim.esim.software_euicc.install_profile`.
6. Both use the same result directory conventions and benchmark runner.
7. AURA uses a separate Privacy Relay process because source-address isolation
   cannot be represented by an in-process function call.

## Shared and mode-specific code

| Shared | Standard-specific | AURA-specific |
|---|---|---|
| Klein/Twisted HTTPS | ES9+ ASN.1/JSON | AURA extension JSON |
| TLS/test certificate setup | X.509 eUICC authentication | BBS+ joint proof |
| Profile repository | BPP/BSP protection | `nu`, `lph`, `Bind_t` |
| software eUICC install | PendingNotification | PR authentication |
| result/benchmark boundary | RSP session shelf | AURA state store |
| matching ID and UPP bytes | Standard ECDH/BPP | P-256/HKDF/AES-GCM |

AURA fields are not inserted into Standard ES9+ ASN.1 objects. They use:

```text
/aura/rsp/v1/initiateAuthentication
/aura/rsp/v1/authenticateClient
/aura/rsp/v1/getBoundProfilePackage
/aura/rsp/v1/handleNotification
```

Four endpoints preserve the same online phase count as the Standard path.

## Protocol state

The typed models are:

- `AuraOrderContext`: `I_ac`, matching ID, `sid`, `pid_h`, `op`, expiry,
  and `PRaddr`;
- `AuraCredentialState`: hidden `x`, `k`, credential expiry and `Cred_D`;
- `AuraTicketState`: public order context plus hidden `eta`, `d`, `Tok_op`;
- `AuraAuthTranscript`: canonical `ctx_t`, request hash, `nu`, `gamma`, `c`,
  `opid`, and `vk_t`;
- `AuraBindingState`: `th_auth`, `ctx_bind`, and `Bind_t`;
- `AuraKeyState`: selected mode, `Q_U`, `Q_S`, `ctx_K`, and secret `K_mac`;
- `AuraInstallReceipt`: `lph`, states, counter, predecessor hash, `rid_inst`,
  and HMAC;
- `AuraSessionState`: order, signed server context, authentication, binding,
  key state, ciphertext hash, status, and cached response.

## Verification order

The service loads the order by `I_ac` and reconstructs the public ticket
context; client copies never override server values. It verifies the PR
identity, expiry, operation, Profile digest, capability transcript, one-time
signature, joint anonymous proof, and nullifier state before creating
`Bind_t`.

Profile delivery verifies `Bind_t`, `ctx_bind`, the selected mode, `Q_U`, and
KA-U before deriving keys. The eUICC verifies the server transcript,
`Bind_t`, `ctx_K`, KA-S, AES-GCM, and `H(Profile) == pid_h` before installation.
Only then is an authenticated InstallReceipt accepted.

All transcript inputs use canonical JSON and explicit domain labels. Every
failure is typed and fail-closed.

## Persistence and logging

Persisted server state may include public orders, sessions, used nullifiers,
cached exact-replay responses, binding data, ciphertext hashes, receipts, and
Profile-local state. The EUM trace index remains logically separate.

The eUICC persists credentials, tickets, Profile salt/handle, and
LocalTicketLog state. Runtime files are excluded from source control.

Logs must not contain `x`, `k`, `eta`, `d`, one-time private keys, ECDHE
private keys, shared secrets, `K_enc`, `K_mac`, or Profile plaintext.

## Compatibility and security risks

- AURA imports are lazy in `osmo-smdpp.py`, so Standard startup does not require
  `py-ecc`.
- Mode selection occurs at process startup, preventing per-request cross-mode
  state confusion.
- The classical P-256 branch is implemented and tested. ML-KEM hybrid is not
  claimed as an implemented delivery branch.
- The BBS+ implementation is research code and has not received a production
  cryptographic audit.
- Standard still contains upstream TODOs for some client-side signature and
  transaction-ID checks; these are recorded as baseline limitations, not
  introduced by AURA.

## Implementation stages and acceptance

1. Dual-mode skeleton: Standard default, same TLS/Profile directory.
2. Anonymous authentication: order reconstruction, joint proof, replay and
   double-use handling, no Bind_t on failure.
3. Bound delivery: Bind_t, P-256, HKDF, AES-GCM, shared install, receipt.
4. Regression: Standard network flow, AURA network flow, and at least 13
   required positive/negative categories.
5. Benchmark: same Profile/interpreter/host, offline issuance and startup
   excluded, one-process online boundary, warm-up, alternating order, raw CSV,
   summary JSON and Student-t 95% confidence interval.

The classical Profile Download integration has completed stages 1–5. Optional
hybrid delivery and lifecycle operations remain future work.
