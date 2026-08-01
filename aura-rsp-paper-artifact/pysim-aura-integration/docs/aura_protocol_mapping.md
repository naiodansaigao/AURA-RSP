# AURA-RSP to pySim/osmo-smdpp mapping

| Protocol role or object | Integrated implementation |
|---|---|
| SM-DP+ HTTPS entry point | `osmo-smdpp.py` |
| Standard ES9+ mode | `osmo-smdpp.py --rsp-mode standard` |
| AURA mode | `osmo-smdpp.py --rsp-mode aura` |
| Software LPA/eUICC | `pySim/esim/aura/client.py` |
| Privacy Relay | `pySim/esim/aura/relay.py` |
| Offline operation-ticket issuance | `pySim/esim/aura/ticket.py` |
| Test EUM/MNO/bootstrap authority | `pySim/esim/aura/bootstrap.py` |
| Joint anonymous proof | `pySim/esim/aura/proof.py`, `bbs.py` |
| Canonical transcript construction | `pySim/esim/aura/context.py` |
| Profile/operation binding | `pySim/esim/aura/binding.py` |
| Ephemeral key agreement and `ctx_K` | `pySim/esim/aura/key_agreement.py` |
| Profile repository shared by both modes | `pySim/esim/profile_store.py` |
| Software Profile installation shared by both modes | `pySim/esim/software_euicc.py` |
| Install receipt | `pySim/esim/aura/receipt.py` |
| Lifecycle receipts and two-phase deletion | `pySim/esim/aura/lifecycle.py` |
| Persistent atomic lifecycle state | `runtime/aura/lifecycle.sqlite` via `LifecycleRepository` |
| Lifecycle software eUICC/LPA | `pySim/esim/aura/lifecycle_client.py` |
| Nullifier, replay and transaction state | `pySim/esim/aura/store.py` |
| AURA service verification order | `pySim/esim/aura/service.py` |
| HTTP request/response adaptation | `pySim/esim/aura/http_api.py` |

## Four-stage download flow

### 1. Initiate authentication

The client sends `I_ac`, `N_U`, and its capability offer. The integrated
SM-DP+ resolves the order, creates `N_S`, `I_t`, and a signed server transcript
containing `sid`, `serverOID`, `PRaddr`, and the complete offer/selection.

### 2. Authenticate client

The software eUICC constructs `ctx_t`, derives `nu` and `lph`, creates a
joint anonymous proof over the credential and operation ticket, and signs the
request with the ticket-local one-time key. The server verifies the transcript
before accepting the nullifier and emits `Bind_t` only after all checks pass.
An identical request receives the cached result; a conflicting use is not
executed as a second business transaction.

### 3. Deliver bound Profile

The client supplies a fresh P-256 public key and a signature binding it to
`I_t` and `Bind_t`. The server derives the session key, binds the complete
agreement transcript into `ctx_K`, and encrypts the repository Profile with
AES-GCM. The client verifies `ctx_K`, the server key-agreement signature,
AEAD integrity, and finally `H(Profile) == pid_h` before calling the shared
software-eUICC installation function.

### 4. Handle notification

The client sends an authenticated `InstallReceipt`. The server verifies its
transaction, Profile-local handle, counter, predecessor hash and HMAC, then
stores the final installed state. Identical notification retry is idempotent.

## Standard-mode regression

The Standard path remains the upstream ES9+ sequence:

`initiateAuthentication -> authenticateClient -> getBoundProfilePackage ->
handleNotification`.

Only two integration-facing changes are made to that path: Profile lookup uses
the shared repository wrapper, and the decoded UPP is passed to the shared
software-eUICC installation evidence function. The existing BPP construction
and ES9+ message processing remain in use.

## Lifecycle flow

For enable, disable and delete, the device first runs the same anonymous
authentication and `Bind_t`/key-agreement stages with a fresh operation
ticket. `prepareLifecycleOperation` establishes the operation-local `K_mac`;
`handleLifecycleReceipt` verifies the authenticated predecessor,
counter, previous hash and operation `rid`, then performs one SQLite CAS.

Delete moves to pending-delete and returns a signed `R_prep`. The device
deletes the local Profile before `commitDelete`, whose receipt binds the
stored `R_prep` and advances to tombstone. Reinstall uses a fresh authenticated
Profile-delivery session and calls `handleReinstallReceipt` only after
decryption, `H(Profile) == pid_h`, and software installation.

Exact retry is accepted only while the receipt remains the current chain head.
Once a later state is committed, replaying the historical receipt yields
`STALE_RECEIPT_REPLAY`.

## Acceptance-test mapping

| Required category | Evidence |
|---|---|
| Standard network regression | `integration-scripts/run_standard_demo.sh` |
| AURA normal download | `test_aura_integration.sh` / `normal` |
| wrong server context | `selftest.py::wrong_server_context` |
| stolen ticket transfer | `selftest.py::stolen_ticket_transfer` |
| exact nullifier replay | network replay plus service-level selftest |
| different valid transcript reuse | `DOUBLE_SPEND_DETECTED:TRACE_RECOVERED` |
| Bind_t cross-transaction transplant | `BIND_T_MISMATCH` |
| ECDHE public-key modification | `INVALID_KA_U_SIGNATURE` |
| downgrade/cross-mode splice | signed-capability check and `UNSUPPORTED_KEY_MODE` |
| Profile ciphertext modification | AES-GCM `InvalidTag` |
| cross-session Profile replay | `ctx_K`/AEAD rejection |
| wrong decrypted Profile | `PROFILE_ORDER_DIGEST_MISMATCH` |
| InstallReceipt modification | `INVALID_INSTALL_RECEIPT` and unchanged state |
| old lifecycle receipt replay | `STALE_RECEIPT_REPLAY` |
| lifecycle field modification | HMAC, predecessor, counter or previous-hash rejection |
| concurrent enable/delete | one SQLite-CAS successor, one rejection |
| lost `R_prep` | same cached signed `R_prep`, no second counter increment |
| lost commit acknowledgement | exact CommitReceipt retry is idempotent |
| server restart during delete | persistent session and pending state converge to tombstone |
| expired ticket after prepare-delete | valid stored pending-delete can still commit |
| illegal reinstall | only tombstone with original `lph/salt_p` is accepted |

`integration-scripts/run_all_tests.sh` executes the complete set. The tests use
real BBS+, P-256, Ed25519, HKDF, AES-GCM and HMAC operations; no sleeps or
fixed proof-verification answers are used.
