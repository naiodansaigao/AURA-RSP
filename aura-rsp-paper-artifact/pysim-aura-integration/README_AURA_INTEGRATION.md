# AURA-RSP integration in Osmocom pySim/osmo-smdpp

This directory adds an AURA-RSP execution mode to the same pySim/osmo-smdpp
source tree used by the Standard RSP baseline.  It is not a third, unrelated
protocol simulator.

## What is shared

Both modes use:

- the same `osmo-smdpp.py` HTTPS process and Klein/Twisted HTTP stack;
- the same `smdpp-data/upp` Profile repository and matching ID;
- the same test TLS/GSMA certificate material;
- the same software eUICC Profile installation function;
- the same WSL2 host and Python environment.

The server is selected at startup:

```text
osmo-smdpp.py --rsp-mode standard
osmo-smdpp.py --rsp-mode aura
```

`standard` exposes the original ES9+ endpoints. `aura` exposes the four
AURA download endpoints in `osmo-smdpp.py`:

1. `/aura/rsp/v1/initiateAuthentication`
2. `/aura/rsp/v1/authenticateClient`
3. `/aura/rsp/v1/getBoundProfilePackage`
4. `/aura/rsp/v1/handleNotification`

The same AURA service also exposes lifecycle endpoints:

5. `/aura/rsp/v1/prepareLifecycleOperation`
6. `/aura/rsp/v1/handleLifecycleReceipt`
7. `/aura/rsp/v1/commitDelete`
8. `/aura/rsp/v1/handleReinstallReceipt`
9. `/aura/rsp/v1/getLifecycleState`

The Privacy Relay is a separate local HTTPS process because source-address
separation requires a network hop. It forwards only AURA endpoints and
authenticates relay-to-server messages with a test HMAC key.

## Security checks implemented on the download path

The AURA mode performs, in protocol order:

1. order and ticket-public-field lookup by `I_ac`;
2. server authentication and full capability-transcript binding;
3. one-time-key signature (`tau_auth`) verification;
4. joint anonymous credential/ticket proof verification;
5. nullifier replay/double-use classification;
6. context-specific `Bind_t` generation and verification;
7. classical P-256 ephemeral key agreement and `ctx_K` binding;
8. AES-GCM encrypted Profile delivery;
9. post-decryption `H(Profile) == pid_h` verification before installation;
10. authenticated `InstallReceipt` verification and idempotent notification.

## Complete Profile lifecycle

After download, the integrated software eUICC and SM-DP+ continue the same
Profile-local chain identified by the original `lph` and `salt_p`:

```text
not-installed(0) -> installed(1) -> enabled(2) -> disabled(3)
installed/enabled/disabled -> pending-delete(4) -> tombstone(5)
tombstone(5) -> installed(1) via reinstall
```

Every enable, disable, delete or reinstall operation uses a fresh operation
ticket, anonymous proof, nullifier, `opid`, one-time key, `Bind_t`, ECDHE
session and `K_mac`. State receipts authenticate `lph`, predecessor and
successor states, the monotonic counter, previous chain hash and the
operation-specific `rid`.

Lifecycle state is stored in SQLite using `BEGIN IMMEDIATE` and a
compare-and-swap update. Exact retry of the current receipt is idempotent;
historical replay and concurrent requests from the same predecessor cannot
create two successors.

Delete is a two-phase operation. The server first persists pending-delete and
returns signed `R_prep`; the device then removes its local Profile and sends
`CommitReceipt`. A valid pending-delete may be committed after the original
ticket expires. The server session store is persistent for the recovery demo,
so commit can continue after an osmo-smdpp process restart.

Reinstall is accepted only from tombstone, reuses the original `lph/salt_p`,
downloads and verifies the Profile under a new authenticated session, and
advances the existing state chain only after software installation succeeds.

The default paper-facing latency benchmark uses the **classical P-256 branch**
to preserve its original timing boundary. The integrated key-agreement module
also implements the Hybrid P-256 + ML-KEM-768 branch used explicitly by
Experiment 9; it is not enabled in the default latency table.

## WSL2 quick start

From this directory:

```bash
bash ./integration-scripts/install_deps.sh
bash ./integration-scripts/run_standard_demo.sh
bash ./integration-scripts/run_aura_demo.sh
```

Expected final markers:

```text
STANDARD_PYSIM_INTEGRATION_ALL_PASS
AURA_PYSIM_INTEGRATION_ALL_PASS
```

Run the AURA integration regression suite:

```bash
bash ./integration-scripts/test_aura_integration.sh
```

It machine-checks normal download, exact authentication replay, a modified
anonymous proof, and a modified `Bind_t`.

Run the complete lifecycle over the real local HTTPS/Privacy Relay path:

```bash
bash ./integration-scripts/run_lifecycle_demo.sh
```

This executes download, enable, disable, enable, two-phase delete and
reinstall. The final marker is
`AURA_INTEGRATED_LIFECYCLE_DEMO_PASS`.

Run replay, tamper, concurrency, atomic-fault, expiry and illegal-reinstall
checks:

```bash
bash ./integration-scripts/run_lifecycle_selftest.sh
```

Run a real osmo-smdpp restart between prepare-delete and commit-delete:

```bash
bash ./integration-scripts/run_lifecycle_restart_recovery.sh
```

Run the release-artifact acceptance suite (Standard network regression, AURA
network regression, download-security checks, and lifecycle network/recovery
checks):

```bash
bash ./integration-scripts/run_all_tests.sh
```

The final marker is `PYSIM_AURA_ALL_TESTS_PASS`.

Run the paper-facing, process-inclusive workflow comparison (for example,
10 iterations per mode):

```bash
bash ./integration-scripts/benchmark.sh 10
```

Outputs:

- `results/latest-legacy-workflow-benchmark.json`
- `results/latest-legacy-workflow-benchmark.csv`

Service startup is excluded. Both modes install the exact same Profile bytes,
and the report asserts the common SHA-256 digest before producing statistics.
The default is one untimed warm-up; measured iterations alternate client order.
This is the process-inclusive boundary used by the original paper table:
Standard launches the historical download and notification clients, while AURA
launches its integrated client. Each AURA sample uses a fresh ticket, `salt_p`
and `lph`, prepared outside the measured interval.

The same-boundary online-protocol benchmark is retained as a separate,
more conservative diagnostic:

```bash
bash ./integration-scripts/benchmark_online.sh 10
```

It excludes client process startup and writes
`results/latest-integration-benchmark.{json,csv}`. The two boundaries must be
reported under different labels and must not be mixed in one latency column.

The verified environment is recorded in
`requirements-aura-integration.lock`. Runtime private keys, tickets, logs and
databases are generated locally and excluded by `.gitignore`.

## Reproducibility boundary

This is a research-grade software eUICC/LPA and SM-DP+ environment. Test
certificates simplify the EUM/GSMA PKI deployment, and no physical eUICC is
required. It demonstrates protocol-message exchange, cryptographic checks,
Profile delivery, software installation evidence, and notification; it does
not claim production SGP.22 certification.

See:

- `docs/aura_protocol_mapping.md`
- `docs/aura_benchmark_methodology.md`
- `UPSTREAM.md`
