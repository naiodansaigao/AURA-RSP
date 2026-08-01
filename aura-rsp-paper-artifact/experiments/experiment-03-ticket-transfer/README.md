# Experiment 3: Ticket Theft and Cross-Device Transfer Matrix

## Research question

Can a valid operation ticket issued for one eUICC be copied together with its
public order/activation material and used by another legitimate eUICC?

This version replaces the former two-device example.  By default, 50 devices
each receive one fresh ticket per round.  Every ticket is then tested against
all 50 devices for 10 rounds:

- 500 diagonal owner controls per configuration;
- 24,500 non-diagonal transfer attacks per configuration;
- 100,000 total matrix decisions across four configurations.

## Compared configurations

1. **Full AURA-RSP.** The credential and ticket BBS+ statements share the same
   hidden witness `x`.
2. **AURA-RSP w/o secret binding.** Experiment-only ablation using separate
   witnesses `x_cred` and `x_ticket`. This is not the normal protocol and is
   never loaded by the integrated SM-DP+ service.
3. **Standard RSP with EID-pre-bound order.** The target EID must match the EID
   bound to the order.
4. **Standard RSP with unbound Activation Code.** Pairwise transferability is
   tested with fresh order state for each source-target pair. This measures
   whether possession of the code is sufficient; it is not a simultaneous
   first-consumer race.

The Standard controls model the two deployment policies and must not be read as
a claim that every Standard RSP deployment permits ticket theft.

## Implementation source

The AURA credential, blind-ticket issuance, BBS+ proof generation, and server
verification calls are imported from:

```text
../../pysim-aura-integration/pySim/esim/aura/
```

The Profile hash and size are loaded from the integrated pySim SM-DP+ Profile
repository. The old standalone `aura-rsp` source is not used.

## Why the matrix and timing paths are separated

The matrix is a correctness test, not a latency benchmark. Credentials and
tickets are issued and holder-verified with the integrated BBS+ implementation.
The harness then uses the known ground-truth holder relation to evaluate every
source-target pair. This avoids pretending that a scalar equality test is a
full cryptographic authentication time.

For every round, the experiment additionally performs real integrated calls for:

- one valid owner joint proof and server verification;
- one honest cross-device proof attempt, which must fail locally;
- one real ablation proof, which must verify only under the experiment verifier;
- one forced invalid transfer submission, which the production verifier must
  reject.

The concurrency test invokes the production `verify_auth_proof()` path at 1, 8,
32, 64, and 128 simultaneous requests. A persistent `ProcessPoolExecutor` uses
one verifier process per available logical CPU by default, so py-ecc pairing
work is genuinely distributed across CPU cores instead of being serialized by
the Python thread GIL. Pool startup/warmup is reported separately and excluded
from online batch latency. The invalid workload is defense-in-depth: an honest
AURA client does not send a proof after local ticket-secret mismatch.

Figure 3(c) plots per-worker cryptographic **service time**. The accompanying
CSV and paper table additionally retain queue-inclusive end-to-end latency,
queue wait, and throughput. Therefore the figure does not hide overload when
logical concurrency exceeds the available worker processes.

## Run

From WSL2 Ubuntu:

```bash
cd experiments/experiment-03-ticket-transfer
bash ./run_demo.sh
```

Quick smoke test:

```bash
bash ./run_demo.sh --devices 4 --rounds 1 --concurrency 1,2
```

Override the verifier process count if the machine is shared:

```bash
bash ./run_demo.sh --workers 8
```

Run the full matrix without the costly concurrency benchmark:

```bash
bash ./run_demo.sh --skip-concurrency
```

Other output modes:

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## Outputs

```text
results/latest/
├── raw/
│   ├── matrix-attempts.csv
│   ├── matrix-attempts.jsonl
│   ├── crypto-samples.csv
│   ├── crypto-samples.jsonl
│   └── concurrency.csv
├── evidence/
│   ├── assertions.json
│   └── source-audit.json
├── paper/
│   ├── figure-3a-ticket-device-acceptance-matrix.png
│   ├── figure-3b-cross-device-transfer-success-rate.png
│   ├── figure-3c-concurrent-authentication-latency.png
│   ├── table-3-ticket-transfer.csv
│   ├── table-3-cryptographic-timing.csv
│   └── table-3-concurrency.csv
├── summary.json
└── summary.md
```

PNG figures are rendered at 600 DPI with compact margins and large labels.

## Machine-checkable expectations

- Full AURA accepts every diagonal owner control and rejects every
  non-diagonal transfer before Profile delivery.
- The experiment-only no-binding ablation accepts non-diagonal transfers,
  isolating the contribution of the hidden-secret equality relation.
- EID-pre-bound Standard orders reject transfer but disclose/use a stable EID.
- Unbound-code Standard orders are transferable under the stated pairwise
  possession model.
- Production AURA proof samples verify for owners, cannot be constructed by an
  honest non-owner, and reject forced invalid submissions.

Passing these assertions supports the narrow conclusion that AURA-RSP provides
cryptographic ticket non-transferability without revealing an EID. It does not
cover device-secret compromise, issuer-key compromise, malicious issuers, or
pure denial of service.
