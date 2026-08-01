# Benchmark methodology

Both benchmarks run Standard RSP and AURA-RSP from this single source tree on
the same WSL2 host. The paper-facing default preserves the historical
process-inclusive workflow boundary:

```bash
bash ./integration-scripts/benchmark.sh 10
```

The stricter same-boundary online diagnostic is available separately:

```bash
bash ./integration-scripts/benchmark_online.sh 10
```

## Controlled variables

- same `osmo-smdpp.py` implementation and HTTP/TLS stack;
- same Profile repository entry and matching ID;
- byte-identical 12,207-byte Profile input;
- same software-eUICC installation function;
- same Python interpreter;
- loopback network path;
- service startup excluded from every timed sample.
- one untimed warm-up per mode by default;
- odd iterations run Standard then AURA, while even iterations reverse order.
- every measured AURA download uses a fresh operation ticket, `salt_p`, and
  `lph`, so each sample represents an independent Profile lifecycle. This
  lifecycle preparation occurs before the online timer starts.

The runner checks the Profile SHA-256 digest across all samples before it emits
the report. It also asserts that the number of unique AURA `lph` values equals
the number of measured iterations. Reusing one `lph` for repeated first-install
samples is intentionally rejected by the lifecycle state machine as
`INSTALL_STATE_CONFLICT`.

## Reported time: online diagnostic

`standard_rsp_wall` covers the Standard ES9+ download, BPP decode/software
installation evidence, and installation notification.

`aura_rsp_wall` covers the online AURA authentication, bound encrypted Profile
delivery, decryption/software installation, and installation notification.
Offline credential bootstrap and operation-ticket issuance are excluded.

Both measurements start after client certificates/configuration have been
loaded and immediately before the first online protocol operation. Both stop
after installation notification succeeds. The Standard download and
notification execute in one Python client process, so a second interpreter
startup is not accidentally counted as protocol time.

`aura_proof_generate` and `aura_proof_verify` are components of the AURA wall
time and must not be added to it again.

## Output and reporting

The paper-facing process-inclusive report is written to
`latest-legacy-workflow-benchmark.{json,csv}`. It includes the historical
Standard download and notification client-process launches and the AURA client
process launch, while excluding service startup and offline AURA ticket
issuance. This is the boundary used for the original latency table.

The online diagnostic writes `latest-integration-benchmark.{json,csv}`. Its
Standard-only cryptographic substages that the upstream client does not expose
are recorded as `null`, never fabricated as zero.

Both JSON files contain summary statistics and both CSV files contain one row
per paired iteration. A two-iteration run is only a smoke test. Paper reporting
should use a predeclared sample count, warm-up policy, fixed host power mode,
and the raw CSV rather than copying an isolated terminal value.
