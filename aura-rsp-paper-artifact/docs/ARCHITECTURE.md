# Architecture

## One source tree, two protocol modes

`pysim-aura-integration/osmo-smdpp.py` is the common SM-DP+ entry point:

```text
--rsp-mode standard  -> original ES9+ endpoints
--rsp-mode aura      -> AURA download and lifecycle endpoints
```

Both modes use the same Profile bytes in `smdpp-data/upp`, the same WSL2 host, Python runtime, HTTPS stack and software Profile installation boundary. This removes a major source of implementation bias in the latency comparison.

## Standard RSP path

```text
software LPA/eUICC -> ES9+ -> osmo-smdpp -> BPP -> software install -> notification
```

The baseline retains stable eUICC authentication material as defined by the test RSP flow.

## AURA-RSP path

```text
software eUICC/LPA -> shared Privacy Relay -> AURA mode osmo-smdpp
                  -> anonymous authentication and ticket checks
                  -> Bind_t and session-key binding
                  -> encrypted Profile and digest verification
                  -> install receipt and lifecycle state chain
```

AURA state and cryptographic implementation modules are under `pySim/esim/aura/`. The Privacy Relay is a separate HTTPS process because source-address isolation requires a network hop.

## Lifecycle

The implemented state chain is:

```text
not-installed -> installed -> enabled -> disabled
installed/enabled/disabled -> pending-delete -> tombstone
tombstone -> installed (reinstall only)
```

Receipts bind `lph`, state transition, counter, predecessor hash and operation identifier. Delete uses prepare/commit recovery; state updates use SQLite transactions and compare-and-swap semantics.
