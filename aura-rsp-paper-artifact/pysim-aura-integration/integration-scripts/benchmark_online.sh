#!/usr/bin/env bash
set -euo pipefail
# Same-boundary online-protocol benchmark. The paper-facing default benchmark
# remains the historical process-inclusive workflow boundary.
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

ITERATIONS="${1:-10}"
WARMUPS="${2:-1}"
if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 [positive-iterations] [nonnegative-warmups]" >&2
    exit 2
fi
if ! [[ "$WARMUPS" =~ ^[0-9]+$ ]]; then
    echo "usage: $0 [positive-iterations] [nonnegative-warmups]" >&2
    exit 2
fi

RAW_DIR="$RESULT_DIR/benchmark-raw"
mkdir -p "$RAW_DIR"
: >"$RAW_DIR/standard.jsonl"
: >"$RAW_DIR/aura.jsonl"

"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
trap '"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true' EXIT
"$ROOT/integration-scripts/bootstrap.sh" >/dev/null

# Both modes run from the same source and startup mechanism.  Different local
# ports let the runner alternate client order without counting service restarts.
"$ROOT/integration-scripts/start_smdpp.sh" standard 9445
"$ROOT/integration-scripts/start_smdpp.sh" aura 9443
"$ROOT/integration-scripts/start_relay.sh"

run_standard() {
    local label="$1"
    STANDARD_PORT=9445 "$ROOT/integration-scripts/standard_once.sh" \
        "$LOG_DIR/benchmark-standard-${label}.log"
}

run_aura() {
    local label="$1"
    "$PYTHON" -m pySim.esim.aura.ticket \
        --fresh-profile-lifecycle >/dev/null
    "$PYTHON" -m pySim.esim.aura.client --mode normal |
        tee "$RAW_DIR/aura-${label}.json" >/dev/null
}

for i in $(seq 1 "$WARMUPS"); do
    run_standard "warmup-${i}" >/dev/null
    run_aura "warmup-${i}"
done

for i in $(seq 1 "$ITERATIONS"); do
    if (( i % 2 == 1 )); then
        run_standard "$i" | tee -a "$RAW_DIR/standard.jsonl"
        run_aura "$i"
    else
        run_aura "$i"
        run_standard "$i" | tee -a "$RAW_DIR/standard.jsonl"
    fi
    echo "BENCHMARK_ITERATION_PASS=$i/$ITERATIONS"
done

"$PYTHON" - "$RAW_DIR" "$RESULT_DIR" "$ITERATIONS" "$WARMUPS" <<'PY'
import csv
import importlib.metadata
import json
import math
import pathlib
import platform
import statistics
import sys
from datetime import datetime, timezone

raw_dir = pathlib.Path(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])
n = int(sys.argv[3])
warmups = int(sys.argv[4])

standard = [
    json.loads(line)
    for line in (raw_dir / "standard.jsonl").read_text().splitlines()
    if line.strip()
]
aura = [
    json.loads((raw_dir / f"aura-{index}.json").read_text())
    for index in range(1, n + 1)
]
assert len(standard) == len(aura) == n
profile_hashes = {
    *(item["profile_sha256"] for item in standard),
    *(item["profile"]["profile_sha256"] for item in aura),
}
assert len(profile_hashes) == 1
aura_lphs = [item["lph"] for item in aura]
assert len(set(aura_lphs)) == n

def describe(values):
    values = [float(value) for value in values]
    ordered = sorted(values)
    p95_index = max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999) - 1))
    result = {
        "n": len(values),
        "mean_ms": round(statistics.mean(values), 3),
        "median_ms": round(statistics.median(values), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
        "p95_ms": round(ordered[p95_index], 3),
        "stdev_ms": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
    }
    if len(values) > 1:
        # Two-sided Student-t critical values for 95% confidence.
        critical = {
            1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
            6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
            11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
            16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
            21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
            26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
        }.get(len(values) - 1, 1.96)
        half = critical * statistics.stdev(values) / math.sqrt(len(values))
        result["ci95_low_ms"] = round(statistics.mean(values) - half, 3)
        result["ci95_high_ms"] = round(statistics.mean(values) + half, 3)
        result["ci95_half_width_ms"] = round(half, 3)
    else:
        result["ci95_low_ms"] = None
        result["ci95_high_ms"] = None
        result["ci95_half_width_ms"] = None
    return result

def cpu_model():
    path = pathlib.Path("/proc/cpuinfo")
    if path.is_file():
        for line in path.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"

def version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None

standard_wall = [item["end_to_end_ms"] for item in standard]
aura_wall = [item["metrics"]["end_to_end_ms"] for item in aura]
report = {
    "status": "PYSIM_AURA_INTEGRATION_BENCHMARK_PASS",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "iterations": n,
    "warmups": warmups,
    "same_profile": True,
    "profile_sha256": next(iter(profile_hashes)),
    "service_startup_excluded": True,
    "sample_isolation": {
        "standard": "fresh ES9+ transaction per sample",
        "aura": (
            "fresh ticket, salt_p and lph per sample; lifecycle preparation "
            "occurs before the timed online boundary"
        ),
        "aura_unique_lph_count": len(set(aura_lphs)),
    },
    "standard_rsp_wall": describe(standard_wall),
    "aura_rsp_wall": describe(aura_wall),
    "aura_proof_generate": describe(
        [item["metrics"]["proof_generation_ms"] for item in aura]
    ),
    "aura_proof_verify": describe(
        [item["metrics"]["proof_verification_ms"] for item in aura]
    ),
    "aura_server_auth": describe(
        [item["metrics"]["server_auth_ms"] for item in aura]
    ),
    "aura_client_auth": describe(
        [item["metrics"]["client_auth_ms"] for item in aura]
    ),
    "aura_binding": describe(
        [item["metrics"]["binding_ms"] for item in aura]
    ),
    "aura_key_agreement": describe(
        [item["metrics"]["key_agreement_ms"] for item in aura]
    ),
    "aura_profile_encryption": describe(
        [item["metrics"]["profile_encryption_ms"] for item in aura]
    ),
    "aura_profile_delivery": describe(
        [item["metrics"]["profile_delivery_ms"] for item in aura]
    ),
    "aura_install": describe(
        [item["metrics"]["install_ms"] for item in aura]
    ),
    "aura_notification": describe(
        [item["metrics"]["notification_ms"] for item in aura]
    ),
    "standard_stage_breakdown_ms": {
        # The upstream Standard client exposes one whole online interval.
        # Unsupported substage values are null rather than fabricated zeros.
        key: None
        for key in (
            "server_auth_ms", "client_auth_ms", "proof_generation_ms",
            "proof_verification_ms", "binding_ms", "key_agreement_ms",
            "profile_encryption_ms", "profile_delivery_ms", "install_ms",
            "notification_ms",
        )
    },
    "comparison": {},
    "execution_order": "odd: standard->aura; even: aura->standard",
    "host": {
        "platform": platform.platform(),
        "cpu": cpu_model(),
        "python": platform.python_version(),
    },
    "dependencies": {
        name: version(name)
        for name in ("py-ecc", "cryptography", "requests", "klein", "Twisted")
    },
    "upstream_pysim_commit": "25e43e1540144be9026a2733bc3a4271b8fa7d25",
    "raw_ms": {
        "standard_rsp_wall": standard_wall,
        "aura_rsp_wall": aura_wall,
        **{
            f"aura_{name}": [item["metrics"][key] for item in aura]
            for name, key in (
                ("server_auth", "server_auth_ms"),
                ("client_auth", "client_auth_ms"),
                ("proof_generate", "proof_generation_ms"),
                ("proof_verify", "proof_verification_ms"),
                ("binding", "binding_ms"),
                ("key_agreement", "key_agreement_ms"),
                ("profile_encryption", "profile_encryption_ms"),
                ("profile_delivery", "profile_delivery_ms"),
                ("install", "install_ms"),
                ("notification", "notification_ms"),
            )
        },
    },
}
std_mean = report["standard_rsp_wall"]["mean_ms"]
aura_mean = report["aura_rsp_wall"]["mean_ms"]
report["comparison"] = {
    "aura_minus_standard_mean_ms": round(aura_mean - std_mean, 3),
    "aura_over_standard_factor": round(aura_mean / std_mean, 3),
    "aura_overhead_percent": round((aura_mean / std_mean - 1) * 100, 2),
}

json_path = result_dir / "latest-integration-benchmark.json"
csv_path = result_dir / "latest-integration-benchmark.csv"
json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
with csv_path.open("w", newline="") as handle:
    writer = csv.DictWriter(
        handle,
        fieldnames=("iteration", "standard_rsp_wall_ms", "aura_rsp_wall_ms",
                    "aura_proof_generate_ms", "aura_proof_verify_ms",
                    "aura_binding_ms", "aura_key_agreement_ms",
                    "aura_profile_encryption_ms", "aura_profile_delivery_ms",
                    "aura_install_ms", "aura_notification_ms",
                    "aura_wire_request_bytes", "aura_wire_response_bytes"),
    )
    writer.writeheader()
    for index, (standard_item, aura_item) in enumerate(zip(standard, aura), 1):
        metrics = aura_item["metrics"]
        writer.writerow({
            "iteration": index,
            "standard_rsp_wall_ms": standard_item["end_to_end_ms"],
            "aura_rsp_wall_ms": metrics["end_to_end_ms"],
            "aura_proof_generate_ms": metrics["proof_generation_ms"],
            "aura_proof_verify_ms": metrics["proof_verification_ms"],
            "aura_binding_ms": metrics["binding_ms"],
            "aura_key_agreement_ms": metrics["key_agreement_ms"],
            "aura_profile_encryption_ms": metrics["profile_encryption_ms"],
            "aura_profile_delivery_ms": metrics["profile_delivery_ms"],
            "aura_install_ms": metrics["install_ms"],
            "aura_notification_ms": metrics["notification_ms"],
            "aura_wire_request_bytes": metrics["wire_request_bytes"],
            "aura_wire_response_bytes": metrics["wire_response_bytes"],
        })
print(json.dumps(report, indent=2, sort_keys=True))
PY
