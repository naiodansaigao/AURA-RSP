#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
trap '"$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true' EXIT

run_case() {
    local mode="$1"
    local marker="$2"
    local output="$RESULT_DIR/aura-integration-${mode}.json"
    "$ROOT/integration-scripts/stop_services.sh" >/dev/null 2>&1 || true
    "$ROOT/integration-scripts/bootstrap.sh" >/dev/null
    "$ROOT/integration-scripts/start_smdpp.sh" aura 9443 >/dev/null
    "$ROOT/integration-scripts/start_relay.sh" >/dev/null
    "$PYTHON" -m pySim.esim.aura.ticket >/dev/null
    "$PYTHON" -m pySim.esim.aura.client --mode "$mode" >"$output"
    grep -q "\"status\": \"$marker\"" "$output"
    printf '%-16s PASS  %s\n' "$mode" "$marker"
}

run_case normal AURA_INTEGRATED_DOWNLOAD_PASS
run_case replay-auth AURA_INTEGRATED_DOWNLOAD_PASS
run_case tamper-proof AURA_INTEGRATED_TAMPER_REJECTED
run_case tamper-bind AURA_INTEGRATED_BIND_REJECTED

"$PYTHON" - "$RESULT_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
normal = json.loads((root / "aura-integration-normal.json").read_text())
replay = json.loads((root / "aura-integration-replay-auth.json").read_text())
proof = json.loads((root / "aura-integration-tamper-proof.json").read_text())
binding = json.loads((root / "aura-integration-tamper-bind.json").read_text())

assert normal["profile"]["profile_sha256"] == replay["profile"]["profile_sha256"]
assert proof["rejected"] is True
assert proof["reason"].startswith("INVALID_PI_AUTH:")
assert binding["rejected"] is True
assert binding["reason"] == "BIND_T_MISMATCH"

summary = {
    "status": "AURA_INTEGRATION_REGRESSION_PASS",
    "cases": {
        "normal_download": "accepted_once",
        "exact_auth_replay": "idempotent_cached_response",
        "tampered_auth_proof": proof["reason"],
        "tampered_bind_t": binding["reason"],
    },
}
(root / "aura-integration-regression-summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(summary, indent=2, sort_keys=True))
PY
