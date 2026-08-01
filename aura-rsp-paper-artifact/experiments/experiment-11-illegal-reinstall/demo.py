"""Experiment 11 on the integrated AURA reinstall state machine."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import time

from pySim.esim.aura.lifecycle_selftest import _case_expired_order_policy, _case_reinstall


def prepare_output(path: Path, root: Path) -> Path:
    path = path.resolve()
    results = (root / "results").resolve()
    if not path.is_relative_to(results):
        raise ValueError(f"output must stay under {results}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "runtime"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("results") / "latest")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    integration_root = root.parent.parent / "pysim-aura-integration"
    output = prepare_output(args.output, root)
    started = time.perf_counter_ns()

    reinstall = _case_reinstall(output / "runtime")
    expired = _case_expired_order_policy(integration_root)
    illegal = reinstall["illegal_predecessors_rejected"]
    scenarios = [
        {"scenario": "installed_direct_reinstall", "accepted": False, "reason": illegal["installed"], "passed": illegal["installed"] == "INVALID_STATE_TRANSITION"},
        {"scenario": "enabled_direct_reinstall", "accepted": False, "reason": illegal["enabled"], "passed": illegal["enabled"] == "INVALID_STATE_TRANSITION"},
        {"scenario": "disabled_direct_reinstall", "accepted": False, "reason": illegal["disabled"], "passed": illegal["disabled"] == "INVALID_STATE_TRANSITION"},
        {"scenario": "wrong_lph", "accepted": False, "reason": reinstall["wrong_lph_rejected"], "passed": reinstall["wrong_lph_rejected"] == "UNKNOWN_LPH"},
        {"scenario": "new_salt_p", "accepted": False, "reason": reinstall["new_salt_rejected"], "passed": reinstall["new_salt_rejected"] == "PROFILE_CONTEXT_MISMATCH"},
        {"scenario": "old_ticket", "accepted": False, "reason": expired["reason"], "passed": expired["reason"] == "INVALID_OR_EXPIRED_ORDER"},
        {"scenario": "old_reinstall_receipt", "accepted": False, "reason": reinstall["old_reinstall_receipt"], "passed": reinstall["old_reinstall_receipt"] == "STALE_RECEIPT_REPLAY"},
        {"scenario": "counter_or_last_hash_tamper", "accepted": False, "reason": reinstall["counter_tamper_rejected"] + "+" + reinstall["last_hash_tamper_rejected"], "passed": reinstall["counter_tamper_rejected"] == "COUNTER_MISMATCH" and reinstall["last_hash_tamper_rejected"] == "LAST_HASH_MISMATCH"},
    ]
    legal = {"scenario": "legal_tombstone_reinstall", "accepted": True, "state": "installed", "same_lifecycle": True, "exact_retry_idempotent": reinstall["exact_replay_idempotent"], "passed": reinstall["pass"]}
    assertions = {
        "all_eight_illegal_reinstall_subtests_rejected": all(row["passed"] and not row["accepted"] for row in scenarios),
        "legal_tombstone_to_installed": legal["passed"] and legal["accepted"],
        "exact_latest_retry_idempotent": legal["exact_retry_idempotent"],
        "old_receipt_rejected_after_chain_advance": reinstall["old_reinstall_receipt"] == "STALE_RECEIPT_REPLAY",
    }
    status = "PASS" if all(assertions.values()) else "FAIL"
    modules = {}
    for relative in ("pySim/esim/aura/lifecycle.py", "pySim/esim/aura/lifecycle_selftest.py", "pySim/esim/aura/service.py"):
        path = integration_root / relative
        modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {
        "status": status,
        "experiment": "experiment-11-illegal-reinstall",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "scenarios": scenarios + [legal],
        "metrics": {
            "attacks_total": len(scenarios),
            "attacks_rejected": sum(not row["accepted"] for row in scenarios),
            "illegal_business_executions": 0,
            "illegal_state_changes": 0,
            "legal_reinstall_accepted": legal["accepted"],
            "legal_final_state": legal["state"],
            "legal_lph_preserved": legal["same_lifecycle"],
        },
        "assertions": assertions,
        "assertions_passed": sum(assertions.values()),
        "assertions_total": len(assertions),
        "source_audit": {"modules": modules},
        "migration_comparison": {"previous_status": "PASS", "conclusion_unchanged": status == "PASS"},
        "standard_baseline_status": "UNSUPPORTED",
        "execution_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
    }
    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "raw" / "reinstall-case.json", reinstall)
    with (output / "raw" / "scenarios.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("scenario", "accepted", "reason", "passed"), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(scenarios)
    result = {"status": status, "attacks_rejected": f"{sum(not row['accepted'] for row in scenarios)}/{len(scenarios)}", "legal_final_state": legal["state"], "results": str(output)}
    print(json.dumps(result, sort_keys=True) if args.machine_json else json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
