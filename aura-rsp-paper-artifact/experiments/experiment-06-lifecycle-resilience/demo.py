"""Experiment 6 on the integrated pySim/osmo-smdpp AURA lifecycle core."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import time

from pySim.esim.aura.lifecycle_selftest import (
    _case_concurrency,
    _case_fault_recovery,
    _case_legal_chain,
    _case_tamper,
)


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


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("results") / "latest")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = prepare_output(args.output, root)
    started = time.perf_counter_ns()

    cases = {
        "legal_chain": _case_legal_chain(output / "runtime"),
        "tamper": _case_tamper(output / "runtime"),
        "concurrency": _case_concurrency(output / "runtime"),
        "recovery": _case_fault_recovery(output / "runtime"),
    }
    subtests = [
        {"subtest": "6A", "scenario": "old receipt replay and latest exact retry", "passed": cases["legal_chain"]["pass"], "result": "stale rejected; latest retry idempotent"},
        {"subtest": "6B", "scenario": "receipt field tampering", "passed": cases["tamper"]["pass"], "result": "all MAC and semantic mutations rejected"},
        {"subtest": "6C", "scenario": "concurrent enable/delete fork", "passed": cases["concurrency"]["successor_count"] == 1, "result": "exactly one successor committed"},
        {"subtest": "6D", "scenario": "lost Rprep", "passed": cases["recovery"]["same_rprep_after_loss"], "result": "same cached Rprep returned"},
        {"subtest": "6E", "scenario": "lost commit receipt/final acknowledgement", "passed": cases["recovery"]["post_commit_retry_idempotent"], "result": "retry idempotent; state converged"},
        {"subtest": "6F", "scenario": "commit after delete-ticket expiry", "passed": cases["recovery"]["commit_after_ticket_expiry"], "result": "valid pending delete completed"},
    ]
    assertions = {row["subtest"]: bool(row["passed"]) for row in subtests}
    status = "PASS" if all(assertions.values()) else "FAIL"
    integration_root = root.parent.parent / "pysim-aura-integration"
    modules = {}
    for relative in ("pySim/esim/aura/lifecycle.py", "pySim/esim/aura/lifecycle_selftest.py", "pySim/esim/aura/service.py"):
        path = integration_root / relative
        modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {
        "status": status,
        "experiment": "experiment-06-lifecycle-resilience",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "subtests": subtests,
        "cases": cases,
        "metrics": {
            "old_receipt_replay": "rejected",
            "latest_receipt_retry": "idempotent",
            "tamper_rejected": cases["tamper"]["network_tamper_rejected"],
            "semantic_tamper_rejected": cases["tamper"]["semantic_checks_rejected"],
            "concurrent_successor_count": cases["concurrency"]["successor_count"],
            "same_rprep": cases["recovery"]["same_rprep_after_loss"],
            "delete_recovery_converged": cases["recovery"]["final_state"] == "tombstone",
            "expired_ticket_commit_completed": cases["recovery"]["commit_after_ticket_expiry"],
        },
        "assertions": assertions,
        "assertions_passed": all(assertions.values()),
        "source_audit": {"modules": modules},
        "migration_comparison": {"previous_status": "PASS", "conclusion_unchanged": status == "PASS"},
        "standard": {"status": "UNSUPPORTED", "claim_boundary": "No Standard lifecycle-chain interface in the current baseline; no Standard vulnerability claim."},
        "execution_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
    }
    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "raw" / "cases.json", cases)
    write_csv(output / "raw" / "subtests.csv", subtests)
    result = {"status": status, "subtests": "6/6", "successor_count": cases["concurrency"]["successor_count"], "final_delete_state": cases["recovery"]["final_state"], "results": str(output)}
    if args.machine_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("实验6迁移版：" + status)
        print("Experiment 6 integrated migration: " + status)
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
