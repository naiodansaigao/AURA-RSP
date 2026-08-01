from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RUNTIME = ROOT / "runtime" / "aura"
PROFILE = ROOT / "smdpp-data" / "upp" / "TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der"


def describe(values: list[float]) -> dict[str, float | int | None]:
    ordered = sorted(values)
    p95_index = max(0, min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1))
    mean = statistics.mean(values)
    result: dict[str, float | int | None] = {
        "n": len(values),
        "mean_ms": round(mean, 3),
        "median_ms": round(statistics.median(values), 3),
        "stdev_ms": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
        "p95_ms": round(ordered[p95_index], 3),
    }
    if len(values) > 1:
        critical = {
            1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
            6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
            11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
            16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
            21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
            26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
        }.get(len(values) - 1, 1.96)
        half = critical * statistics.stdev(values) / math.sqrt(len(values))
        result.update({
            "ci95_low_ms": round(mean - half, 3),
            "ci95_high_ms": round(mean + half, 3),
            "ci95_half_width_ms": round(half, 3),
        })
    else:
        result.update({
            "ci95_low_ms": None,
            "ci95_high_ms": None,
            "ci95_half_width_ms": None,
        })
    return result


def run(command: list[str], *, env: dict[str, str] | None = None) -> float:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=240,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr[-4000:]}"
        )
    return elapsed_ms


def issue_ticket() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pySim.esim.aura.ticket",
            "--fresh-profile-lifecycle",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr[-4000:])


def run_standard(label: str) -> float:
    env = os.environ.copy()
    env["STANDARD_PORT"] = "9445"
    return run(
        ["bash", "integration-scripts/standard_legacy_once.sh",
         str(ROOT / "logs" / f"standard-legacy-{label}.log")],
        env=env,
    )


def run_aura() -> tuple[float, dict]:
    issue_ticket()
    elapsed = run([sys.executable, "-m", "pySim.esim.aura.client", "--mode", "normal"])
    report = json.loads((RUNTIME / "last-run.json").read_text(encoding="utf-8"))
    return elapsed, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0:
        raise SystemExit("iterations must be positive and warmups nonnegative")

    for index in range(1, args.warmups + 1):
        run_standard(f"warmup-{index}")
        run_aura()

    standard: list[float] = []
    aura: list[float] = []
    aura_internal: list[float] = []
    proof_generate: list[float] = []
    proof_verify: list[float] = []
    aura_lphs: list[str] = []
    for index in range(1, args.iterations + 1):
        if index % 2:
            standard.append(run_standard(str(index)))
            aura_elapsed, aura_report = run_aura()
        else:
            aura_elapsed, aura_report = run_aura()
            standard.append(run_standard(str(index)))
        aura.append(aura_elapsed)
        aura_internal.append(float(aura_report["metrics"]["end_to_end_ms"]))
        proof_generate.append(float(aura_report["metrics"]["proof_generation_ms"]))
        proof_verify.append(float(aura_report["metrics"]["proof_verification_ms"]))
        aura_lphs.append(str(aura_report["lph"]))
        print(f"LEGACY_BENCHMARK_ITERATION_PASS={index}/{args.iterations}")

    if len(set(aura_lphs)) != args.iterations:
        raise RuntimeError(
            "AURA benchmark samples did not use independent Profile lifecycles"
        )
    standard_stats = describe(standard)
    aura_stats = describe(aura)
    standard_mean = float(standard_stats["mean_ms"])
    aura_mean = float(aura_stats["mean_ms"])
    profile = PROFILE.read_bytes()
    report = {
        "status": "PYSIM_AURA_LEGACY_WORKFLOW_BENCHMARK_PASS",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "iterations": args.iterations,
        "warmups": args.warmups,
        "scope": {
            "name": "legacy-compatible process-inclusive workflow wall clock",
            "service_startup_excluded": True,
            "offline_aura_ticket_issuance_excluded": True,
            "client_process_startup_included": True,
            "standard_client_process_launches_per_iteration": 2,
            "aura_client_process_launches_per_iteration": 1,
            "aura_unique_lph_count": len(set(aura_lphs)),
            "aura_sample_isolation": (
                "fresh ticket, salt_p and lph per sample; lifecycle preparation "
                "is outside the measured process-inclusive workflow"
            ),
            "warning": (
                "This reproduces the historical wrapper boundary but does not "
                "isolate protocol cost and gives Standard one extra interpreter startup."
            ),
            "same_profile": True,
            "profile_bytes": len(profile),
            "profile_sha256": hashlib.sha256(profile).hexdigest(),
        },
        "standard_rsp_workflow_wall": standard_stats,
        "aura_rsp_workflow_wall": aura_stats,
        "aura_internal_online": describe(aura_internal),
        "aura_proof_generate": describe(proof_generate),
        "aura_proof_verify": describe(proof_verify),
        "comparison": {
            "aura_minus_standard_mean_ms": round(aura_mean - standard_mean, 3),
            "aura_over_standard_factor": round(aura_mean / standard_mean, 3),
            "aura_overhead_percent": round((aura_mean / standard_mean - 1) * 100, 2),
        },
        "execution_order": "odd: standard->aura; even: aura->standard",
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "raw_ms": {
            "standard_rsp_workflow_wall": [round(value, 3) for value in standard],
            "aura_rsp_workflow_wall": [round(value, 3) for value in aura],
            "aura_internal_online": aura_internal,
            "aura_proof_generate": proof_generate,
            "aura_proof_verify": proof_verify,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS / "latest-legacy-workflow-benchmark.json"
    csv_path = RESULTS / "latest-legacy-workflow-benchmark.csv"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("iteration", "standard_workflow_wall_ms",
                         "aura_workflow_wall_ms", "aura_internal_online_ms",
                         "aura_proof_generate_ms", "aura_proof_verify_ms"))
        writer.writerows(zip(standard, aura, aura_internal,
                             proof_generate, proof_verify))
    print(json.dumps(report, indent=2, sort_keys=True))
    print(report["status"])


if __name__ == "__main__":
    main()
