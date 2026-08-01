#!/usr/bin/env python3
"""AURA-RSP exact replay, double-spend and conditional tracing experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from integration_adapter import IntegratedDoubleSpendAdapter
from sqlite_backend import SQLiteUsedNullifier


ROOT = Path(__file__).resolve().parent
INTEGRATION_ROOT = (ROOT / "../../pysim-aura-integration").resolve()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def stats(values: Iterable[float]) -> dict[str, float | int]:
    data = [float(value) for value in values]
    return {
        "n": len(data),
        "mean_ms": round(statistics.fmean(data), 6) if data else 0.0,
        "p50_ms": round(percentile(data, 0.50), 6),
        "p95_ms": round(percentile(data, 0.95), 6),
        "p99_ms": round(percentile(data, 0.99), 6),
        "max_ms": round(max(data), 6) if data else 0.0,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def stable_hex(seed: int, label: str, length: int = 16) -> str:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(f"EXP04|{seed}|{label}|{counter}".encode()).digest()
        )
        counter += 1
    return bytes(output[:length]).hex()


def scalar(adapter: IntegratedDoubleSpendAdapter, seed: int, label: str) -> int:
    value = int(stable_hex(seed, label, 32), 16) % adapter.curve_order
    return value or 1


def make_ticket_fixture(
    adapter: IntegratedDoubleSpendAdapter,
    seed: int,
    scenario: str,
    index: int,
) -> dict[str, Any]:
    prefix = f"{scenario}:{index}"
    k = scalar(adapter, seed, prefix + ":k")
    d_value = scalar(adapter, seed, prefix + ":d")
    nu = "nu-" + stable_hex(seed, prefix + ":nu", 24)
    eid = "89" + f"{int(stable_hex(seed, prefix + ':eid', 15), 16):030d}"[-30:]
    return {"nu": nu, "k": k, "d": d_value, "eid": eid, "r_tr": stable_hex(seed, prefix + ":rtr", 32)}


def transcript(
    adapter: IntegratedDoubleSpendAdapter,
    seed: int,
    fixture: dict[str, Any],
    scenario: str,
    ticket_index: int,
    sequence: int,
) -> dict[str, str]:
    label = f"{scenario}:{ticket_index}:transcript:{sequence}"
    gamma = scalar(adapter, seed, label + ":gamma")
    c_value = (fixture["d"] + gamma * fixture["k"]) % adapter.curve_order
    auth_hash = hashlib.sha256(
        f"{fixture['nu']}|{label}|{gamma}|{c_value}".encode()
    ).hexdigest()
    return {
        "nu": fixture["nu"],
        "gamma": adapter.scalar_to_b64(gamma),
        "c_value": adapter.scalar_to_b64(c_value),
        "opid": stable_hex(seed, label + ":opid", 16),
        "transaction_id": stable_hex(seed, label + ":tx", 16).upper(),
        "auth_hash": auth_hash,
    }


def classify_event(
    backend: SQLiteUsedNullifier,
    event: dict[str, Any],
    scenario_id: str,
) -> dict[str, Any]:
    result = backend.classify(
        nu=event["nu"],
        auth_hash=event["auth_hash"],
        gamma=event["gamma"],
        c_value=event["c_value"],
        opid=event["opid"],
        transaction_id=event["transaction_id"],
        response={"Bind_t": "cached-test-binding", "replayed": False},
    )
    return {
        "scenario": scenario_id,
        "ticket_index": event["ticket_index"],
        "request_type": event["request_type"],
        "sequence": event["sequence"],
        "configured_copies": event["configured_copies"],
        "arrival_offset_ms": round(event["arrival_offset_ms"], 3),
        "outcome": result["outcome"],
        "error_code": result["error_code"] or "",
        "business_executed": result["business_executed"],
        "trace_triggered": result["trace_event_new"],
        "trace_eid": (result["trace"] or {}).get("eid", ""),
        "expected_eid": event["expected_eid"],
        "recovered_k_correct": result["recovered_k"] in (None, event["expected_k"]),
        "query_ms": round(result["query_ms"], 6),
        "decision_ms": round(result["decision_ms"], 6),
        "trace_lookup_ms": round(result["trace_lookup_ms"], 6),
        "latency_ms": round(result["total_ms"], 6),
        "transaction_retries": result["retries"],
    }


def run_mixed_scenario(
    *,
    adapter: IntegratedDoubleSpendAdapter,
    backend_path: Path,
    seed: int,
    ticket_count: int,
    double_spend_percent: int,
    replay_ticket_fraction: float,
    replay_counts: list[int],
    double_transcript_counts: list[int],
    concurrency: int,
    arrival_span_ms: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    scenario_id = f"double-{double_spend_percent:02d}pct"
    if backend_path.exists():
        backend_path.unlink()
    backend = SQLiteUsedNullifier(backend_path, adapter.classify_nullifier)
    rng = random.Random(seed + double_spend_percent * 1009)
    double_count = round(ticket_count * double_spend_percent / 100)
    replay_count = round((ticket_count - double_count) * replay_ticket_fraction)
    classes = (
        ["double_spend"] * double_count
        + ["replay"] * replay_count
        + ["normal"] * (ticket_count - double_count - replay_count)
    )
    rng.shuffle(classes)
    tasks: list[dict[str, Any]] = []
    for index, ticket_class in enumerate(classes):
        fixture = make_ticket_fixture(adapter, seed, scenario_id, index)
        expected_k = adapter.scalar_to_b64(fixture["k"])
        backend.put_trace(expected_k, fixture["eid"], fixture["r_tr"])
        first = transcript(adapter, seed, fixture, scenario_id, index, 0)
        arrival = rng.uniform(0, arrival_span_ms) if arrival_span_ms else 0.0
        events = [
            {
                **first,
                "ticket_index": index,
                "request_type": "normal",
                "sequence": 0,
                "configured_copies": 1,
                "arrival_offset_ms": arrival,
                "expected_eid": fixture["eid"],
                "expected_k": expected_k,
            }
        ]
        if ticket_class == "replay":
            copies = replay_counts[index % len(replay_counts)]
            for sequence in range(1, copies + 1):
                events.append(
                    {
                        **first,
                        "ticket_index": index,
                        "request_type": "exact_replay",
                        "sequence": sequence,
                        "configured_copies": copies,
                        "arrival_offset_ms": arrival + sequence * 0.001,
                        "expected_eid": fixture["eid"],
                        "expected_k": expected_k,
                    }
                )
        elif ticket_class == "double_spend":
            count = double_transcript_counts[index % len(double_transcript_counts)]
            for sequence in range(1, count):
                distinct = transcript(adapter, seed, fixture, scenario_id, index, sequence)
                events.append(
                    {
                        **distinct,
                        "ticket_index": index,
                        "request_type": "double_spend",
                        "sequence": sequence,
                        "configured_copies": count,
                        "arrival_offset_ms": arrival + sequence * 0.001,
                        "expected_eid": fixture["eid"],
                        "expected_k": expected_k,
                    }
                )
        tasks.append({"arrival_offset_ms": arrival, "events": events})

    tasks.sort(key=lambda item: item["arrival_offset_ms"])
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()

    def process_ticket(item: dict[str, Any]) -> list[dict[str, Any]]:
        local_rows = [classify_event(backend, event, scenario_id) for event in item["events"]]
        backend.close_thread()
        return local_rows

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for item in tasks:
            target = started + item["arrival_offset_ms"] / 1000.0
            remaining = target - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
            futures.append(executor.submit(process_ticket, item))
        for future in as_completed(futures):
            rows.extend(future.result())

    rows.sort(key=lambda row: (int(row["ticket_index"]), int(row["sequence"])))
    elapsed_ms = (time.perf_counter() - started) * 1000
    by_type = {
        request_type: stats(
            row["latency_ms"] for row in rows if row["request_type"] == request_type
        )
        for request_type in ("normal", "exact_replay", "double_spend")
    }
    double_rows = [row for row in rows if row["request_type"] == "double_spend"]
    replay_rows = [row for row in rows if row["request_type"] == "exact_replay"]
    normal_rows = [row for row in rows if row["request_type"] == "normal"]
    summary = {
        "scenario": scenario_id,
        "ticket_count": ticket_count,
        "double_spend_percent": double_spend_percent,
        "concurrency": concurrency,
        "arrival_span_ms": arrival_span_ms,
        "requests": len(rows),
        "normal_requests": len(normal_rows),
        "exact_replay_requests": len(replay_rows),
        "double_spend_requests": len(double_rows),
        "business_execution_count": backend.count("business_executions"),
        "unique_trace_count": backend.count("trace_events"),
        "double_spend_detection_rate": round(
            sum(row["outcome"] == "double_spend" for row in double_rows)
            / max(1, len(double_rows)),
            6,
        ),
        "exact_replay_false_positive_rate": round(
            sum(row["outcome"] != "exact_replay" for row in replay_rows)
            / max(1, len(replay_rows)),
            6,
        ),
        "false_trace_count": sum(
            row["trace_triggered"] and row["request_type"] != "double_spend"
            for row in rows
        ),
        "eid_recovery_accuracy": round(
            sum(row["trace_eid"] == row["expected_eid"] for row in double_rows)
            / max(1, len(double_rows)),
            6,
        ),
        "transaction_retry_count": backend.retry_count,
        "wall_ms": round(elapsed_ms, 3),
        "throughput_req_s": round(len(rows) / max(elapsed_ms / 1000, 1e-9), 3),
        "latency_by_request_type": by_type,
    }
    backend.close_thread()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(backend_path) + suffix)
        if candidate.exists():
            candidate.unlink()
    return summary, rows


def run_scale_experiment(
    *,
    adapter: IntegratedDoubleSpendAdapter,
    runtime: Path,
    seed: int,
    sizes: list[int],
    samples_per_type: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summaries: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    for size in sizes:
        path = runtime / f"scale-{size}.sqlite"
        if path.exists():
            path.unlink()
        backend = SQLiteUsedNullifier(path, adapter.classify_nullifier)
        prefill_ms = backend.prefill(size)
        size_rows: list[dict[str, Any]] = []
        for request_type in ("normal", "exact_replay", "double_spend"):
            for sample_index in range(samples_per_type):
                fixture = make_ticket_fixture(
                    adapter, seed, f"scale-{size}-{request_type}", sample_index
                )
                expected_k = adapter.scalar_to_b64(fixture["k"])
                backend.put_trace(expected_k, fixture["eid"], fixture["r_tr"])
                first = transcript(
                    adapter,
                    seed,
                    fixture,
                    f"scale-{size}-{request_type}",
                    sample_index,
                    0,
                )
                if request_type == "normal":
                    measured = first
                else:
                    backend.classify(
                        nu=first["nu"],
                        auth_hash=first["auth_hash"],
                        gamma=first["gamma"],
                        c_value=first["c_value"],
                        opid=first["opid"],
                        transaction_id=first["transaction_id"],
                        response={"Bind_t": "scale-binding"},
                    )
                    measured = (
                        first
                        if request_type == "exact_replay"
                        else transcript(
                            adapter,
                            seed,
                            fixture,
                            f"scale-{size}-{request_type}",
                            sample_index,
                            1,
                        )
                    )
                count_before = backend.count()
                result = backend.classify(
                    nu=measured["nu"],
                    auth_hash=measured["auth_hash"],
                    gamma=measured["gamma"],
                    c_value=measured["c_value"],
                    opid=measured["opid"],
                    transaction_id=measured["transaction_id"],
                    response={"Bind_t": "scale-binding"},
                )
                row = {
                    "baseline_size": size,
                    "db_size_before": count_before,
                    "request_type": request_type,
                    "sample": sample_index,
                    "outcome": result["outcome"],
                    "query_ms": round(result["query_ms"], 6),
                    "decision_ms": round(result["decision_ms"], 6),
                    "trace_lookup_ms": round(result["trace_lookup_ms"], 6),
                    "latency_ms": round(result["total_ms"], 6),
                    "transaction_retries": result["retries"],
                    "recovered_eid_correct": (
                        result["trace"] is None
                        or result["trace"].get("eid") == fixture["eid"]
                    ),
                }
                samples.append(row)
                size_rows.append(row)
        type_summary = {
            request_type: stats(
                row["latency_ms"]
                for row in size_rows
                if row["request_type"] == request_type
            )
            for request_type in ("normal", "exact_replay", "double_spend")
        }
        summaries.append(
            {
                "database_size": size,
                "prefill_ms": round(prefill_ms, 3),
                "database_bytes": path.stat().st_size,
                "samples_per_type": samples_per_type,
                "transaction_retry_count": sum(
                    int(row["transaction_retries"]) for row in size_rows
                ),
                "latency": type_summary,
            }
        )
        backend.close_thread()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(path) + suffix)
            if candidate.exists():
                candidate.unlink()
    return summaries, samples


def run_trace_breakdown(
    adapter: IntegratedDoubleSpendAdapter,
    runtime: Path,
    samples: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    first, first_generation_ms = adapter.build_transcript(0)
    second, second_generation_ms = adapter.build_transcript(1)
    breakdown_rows: list[dict[str, Any]] = []
    verification_pairs: list[float] = []
    for index in range(samples):
        started = time.perf_counter_ns()
        first_ok, first_reason, first_ms = adapter.verify_transcript(first)
        second_ok, second_reason, second_ms = adapter.verify_transcript(second)
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        verification_pairs.append(elapsed)
        breakdown_rows.append(
            {
                "component": "two_transcript_verification",
                "sample": index,
                "latency_ms": round(elapsed, 6),
                "accepted": first_ok and second_ok,
                "detail": f"{first_reason}|{second_reason};individual={first_ms:.3f}+{second_ms:.3f}",
            }
        )

    iterations = 2000
    recovery_values: list[float] = []
    recovered = None
    for index in range(iterations):
        started = time.perf_counter_ns()
        recovered = adapter.recover_trace_key(
            first.proof["gamma"], first.proof["c"], second.proof["gamma"], second.proof["c"]
        )
        recovery_values.append((time.perf_counter_ns() - started) / 1_000_000)
    for index, value in enumerate(recovery_values):
        breakdown_rows.append(
            {"component": "k_recovery", "sample": index, "latency_ms": round(value, 6), "accepted": recovered == adapter.trace_key_b64(), "detail": "mod-q recovery"}
        )

    trace_path = runtime / "trace-breakdown.sqlite"
    if trace_path.exists():
        trace_path.unlink()
    backend = SQLiteUsedNullifier(trace_path, adapter.classify_nullifier)
    backend.put_trace(adapter.trace_key_b64(), adapter.eid, adapter.r_tr)
    lookup_values: list[float] = []
    lookup = None
    for index in range(iterations):
        started = time.perf_counter_ns()
        lookup = backend.lookup_trace(adapter.trace_key_b64())
        value = (time.perf_counter_ns() - started) / 1_000_000
        lookup_values.append(value)
        breakdown_rows.append(
            {"component": "trace_index_lookup", "sample": index, "latency_ms": round(value, 6), "accepted": lookup is not None, "detail": "indexed SQLite lookup"}
        )
    verification_values: list[float] = []
    for index in range(iterations):
        started = time.perf_counter_ns()
        correct = bool(lookup and lookup["eid"] == adapter.eid and lookup["r_tr"] == adapter.r_tr)
        value = (time.perf_counter_ns() - started) / 1_000_000
        verification_values.append(value)
        breakdown_rows.append(
            {"component": "eid_result_check", "sample": index, "latency_ms": round(value, 6), "accepted": correct, "detail": "EID and trace-record equality"}
        )
    backend.close_thread()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(trace_path) + suffix)
        if candidate.exists():
            candidate.unlink()

    return (
        {
            "proof_generation_ms": {
                "first": round(first_generation_ms, 3),
                "second": round(second_generation_ms, 3),
            },
            "two_transcript_verification": stats(verification_pairs),
            "k_recovery": stats(recovery_values),
            "trace_index_lookup": stats(lookup_values),
            "eid_result_check": stats(verification_values),
            "recovered_k_correct": recovered == adapter.trace_key_b64(),
            "recovered_eid_correct": bool(lookup and lookup["eid"] == adapter.eid),
            "normal_transcript_exposes_eid": adapter.eid in json.dumps(first.proof, sort_keys=True),
        },
        breakdown_rows,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "config.json"))
    parser.add_argument("--output", default=str(ROOT / "results" / "latest"))
    parser.add_argument("--tickets", type=int)
    parser.add_argument("--max-db-size", type=int)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    output = Path(args.output).resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    raw = output / "raw"
    runtime = output / "runtime"
    paper = output / "paper"
    raw.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(parents=True, exist_ok=True)
    paper.mkdir(parents=True, exist_ok=True)

    seed = int(config["seed"])
    ticket_count = args.tickets or int(config["mixed_load"]["tickets"])
    sizes = [int(value) for value in config["database_scale"]["sizes"]]
    if args.max_db_size:
        sizes = [value for value in sizes if value <= args.max_db_size]
    started = time.perf_counter_ns()
    adapter = IntegratedDoubleSpendAdapter(INTEGRATION_ROOT, seed)

    mixed_summaries: list[dict[str, Any]] = []
    mixed_rows: list[dict[str, Any]] = []
    percentages = config["mixed_load"]["double_spend_percentages"]
    concurrencies = config["mixed_load"]["concurrency_levels"]
    arrival_spans = config["mixed_load"]["arrival_spans_ms"]
    for index, percentage in enumerate(percentages):
        summary, rows = run_mixed_scenario(
            adapter=adapter,
            backend_path=runtime / f"mixed-{percentage}.sqlite",
            seed=seed,
            ticket_count=ticket_count,
            double_spend_percent=int(percentage),
            replay_ticket_fraction=float(config["mixed_load"]["replay_ticket_fraction"]),
            replay_counts=[int(value) for value in config["mixed_load"]["replay_counts"]],
            double_transcript_counts=[int(value) for value in config["mixed_load"]["double_transcript_counts"]],
            concurrency=int(concurrencies[index % len(concurrencies)]),
            arrival_span_ms=int(arrival_spans[index % len(arrival_spans)]),
        )
        mixed_summaries.append(summary)
        mixed_rows.extend(rows)
        print(
            f"EXP04_PROGRESS mixed={percentage}% requests={summary['requests']} "
            f"wall_ms={summary['wall_ms']}",
            file=sys.stderr,
        )

    scale_summaries, scale_rows = run_scale_experiment(
        adapter=adapter,
        runtime=runtime,
        seed=seed,
        sizes=sizes,
        samples_per_type=int(config["database_scale"]["samples_per_type"]),
    )
    trace_summary, trace_rows = run_trace_breakdown(
        adapter,
        runtime,
        int(config["trace_breakdown"]["cryptographic_samples"]),
    )

    all_double = [row for row in mixed_rows if row["request_type"] == "double_spend"]
    all_replay = [row for row in mixed_rows if row["request_type"] == "exact_replay"]
    all_normal = [row for row in mixed_rows if row["request_type"] == "normal"]
    assertions = {
        "all_first_uses_execute_once": all(row["outcome"] == "new" for row in all_normal),
        "all_exact_replays_are_idempotent": all(row["outcome"] == "exact_replay" for row in all_replay),
        "all_double_spends_detected": all(row["outcome"] == "double_spend" for row in all_double),
        "no_second_business_execution": all(not row["business_executed"] for row in all_replay + all_double),
        "no_exact_replay_false_positive": all(summary["exact_replay_false_positive_rate"] == 0 for summary in mixed_summaries),
        "no_false_trace": all(summary["false_trace_count"] == 0 for summary in mixed_summaries),
        "all_recovered_eids_correct": all(row["trace_eid"] == row["expected_eid"] for row in all_double),
        "production_transcripts_both_valid": all(row["accepted"] for row in trace_rows if row["component"] == "two_transcript_verification"),
        "production_k_recovery_correct": trace_summary["recovered_k_correct"],
        "production_eid_recovery_correct": trace_summary["recovered_eid_correct"],
        "single_transcript_does_not_expose_eid": not trace_summary["normal_transcript_exposes_eid"],
        "all_scale_outcomes_correct": all(
            row["outcome"]
            == {"normal": "new", "exact_replay": "exact_replay", "double_spend": "double_spend"}[row["request_type"]]
            for row in scale_rows
        ),
        "all_scale_eids_correct": all(row["recovered_eid_correct"] for row in scale_rows),
    }
    status = "PASS" if all(assertions.values()) else "FAIL"
    summary = {
        "status": status,
        "experiment": "double_spend_exact_replay_conditional_tracing",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "seed": seed,
        "ticket_count_per_mixed_scenario": ticket_count,
        "mixed_load": mixed_summaries,
        "database_scale": scale_summaries,
        "trace_breakdown": trace_summary,
        "aggregate": {
            "business_execution_count": sum(item["business_execution_count"] for item in mixed_summaries),
            "double_spend_detection_rate": round(sum(row["outcome"] == "double_spend" for row in all_double) / max(1, len(all_double)), 6),
            "exact_replay_false_positive_rate": round(sum(row["outcome"] != "exact_replay" for row in all_replay) / max(1, len(all_replay)), 6),
            "false_trace_count": sum(item["false_trace_count"] for item in mixed_summaries),
            "eid_recovery_accuracy": round(sum(row["trace_eid"] == row["expected_eid"] for row in all_double) / max(1, len(all_double)), 6),
            "transaction_retry_count": sum(item["transaction_retry_count"] for item in mixed_summaries) + sum(item["transaction_retry_count"] for item in scale_summaries),
            "latency": {
                request_type: stats(row["latency_ms"] for row in mixed_rows if row["request_type"] == request_type)
                for request_type in ("normal", "exact_replay", "double_spend")
            },
        },
        "assertions": assertions,
        "source_audit": adapter.source_audit(),
        "measurement_scope": {
            "mixed_and_scale": "post-proof-verification production nullifier classifier with indexed SQLite atomic state",
            "cryptographic_trace": "real integrated create_auth_proof and verify_auth_proof for two valid distinct transcripts",
            "arrival_interval": "ticket start offsets span the configured 0--5000 ms window; per-ticket transcript order is preserved",
            "business_execution": "one atomic business_executions row per first accepted nullifier",
        },
        "host": {"platform": platform.platform(), "python": platform.python_version(), "logical_cpus": os.cpu_count()},
        "runtime_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
    }

    write_jsonl(raw / "mixed-events.jsonl", mixed_rows)
    write_csv(raw / "mixed-events.csv", mixed_rows)
    write_csv(raw / "mixed-scenarios.csv", mixed_summaries)
    write_csv(raw / "scale-samples.csv", scale_rows)
    write_csv(raw / "trace-breakdown-samples.csv", trace_rows)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (output / "evidence").mkdir(exist_ok=True)
    (output / "evidence" / "assertions.json").write_text(json.dumps(assertions, indent=2, sort_keys=True), encoding="utf-8")

    from plot_results import create_figures

    create_figures(summary, scale_rows, mixed_rows, paper)
    if args.machine_json:
        print(json.dumps({"status": status, "results": str(output), "tickets": ticket_count, "max_database_size": max(sizes), "double_spend_detection_rate": summary["aggregate"]["double_spend_detection_rate"], "false_trace_count": summary["aggregate"]["false_trace_count"]}, sort_keys=True))
    else:
        if args.lang in ("zh", "both"):
            print("\n实验4：双花、精确重传与条件追踪")
            print(f"状态: {status} | 每场景票据: {ticket_count} | 最大数据库: {max(sizes):,}")
            print(f"双花检测率: {summary['aggregate']['double_spend_detection_rate']:.4f} | 重传误报率: {summary['aggregate']['exact_replay_false_positive_rate']:.4f} | 错误追踪: {summary['aggregate']['false_trace_count']}")
        if args.lang in ("en", "both"):
            print("\nExperiment 4: Double Spend, Exact Replay, and Conditional Tracing")
            print(f"Status: {status} | tickets/scenario: {ticket_count} | max database: {max(sizes):,}")
            print(f"Double-spend detection: {summary['aggregate']['double_spend_detection_rate']:.4f} | replay false positives: {summary['aggregate']['exact_replay_false_positive_rate']:.4f} | false traces: {summary['aggregate']['false_trace_count']}")
        print(f"RESULTS={output}")
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
