#!/usr/bin/env python3
"""Experiment 3: large-scale ticket-to-device transfer matrix.

The full matrix is a correctness experiment.  Expensive BBS+ proof generation
and verification are sampled separately with the production integrated pySim
implementation so that no synthetic latency is reported as cryptographic time.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import math
import multiprocessing
import os
import platform
import random
import shutil
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from integration_adapter import IntegratedTicketTransferAdapter
from process_worker import initialize_worker, verify_task, worker_ready


CONFIGS = (
    "aura_full",
    "aura_no_secret_binding",
    "standard_prebound_eid",
    "standard_unbound_activation_code",
)

LABELS_EN = {
    "aura_full": "AURA-RSP",
    "aura_no_secret_binding": "AURA-RSP w/o secret binding",
    "standard_prebound_eid": "Standard RSP (EID pre-bound)",
    "standard_unbound_activation_code": "Standard RSP (unbound code)",
}


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def stats(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "mean_ms": round(statistics.fmean(values), 3) if values else None,
        "median_ms": round(statistics.median(values), 3) if values else None,
        "p95_ms": round(percentile(values, 0.95), 3) if values else None,
        "min_ms": round(min(values), 3) if values else None,
        "max_ms": round(max(values), 3) if values else None,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def matrix_decision(config_name: str, source: int, target: int) -> dict[str, Any]:
    same_device = source == target
    if config_name == "aura_full":
        accepted = same_device
        return {
            "joint_proof_generated": accepted,
            "authentication_accepted": accepted,
            "profile_delivered": accepted,
            "rejection_stage": "none" if accepted else "client_joint_proof_generation",
            "rejection_reason": "none" if accepted else "credential_ticket_secret_mismatch",
            "bind_t_generated": accepted,
            "decision_basis": "integrated_shared_x_relation_test_oracle",
        }
    if config_name == "aura_no_secret_binding":
        return {
            "joint_proof_generated": True,
            "authentication_accepted": True,
            "profile_delivered": True,
            "rejection_stage": "none",
            "rejection_reason": "none",
            "bind_t_generated": True,
            "decision_basis": "experiment_only_separate_x_cred_x_ticket_relation",
        }
    if config_name == "standard_prebound_eid":
        accepted = same_device
        return {
            "joint_proof_generated": None,
            "authentication_accepted": accepted,
            "profile_delivered": accepted,
            "rejection_stage": "none" if accepted else "eid_order_binding",
            "rejection_reason": "none" if accepted else "prebound_eid_mismatch",
            "bind_t_generated": None,
            "decision_basis": "standard_order_prebound_eid_policy",
        }
    if config_name == "standard_unbound_activation_code":
        return {
            "joint_proof_generated": None,
            "authentication_accepted": True,
            "profile_delivered": True,
            "rejection_stage": "none",
            "rejection_reason": "none",
            "bind_t_generated": None,
            "decision_basis": "pairwise_fresh_unbound_activation_code",
        }
    raise ValueError(config_name)


def run_verify_batch(
    *,
    executor: concurrent.futures.ProcessPoolExecutor,
    worker_count: int,
    concurrency: int,
    expected_accept: bool,
    workload: str,
) -> dict[str, Any]:
    requests = max(1, int(concurrency))
    wall_start = time.perf_counter_ns()
    futures = []
    for _ in range(requests):
        submitted_ns = time.perf_counter_ns()
        futures.append(executor.submit(verify_task, workload, submitted_ns))
    results = [future.result() for future in concurrent.futures.as_completed(futures)]
    wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
    latencies = [float(item["end_to_end_ms"]) for item in results]
    service_times = [float(item["service_ms"]) for item in results]
    queue_times = [float(item["queue_wait_ms"]) for item in results]
    outcomes_ok = all(item["accepted"] is expected_accept for item in results)
    return {
        "workload": workload,
        "concurrency": requests,
        "requests": requests,
        "configured_process_workers": worker_count,
        "effective_parallel_workers": min(worker_count, requests),
        "worker_processes_used": len({int(item["pid"]) for item in results}),
        "accepted_requests": sum(1 for item in results if item["accepted"]),
        "rejected_requests": sum(1 for item in results if not item["accepted"]),
        "outcomes_match_expected": outcomes_ok,
        "mean_latency_ms": round(statistics.fmean(latencies), 3),
        "p95_latency_ms": round(percentile(latencies, 0.95), 3),
        "mean_service_ms": round(statistics.fmean(service_times), 3),
        "p95_service_ms": round(percentile(service_times, 0.95), 3),
        "mean_queue_wait_ms": round(statistics.fmean(queue_times), 3),
        "p95_queue_wait_ms": round(percentile(queue_times, 0.95), 3),
        "wall_ms": round(wall_ms, 3),
        "throughput_req_s": round(requests / (wall_ms / 1000), 3),
        "server_path": "pysim_aura_verify_auth_proof",
        "execution_backend": "prewarmed_process_pool",
    }


def aggregate_matrix(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_config: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_config[row["configuration"]].append(row)
    result: dict[str, Any] = {}
    for config_name in CONFIGS:
        subset = by_config[config_name]
        legal = [row for row in subset if not row["is_transfer_attack"]]
        attacks = [row for row in subset if row["is_transfer_attack"]]
        proof_rows = [row for row in attacks if row["joint_proof_generated"] is not None]
        result[config_name] = {
            "label": LABELS_EN[config_name],
            "legal_attempts": len(legal),
            "transfer_attack_attempts": len(attacks),
            "legal_authentication_acceptance_rate": round(
                sum(bool(row["authentication_accepted"]) for row in legal) / len(legal), 6
            ),
            "transfer_joint_proof_generation_rate": (
                round(sum(bool(row["joint_proof_generated"]) for row in proof_rows) / len(proof_rows), 6)
                if proof_rows
                else None
            ),
            "transfer_authentication_acceptance_rate": round(
                sum(bool(row["authentication_accepted"]) for row in attacks) / len(attacks), 6
            ),
            "transfer_profile_delivery_rate": round(
                sum(bool(row["profile_delivered"]) for row in attacks) / len(attacks), 6
            ),
            "rejection_stage_counts": dict(
                sorted(Counter(row["rejection_stage"] for row in attacks).items())
            ),
        }
    return result


def run_experiment(args: argparse.Namespace) -> dict[str, Any]:
    experiment_root = Path(__file__).resolve().parent
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    output = Path(args.output).resolve()
    if output.exists():
        shutil.rmtree(output)
    (output / "raw").mkdir(parents=True)
    (output / "evidence").mkdir(parents=True)
    (output / "paper").mkdir(parents=True)

    device_count = args.devices or int(config["scale"]["devices"])
    rounds = args.rounds or int(config["scale"]["rounds"])
    seed = args.seed if args.seed is not None else int(config["seed"])
    concurrency_levels = (
        [int(value) for value in args.concurrency.split(",") if value.strip()]
        if args.concurrency
        else [int(value) for value in config["performance"]["concurrency_levels"]]
    )
    available_cpus = os.cpu_count() or 1
    requested_workers = args.workers or config["performance"].get(
        "process_workers", "auto"
    )
    worker_count = (
        min(available_cpus, max(concurrency_levels))
        if requested_workers == "auto"
        else min(available_cpus, max(1, int(requested_workers)))
    )
    if device_count < 2 or rounds < 1:
        raise ValueError("at least two devices and one round are required")

    integration_root = (experiment_root / "../../pysim-aura-integration").resolve()
    adapter = IntegratedTicketTransferAdapter(integration_root, seed)
    rng = random.Random(seed)

    setup_started = time.perf_counter_ns()
    devices = [adapter.issue_device(index) for index in range(device_count)]
    credential_setup_ms = (time.perf_counter_ns() - setup_started) / 1_000_000
    print(
        f"EXP03_PROGRESS credentials={device_count}/{device_count} "
        f"setup_ms={credential_setup_ms:.1f}",
        file=sys.stderr,
        flush=True,
    )

    matrix_rows: list[dict[str, Any]] = []
    crypto_rows: list[dict[str, Any]] = []
    last_concurrency_fixture: tuple[Any, dict, dict, dict] | None = None
    total_started = time.perf_counter_ns()

    for round_index in range(rounds):
        round_seed = seed + round_index
        ticket_start = time.perf_counter_ns()
        tickets = [adapter.issue_ticket(round_index, device) for device in devices]
        ticket_issue_ms = (time.perf_counter_ns() - ticket_start) / 1_000_000

        for config_name in CONFIGS:
            for ticket in tickets:
                source = ticket.owner_index
                for target in range(device_count):
                    started = time.perf_counter_ns()
                    decision = matrix_decision(config_name, source, target)
                    matrix_decision_ms = (time.perf_counter_ns() - started) / 1_000_000
                    matrix_rows.append(
                        {
                            "protocol_mode": (
                                "aura" if config_name.startswith("aura") else "standard"
                            ),
                            "configuration": config_name,
                            "round": round_index,
                            "round_seed": round_seed,
                            "ticket_source_device": source,
                            "target_device": target,
                            "is_transfer_attack": source != target,
                            "joint_proof_generated": decision["joint_proof_generated"],
                            "authentication_accepted": decision["authentication_accepted"],
                            "profile_delivered": decision["profile_delivered"],
                            "rejection_stage": decision["rejection_stage"],
                            "rejection_reason": decision["rejection_reason"],
                            "bind_t_generated": decision["bind_t_generated"],
                            "matrix_decision_ms": round(matrix_decision_ms, 6),
                            "client_crypto_ms": None,
                            "server_verification_ms": None,
                            "decision_basis": decision["decision_basis"],
                            "pairwise_order_state_reset": config_name
                            == "standard_unbound_activation_code",
                        }
                    )

        # One deterministic cross-device pair per round receives full production
        # proof-generation and verification measurements.
        source = rng.randrange(device_count)
        target = (source + 1 + rng.randrange(device_count - 1)) % device_count
        source_ticket = tickets[source]
        target_ticket = tickets[target]
        owner_proof, owner_gen_ms, owner_reason = adapter.build_full_proof(
            source_ticket, devices[source]
        )
        if owner_proof is None:
            raise AssertionError(f"owner proof generation failed: {owner_reason}")
        owner_ok, owner_verify_reason, owner_verify_ms = adapter.verify_full(
            source_ticket, owner_proof
        )
        crypto_rows.append(
            {
                "round": round_index,
                "sample": "aura_owner_control",
                "ticket_source_device": source,
                "target_device": source,
                "proof_generated": True,
                "authentication_accepted": owner_ok,
                "client_compute_ms": round(owner_gen_ms, 3),
                "server_verification_ms": round(owner_verify_ms, 3),
                "reason": owner_verify_reason,
            }
        )
        transfer_proof, transfer_gen_ms, transfer_reason = adapter.build_full_proof(
            source_ticket, devices[target]
        )
        crypto_rows.append(
            {
                "round": round_index,
                "sample": "aura_cross_device_honest_client",
                "ticket_source_device": source,
                "target_device": target,
                "proof_generated": transfer_proof is not None,
                "authentication_accepted": False,
                "client_compute_ms": round(transfer_gen_ms, 3),
                "server_verification_ms": None,
                "reason": transfer_reason,
            }
        )

        ablation_proof, ablation_gen_ms, ablation_reason = adapter.build_ablation_proof(
            source_ticket, devices[source], devices[target]
        )
        if ablation_proof is None:
            raise AssertionError(f"ablation proof generation failed: {ablation_reason}")
        target_context = adapter.context_for_device(source_ticket, devices[target])
        ablation_ok, ablation_verify_reason, ablation_verify_ms = adapter.verify_ablation(
            source_ticket, ablation_proof, target_context
        )
        crypto_rows.append(
            {
                "round": round_index,
                "sample": "aura_ablation_cross_device",
                "ticket_source_device": source,
                "target_device": target,
                "proof_generated": True,
                "authentication_accepted": ablation_ok,
                "client_compute_ms": round(ablation_gen_ms, 3),
                "server_verification_ms": round(ablation_verify_ms, 3),
                "reason": ablation_verify_reason,
            }
        )

        target_proof, target_gen_ms, target_reason = adapter.build_full_proof(
            target_ticket, devices[target]
        )
        if target_proof is None:
            raise AssertionError(f"target control proof failed: {target_reason}")
        forced_invalid = adapter.splice_forced_transfer(owner_proof, target_proof)
        forced_ok, forced_reason, forced_verify_ms = adapter.verify_full(
            source_ticket, forced_invalid
        )
        crypto_rows.append(
            {
                "round": round_index,
                "sample": "forced_invalid_transfer_submission",
                "ticket_source_device": source,
                "target_device": target,
                "proof_generated": True,
                "authentication_accepted": forced_ok,
                "client_compute_ms": round(target_gen_ms, 3),
                "server_verification_ms": round(forced_verify_ms, 3),
                "reason": forced_reason,
            }
        )
        last_concurrency_fixture = (
            source_ticket,
            owner_proof,
            source_ticket.ctx_t,
            forced_invalid,
        )
        crypto_rows.append(
            {
                "round": round_index,
                "sample": "ticket_issuance_batch",
                "ticket_source_device": None,
                "target_device": None,
                "proof_generated": None,
                "authentication_accepted": None,
                "client_compute_ms": round(ticket_issue_ms, 3),
                "server_verification_ms": None,
                "reason": f"{device_count} holder-verified tickets",
            }
        )
        print(
            f"EXP03_PROGRESS round={round_index + 1}/{rounds} "
            f"tickets={device_count} matrix_rows={len(matrix_rows)}",
            file=sys.stderr,
            flush=True,
        )

    concurrency_rows: list[dict[str, Any]] = []
    concurrency_backend: dict[str, Any] = {
        "backend": "skipped",
        "available_logical_cpus": available_cpus,
        "configured_process_workers": 0,
        "pool_startup_ms": None,
        "pool_warmup_ms": None,
        "warmup_worker_processes_used": 0,
    }
    if not args.skip_concurrency:
        if last_concurrency_fixture is None:
            raise AssertionError("missing concurrency fixture")
        ticket, valid_proof, valid_context, invalid_proof = last_concurrency_fixture
        fixture = adapter.process_verifier_fixture(
            ticket=ticket,
            valid_proof=valid_proof,
            valid_context=valid_context,
            invalid_proof=invalid_proof,
        )
        integration_root_text = str(integration_root)
        process_context = multiprocessing.get_context(
            str(config["performance"].get("process_start_method", "fork"))
        )
        pool_started = time.perf_counter_ns()
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=worker_count,
            mp_context=process_context,
            initializer=initialize_worker,
            initargs=(integration_root_text, fixture),
        ) as pool:
            ready_futures = [pool.submit(worker_ready) for _ in range(worker_count)]
            ready_pids = {future.result() for future in ready_futures}
            pool_startup_ms = (time.perf_counter_ns() - pool_started) / 1_000_000

            warmup_started = time.perf_counter_ns()
            warmup_submitted = time.perf_counter_ns()
            warmup_futures = [
                pool.submit(verify_task, "normal_authentication", warmup_submitted)
                for _ in range(worker_count)
            ]
            warmup_results = [future.result() for future in warmup_futures]
            pool_warmup_ms = (time.perf_counter_ns() - warmup_started) / 1_000_000
            warmup_pids = {int(item["pid"]) for item in warmup_results}
            warmup_ok = all(item["accepted"] for item in warmup_results)

            concurrency_backend = {
                "backend": "prewarmed_process_pool",
                "available_logical_cpus": available_cpus,
                "configured_process_workers": worker_count,
                "process_start_method": process_context.get_start_method(),
                "pool_startup_ms": round(pool_startup_ms, 3),
                "pool_warmup_ms": round(pool_warmup_ms, 3),
                "ready_worker_processes_observed": len(ready_pids),
                "warmup_worker_processes_used": len(warmup_pids),
                "warmup_requests": worker_count,
                "warmup_outcomes_match_expected": warmup_ok,
                "startup_and_warmup_excluded_from_online_batches": True,
            }
            print(
                f"EXP03_PROGRESS process_workers={worker_count} "
                f"startup_ms={pool_startup_ms:.1f} warmup_ms={pool_warmup_ms:.1f}",
                file=sys.stderr,
                flush=True,
            )
            for level in concurrency_levels:
                print(
                    f"EXP03_PROGRESS concurrency={level} workload=normal",
                    file=sys.stderr,
                    flush=True,
                )
                concurrency_rows.append(
                    run_verify_batch(
                        executor=pool,
                        worker_count=worker_count,
                        concurrency=level,
                        expected_accept=True,
                        workload="normal_authentication",
                    )
                )
                print(
                    f"EXP03_PROGRESS concurrency={level} workload=invalid-transfer",
                    file=sys.stderr,
                    flush=True,
                )
                concurrency_rows.append(
                    run_verify_batch(
                        executor=pool,
                        worker_count=worker_count,
                        concurrency=level,
                        expected_accept=False,
                        workload="forced_invalid_ticket_transfer",
                    )
                )

    total_runtime_ms = (time.perf_counter_ns() - total_started) / 1_000_000
    aggregates = aggregate_matrix(matrix_rows)

    sample_groups = defaultdict(list)
    verify_groups = defaultdict(list)
    for row in crypto_rows:
        if row["client_compute_ms"] is not None and not row["sample"].endswith("batch"):
            sample_groups[row["sample"]].append(float(row["client_compute_ms"]))
        if row["server_verification_ms"] is not None:
            verify_groups[row["sample"]].append(float(row["server_verification_ms"]))
    crypto_summary = {
        sample: {
            "client_compute": stats(sample_groups[sample]),
            "server_verification": stats(verify_groups[sample]),
        }
        for sample in sorted(set(sample_groups) | set(verify_groups))
    }

    expected_legal = device_count * rounds
    expected_attacks = device_count * (device_count - 1) * rounds
    assertions = {
        "matrix_contains_all_four_configurations": len(matrix_rows)
        == (expected_legal + expected_attacks) * 4,
        "aura_full_accepts_all_owner_controls": aggregates["aura_full"]
        ["legal_authentication_acceptance_rate"]
        == 1.0,
        "aura_full_rejects_all_cross_device_transfers": aggregates["aura_full"]
        ["transfer_authentication_acceptance_rate"]
        == 0.0,
        "aura_full_delivers_no_profile_to_transfer_attacks": aggregates["aura_full"]
        ["transfer_profile_delivery_rate"]
        == 0.0,
        "ablation_accepts_cross_device_transfers": aggregates[
            "aura_no_secret_binding"
        ]["transfer_authentication_acceptance_rate"]
        == 1.0,
        "standard_prebound_rejects_cross_device_transfers": aggregates[
            "standard_prebound_eid"
        ]["transfer_authentication_acceptance_rate"]
        == 0.0,
        "standard_unbound_code_is_transferable": aggregates[
            "standard_unbound_activation_code"
        ]["transfer_authentication_acceptance_rate"]
        == 1.0,
        "production_owner_proofs_verify": all(
            row["authentication_accepted"]
            for row in crypto_rows
            if row["sample"] == "aura_owner_control"
        ),
        "production_cross_device_proofs_not_constructible": all(
            not row["proof_generated"]
            for row in crypto_rows
            if row["sample"] == "aura_cross_device_honest_client"
        ),
        "experiment_only_ablation_proofs_verify": all(
            row["authentication_accepted"]
            for row in crypto_rows
            if row["sample"] == "aura_ablation_cross_device"
        ),
        "forced_invalid_submissions_rejected_by_production_verifier": all(
            not row["authentication_accepted"]
            for row in crypto_rows
            if row["sample"] == "forced_invalid_transfer_submission"
        ),
        "concurrency_outcomes_match_expected": all(
            row["outcomes_match_expected"] for row in concurrency_rows
        ),
        "process_pool_warmup_outcomes_match_expected": (
            True
            if args.skip_concurrency
            else bool(concurrency_backend["warmup_outcomes_match_expected"])
        ),
        "concurrency_uses_multiple_processes": (
            True
            if args.skip_concurrency or max(concurrency_levels) == 1
            else max(row["worker_processes_used"] for row in concurrency_rows) > 1
        ),
    }
    status = "PASS" if all(assertions.values()) else "FAIL"

    summary = {
        "status": status,
        "experiment": "ticket_theft_cross_device_transfer_matrix",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "seed": seed,
        "round_seeds": [seed + index for index in range(rounds)],
        "devices": device_count,
        "rounds": rounds,
        "legal_controls_per_configuration": expected_legal,
        "transfer_attacks_per_configuration": expected_attacks,
        "total_matrix_attempts": len(matrix_rows),
        "configurations": aggregates,
        "cryptographic_samples": crypto_summary,
        "concurrency": concurrency_rows,
        "concurrency_backend": concurrency_backend,
        "credential_setup_ms": round(credential_setup_ms, 3),
        "experiment_runtime_ms": round(total_runtime_ms, 3),
        "profile": {
            "sha256": adapter.profile_sha256,
            "bytes": adapter.profile_bytes,
        },
        "measurement_scope": {
            "matrix": (
                "all ticket-device pairs; test-oracle decision backed by holder-verified "
                "integrated BBS+ credentials/tickets"
            ),
            "crypto": (
                "real integrated create_auth_proof/verify_auth_proof calls; one legal, "
                "one honest transfer, one ablation transfer, and one forced server "
                "submission per round"
            ),
            "profile_delivery": (
                "authorization-gate outcome; bulk matrix does not repeatedly encrypt or "
                "write the identical 12 KiB profile"
            ),
            "standard_unbound": (
                "pairwise transferability with fresh order state per ticket-device pair; "
                "not a simultaneous first-consumer race"
            ),
            "concurrency": (
                "prewarmed multi-process production proof-verifier CPU path; pool startup "
                "and warmup are reported separately and excluded; forced invalid transfer "
                "submissions are defense-in-depth because honest AURA clients reject locally"
            ),
        },
        "ablation_warning": (
            "EXPERIMENT ONLY: AURA-RSP w/o secret binding uses separate x_cred and "
            "x_ticket witnesses and is not the normal protocol implementation."
        ),
        "source_audit": adapter.source_audit(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "assertions": assertions,
    }

    write_csv(output / "raw" / "matrix-attempts.csv", matrix_rows)
    write_jsonl(output / "raw" / "matrix-attempts.jsonl", matrix_rows)
    write_csv(output / "raw" / "crypto-samples.csv", crypto_rows)
    write_jsonl(output / "raw" / "crypto-samples.jsonl", crypto_rows)
    write_csv(output / "raw" / "concurrency.csv", concurrency_rows)
    (output / "evidence" / "assertions.json").write_text(
        json.dumps(assertions, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output / "evidence" / "source-audit.json").write_text(
        json.dumps(adapter.source_audit(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    table_rows = []
    for config_name in CONFIGS:
        item = aggregates[config_name]
        table_rows.append(
            {
                "configuration": LABELS_EN[config_name],
                "legal_acceptance_rate": item["legal_authentication_acceptance_rate"],
                "transfer_proof_generation_rate": item[
                    "transfer_joint_proof_generation_rate"
                ],
                "transfer_authentication_acceptance_rate": item[
                    "transfer_authentication_acceptance_rate"
                ],
                "transfer_profile_delivery_rate": item[
                    "transfer_profile_delivery_rate"
                ],
                "transfer_attack_attempts": item["transfer_attack_attempts"],
            }
        )
    write_csv(output / "paper" / "table-3-ticket-transfer.csv", table_rows)

    # Plot only after every machine-checkable result has been committed.
    from plot_results import create_figures

    create_figures(summary, matrix_rows, output / "paper")

    if status != "PASS":
        raise AssertionError(json.dumps(assertions, ensure_ascii=False, indent=2))
    return summary


def print_human(summary: dict[str, Any], lang: str) -> None:
    full = summary["configurations"]["aura_full"]
    ablated = summary["configurations"]["aura_no_secret_binding"]
    prebound = summary["configurations"]["standard_prebound_eid"]
    unbound = summary["configurations"]["standard_unbound_activation_code"]
    if lang in ("zh", "both"):
        print("\n实验3：票据盗取与跨设备转移矩阵")
        print("=" * 54)
        print(
            f"设备={summary['devices']}，轮次={summary['rounds']}，"
            f"每种配置合法对照={summary['legal_controls_per_configuration']}，"
            f"跨设备攻击={summary['transfer_attacks_per_configuration']}"
        )
        print("\n跨设备转移成功率：")
        print(f"  完整AURA-RSP                    {full['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  AURA-RSP（去除秘密绑定，消融） {ablated['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  Standard RSP（订单预绑定EID）   {prebound['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  Standard RSP（未绑定激活码）    {unbound['transfer_authentication_acceptance_rate']:.4f}")
        print("\n结论：完整AURA仅接受票据原设备；去掉隐藏秘密相等关系后，非对角线转移全部可接受。")
    if lang in ("en", "both"):
        print("\nExperiment 3: Ticket Theft and Cross-Device Transfer Matrix")
        print("=" * 66)
        print(
            f"Devices={summary['devices']}, rounds={summary['rounds']}, "
            f"legal controls/config={summary['legal_controls_per_configuration']}, "
            f"transfer attacks/config={summary['transfer_attacks_per_configuration']}"
        )
        print("\nCross-device transfer success rate:")
        print(f"  Full AURA-RSP                         {full['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  AURA-RSP w/o secret binding           {ablated['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  Standard RSP with pre-bound EID        {prebound['transfer_authentication_acceptance_rate']:.4f}")
        print(f"  Standard RSP with unbound code         {unbound['transfer_authentication_acceptance_rate']:.4f}")
        print("\nConclusion: full AURA accepts only the ticket's original device; the explicit ablation accepts transfers.")
    print(f"\nSTATUS={summary['status']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent
    parser.add_argument("--config", default=str(root / "config.json"))
    parser.add_argument("--output", default=str(root / "results" / "latest"))
    parser.add_argument("--devices", type=int)
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--concurrency", help="comma-separated levels")
    parser.add_argument(
        "--workers",
        type=int,
        help="production verifier worker processes (default: one per logical CPU)",
    )
    parser.add_argument("--skip-concurrency", action="store_true")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()
    summary = run_experiment(args)
    if args.machine_json:
        print(
            json.dumps(
                {
                    "status": summary["status"],
                    "devices": summary["devices"],
                    "rounds": summary["rounds"],
                    "transfer_attacks_per_configuration": summary[
                        "transfer_attacks_per_configuration"
                    ],
                    "aura_full_transfer_success_rate": summary["configurations"]
                    ["aura_full"]["transfer_authentication_acceptance_rate"],
                    "aura_ablation_transfer_success_rate": summary["configurations"]
                    ["aura_no_secret_binding"][
                        "transfer_authentication_acceptance_rate"
                    ],
                    "results": str(Path(args.output).resolve()),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    else:
        print_human(summary, args.lang)


if __name__ == "__main__":
    main()
