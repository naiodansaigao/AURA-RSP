from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import shutil
import statistics
import sys
import time
import xml.sax.saxutils as saxutils
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def token(seed: int, label: str, length: int = 24) -> str:
    return hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:length]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: (
                        json.dumps(value, ensure_ascii=False, sort_keys=True)
                        if isinstance(value, (dict, list))
                        else value
                    )
                    for key, value in row.items()
                }
            )


def resolve_path(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def prepare_output(path: Path, experiment_root: Path) -> Path:
    output = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if output == results_root or results_root not in output.parents:
        raise ValueError(f"output must be below {results_root}")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    return output


def device_ip(prefix: str, index: int) -> str:
    third = index // 254
    fourth = index % 254 + 1
    return f"{prefix}.{third}.{fourth}"


def generate_trace(
    config: dict[str, Any],
    devices: int,
    transactions: int,
) -> dict[str, list[dict[str, Any]]]:
    seed = int(config["seed"])
    rng = random.Random(seed)
    events: list[dict[str, Any]] = []
    total = devices * transactions
    base_times = sorted(
        rng.uniform(0.0, float(config["trace_duration_ms"]))
        for _ in range(total)
    )
    assignments = [
        (device_index, tx_index)
        for device_index in range(devices)
        for tx_index in range(transactions)
    ]
    rng.shuffle(assignments)
    buckets = [int(value) for value in config["message_size_buckets"]]

    for event_index, ((device_index, tx_index), base_time) in enumerate(
        zip(assignments, base_times, strict=True)
    ):
        device_label = f"Device-{device_index + 1:03d}"
        transaction_label = (
            f"{device_label}:transaction-{tx_index + 1:02d}"
        )
        ingress_time = base_time + rng.gauss(
            0.0, float(config["ingress_clock_jitter_ms"])
        )
        relay_delay = max(
            5.0,
            rng.gauss(
                float(config["relay_delay_mean_ms"]),
                float(config["relay_delay_stddev_ms"]),
            ),
        )
        session_time = (
            ingress_time
            + relay_delay
            + rng.gauss(
                0.0, float(config["egress_clock_jitter_ms"])
            )
        )
        flow_size = (
            rng.choice(buckets)
            + rng.randint(
                -int(config["message_size_variation_bytes"]),
                int(config["message_size_variation_bytes"]),
            )
        )
        egress_size = (
            flow_size
            + int(config["relay_message_overhead_bytes"])
            + rng.randint(
                -int(config["message_size_noise_bytes"]),
                int(config["message_size_noise_bytes"]),
            )
        )
        events.append(
            {
                "event_index": event_index,
                "device_id": device_label,
                "device_ip": device_ip(
                    str(config["device_ip_prefix"]), device_index
                ),
                "transaction_id": "TX-" + token(
                    seed, transaction_label, 28
                ),
                "ingress_id": "IN-" + token(
                    seed, f"ingress:{transaction_label}", 26
                ),
                "session_id": "SESS-" + token(
                    seed, f"session:{transaction_label}", 26
                ),
                "profile_request": "PRQ-" + token(
                    seed, f"profile:{transaction_label}", 22
                ),
                "ingress_time_ms": round(ingress_time, 3),
                "session_time_ms": round(session_time, 3),
                "relay_delay_ms": round(relay_delay, 3),
                "flow_size_bytes": flow_size,
                "message_size_bytes": egress_size,
            }
        )

    ground_truth: list[dict[str, Any]] = []
    direct_smdpp: list[dict[str, Any]] = []
    shared_smdpp: list[dict[str, Any]] = []
    pr_ingress: list[dict[str, Any]] = []
    smdpp_egress: list[dict[str, Any]] = []

    for event in events:
        ground_truth.append(dict(event))
        common_egress = {
            "session_id": event["session_id"],
            "session_time_ms": event["session_time_ms"],
            "message_size_bytes": event["message_size_bytes"],
            "profile_request": event["profile_request"],
            "protocol": "AURA-RSP",
        }
        direct_smdpp.append(
            {
                **common_egress,
                "network_mode": "direct",
                "observed_source_ip": event["device_ip"],
            }
        )
        shared_smdpp.append(
            {
                **common_egress,
                "network_mode": "shared_pr",
                "observed_source_ip": config["privacy_relay_ip"],
            }
        )
        pr_ingress.append(
            {
                "ingress_id": event["ingress_id"],
                "device_ip": event["device_ip"],
                "ingress_time_ms": event["ingress_time_ms"],
                "flow_size_bytes": event["flow_size_bytes"],
            }
        )
        smdpp_egress.append(
            {
                **common_egress,
                "observed_source_ip": config["privacy_relay_ip"],
            }
        )

    return {
        "ground_truth": ground_truth,
        "direct_smdpp": direct_smdpp,
        "shared_smdpp": shared_smdpp,
        "pr_ingress": pr_ingress,
        "smdpp_egress": smdpp_egress,
    }


def binary_score_auc(
    positive_score_one: int,
    positive_score_zero: int,
    negative_score_one: int,
    negative_score_zero: int,
) -> float:
    positives = positive_score_one + positive_score_zero
    negatives = negative_score_one + negative_score_zero
    if positives == 0 or negatives == 0:
        raise ValueError("ROC-AUC requires both pair classes")
    wins = positive_score_one * negative_score_zero
    ties = (
        positive_score_one * negative_score_one
        + positive_score_zero * negative_score_zero
    )
    return (wins + 0.5 * ties) / (positives * negatives)


def ip_linkability(
    records: list[dict[str, Any]],
    truth_by_session: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    counts = Counter(
        truth_by_session[record["session_id"]]["device_id"]
        for record in records
    )
    if len(counts) < 2:
        raise ValueError("at least two devices are required")
    tp = fp = tn = fn = 0
    positive_score_one = positive_score_zero = 0
    negative_score_one = negative_score_zero = 0
    for first, second in combinations(records, 2):
        same_device = (
            truth_by_session[first["session_id"]]["device_id"]
            == truth_by_session[second["session_id"]]["device_id"]
        )
        same_address = (
            first["observed_source_ip"]
            == second["observed_source_ip"]
        )
        if same_device:
            if same_address:
                tp += 1
                positive_score_one += 1
            else:
                fn += 1
                positive_score_zero += 1
        elif same_address:
            fp += 1
            negative_score_one += 1
        else:
            tn += 1
            negative_score_zero += 1

    tpr = tp / (tp + fn)
    tnr = tn / (tn + fp)
    precision = tp / (tp + fp) if tp + fp else 0.0
    auc = binary_score_auc(
        positive_score_one,
        positive_score_zero,
        negative_score_one,
        negative_score_zero,
    )

    clusters: dict[str, list[str]] = defaultdict(list)
    for record in records:
        clusters[record["observed_source_ip"]].append(record["session_id"])
    true_groups: dict[str, set[str]] = defaultdict(set)
    for session_id, truth in truth_by_session.items():
        true_groups[truth["device_id"]].add(session_id)

    cluster_rows: list[dict[str, Any]] = []
    address_device_counts: list[int] = []
    correct_if_guessing = 0.0
    exact_recovered = 0
    for address, session_ids in sorted(clusters.items()):
        device_counter = Counter(
            truth_by_session[session_id]["device_id"]
            for session_id in session_ids
        )
        device_count = len(device_counter)
        address_device_counts.append(device_count)
        correct_if_guessing += len(session_ids) / device_count
        cluster_set = set(session_ids)
        exact_devices = [
            device
            for device, true_sessions in true_groups.items()
            if true_sessions == cluster_set
        ]
        exact_recovered += len(exact_devices)
        cluster_rows.append(
            {
                "observed_source_ip": address,
                "session_count": len(session_ids),
                "device_count": device_count,
                "largest_device_share": max(device_counter.values())
                / len(session_ids),
                "exact_device_cluster": bool(exact_devices),
            }
        )

    metric = {
        "observed_source_addresses": len(clusters),
        "ip_pairwise_roc_auc": round(auc, 6),
        "ip_pairwise_balanced_accuracy": round((tpr + tnr) / 2, 6),
        "ip_pairwise_precision": round(precision, 6),
        "same_device_pair_recall": round(tpr, 6),
        "different_device_pair_recall": round(tnr, 6),
        "exact_device_history_recovery": round(
            exact_recovered / len(true_groups), 6
        ),
        "mean_device_anonymity_set": round(
            statistics.fmean(address_device_counts), 6
        ),
        "median_device_anonymity_set": round(
            statistics.median(address_device_counts), 6
        ),
        "expected_ip_identification_rate": round(
            correct_if_guessing / len(records), 6
        ),
    }
    confusion = {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "positive_pairs": tp + fn,
        "negative_pairs": tn + fp,
    }
    return metric, cluster_rows, confusion


def collusion_match(
    ingress: list[dict[str, Any]],
    egress: list[dict[str, Any]],
    config: dict[str, Any],
    *,
    use_size: bool,
) -> list[dict[str, Any]]:
    expected_delay = float(config["attacker_expected_delay_ms"])
    expected_overhead = float(config["attacker_expected_overhead_bytes"])
    time_scale = float(config["attacker_time_scale_ms"])
    size_scale = float(config["attacker_size_scale_bytes"])
    size_weight = float(config["attacker_size_weight"])
    candidates: list[tuple[float, str, str, float, float]] = []
    for in_row in ingress:
        for out_row in egress:
            time_residual = abs(
                (
                    float(out_row["session_time_ms"])
                    - float(in_row["ingress_time_ms"])
                )
                - expected_delay
            )
            size_residual = abs(
                (
                    int(out_row["message_size_bytes"])
                    - int(in_row["flow_size_bytes"])
                )
                - expected_overhead
            )
            cost = time_residual / time_scale
            if use_size:
                cost += size_weight * size_residual / size_scale
            candidates.append(
                (
                    round(cost, 9),
                    str(in_row["ingress_id"]),
                    str(out_row["session_id"]),
                    round(time_residual, 3),
                    round(size_residual, 3),
                )
            )
    candidates.sort()
    used_ingress: set[str] = set()
    used_sessions: set[str] = set()
    matches: list[dict[str, Any]] = []
    for cost, ingress_id, session_id, time_residual, size_residual in candidates:
        if ingress_id in used_ingress or session_id in used_sessions:
            continue
        used_ingress.add(ingress_id)
        used_sessions.add(session_id)
        matches.append(
            {
                "ingress_id": ingress_id,
                "session_id": session_id,
                "cost": cost,
                "time_residual_ms": time_residual,
                "size_residual_bytes": size_residual,
                "features": "time+size" if use_size else "time-only",
            }
        )
        if len(matches) == len(ingress):
            break
    if len(matches) != len(ingress) or len(matches) != len(egress):
        raise RuntimeError("one-to-one matcher did not cover every record")
    return matches


def evaluate_matches(
    matches: list[dict[str, Any]],
    truth_by_ingress: dict[str, dict[str, Any]],
    truth_by_session: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    device_totals = Counter(
        truth["device_id"] for truth in truth_by_ingress.values()
    )
    device_correct = Counter()
    for match in matches:
        ingress_truth = truth_by_ingress[match["ingress_id"]]
        session_truth = truth_by_session[match["session_id"]]
        correct = (
            ingress_truth["transaction_id"]
            == session_truth["transaction_id"]
        )
        if correct:
            device_correct[ingress_truth["device_id"]] += 1
        rows.append(
            {
                **match,
                "correct": correct,
                "recovered_device_ip": ingress_truth["device_ip"],
                "evaluation_device_id": ingress_truth["device_id"],
            }
        )
    correct_count = sum(bool(row["correct"]) for row in rows)
    full_devices = sum(
        device_correct[device] == total
        for device, total in device_totals.items()
    )
    partial_devices = sum(
        0 < device_correct[device] < total
        for device, total in device_totals.items()
    )
    metrics = {
        "matched_records": len(rows),
        "correct_matches": correct_count,
        "incorrect_matches": len(rows) - correct_count,
        "match_accuracy": round(correct_count / len(rows), 6),
        "false_match_rate": round(
            (len(rows) - correct_count) / len(rows), 6
        ),
        "full_device_history_recovery": round(
            full_devices / len(device_totals), 6
        ),
        "partial_device_history_recovery": round(
            partial_devices / len(device_totals), 6
        ),
        "median_time_residual_ms": round(
            statistics.median(
                float(row["time_residual_ms"]) for row in rows
            ),
            3,
        ),
        "median_size_residual_bytes": round(
            statistics.median(
                float(row["size_residual_bytes"]) for row in rows
            ),
            3,
        ),
    }
    return metrics, rows


def source_audit(
    experiment_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    definitions = {
        "relay_session": (
            "relay",
            "self.http = requests.Session()",
        ),
        "relay_upstream_post": (
            "relay",
            "return self.http.post(",
        ),
        "relay_tls_peer_verification": (
            "relay",
            "self.http.verify = str(",
        ),
        "relay_authenticated_identity": (
            "relay",
            '"X-AURA-PR-AUTH": tag',
        ),
        "server_pr_authentication_entry": (
            "server",
            "def _aura_pr_identity(",
        ),
        "server_pr_hmac_verification": (
            "server",
            "if not hmac.compare_digest(expected, supplied):",
        ),
    }
    sources: dict[str, tuple[Path, list[str]]] = {}
    for name, value in config["aura_source"].items():
        path = resolve_path(experiment_root, value)
        sources[name] = (
            path,
            path.read_text(encoding="utf-8").splitlines(),
        )
    checkpoints: dict[str, Any] = {}
    for label, (source_name, pattern) in definitions.items():
        path, lines = sources[source_name]
        line_number = next(
            (
                index
                for index, line in enumerate(lines, start=1)
                if pattern in line
            ),
            None,
        )
        checkpoints[label] = {
            "file": config["aura_source"][source_name],
            "pattern": pattern,
            "line": line_number,
        }
    return {
        "all_checkpoints_found": all(
            entry["line"] is not None for entry in checkpoints.values()
        ),
        "checkpoints": checkpoints,
        "source_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, (path, _) in sources.items()
        },
        "interpretation": (
            "The integrated relay creates the upstream TLS connection and "
            "authenticates PRaddr with a nonce-bound HMAC; the SM-DP+ sees "
            "the relay source and authenticated relay identity, not a "
            "downstream device source address."
        ),
    }


def public_log_hygiene(
    traces: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    attacker_sets = (
        "direct_smdpp",
        "shared_smdpp",
        "pr_ingress",
        "smdpp_egress",
    )
    forbidden = {"device_id", "transaction_id", "eid", "certificate"}
    leaks: list[dict[str, str]] = []
    for name in attacker_sets:
        for row in traces[name]:
            for key in row:
                if key.lower() in forbidden:
                    leaks.append({"log": name, "field": key})
    common_collusion_fields = (
        set(traces["pr_ingress"][0])
        & set(traces["smdpp_egress"][0])
    )
    common_collusion_fields -= {
        "ingress_time_ms",
        "session_time_ms",
        "flow_size_bytes",
        "message_size_bytes",
    }
    return {
        "forbidden_identity_fields": leaks,
        "shared_transaction_identifier_fields": sorted(
            common_collusion_fields
        ),
        "attacker_logs_clean": not leaks and not common_collusion_fields,
    }


def build_assertions(
    *,
    config: dict[str, Any],
    devices: int,
    transactions: int,
    direct: dict[str, Any],
    shared: dict[str, Any],
    collusion_time: dict[str, Any],
    collusion_time_size: dict[str, Any],
    audit: dict[str, Any],
    hygiene: dict[str, Any],
) -> list[dict[str, Any]]:
    thresholds = config["assertions"]
    values = [
        (
            "direct_ip_auc_near_one",
            "12A",
            f">={thresholds['direct_min_ip_auc']}",
            direct["ip_pairwise_roc_auc"],
            direct["ip_pairwise_roc_auc"]
            >= float(thresholds["direct_min_ip_auc"]),
        ),
        (
            "direct_exact_history_recovered",
            "12A",
            1.0,
            direct["exact_device_history_recovery"],
            direct["exact_device_history_recovery"] == 1.0,
        ),
        (
            "direct_anonymity_set_is_one",
            "12A",
            1.0,
            direct["mean_device_anonymity_set"],
            direct["mean_device_anonymity_set"] == 1.0,
        ),
        (
            "shared_pr_single_visible_source",
            "12B",
            1,
            shared["observed_source_addresses"],
            shared["observed_source_addresses"] == 1,
        ),
        (
            "shared_pr_ip_auc_is_random",
            "12B",
            0.5,
            shared["ip_pairwise_roc_auc"],
            shared["ip_pairwise_roc_auc"] == 0.5,
        ),
        (
            "shared_pr_anonymity_set_contains_all_devices",
            "12B",
            devices,
            shared["mean_device_anonymity_set"],
            shared["mean_device_anonymity_set"] == devices,
        ),
        (
            "shared_pr_no_exact_device_history",
            "12B",
            f"<={thresholds['shared_max_exact_history_recovery']}",
            shared["exact_device_history_recovery"],
            shared["exact_device_history_recovery"]
            <= float(
                thresholds["shared_max_exact_history_recovery"]
            ),
        ),
        (
            "shared_pr_ip_identification_rate_is_uniform_guess",
            "12B",
            round(1.0 / devices, 6),
            shared["expected_ip_identification_rate"],
            math.isclose(
                shared["expected_ip_identification_rate"],
                round(1.0 / devices, 6),
                abs_tol=1e-9,
            ),
        ),
        (
            "collusion_time_size_recovers_connections",
            "12C",
            f">={thresholds['collusion_min_time_size_accuracy']}",
            collusion_time_size["match_accuracy"],
            collusion_time_size["match_accuracy"]
            >= float(thresholds["collusion_min_time_size_accuracy"]),
        ),
        (
            "collusion_beats_ip_only_guessing",
            "12C",
            f">{shared['expected_ip_identification_rate']}",
            collusion_time_size["match_accuracy"],
            collusion_time_size["match_accuracy"]
            > shared["expected_ip_identification_rate"],
        ),
        (
            "time_and_size_not_worse_than_time_only",
            "12C",
            f">={collusion_time['match_accuracy']}",
            collusion_time_size["match_accuracy"],
            collusion_time_size["match_accuracy"]
            >= collusion_time["match_accuracy"],
        ),
        (
            "all_records_matched_once",
            "12C",
            devices * transactions,
            collusion_time_size["matched_records"],
            collusion_time_size["matched_records"]
            == devices * transactions,
        ),
        (
            "attacker_logs_do_not_share_transaction_identifier",
            "hygiene",
            True,
            hygiene["attacker_logs_clean"],
            hygiene["attacker_logs_clean"],
        ),
        (
            "production_relay_source_checkpoints_present",
            "source_audit",
            True,
            audit["all_checkpoints_found"],
            audit["all_checkpoints_found"],
        ),
        (
            "collusion_is_expected_boundary_failure",
            "scope",
            "EXPECTED_BOUNDARY_FAILURE",
            "EXPECTED_BOUNDARY_FAILURE",
            True,
        ),
    ]
    return [
        {
            "assertion": name,
            "class": category,
            "expected": expected,
            "observed": observed,
            "passed": passed,
        }
        for name, category, expected, observed, passed in values
    ]


def render_terminal(
    summary: dict[str, Any], language: str, machine_json: bool
) -> None:
    if machine_json:
        compact = {
            "status": summary["status"],
            "devices": summary["devices"],
            "transactions": summary["transactions"],
            "direct_ip_auc": summary["modes"]["12A_direct"][
                "ip_pairwise_roc_auc"
            ],
            "shared_pr_ip_auc": summary["modes"]["12B_shared_pr"][
                "ip_pairwise_roc_auc"
            ],
            "shared_pr_anonymity_set": summary["modes"]["12B_shared_pr"][
                "mean_device_anonymity_set"
            ],
            "collusion_time_only_accuracy": summary["modes"][
                "12C_collusion"
            ]["time_only"]["match_accuracy"],
            "collusion_time_size_accuracy": summary["modes"][
                "12C_collusion"
            ]["time_and_size"]["match_accuracy"],
            "boundary": summary["modes"]["12C_collusion"]["interpretation"],
            "assertions": (
                f"{summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "results": summary["results_dir"],
        }
        print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")))
        return

    direct = summary["modes"]["12A_direct"]
    shared = summary["modes"]["12B_shared_pr"]
    collusion = summary["modes"]["12C_collusion"]
    if language in ("zh", "both"):
        print("\n实验12：PR源地址保护与PR–SM-DP+合谋")
        print("=" * 112)
        print(
            f"{'模式':<24}{'可见源地址':>14}{'IP ROC-AUC':>16}"
            f"{'设备匿名集':>16}{'完整历史恢复':>18}"
        )
        print("-" * 112)
        print(
            f"{'12A 设备直连':<24}"
            f"{direct['observed_source_addresses']:>14}"
            f"{direct['ip_pairwise_roc_auc']:>16.4f}"
            f"{direct['mean_device_anonymity_set']:>16.2f}"
            f"{direct['exact_device_history_recovery']:>18.4f}"
        )
        print(
            f"{'12B 共享PR':<24}"
            f"{shared['observed_source_addresses']:>14}"
            f"{shared['ip_pairwise_roc_auc']:>16.4f}"
            f"{shared['mean_device_anonymity_set']:>16.2f}"
            f"{shared['exact_device_history_recovery']:>18.4f}"
        )
        print("-" * 112)
        print(
            "12C合谋匹配："
            f"仅时间={collusion['time_only']['match_accuracy']:.4f}，"
            f"时间+流量={collusion['time_and_size']['match_accuracy']:.4f}，"
            "结论=预期边界失效"
        )
        print(
            f"机器断言={summary['assertions_passed']}/"
            f"{summary['assertions_total']}；状态={summary['status']}"
        )

    if language in ("en", "both"):
        print("\nExperiment 12: PR Source-Address Privacy and Collusion")
        print("=" * 112)
        print(
            f"{'Mode':<28}{'Source IPs':>14}{'IP ROC-AUC':>16}"
            f"{'Anon. set':>16}{'Exact history':>18}"
        )
        print("-" * 112)
        print(
            f"{'12A Direct connection':<28}"
            f"{direct['observed_source_addresses']:>14}"
            f"{direct['ip_pairwise_roc_auc']:>16.4f}"
            f"{direct['mean_device_anonymity_set']:>16.2f}"
            f"{direct['exact_device_history_recovery']:>18.4f}"
        )
        print(
            f"{'12B Shared PR':<28}"
            f"{shared['observed_source_addresses']:>14}"
            f"{shared['ip_pairwise_roc_auc']:>16.4f}"
            f"{shared['mean_device_anonymity_set']:>16.2f}"
            f"{shared['exact_device_history_recovery']:>18.4f}"
        )
        print("-" * 112)
        print(
            "12C collusion matching: "
            f"time-only={collusion['time_only']['match_accuracy']:.4f}, "
            f"time+size={collusion['time_and_size']['match_accuracy']:.4f}, "
            "interpretation=expected boundary failure"
        )
        print(
            f"Assertions={summary['assertions_passed']}/"
            f"{summary['assertions_total']}; status={summary['status']}"
        )


def render_report(
    output: Path, summary: dict[str, Any], language: str
) -> None:
    direct = summary["modes"]["12A_direct"]
    shared = summary["modes"]["12B_shared_pr"]
    collusion = summary["modes"]["12C_collusion"]
    if language == "zh":
        text = f"""# 实验12：PR源地址保护与PR–SM-DP+合谋

- 实验状态：**{summary['status']}**
- 设备：{summary['devices']}
- 每设备事务：{summary['transactions_per_device']}
- 机器断言：{summary['assertions_passed']}/{summary['assertions_total']}

## 三种模式

| 指标 | 12A 直连 | 12B 共享PR |
|---|---:|---:|
| SM-DP+可见源地址数 | {direct['observed_source_addresses']} | {shared['observed_source_addresses']} |
| IP-only ROC-AUC | {direct['ip_pairwise_roc_auc']:.4f} | {shared['ip_pairwise_roc_auc']:.4f} |
| Pairwise balanced accuracy | {direct['ip_pairwise_balanced_accuracy']:.4f} | {shared['ip_pairwise_balanced_accuracy']:.4f} |
| 平均设备匿名集 | {direct['mean_device_anonymity_set']:.2f} | {shared['mean_device_anonymity_set']:.2f} |
| 完整设备历史恢复率 | {direct['exact_device_history_recovery']:.4f} | {shared['exact_device_history_recovery']:.4f} |
| 仅凭IP猜中设备概率 | {direct['expected_ip_identification_rate']:.4f} | {shared['expected_ip_identification_rate']:.4f} |

## 12C 合谋

| 匹配器 | 事务匹配准确率 | 错误匹配率 | 完整设备历史恢复率 |
|---|---:|---:|---:|
| 仅时间 | {collusion['time_only']['match_accuracy']:.4f} | {collusion['time_only']['false_match_rate']:.4f} | {collusion['time_only']['full_device_history_recovery']:.4f} |
| 时间+流量大小 | {collusion['time_and_size']['match_accuracy']:.4f} | {collusion['time_and_size']['false_match_rate']:.4f} | {collusion['time_and_size']['full_device_history_recovery']:.4f} |

## 结论

直连模式下，稳定源IP能够辅助SM-DP+恢复设备跨事务历史。共享PR使所有设备进入同一
源地址匿名集，IP-only关联降到随机水平。PR与SM-DP+合谋后，入口和出口的时间/流量
特征能够重新关联连接。

12C是论文已经声明的威胁模型边界下的预期隐私失效，不是AURA认证或Profile交付协议
漏洞。本结果来自固定种子的受控元数据轨迹，不代表真实公网匿名性的绝对数值。
"""
    else:
        text = f"""# Experiment 12: PR Source-Address Privacy and PR–SM-DP+ Collusion

- Status: **{summary['status']}**
- Devices: {summary['devices']}
- Transactions per device: {summary['transactions_per_device']}
- Machine assertions: {summary['assertions_passed']}/{summary['assertions_total']}

## Network modes

| Metric | 12A Direct | 12B Shared PR |
|---|---:|---:|
| Source addresses visible to SM-DP+ | {direct['observed_source_addresses']} | {shared['observed_source_addresses']} |
| IP-only ROC-AUC | {direct['ip_pairwise_roc_auc']:.4f} | {shared['ip_pairwise_roc_auc']:.4f} |
| Pairwise balanced accuracy | {direct['ip_pairwise_balanced_accuracy']:.4f} | {shared['ip_pairwise_balanced_accuracy']:.4f} |
| Mean device anonymity set | {direct['mean_device_anonymity_set']:.2f} | {shared['mean_device_anonymity_set']:.2f} |
| Exact device-history recovery | {direct['exact_device_history_recovery']:.4f} | {shared['exact_device_history_recovery']:.4f} |
| Expected device identification from IP | {direct['expected_ip_identification_rate']:.4f} | {shared['expected_ip_identification_rate']:.4f} |

## 12C Collusion

| Matcher | Transaction accuracy | False-match rate | Full device-history recovery |
|---|---:|---:|---:|
| Time only | {collusion['time_only']['match_accuracy']:.4f} | {collusion['time_only']['false_match_rate']:.4f} | {collusion['time_only']['full_device_history_recovery']:.4f} |
| Time and flow size | {collusion['time_and_size']['match_accuracy']:.4f} | {collusion['time_and_size']['false_match_rate']:.4f} | {collusion['time_and_size']['full_device_history_recovery']:.4f} |

## Conclusion

With direct connections, a stable source IP helps the SM-DP+ recover cross-
transaction device history. A shared PR places all devices in one source-address
anonymity set and reduces IP-only linkage to random performance. When the PR and
SM-DP+ collude, timing and flow-size metadata can relink connections.

12C is an expected privacy failure at the explicitly stated threat-model
boundary, not a flaw in AURA authentication or Profile delivery. The numeric
result comes from a fixed-seed controlled metadata trace, not a claim about an
absolute real-Internet anonymity level.
"""
    (output / f"report-{language}.md").write_text(text, encoding="utf-8")


def svg_escape(value: str) -> str:
    return saxutils.escape(value)


def render_grouped_bars(
    path: Path,
    direct: dict[str, Any],
    shared: dict[str, Any],
    language: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    zh = language == "zh"
    title = (
        "实验12：直连与共享PR的IP关联能力"
        if zh
        else "Experiment 12: IP Linkability, Direct vs Shared PR"
    )
    labels = (
        ["ROC-AUC", "平衡准确率", "完整历史恢复", "IP设备识别率"]
        if zh
        else [
            "ROC-AUC",
            "Balanced accuracy",
            "Exact history",
            "IP identification",
        ]
    )
    direct_values = [
        direct["ip_pairwise_roc_auc"],
        direct["ip_pairwise_balanced_accuracy"],
        direct["exact_device_history_recovery"],
        direct["expected_ip_identification_rate"],
    ]
    shared_values = [
        shared["ip_pairwise_roc_auc"],
        shared["ip_pairwise_balanced_accuracy"],
        shared["exact_device_history_recovery"],
        shared["expected_ip_identification_rate"],
    ]
    width, height = 1740, 930
    left, top, bottom = 150, 155, 190
    plot_w, plot_h = 1510, height - top - bottom
    group_w = plot_w / len(labels)
    bar_w = 105
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,'Microsoft YaHei',sans-serif;fill:#0b2345}",
        ".title{font-size:42px;font-weight:700}.axis{font-size:25px}.label{font-size:25px}.value{font-size:25px;font-weight:700}.legend{font-size:27px}",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{width/2}" y="66" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for tick in range(6):
        value = tick / 5
        y = top + plot_h - value * plot_h
        parts += [
            f'<line x1="{left}" y1="{y}" x2="{left+plot_w}" y2="{y}" stroke="#d9e1ea" stroke-width="2"/>',
            f'<text x="{left-24}" y="{y+9}" text-anchor="end" class="axis">{value:.1f}</text>',
        ]
    parts += [
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" stroke="#486581" stroke-width="3"/>',
        f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#486581" stroke-width="3"/>',
    ]
    colors = ("#2563a6", "#e07a1f")
    for index, label in enumerate(labels):
        center = left + group_w * (index + 0.5)
        for offset, value, color in (
            (-bar_w * 0.62, direct_values[index], colors[0]),
            (bar_w * 0.62, shared_values[index], colors[1]),
        ):
            x = center + offset - bar_w / 2
            bar_h = value * plot_h
            y = top + plot_h - bar_h
            parts += [
                f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" rx="8" fill="{color}"/>',
                f'<text x="{x+bar_w/2}" y="{max(top+28,y-14)}" text-anchor="middle" class="value">{value:.3f}</text>',
            ]
        parts.append(
            f'<text x="{center}" y="{top+plot_h+54}" text-anchor="middle" class="label">{svg_escape(label)}</text>'
        )
    direct_name = "12A 直连" if zh else "12A Direct"
    shared_name = "12B 共享PR" if zh else "12B Shared PR"
    legend_y = height - 52
    parts += [
        f'<rect x="570" y="{legend_y-24}" width="34" height="34" rx="5" fill="{colors[0]}"/>',
        f'<text x="620" y="{legend_y+4}" class="legend">{svg_escape(direct_name)}</text>',
        f'<rect x="925" y="{legend_y-24}" width="34" height="34" rx="5" fill="{colors[1]}"/>',
        f'<text x="975" y="{legend_y+4}" class="legend">{svg_escape(shared_name)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_collusion_bars(
    path: Path,
    shared: dict[str, Any],
    time_only: dict[str, Any],
    time_size: dict[str, Any],
    language: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    zh = language == "zh"
    title = (
        "实验12C：合谋使源地址匿名性重新失效"
        if zh
        else "Experiment 12C: Collusion Relinks Connections"
    )
    labels = (
        ["仅共享IP猜测", "合谋：仅时间", "合谋：时间+流量", "完整设备历史"]
        if zh
        else [
            "Shared-IP guess",
            "Collusion: time",
            "Collusion: time+size",
            "Full device history",
        ]
    )
    values = [
        shared["expected_ip_identification_rate"],
        time_only["match_accuracy"],
        time_size["match_accuracy"],
        time_size["full_device_history_recovery"],
    ]
    colors = ["#7a8da3", "#d8892b", "#b83c32", "#7a2e84"]
    width, height = 1740, 930
    left, top, bottom = 150, 155, 205
    plot_w, plot_h = 1510, height - top - bottom
    group_w = plot_w / len(labels)
    bar_w = 205
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,'Microsoft YaHei',sans-serif;fill:#0b2345}",
        ".title{font-size:42px;font-weight:700}.axis{font-size:25px}.label{font-size:24px}.value{font-size:28px;font-weight:700}.note{font-size:26px}",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{width/2}" y="66" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for tick in range(6):
        value = tick / 5
        y = top + plot_h - value * plot_h
        parts += [
            f'<line x1="{left}" y1="{y}" x2="{left+plot_w}" y2="{y}" stroke="#d9e1ea" stroke-width="2"/>',
            f'<text x="{left-24}" y="{y+9}" text-anchor="end" class="axis">{value:.1f}</text>',
        ]
    parts += [
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" stroke="#486581" stroke-width="3"/>',
        f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#486581" stroke-width="3"/>',
    ]
    for index, (label, value, color) in enumerate(
        zip(labels, values, colors, strict=True)
    ):
        center = left + group_w * (index + 0.5)
        x = center - bar_w / 2
        bar_h = value * plot_h
        y = top + plot_h - bar_h
        parts += [
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" rx="10" fill="{color}"/>',
            f'<text x="{center}" y="{max(top+32,y-16)}" text-anchor="middle" class="value">{value:.3f}</text>',
            f'<text x="{center}" y="{top+plot_h+54}" text-anchor="middle" class="label">{svg_escape(label)}</text>',
        ]
    note = (
        "12C为威胁模型已声明的预期边界结果"
        if zh
        else "12C is an expected result at the stated threat-model boundary"
    )
    parts += [
        f'<text x="{width/2}" y="{height-48}" text-anchor="middle" class="note">{svg_escape(note)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--devices", type=int)
    parser.add_argument("--transactions", type=int)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(__file__).resolve().parent
    config = load_json(Path(args.config))
    devices = args.devices or int(config["device_count"])
    transactions = args.transactions or int(
        config["transactions_per_device"]
    )
    if devices < 4:
        raise ValueError("--devices must be at least 4")
    if transactions < 2:
        raise ValueError("--transactions must be at least 2")
    output = prepare_output(Path(args.output), experiment_root)

    started = time.perf_counter()
    traces = generate_trace(config, devices, transactions)
    truth_by_session = {
        row["session_id"]: row for row in traces["ground_truth"]
    }
    truth_by_ingress = {
        row["ingress_id"]: row for row in traces["ground_truth"]
    }
    direct_metrics, direct_clusters, direct_confusion = ip_linkability(
        traces["direct_smdpp"], truth_by_session
    )
    shared_metrics, shared_clusters, shared_confusion = ip_linkability(
        traces["shared_smdpp"], truth_by_session
    )
    time_matches = collusion_match(
        traces["pr_ingress"],
        traces["smdpp_egress"],
        config,
        use_size=False,
    )
    time_metrics, time_match_rows = evaluate_matches(
        time_matches, truth_by_ingress, truth_by_session
    )
    time_size_matches = collusion_match(
        traces["pr_ingress"],
        traces["smdpp_egress"],
        config,
        use_size=True,
    )
    time_size_metrics, time_size_match_rows = evaluate_matches(
        time_size_matches, truth_by_ingress, truth_by_session
    )
    audit = source_audit(experiment_root, config)
    hygiene = public_log_hygiene(traces)
    assertions = build_assertions(
        config=config,
        devices=devices,
        transactions=transactions,
        direct=direct_metrics,
        shared=shared_metrics,
        collusion_time=time_metrics,
        collusion_time_size=time_size_metrics,
        audit=audit,
        hygiene=hygiene,
    )
    passed = sum(bool(row["passed"]) for row in assertions)
    status = "PASS" if passed == len(assertions) else "FAIL"

    trace_hash = hashlib.sha256(
        canonical(
            {
                "ground_truth": traces["ground_truth"],
                "direct_smdpp": traces["direct_smdpp"],
                "shared_smdpp": traces["shared_smdpp"],
                "pr_ingress": traces["pr_ingress"],
                "smdpp_egress": traces["smdpp_egress"],
            }
        )
    ).hexdigest()
    summary = {
        "experiment": config["experiment_name"],
        "status": status,
        "seed": int(config["seed"]),
        "devices": devices,
        "transactions_per_device": transactions,
        "transactions": devices * transactions,
        "trace_sha256": trace_hash,
        "modes": {
            "12A_direct": direct_metrics,
            "12B_shared_pr": shared_metrics,
            "12C_collusion": {
                "time_only": time_metrics,
                "time_and_size": time_size_metrics,
                "interpretation": "EXPECTED_BOUNDARY_FAILURE",
            },
        },
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "source_audit": audit,
        "log_hygiene": hygiene,
        "scope": {
            "trace_type": "fixed-seed controlled network metadata",
            "physical_euicc": False,
            "real_public_network_capture": False,
            "protocol_changes": False,
            "pr_protection": "source-address isolation against SM-DP+ alone",
            "excluded_guarantee": (
                "PR-SM-DP+ collusion or simultaneous ingress/egress observer"
            ),
        },
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "elapsed_ms": round(
            (time.perf_counter() - started) * 1000, 3
        ),
        "results_dir": output.relative_to(experiment_root).as_posix(),
    }

    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "source-audit.json", audit)
    write_json(output / "evidence" / "log-hygiene.json", hygiene)
    write_jsonl(
        output / "raw" / "ground-truth.jsonl",
        traces["ground_truth"],
    )
    write_jsonl(
        output / "raw" / "direct-smdpp.jsonl",
        traces["direct_smdpp"],
    )
    write_jsonl(
        output / "raw" / "shared-pr-smdpp.jsonl",
        traces["shared_smdpp"],
    )
    write_jsonl(
        output / "raw" / "pr-ingress.jsonl",
        traces["pr_ingress"],
    )
    write_jsonl(
        output / "raw" / "smdpp-egress.jsonl",
        traces["smdpp_egress"],
    )
    write_csv(output / "assertions.csv", assertions)
    mode_rows = [
        {"mode": "12A_direct", **direct_metrics},
        {"mode": "12B_shared_pr", **shared_metrics},
        {
            "mode": "12C_time_only",
            **time_metrics,
            "interpretation": "EXPECTED_BOUNDARY_FAILURE",
        },
        {
            "mode": "12C_time_and_size",
            **time_size_metrics,
            "interpretation": "EXPECTED_BOUNDARY_FAILURE",
        },
    ]
    write_csv(output / "mode-metrics.csv", mode_rows)
    write_csv(
        output / "analysis" / "direct-address-clusters.csv",
        direct_clusters,
    )
    write_csv(
        output / "analysis" / "shared-pr-address-clusters.csv",
        shared_clusters,
    )
    write_csv(
        output / "analysis" / "ip-confusion-matrices.csv",
        [
            {"mode": "12A_direct", **direct_confusion},
            {"mode": "12B_shared_pr", **shared_confusion},
        ],
    )
    write_csv(
        output / "analysis" / "collusion-time-only-matches.csv",
        time_match_rows,
    )
    write_csv(
        output / "analysis" / "collusion-time-size-matches.csv",
        time_size_match_rows,
    )
    render_report(output, summary, "zh")
    render_report(output, summary, "en")
    render_grouped_bars(
        output / "paper" / "ip-linkability-zh.svg",
        direct_metrics,
        shared_metrics,
        "zh",
    )
    render_grouped_bars(
        output / "paper" / "ip-linkability-en.svg",
        direct_metrics,
        shared_metrics,
        "en",
    )
    render_collusion_bars(
        output / "paper" / "collusion-boundary-zh.svg",
        shared_metrics,
        time_metrics,
        time_size_metrics,
        "zh",
    )
    render_collusion_bars(
        output / "paper" / "collusion-boundary-en.svg",
        shared_metrics,
        time_metrics,
        time_size_metrics,
        "en",
    )
    write_csv(output / "paper" / "table-mode-metrics.csv", mode_rows)
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "ip_linkability": (
                    "图：设备直连与共享PR时SM-DP+仅凭源IP进行关联的能力。"
                ),
                "collusion": (
                    "图：共享PR的IP匿名集与PR–SM-DP+合谋流量匹配结果；"
                    "合谋成功是威胁模型边界下的预期结果。"
                ),
            },
            "en": {
                "ip_linkability": (
                    "Figure: Source-IP-only linkability for direct "
                    "connections and a shared Privacy Relay."
                ),
                "collusion": (
                    "Figure: Shared-PR IP anonymity versus PR–SM-DP+ "
                    "traffic-correlation results; collusion success is "
                    "expected at the stated threat-model boundary."
                ),
            },
        },
    )
    render_terminal(summary, args.lang, args.machine_json)
    if not args.machine_json:
        print(f"\nRESULTS={summary['results_dir']}")
        print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(run())
