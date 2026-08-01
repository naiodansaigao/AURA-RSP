#!/usr/bin/env python3
"""Experiment 02: MNO/Reseller collusion and leaked SM-DP+ logs.

The program generates implementation-derived protocol-visible logs and then
evaluates what an attacker can reconstruct.  It does not claim to execute one
thousand live RSP network downloads.  AURA lifecycle rows use the integrated
install-receipt and authenticated state-receipt formulas.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import itertools
import json
import math
import random
import shutil
import statistics
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from integration_adapter import IntegratedLogFactory


LANG = {
    "zh": {
        "title": "实验2：MNO/Reseller 与 SM-DP+ 合谋及日志泄露",
        "status": "状态",
        "scale": "实验规模",
        "transactions": "条下载日志/协议",
        "metric": "指标",
        "order_join": "订单—下载记录连接率",
        "cross_mno_recovery": "跨MNO完整历史恢复率",
        "multi_mno_clusters": "多MNO设备簇比例",
        "cross_profile_link": "跨Profile关联率",
        "mean_profiles": "平均每簇Profile数",
        "max_profiles": "单簇最大Profile数",
        "full_history": "完整设备历史恢复率",
        "within_lifecycle": "同Profile生命周期连接率",
        "clusters": "攻击者观察到的簇数量",
        "plain": "直观结论",
        "std_conclusion": "Standard RSP：稳定EID/证书/公钥使合谋方和泄露日志恢复设备级Profile历史。",
        "aura_conclusion": "AURA-RSP：订单和单个Profile生命周期仍可见，但不同Profile无法归并为同一物理设备。",
        "paper": "论文图表",
        "full": "完整结果",
        "device_unit": "个eUICC",
        "mno_unit": "个MNO",
        "collusion_title": "2A：MNO/Reseller 与共享 SM-DP+ 合谋",
        "leak_title": "2B：SM-DP+ 数据库泄露",
        "figure_2a_title": "2A 合谋后的跨MNO设备历史恢复",
        "figure_2a_subtitle": "订单均可归因；差异在于能否继续跨Profile恢复同一物理eUICC",
        "figure_2b_title": "2B 日志泄露后的设备历史影响半径",
        "figure_2b_subtitle": "每个攻击者可见簇中包含的不同Profile数量",
        "figure_graph_title": "泄露日志重建的设备—Profile关系示例",
        "higher_link": "数值越高表示泄露后可恢复的设备历史越完整",
        "profile_count": "Profile数量",
        "random_note": "生命周期事件只验证日志关联语义，非完整状态机执行",
    },
    "en": {
        "title": "Experiment 2: MNO/Reseller Collusion and SM-DP+ Log Leakage",
        "status": "Status",
        "scale": "Scale",
        "transactions": "download logs/protocol",
        "metric": "Metric",
        "order_join": "Order-to-download join rate",
        "cross_mno_recovery": "Cross-MNO exact history recovery",
        "multi_mno_clusters": "Multi-MNO device-cluster rate",
        "cross_profile_link": "Cross-profile link rate",
        "mean_profiles": "Mean profiles per cluster",
        "max_profiles": "Maximum profiles per cluster",
        "full_history": "Full device-history recovery",
        "within_lifecycle": "Within-profile lifecycle link rate",
        "clusters": "Attacker-visible cluster count",
        "plain": "Plain-language conclusion",
        "std_conclusion": "Standard RSP: stable EID/certificate/public-key values expose device-level profile histories under collusion or leakage.",
        "aura_conclusion": "AURA-RSP: each order and profile lifecycle remains visible, but distinct profiles cannot be merged into one physical-device history.",
        "paper": "Paper figures",
        "full": "Full results",
        "device_unit": "eUICCs",
        "mno_unit": "MNOs",
        "collusion_title": "2A: MNO/Reseller and Shared SM-DP+ Collusion",
        "leak_title": "2B: SM-DP+ Database Leakage",
        "figure_2a_title": "2A Cross-MNO History Recovery under Collusion",
        "figure_2a_subtitle": "Orders remain attributable in both modes; only Standard RSP exposes cross-profile device history",
        "figure_2b_title": "2B Device-History Impact Radius after Log Leakage",
        "figure_2b_subtitle": "Number of distinct profiles contained in each attacker-visible cluster",
        "figure_graph_title": "Example Device–Profile Histories Reconstructed from Leaked Logs",
        "higher_link": "Higher values indicate more complete device-history reconstruction",
        "profile_count": "Number of profiles",
        "random_note": "Lifecycle events test log-linkage semantics, not a complete state-machine execution",
    },
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_records(rows: list[dict[str, Any]]) -> str:
    payload = "\n".join(canonical_json(row) for row in rows).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def display_ljust(value: str, width: int) -> str:
    display_width = sum(
        2 if unicodedata.east_asian_width(character) in ("W", "F") else 1
        for character in value
    )
    return value + " " * max(width - display_width, 1)


def escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class DeterministicTokens:
    def __init__(self, seed: int):
        self.master = hashlib.sha256(f"experiment-02:{seed}".encode()).digest()

    def raw(self, domain: str, index: str, length: int = 32) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hmac.new(
                    self.master,
                    f"{domain}:{index}:{counter}".encode(),
                    hashlib.sha256,
                ).digest()
            )
            counter += 1
        return bytes(output[:length])

    def hex(self, domain: str, index: str, length: int = 32) -> str:
        return self.raw(domain, index, length).hex()

    def b64(self, domain: str, index: str, length: int = 32) -> str:
        return b64(self.raw(domain, index, length))


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if int(config["device_count"]) < 2:
        raise ValueError("device_count must be at least 2")
    if len(config["mnos"]) < 2 or len(config["colluding_mnos"]) < 2:
        raise ValueError("at least two MNOs and two colluding MNOs are required")
    if not set(config["colluding_mnos"]).issubset(config["mnos"]):
        raise ValueError("colluding_mnos must be a subset of mnos")
    return config


def load_profile(config_path: Path, config: dict[str, Any]) -> bytes:
    path = (config_path.parent / config["profile_source"]).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"profile source not found: {path}")
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("profile source is too small")
    return data


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                keys.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: canonical_json(value) if isinstance(value, (list, dict)) else value
                    for key, value in row.items()
                }
            )


def derived_profile_hash(
    base_profile: bytes,
    tokens: DeterministicTokens,
    logical_id: str,
) -> str:
    derived = base_profile[:-32] + tokens.raw("profile-marker", logical_id, 32)
    return hashlib.sha256(derived).hexdigest()


def generate_logs(
    config: dict[str, Any],
    base_profile: bytes,
    implementation: IntegratedLogFactory,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    seed = int(config["seed"])
    rng = random.Random(seed)
    tokens = DeterministicTokens(seed)
    slots: list[dict[str, Any]] = []
    for device_index in range(int(config["device_count"])):
        device = f"Device-{device_index + 1:04d}"
        eid = "89049032" + f"{device_index + 1:024d}"
        identity = implementation.standard_device_identity(device, eid)
        for mno_index, mno in enumerate(config["mnos"]):
            logical_id = f"D{device_index + 1:04d}-M{mno_index + 1:02d}"
            profile_hash = derived_profile_hash(base_profile, tokens, logical_id)
            slots.append(
                {
                    "logical_id": logical_id,
                    "true_device_id": device,
                    "mno": mno,
                    "identity": identity,
                    "profile_hash": profile_hash,
                    "profile_size": len(base_profile),
                    "order_time": 1_800_000_000
                    + rng.randrange(int(config["time_window_seconds"])),
                }
            )
    rng.shuffle(slots)
    mno_logs: list[dict[str, Any]] = []
    smdpp_logs: list[dict[str, Any]] = []
    lifecycle_logs: list[dict[str, Any]] = []
    truth: list[dict[str, Any]] = []

    for event_index, slot in enumerate(slots):
        logical_id = slot["logical_id"]
        common_order = {
            "event_index": event_index,
            "mno": slot["mno"],
            "order_id": "ORDER-" + tokens.hex("order", logical_id, 12).upper(),
            "test_account_id": "ACCOUNT-" + tokens.hex("account", logical_id, 12),
            "sid": implementation.config["sid"],
            "pid_h": slot["profile_hash"],
            "op": "download",
            "order_time_unix": slot["order_time"],
            "profile_id": "PROFILE-" + tokens.hex("profile-id", logical_id, 10),
            "profile_hash": slot["profile_hash"],
            "profile_size": slot["profile_size"],
        }
        for mode in ("standard_rsp", "aura_rsp"):
            if mode == "standard_rsp":
                activation_handle = (
                    "MID-" + tokens.hex("std-matching-id", logical_id, 16).upper()
                )
                transaction_id = tokens.hex("std-transaction", logical_id, 16).upper()
                authorization_kind = "matching_id"
                identity_fields = {
                    **slot["identity"],
                    "euicc_signature_hash": implementation.standard_auth_hash(
                        transaction_id=transaction_id,
                        identity=slot["identity"],
                        logical_id=logical_id,
                    ),
                }
                transcript_fields = {
                    "matching_id": activation_handle,
                    "server_challenge": tokens.b64(
                        "standard-server-challenge", logical_id, 32
                    ),
                }
                lifecycle_link = slot["identity"]["eid"]
                lifecycle_evidence = [
                    {
                        "event": event,
                        "counter": counter,
                        "state": counter,
                        "last_hash": "",
                        "receipt_hash": tokens.hex(
                            f"standard-lifecycle-{event}", logical_id
                        ),
                        "semantic_scope": "standard_smdpp_audit_log",
                    }
                    for counter, event in enumerate(config["lifecycle_events"])
                ]
            else:
                transaction_id = tokens.hex("aura-transaction", logical_id, 16).upper()
                transcript_fields, lifecycle_evidence = (
                    implementation.aura_download_bundle(
                        device_id=slot["true_device_id"],
                        logical_id=logical_id,
                        transaction_id=transaction_id,
                        pid_h=slot["profile_hash"],
                        timestamp=slot["order_time"],
                    )
                )
                activation_handle = transcript_fields["I_ac"]
                authorization_kind = "I_ac"
                identity_fields = {}
                lifecycle_link = transcript_fields["lph"]

            mno_logs.append(
                {
                    "protocol_mode": mode,
                    **common_order,
                    "order_id": "ORDER-"
                    + tokens.hex(f"{mode}-order", logical_id, 12).upper(),
                    "test_account_id": "ACCOUNT-"
                    + tokens.hex(f"{mode}-account", logical_id, 12),
                    "I_ac": activation_handle,
                    "authorization_kind": authorization_kind,
                    "order_status": "fulfilled",
                }
            )
            smdpp_logs.append(
                {
                    "protocol_mode": mode,
                    "transaction_id": transaction_id,
                    "I_ac": activation_handle,
                    "sid": transcript_fields.get(
                        "sid", implementation.config["sid"]
                    ),
                    "pid_h": slot["profile_hash"],
                    "op": "download",
                    "mno": slot["mno"],
                    "profile_id": common_order["profile_id"],
                    "profile_hash": slot["profile_hash"],
                    "profile_size": slot["profile_size"],
                    "authentication_result": "accepted",
                    "download_result": "completed",
                    "install_result": "confirmed",
                    "event_time_unix": slot["order_time"] + 30,
                    "network_egress": config["shared_network_egress"],
                    "smdpp": config["shared_smdpp"],
                    **identity_fields,
                    **transcript_fields,
                }
            )
            for evidence in lifecycle_evidence:
                lifecycle_logs.append(
                    {
                        "protocol_mode": mode,
                        "transaction_id": transaction_id,
                        "profile_id": common_order["profile_id"],
                        "pid_h": slot["profile_hash"],
                        "mno": slot["mno"],
                        "lifecycle_link": lifecycle_link,
                        **evidence,
                        "event_time_unix": slot["order_time"]
                        + 30
                        + int(evidence["counter"]) * 10,
                    }
                )
            truth.append(
                {
                    "protocol_mode": mode,
                    "transaction_id": transaction_id,
                    "I_ac": activation_handle,
                    "logical_download_id": logical_id,
                    "true_device_id": slot["true_device_id"],
                    "mno": slot["mno"],
                    "profile_id": common_order["profile_id"],
                }
            )
    return mno_logs, smdpp_logs, lifecycle_logs, truth


def attacker_cluster_key(row: dict[str, Any], mode: str) -> str:
    if mode == "standard_rsp":
        return "STD:" + row["eid"]
    return "AURA:" + row["lph"]


def evaluate_clusters(
    rows: list[dict[str, Any]],
    truth_by_tx: dict[str, dict[str, str]],
    expected_profiles_per_device: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[attacker_cluster_key(row, row["protocol_mode"])].append(row)
    true_devices: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        truth = truth_by_tx[row["transaction_id"]]
        true_devices[truth["true_device_id"]].add(row["profile_id"])

    positive_total = 0
    positive_linked = 0
    negative_total = 0
    negative_linked = 0
    cluster_by_tx = {
        row["transaction_id"]: cluster_id
        for cluster_id, members in clusters.items()
        for row in members
    }
    for left, right in itertools.combinations(rows, 2):
        if left["mno"] == right["mno"]:
            continue
        left_truth = truth_by_tx[left["transaction_id"]]
        right_truth = truth_by_tx[right["transaction_id"]]
        same_device = left_truth["true_device_id"] == right_truth["true_device_id"]
        same_cluster = (
            cluster_by_tx[left["transaction_id"]]
            == cluster_by_tx[right["transaction_id"]]
        )
        if same_device:
            positive_total += 1
            positive_linked += int(same_cluster)
        else:
            negative_total += 1
            negative_linked += int(same_cluster)

    exact_recovered = 0
    per_device: list[dict[str, Any]] = []
    for device, profiles in sorted(true_devices.items()):
        relevant_tx = [
            row["transaction_id"]
            for row in rows
            if truth_by_tx[row["transaction_id"]]["true_device_id"] == device
        ]
        candidate_clusters = Counter(cluster_by_tx[tx] for tx in relevant_tx)
        best_cluster, recovered_count = candidate_clusters.most_common(1)[0]
        cluster_members = clusters[best_cluster]
        cluster_devices = {
            truth_by_tx[row["transaction_id"]]["true_device_id"]
            for row in cluster_members
        }
        recovered_profiles = {
            row["profile_id"]
            for row in cluster_members
            if truth_by_tx[row["transaction_id"]]["true_device_id"] == device
        }
        exact = (
            len(recovered_profiles) == expected_profiles_per_device
            and len(cluster_devices) == 1
            and len(cluster_members) == expected_profiles_per_device
        )
        exact_recovered += int(exact)
        per_device.append(
            {
                "true_device_id": device,
                "expected_profile_count": expected_profiles_per_device,
                "recovered_profile_count": len(recovered_profiles),
                "recovered_fraction": round(
                    len(recovered_profiles) / expected_profiles_per_device, 6
                ),
                "exact_history_recovered": exact,
            }
        )

    profile_counts = [
        len({row["profile_id"] for row in members}) for members in clusters.values()
    ]
    multi_mno_clusters = sum(
        len({row["mno"] for row in members}) > 1 for members in clusters.values()
    )
    metrics = {
        "transaction_count": len(rows),
        "attacker_visible_cluster_count": len(clusters),
        "mean_profiles_per_cluster": round(statistics.fmean(profile_counts), 6),
        "median_profiles_per_cluster": round(statistics.median(profile_counts), 6),
        "max_profiles_per_cluster": max(profile_counts),
        "multi_mno_cluster_rate": round(
            multi_mno_clusters / len(clusters) if clusters else 0.0, 6
        ),
        "cross_profile_pair_link_rate": round(
            positive_linked / positive_total if positive_total else 0.0, 6
        ),
        "false_link_rate": round(
            negative_linked / negative_total if negative_total else 0.0, 6
        ),
        "exact_device_history_recovery_rate": round(
            exact_recovered / len(true_devices), 6
        ),
        "mean_profiles_recovered_per_true_device": round(
            statistics.fmean(row["recovered_profile_count"] for row in per_device),
            6,
        ),
        "mean_history_exposure_fraction": round(
            statistics.fmean(row["recovered_fraction"] for row in per_device), 6
        ),
    }
    return metrics, per_device, clusters


def analyze_collusion(
    mode: str,
    mno_logs: list[dict[str, Any]],
    smdpp_logs: list[dict[str, Any]],
    truth_by_tx: dict[str, dict[str, str]],
    colluding_mnos: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    scoped_orders = [
        row
        for row in mno_logs
        if row["protocol_mode"] == mode and row["mno"] in colluding_mnos
    ]
    smdpp_by_iac = {
        row["I_ac"]: row for row in smdpp_logs if row["protocol_mode"] == mode
    }
    joined: list[dict[str, Any]] = []
    for order in scoped_orders:
        transaction = smdpp_by_iac.get(order["I_ac"])
        if transaction is None:
            continue
        joined.append(
            {
                **transaction,
                "order_id": order["order_id"],
                "test_account_id": order["test_account_id"],
                "order_time_unix": order["order_time_unix"],
            }
        )
    cluster_metrics, per_device, clusters = evaluate_clusters(
        joined,
        truth_by_tx,
        expected_profiles_per_device=len(colluding_mnos),
    )
    result = {
        "protocol_mode": mode,
        "colluding_mnos": colluding_mnos,
        "orders_in_scope": len(scoped_orders),
        "joined_orders": len(joined),
        "order_join_rate": round(
            len(joined) / len(scoped_orders) if scoped_orders else 0.0, 6
        ),
        **cluster_metrics,
    }
    return result, per_device, clusters


def analyze_leakage(
    mode: str,
    smdpp_logs: list[dict[str, Any]],
    lifecycle_logs: list[dict[str, Any]],
    truth_by_tx: dict[str, dict[str, str]],
    profiles_per_device: int,
    lifecycle_events_per_profile: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    rows = [row for row in smdpp_logs if row["protocol_mode"] == mode]
    lifecycle = [
        row for row in lifecycle_logs if row["protocol_mode"] == mode
    ]
    metrics, per_device, clusters = evaluate_clusters(
        rows,
        truth_by_tx,
        expected_profiles_per_device=profiles_per_device,
    )
    events_by_profile = Counter(row["profile_id"] for row in lifecycle)
    complete_lifecycle = sum(
        count == lifecycle_events_per_profile for count in events_by_profile.values()
    )
    lifecycle_by_cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in lifecycle:
        prefix = "STD:" if mode == "standard_rsp" else "AURA:"
        lifecycle_by_cluster[prefix + row["lifecycle_link"]].append(row)
    download_records_per_cluster = [len(members) for members in clusters.values()]
    mnos_per_cluster = [
        len({row["mno"] for row in members}) for members in clusters.values()
    ]
    lifecycle_records_per_cluster = [
        len(lifecycle_by_cluster.get(cluster_id, [])) for cluster_id in clusters
    ]
    metrics.update(
        {
            "leaked_download_records": len(rows),
            "leaked_lifecycle_records": len(lifecycle),
            "within_profile_lifecycle_link_rate": round(
                complete_lifecycle / len(events_by_profile)
                if events_by_profile
                else 0.0,
                6,
            ),
            "lifecycle_events_per_profile": lifecycle_events_per_profile,
            "lifecycle_scope": "integrated_authenticated_state_chain_logs",
            "mean_download_records_per_cluster": round(
                statistics.mean(download_records_per_cluster), 6
            ),
            "mean_mnos_per_cluster": round(
                statistics.mean(mnos_per_cluster), 6
            ),
            "mean_lifecycle_records_per_cluster": round(
                statistics.mean(lifecycle_records_per_cluster), 6
            ),
        }
    )
    return metrics, per_device, clusters


def assertion(
    output: list[dict[str, Any]],
    name: str,
    passed: bool,
    actual: Any,
    expected: str,
) -> None:
    output.append(
        {
            "name": name,
            "passed": bool(passed),
            "actual": actual,
            "expected": expected,
        }
    )


def prepare_output(path: Path, experiment_root: Path) -> None:
    resolved = path.resolve()
    safe_parent = (experiment_root / "results").resolve()
    if resolved == safe_parent or safe_parent not in resolved.parents:
        raise ValueError(f"refusing to reset output outside {safe_parent}: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    for subdir in ("raw", "analysis", "exports", "paper"):
        (resolved / subdir).mkdir(parents=True)


def write_database_exports(
    output: Path,
    smdpp_logs: list[dict[str, Any]],
    lifecycle_logs: list[dict[str, Any]],
) -> None:
    for mode in ("standard_rsp", "aura_rsp"):
        export = {
            "protocol_mode": mode,
            "export_type": "simulated_smdpp_database_and_logs",
            "download_records": [
                row for row in smdpp_logs if row["protocol_mode"] == mode
            ],
            "lifecycle_records": [
                row for row in lifecycle_logs if row["protocol_mode"] == mode
            ],
        }
        (output / "exports" / f"{mode}_smdpp_database_export.json").write_text(
            json.dumps(export, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def grouped_bar_svg(
    title: str,
    subtitle: str,
    labels: list[str],
    standard_values: list[float],
    aura_values: list[float],
    y_label: str,
    y_max: float,
    note: str,
) -> str:
    width = 1700
    height = 1020
    x_left = 145
    y_top = 150
    y_bottom = 790
    plot_height = y_bottom - y_top
    centers = [310, 680, 1050, 1420][: len(labels)]
    blue = "#2F5597"
    orange = "#ED7D31"
    gray = "#666666"
    font = "Arial, Microsoft YaHei, sans-serif"
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<title>{escape_xml(title)}</title>",
        f"<desc>{escape_xml(subtitle)}</desc>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="60" text-anchor="middle" font-family="{font}" font-size="39" font-weight="600" fill="#222222">{escape_xml(title)}</text>',
        f'<text x="{width / 2}" y="108" text-anchor="middle" font-family="{font}" font-size="22" fill="{gray}">{escape_xml(subtitle)}</text>',
    ]
    for tick in range(6):
        value = y_max * tick / 5
        y_value = y_bottom - tick / 5 * plot_height
        svg.extend(
            [
                f'<line x1="{x_left}" y1="{y_value:.1f}" x2="1645" y2="{y_value:.1f}" stroke="#dddddd" stroke-width="1"/>',
                f'<text x="{x_left - 20}" y="{y_value + 7:.1f}" text-anchor="end" font-family="{font}" font-size="20" fill="#444444">{value:.1f}</text>',
            ]
        )
    svg.extend(
        [
            f'<line x1="{x_left}" y1="{y_top}" x2="{x_left}" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<line x1="{x_left}" y1="{y_bottom}" x2="1645" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<text x="42" y="{(y_top + y_bottom) / 2}" transform="rotate(-90 42 {(y_top + y_bottom) / 2})" text-anchor="middle" font-family="{font}" font-size="25" fill="#222222">{escape_xml(y_label)}</text>',
        ]
    )
    for center, label, standard, aura in zip(
        centers, labels, standard_values, aura_values
    ):
        for x_value, value, color in (
            (center - 112, standard, blue),
            (center + 16, aura, orange),
        ):
            bar_height = value / y_max * plot_height if y_max else 0
            visible = max(bar_height, 2)
            svg.extend(
                [
                    f'<rect x="{x_value}" y="{y_bottom - visible:.1f}" width="96" height="{visible:.1f}" fill="{color}"/>',
                    f'<text x="{x_value + 48}" y="{max(y_bottom - bar_height - 15, y_top - 7):.1f}" text-anchor="middle" font-family="{font}" font-size="23" font-weight="600" fill="#222222">{value:.3f}</text>',
                ]
            )
        words = label.split("\n")
        for line_index, line in enumerate(words):
            svg.append(
                f'<text x="{center}" y="{y_bottom + 48 + line_index * 30}" text-anchor="middle" font-family="{font}" font-size="21" fill="#222222">{escape_xml(line)}</text>'
            )
    svg.extend(
        [
            f'<rect x="560" y="905" width="30" height="22" fill="{blue}"/>',
            f'<text x="605" y="925" font-family="{font}" font-size="23" fill="#222222">Standard RSP</text>',
            f'<rect x="900" y="905" width="30" height="22" fill="{orange}"/>',
            f'<text x="945" y="925" font-family="{font}" font-size="23" fill="#222222">AURA-RSP</text>',
            f'<text x="{width / 2}" y="982" text-anchor="middle" font-family="{font}" font-size="18" fill="{gray}">{escape_xml(note)}</text>',
            "</svg>",
        ]
    )
    return "\n".join(svg) + "\n"


def write_history_graph(
    path: Path,
    language: str,
    mode: str,
    rows: list[dict[str, Any]],
    truth_by_tx: dict[str, dict[str, str]],
    device_limit: int,
) -> None:
    text = LANG[language]
    allowed = {f"Device-{index + 1:04d}" for index in range(device_limit)}
    selected = [
        row
        for row in rows
        if truth_by_tx[row["transaction_id"]]["true_device_id"] in allowed
    ]
    selected.sort(
        key=lambda row: (
            truth_by_tx[row["transaction_id"]]["true_device_id"],
            row["mno"],
        )
    )
    width = 1650
    row_height = 66
    height = 150 + len(selected) * row_height
    font = "Arial, Microsoft YaHei, sans-serif"
    blue = "#2F5597"
    orange = "#ED7D31"
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<title>{escape_xml(text['figure_graph_title'])}</title>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="55" text-anchor="middle" font-family="{font}" font-size="37" font-weight="600" fill="#222222">{escape_xml(text["figure_graph_title"])}</text>',
        f'<text x="{width / 2}" y="96" text-anchor="middle" font-family="{font}" font-size="22" fill="#555555">{escape_xml("Standard RSP" if mode == "standard_rsp" else "AURA-RSP")}</text>',
    ]
    for index, row in enumerate(selected):
        y_value = 145 + index * row_height
        if mode == "standard_rsp":
            left = "Stable-EID-" + row["eid"][-4:]
            basis = (
                "相同EID/证书/公钥"
                if language == "zh"
                else "same EID/certificate/public key"
            )
            color = blue
        else:
            left = "lph-" + row["lph"][:10]
            basis = (
                "仅当前Profile生命周期"
                if language == "zh"
                else "current profile lifecycle only"
            )
            color = orange
        right = f'{row["mno"]} / {row["profile_id"][-12:]}'
        svg.extend(
            [
                f'<rect x="55" y="{y_value - 29}" width="360" height="44" rx="7" fill="{color}" fill-opacity="0.16" stroke="{color}" stroke-width="2"/>',
                f'<text x="75" y="{y_value}" font-family="{font}" font-size="21" fill="#222222">{escape_xml(left)}</text>',
                f'<line x1="415" y1="{y_value - 7}" x2="1060" y2="{y_value - 7}" stroke="#555555" stroke-width="2"/>',
                f'<text x="737" y="{y_value - 15}" text-anchor="middle" font-family="{font}" font-size="18" fill="#555555">{escape_xml(basis)}</text>',
                f'<rect x="1060" y="{y_value - 29}" width="520" height="44" rx="22" fill="#f4f4f4" stroke="#555555"/>',
                f'<text x="1080" y="{y_value}" font-family="{font}" font-size="21" fill="#222222">{escape_xml(right)}</text>',
            ]
        )
    svg.append("</svg>")
    path.write_text("\n".join(svg) + "\n", encoding="utf-8")


def write_paper_outputs(
    output: Path,
    report: dict[str, Any],
    smdpp_logs: list[dict[str, Any]],
    truth_by_tx: dict[str, dict[str, str]],
    graph_device_limit: int,
) -> None:
    paper = output / "paper"
    for language in ("zh", "en"):
        text = LANG[language]
        std_2a = report["subexperiment_2a_collusion"]["standard_rsp"]
        aura_2a = report["subexperiment_2a_collusion"]["aura_rsp"]
        labels_2a = [
            text["order_join"],
            text["cross_mno_recovery"],
            text["multi_mno_clusters"],
            text["cross_profile_link"],
        ]
        svg_2a = grouped_bar_svg(
            text["figure_2a_title"],
            text["figure_2a_subtitle"],
            labels_2a,
            [
                std_2a["order_join_rate"],
                std_2a["exact_device_history_recovery_rate"],
                std_2a["multi_mno_cluster_rate"],
                std_2a["cross_profile_pair_link_rate"],
            ],
            [
                aura_2a["order_join_rate"],
                aura_2a["exact_device_history_recovery_rate"],
                aura_2a["multi_mno_cluster_rate"],
                aura_2a["cross_profile_pair_link_rate"],
            ],
            "比例" if language == "zh" else "Rate",
            1.0,
            text["higher_link"],
        )
        (paper / f"figure-1-collusion-results-{language}.svg").write_text(
            svg_2a,
            encoding="utf-8",
        )
        std_2b = report["subexperiment_2b_log_leakage"]["standard_rsp"]
        aura_2b = report["subexperiment_2b_log_leakage"]["aura_rsp"]
        svg_2b = grouped_bar_svg(
            text["figure_2b_title"],
            text["figure_2b_subtitle"],
            [text["mean_profiles"], text["max_profiles"]],
            [
                std_2b["mean_profiles_per_cluster"],
                std_2b["max_profiles_per_cluster"],
            ],
            [
                aura_2b["mean_profiles_per_cluster"],
                aura_2b["max_profiles_per_cluster"],
            ],
            text["profile_count"],
            float(report["design"]["profiles_per_device"]),
            text["random_note"],
        )
        (paper / f"figure-2-log-leakage-radius-{language}.svg").write_text(
            svg_2b,
            encoding="utf-8",
        )
        for mode in ("standard_rsp", "aura_rsp"):
            write_history_graph(
                paper / f"figure-3-history-graph-{mode}-{language}.svg",
                language,
                mode,
                [row for row in smdpp_logs if row["protocol_mode"] == mode],
                truth_by_tx,
                graph_device_limit,
            )

        table_rows = [
            {
                text["metric"]: text["order_join"],
                "Standard RSP": f'{std_2a["order_join_rate"]:.4f}',
                "AURA-RSP": f'{aura_2a["order_join_rate"]:.4f}',
            },
            {
                text["metric"]: text["cross_mno_recovery"],
                "Standard RSP": f'{std_2a["exact_device_history_recovery_rate"]:.4f}',
                "AURA-RSP": f'{aura_2a["exact_device_history_recovery_rate"]:.4f}',
            },
            {
                text["metric"]: text["mean_profiles"] + " (2B)",
                "Standard RSP": f'{std_2b["mean_profiles_per_cluster"]:.4f}',
                "AURA-RSP": f'{aura_2b["mean_profiles_per_cluster"]:.4f}',
            },
            {
                text["metric"]: text["full_history"] + " (2B)",
                "Standard RSP": f'{std_2b["exact_device_history_recovery_rate"]:.4f}',
                "AURA-RSP": f'{aura_2b["exact_device_history_recovery_rate"]:.4f}',
            },
            {
                text["metric"]: text["within_lifecycle"] + " (2B)",
                "Standard RSP": f'{std_2b["within_profile_lifecycle_link_rate"]:.4f}',
                "AURA-RSP": f'{aura_2b["within_profile_lifecycle_link_rate"]:.4f}',
            },
        ]
        write_csv(paper / f"table-1-collusion-leakage-{language}.csv", table_rows)
        heading = text["metric"]
        md = [
            f"| {heading} | Standard RSP | AURA-RSP |",
            "|---|---:|---:|",
        ]
        md.extend(
            f'| {row[heading]} | {row["Standard RSP"]} | {row["AURA-RSP"]} |'
            for row in table_rows
        )
        (paper / f"table-1-collusion-leakage-{language}.md").write_text(
            "\n".join(md) + "\n",
            encoding="utf-8",
        )

    captions_zh = f"""图1  MNO/Reseller与共享SM-DP+合谋分析。两种协议均能通过订单授权标识将MNO订单与当前下载记录对应；Standard RSP进一步利用稳定EID、eUICC证书和公钥恢复跨MNO设备历史，而AURA-RSP无法跨不同Profile生命周期形成设备簇。

图2  SM-DP+日志泄露的历史影响半径。Standard RSP泄露后每个稳定设备簇平均包含{report["subexperiment_2b_log_leakage"]["standard_rsp"]["mean_profiles_per_cluster"]:.1f}个Profile；AURA-RSP每个lph簇平均仅包含{report["subexperiment_2b_log_leakage"]["aura_rsp"]["mean_profiles_per_cluster"]:.1f}个Profile，泄露影响由设备级历史缩小到订单级和单Profile生命周期。

图3  泄露日志重建关系示例。AURA-RSP并不隐藏某个订单已经完成下载，也不阻止同一lph下的生命周期事件关联；它阻止的是把不同票据和不同Profile生命周期继续归并为同一物理eUICC。

注：本实验为集成实现派生的协议可见日志实验，并未执行每种协议{report["design"]["transactions_per_protocol"]}次完整网络下载。AURA生命周期记录使用集成版安装收据和认证状态收据公式；完整HTTPS闭环由集成回归测试单独覆盖。
"""
    captions_en = f"""Figure 1. Collusion between MNO/Reseller logs and a shared SM-DP+. In both modes, an order authorization handle links an MNO order to its current download. Standard RSP additionally exposes stable EID, eUICC-certificate, and public-key values that recover cross-MNO device history; AURA-RSP does not form a device cluster across distinct profile lifecycles.

Figure 2. History impact radius after SM-DP+ log leakage. Each leaked Standard RSP device cluster contains {report["subexperiment_2b_log_leakage"]["standard_rsp"]["mean_profiles_per_cluster"]:.1f} profiles on average. Each AURA-RSP lph cluster contains only {report["subexperiment_2b_log_leakage"]["aura_rsp"]["mean_profiles_per_cluster"]:.1f} profile on average, reducing the leakage radius from device-level history to an order and a single profile lifecycle.

Figure 3. Example relationship reconstruction from leaked logs. AURA-RSP does not hide that a specific order completed a download, nor does it prevent events under the same lph from being linked. It prevents distinct tickets and profile lifecycles from being merged into one physical-eUICC history.

Note: this is an implementation-derived protocol-visible log experiment; it does not execute {report["design"]["transactions_per_protocol"]} complete network downloads per protocol. AURA lifecycle rows use the integrated install-receipt and authenticated state-receipt formulas; complete HTTPS execution is covered separately by the integration regression suite.
"""
    (paper / "captions-and-analysis-zh.txt").write_text(
        captions_zh, encoding="utf-8"
    )
    (paper / "captions-and-analysis-en.txt").write_text(
        captions_en, encoding="utf-8"
    )


def print_human_summary(
    report: dict[str, Any],
    output: Path,
    language: str,
) -> None:
    text = LANG[language]
    std_2a = report["subexperiment_2a_collusion"]["standard_rsp"]
    aura_2a = report["subexperiment_2a_collusion"]["aura_rsp"]
    std_2b = report["subexperiment_2b_log_leakage"]["standard_rsp"]
    aura_2b = report["subexperiment_2b_log_leakage"]["aura_rsp"]
    line = "=" * 96
    print()
    print(line)
    print(text["title"])
    print(
        f'{text["status"]}: [{report["status"]}]    '
        f'{text["scale"]}: {report["design"]["device_count"]} '
        f'{text["device_unit"]} × {report["design"]["profiles_per_device"]} '
        f'{text["mno_unit"]} = {report["design"]["transactions_per_protocol"]} '
        f'{text["transactions"]}'
    )
    print(line)
    heading = "指标" if language == "zh" else "Metric"
    print(text["collusion_title"])
    print(f'{display_ljust(heading, 50)} {"Standard RSP":>20} {"AURA-RSP":>20}')
    print("-" * 96)
    for label, std_value, aura_value in (
        (text["order_join"], std_2a["order_join_rate"], aura_2a["order_join_rate"]),
        (
            text["cross_mno_recovery"],
            std_2a["exact_device_history_recovery_rate"],
            aura_2a["exact_device_history_recovery_rate"],
        ),
        (
            text["multi_mno_clusters"],
            std_2a["multi_mno_cluster_rate"],
            aura_2a["multi_mno_cluster_rate"],
        ),
        (
            text["cross_profile_link"],
            std_2a["cross_profile_pair_link_rate"],
            aura_2a["cross_profile_pair_link_rate"],
        ),
    ):
        print(
            f"{display_ljust(label, 50)} "
            f"{std_value:>20.4f} {aura_value:>20.4f}"
        )
    print()
    print(text["leak_title"])
    print(f'{display_ljust(heading, 50)} {"Standard RSP":>20} {"AURA-RSP":>20}')
    print("-" * 96)
    for label, std_value, aura_value, precision in (
        (
            text["clusters"],
            std_2b["attacker_visible_cluster_count"],
            aura_2b["attacker_visible_cluster_count"],
            0,
        ),
        (
            text["mean_profiles"],
            std_2b["mean_profiles_per_cluster"],
            aura_2b["mean_profiles_per_cluster"],
            4,
        ),
        (
            text["max_profiles"],
            std_2b["max_profiles_per_cluster"],
            aura_2b["max_profiles_per_cluster"],
            0,
        ),
        (
            text["full_history"],
            std_2b["exact_device_history_recovery_rate"],
            aura_2b["exact_device_history_recovery_rate"],
            4,
        ),
        (
            text["within_lifecycle"],
            std_2b["within_profile_lifecycle_link_rate"],
            aura_2b["within_profile_lifecycle_link_rate"],
            4,
        ),
    ):
        print(
            f"{display_ljust(label, 50)} "
            f"{std_value:>20.{precision}f} {aura_value:>20.{precision}f}"
        )
    print("-" * 96)
    print(f'{text["plain"]}:')
    print(f'  {text["std_conclusion"]}')
    print(f'  {text["aura_conclusion"]}')
    print(f'{text["paper"]}: {output / "paper"}')
    print(f'{text["full"]}: {output / "summary.md"}')
    print(line)


def summary_markdown(report: dict[str, Any]) -> str:
    std_2a = report["subexperiment_2a_collusion"]["standard_rsp"]
    aura_2a = report["subexperiment_2a_collusion"]["aura_rsp"]
    std_2b = report["subexperiment_2b_log_leakage"]["standard_rsp"]
    aura_2b = report["subexperiment_2b_log_leakage"]["aura_rsp"]
    return f"""# 实验2：MNO/Reseller 与 SM-DP+ 合谋及日志泄露

状态：**{report["status"]}**

默认规模为 {report["design"]["device_count"]} 个eUICC × {report["design"]["profiles_per_device"]} 个MNO = 每种协议 {report["design"]["transactions_per_protocol"]} 条受控下载日志。实验不声称执行了相同数量的完整网络下载。

## 2A 合谋分析

| 指标 | Standard RSP | AURA-RSP |
|---|---:|---:|
| 订单—下载记录连接率 | {std_2a["order_join_rate"]:.4f} | {aura_2a["order_join_rate"]:.4f} |
| 跨MNO完整历史恢复率 | {std_2a["exact_device_history_recovery_rate"]:.4f} | {aura_2a["exact_device_history_recovery_rate"]:.4f} |
| 多MNO设备簇比例 | {std_2a["multi_mno_cluster_rate"]:.4f} | {aura_2a["multi_mno_cluster_rate"]:.4f} |
| 跨Profile关联率 | {std_2a["cross_profile_pair_link_rate"]:.4f} | {aura_2a["cross_profile_pair_link_rate"]:.4f} |

## 2B 日志泄露

| 指标 | Standard RSP | AURA-RSP |
|---|---:|---:|
| 泄露下载记录 | {std_2b["leaked_download_records"]} | {aura_2b["leaked_download_records"]} |
| 攻击者观察簇数量 | {std_2b["attacker_visible_cluster_count"]} | {aura_2b["attacker_visible_cluster_count"]} |
| 平均每簇Profile数 | {std_2b["mean_profiles_per_cluster"]:.4f} | {aura_2b["mean_profiles_per_cluster"]:.4f} |
| 单簇最大Profile数 | {std_2b["max_profiles_per_cluster"]} | {aura_2b["max_profiles_per_cluster"]} |
| 完整设备历史恢复率 | {std_2b["exact_device_history_recovery_rate"]:.4f} | {aura_2b["exact_device_history_recovery_rate"]:.4f} |
| 同Profile生命周期连接率 | {std_2b["within_profile_lifecycle_link_rate"]:.4f} | {aura_2b["within_profile_lifecycle_link_rate"]:.4f} |

## 结论

- 两种协议都允许MNO确认自己的订单和Profile已经完成下载；AURA-RSP并不隐藏业务事实。
- Standard RSP中的稳定EID、证书和公钥把日志泄露影响扩大为完整设备历史。
- AURA-RSP把可关联范围限制到一个订单和一个Profile生命周期，不把不同Profile继续连接到同一物理eUICC。
- AURA生命周期记录由集成版安装收据和认证状态收据公式生成；完整HTTPS闭环由集成回归测试单独覆盖。
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--devices", type=int, help="override device_count")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    started = time.perf_counter()
    config_path = args.config.resolve()
    experiment_root = Path(__file__).resolve().parent
    integration_root = (experiment_root / "../../pysim-aura-integration").resolve()
    config = load_config(config_path)
    if args.devices is not None:
        config["device_count"] = args.devices
    base_profile = load_profile(config_path, config)
    tokens = DeterministicTokens(int(config["seed"]))
    implementation = IntegratedLogFactory(integration_root, tokens)
    prepare_output(args.output, experiment_root)
    output = args.output.resolve()

    mno_logs, smdpp_logs, lifecycle_logs, truth = generate_logs(
        config, base_profile, implementation
    )
    second = generate_logs(config, base_profile, implementation)
    reproducible = all(
        sha256_records(first_rows) == sha256_records(second_rows)
        for first_rows, second_rows in zip(
            (mno_logs, smdpp_logs, lifecycle_logs, truth),
            second,
        )
    )
    public_fields = set().union(
        *(row.keys() for row in mno_logs + smdpp_logs + lifecycle_logs)
    )
    if {"true_device_id", "logical_download_id"} & public_fields:
        raise RuntimeError("ground truth leaked into attacker-visible logs")

    write_jsonl(output / "raw" / "mno_reseller_logs.jsonl", mno_logs)
    write_jsonl(output / "raw" / "smdpp_logs.jsonl", smdpp_logs)
    write_jsonl(output / "raw" / "lifecycle_logs.jsonl", lifecycle_logs)
    write_jsonl(output / "raw" / "ground_truth.jsonl", truth)
    write_csv(output / "raw" / "mno_reseller_logs.csv", mno_logs)
    write_csv(output / "raw" / "smdpp_logs.csv", smdpp_logs)
    write_csv(output / "raw" / "lifecycle_logs.csv", lifecycle_logs)
    write_csv(output / "raw" / "ground_truth.csv", truth)
    write_database_exports(output, smdpp_logs, lifecycle_logs)

    truth_by_tx = {
        row["transaction_id"]: {
            "true_device_id": row["true_device_id"],
            "profile_id": row["profile_id"],
            "mno": row["mno"],
        }
        for row in truth
    }
    result_2a: dict[str, Any] = {}
    result_2b: dict[str, Any] = {}
    collusion_device_rows: list[dict[str, Any]] = []
    leakage_device_rows: list[dict[str, Any]] = []
    for mode in ("standard_rsp", "aura_rsp"):
        result, per_device, _ = analyze_collusion(
            mode,
            mno_logs,
            smdpp_logs,
            truth_by_tx,
            list(config["colluding_mnos"]),
        )
        result_2a[mode] = result
        collusion_device_rows.extend(
            {"protocol_mode": mode, **row} for row in per_device
        )
        leak_result, leak_per_device, _ = analyze_leakage(
            mode,
            smdpp_logs,
            lifecycle_logs,
            truth_by_tx,
            len(config["mnos"]),
            len(config["lifecycle_events"]),
        )
        result_2b[mode] = leak_result
        leakage_device_rows.extend(
            {"protocol_mode": mode, **row} for row in leak_per_device
        )
    write_csv(
        output / "analysis" / "collusion_profile_recovery_by_device.csv",
        collusion_device_rows,
    )
    write_csv(
        output / "analysis" / "leakage_profile_recovery_by_device.csv",
        leakage_device_rows,
    )
    write_jsonl(
        output / "analysis" / "collusion_profile_recovery_by_device.jsonl",
        collusion_device_rows,
    )
    write_jsonl(
        output / "analysis" / "leakage_profile_recovery_by_device.jsonl",
        leakage_device_rows,
    )

    expected_per_mode = int(config["device_count"]) * len(config["mnos"])
    accounts = [row["test_account_id"] for row in mno_logs]
    assertions: list[dict[str, Any]] = []
    assertion(
        assertions,
        "transaction_count_per_mode",
        all(
            sum(row["protocol_mode"] == mode for row in smdpp_logs)
            == expected_per_mode
            for mode in ("standard_rsp", "aura_rsp")
        ),
        expected_per_mode,
        f"{expected_per_mode} per protocol",
    )
    assertion(
        assertions,
        "all_test_accounts_unique",
        len(accounts) == len(set(accounts)),
        {"records": len(accounts), "unique": len(set(accounts))},
        "one unique account per order and protocol",
    )
    assertion(
        assertions,
        "ground_truth_separated",
        not ({"true_device_id", "logical_download_id"} & public_fields),
        sorted(public_fields),
        "ground-truth fields absent from public logs",
    )
    assertion(
        assertions,
        "generator_reproducible",
        reproducible,
        reproducible,
        "true",
    )
    limits = config["assertions"]
    for mode in ("standard_rsp", "aura_rsp"):
        assertion(
            assertions,
            f"2a_{mode}_order_join_complete",
            result_2a[mode]["order_join_rate"]
            >= float(limits["min_order_join_rate"]),
            result_2a[mode]["order_join_rate"],
            f'>= {limits["min_order_join_rate"]}',
        )
    assertion(
        assertions,
        "2a_standard_cross_mno_history_recovered",
        result_2a["standard_rsp"]["exact_device_history_recovery_rate"]
        >= float(limits["standard_min_history_recovery"]),
        result_2a["standard_rsp"]["exact_device_history_recovery_rate"],
        f'>= {limits["standard_min_history_recovery"]}',
    )
    assertion(
        assertions,
        "2a_aura_no_cross_profile_device_link",
        result_2a["aura_rsp"]["cross_profile_pair_link_rate"]
        <= float(limits["aura_max_cross_profile_link_rate"]),
        result_2a["aura_rsp"]["cross_profile_pair_link_rate"],
        f'<= {limits["aura_max_cross_profile_link_rate"]}',
    )
    assertion(
        assertions,
        "2b_standard_leak_radius_is_device_history",
        math.isclose(
            result_2b["standard_rsp"]["mean_profiles_per_cluster"],
            float(limits["standard_expected_leak_profiles_per_cluster"]),
        ),
        result_2b["standard_rsp"]["mean_profiles_per_cluster"],
        str(limits["standard_expected_leak_profiles_per_cluster"]),
    )
    assertion(
        assertions,
        "2b_aura_leak_radius_is_single_profile",
        math.isclose(
            result_2b["aura_rsp"]["mean_profiles_per_cluster"],
            float(limits["aura_expected_leak_profiles_per_cluster"]),
        ),
        result_2b["aura_rsp"]["mean_profiles_per_cluster"],
        str(limits["aura_expected_leak_profiles_per_cluster"]),
    )
    assertion(
        assertions,
        "2b_aura_within_profile_lifecycle_visible",
        result_2b["aura_rsp"]["within_profile_lifecycle_link_rate"] == 1.0,
        result_2b["aura_rsp"]["within_profile_lifecycle_link_rate"],
        "1.0",
    )
    exposure_radius = {
        "standard_downloads": result_2b["standard_rsp"][
            "mean_download_records_per_cluster"
        ],
        "aura_downloads": result_2b["aura_rsp"][
            "mean_download_records_per_cluster"
        ],
        "standard_mnos": result_2b["standard_rsp"]["mean_mnos_per_cluster"],
        "aura_mnos": result_2b["aura_rsp"]["mean_mnos_per_cluster"],
        "standard_lifecycle": result_2b["standard_rsp"][
            "mean_lifecycle_records_per_cluster"
        ],
        "aura_lifecycle": result_2b["aura_rsp"][
            "mean_lifecycle_records_per_cluster"
        ],
    }
    expected_exposure_radius = {
        "standard_downloads": float(len(config["mnos"])),
        "aura_downloads": 1.0,
        "standard_mnos": float(len(config["mnos"])),
        "aura_mnos": 1.0,
        "standard_lifecycle": float(
            len(config["mnos"]) * len(config["lifecycle_events"])
        ),
        "aura_lifecycle": float(len(config["lifecycle_events"])),
    }
    assertion(
        assertions,
        "2b_exposure_radius_aggregates_consistent",
        exposure_radius == expected_exposure_radius,
        exposure_radius,
        expected_exposure_radius,
    )
    assertion(
        assertions,
        "no_false_device_links",
        result_2a["standard_rsp"]["false_link_rate"] == 0.0
        and result_2a["aura_rsp"]["false_link_rate"] == 0.0
        and result_2b["standard_rsp"]["false_link_rate"] == 0.0
        and result_2b["aura_rsp"]["false_link_rate"] == 0.0,
        {
            "2a_standard": result_2a["standard_rsp"]["false_link_rate"],
            "2a_aura": result_2a["aura_rsp"]["false_link_rate"],
            "2b_standard": result_2b["standard_rsp"]["false_link_rate"],
            "2b_aura": result_2b["aura_rsp"]["false_link_rate"],
        },
        "all zero",
    )
    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    report = {
        "experiment": config["experiment_name"],
        "status": status,
        "method": "implementation_derived_protocol_visible_log_experiment",
        "design": {
            "seed": config["seed"],
            "device_count": config["device_count"],
            "mnos": config["mnos"],
            "colluding_mnos": config["colluding_mnos"],
            "profiles_per_device": len(config["mnos"]),
            "transactions_per_protocol": expected_per_mode,
            "complete_network_downloads_executed": False,
            "lifecycle_scope": "integrated_authenticated_state_chain_logs",
            "unique_test_account_per_order": True,
            "profile_source_sha256": hashlib.sha256(base_profile).hexdigest(),
            "profile_bytes": len(base_profile),
            "implementation_audit": implementation.audit(),
        },
        "subexperiment_2a_collusion": result_2a,
        "subexperiment_2b_log_leakage": result_2b,
        "reproducibility_hashes": {
            "mno_logs_sha256": sha256_records(mno_logs),
            "smdpp_logs_sha256": sha256_records(smdpp_logs),
            "lifecycle_logs_sha256": sha256_records(lifecycle_logs),
            "ground_truth_sha256": sha256_records(truth),
        },
        "assertions": assertions,
        "execution_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    (output / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "summary.md").write_text(
        summary_markdown(report),
        encoding="utf-8",
    )
    flat_rows = []
    for subexperiment, results in (
        ("2a_collusion", result_2a),
        ("2b_log_leakage", result_2b),
    ):
        for mode, metrics in results.items():
            flat_rows.append(
                {
                    "subexperiment": subexperiment,
                    "protocol_mode": mode,
                    **{
                        key: value
                        for key, value in metrics.items()
                        if not isinstance(value, (list, dict))
                    },
                }
            )
    write_csv(output / "summary.csv", flat_rows)
    write_paper_outputs(
        output,
        report,
        smdpp_logs,
        truth_by_tx,
        int(config["graph_device_limit"]),
    )

    machine = {
        "status": status,
        "transactions_per_protocol": expected_per_mode,
        "2a_standard_history_recovery": result_2a["standard_rsp"][
            "exact_device_history_recovery_rate"
        ],
        "2a_aura_history_recovery": result_2a["aura_rsp"][
            "exact_device_history_recovery_rate"
        ],
        "2b_standard_mean_profiles_per_cluster": result_2b["standard_rsp"][
            "mean_profiles_per_cluster"
        ],
        "2b_aura_mean_profiles_per_cluster": result_2b["aura_rsp"][
            "mean_profiles_per_cluster"
        ],
        "results": str(output),
    }
    if args.machine_json:
        print(canonical_json(machine))
    else:
        languages = ("zh", "en") if args.lang == "both" else (args.lang,)
        for language in languages:
            print_human_summary(report, output, language)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
