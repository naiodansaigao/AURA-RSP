#!/usr/bin/env python3
"""Experiment 01: shared SM-DP+ cross-profile linkability.

This is a controlled transcript experiment.  It intentionally does not claim
to execute a complete RSP network download for every synthetic transaction.
The generated records preserve the equality and freshness semantics of fields
that the current Standard RSP and AURA-RSP implementations expose to SM-DP+.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PAIR_FEATURES = [
    "eq_eid",
    "eq_euicc_certificate_fingerprint",
    "eq_euicc_public_key_fingerprint",
    "stable_identifier_prefix_similarity",
    "eq_I_ac",
    "eq_pid_h",
    "eq_nu",
    "eq_lph",
    "eq_opid",
    "eq_vk_t",
    "eq_proof_hash",
    "eq_Bind_t_hash",
    "eq_session_public_key",
    "ephemeral_prefix_similarity",
    "same_mno",
    "same_network_egress",
    "same_profile_size",
    "time_similarity",
]

STANDARD_STABLE_FIELDS = [
    "eid",
    "euicc_certificate_fingerprint",
    "euicc_public_key_fingerprint",
]

AURA_PER_TRANSACTION_FIELDS = [
    "I_ac",
    "pid_h",
    "nu",
    "lph",
    "opid",
    "vk_t",
    "proof_hash",
    "Bind_t_hash",
    "session_public_key",
]

LANG = {
    "zh": {
        "experiment_title": "实验1：共享 SM-DP+ 跨 Profile 关联",
        "figure_title": "共享 SM-DP+ 跨 Profile 关联实验",
        "figure_subtitle": "Standard RSP 与 AURA-RSP 对比（数值越高表示越容易被关联）",
        "metric_value": "指标值",
        "pair_auc": "成对关联 ROC-AUC",
        "pair_accuracy": "成对分类准确率",
        "cluster_b3": "直接聚类 B3 F1",
        "cluster_ari": "调整兰德指数（ARI）",
        "exact_recovery": "完整设备簇恢复率",
        "cross_profile": "跨 Profile 直接关联率",
        "random_baseline": "随机猜测基线 0.5",
        "roc_title": "成对跨 Profile 关联 ROC 曲线",
        "fpr": "假阳性率（FPR）",
        "tpr": "真阳性率（TPR）",
        "random_guess": "随机猜测",
        "status": "状态",
        "scale": "实验规模",
        "transactions": "条事务/协议",
        "conclusion": "直观结论",
        "standard_conclusion": "Standard RSP：稳定 EID/证书/公钥可将跨 MNO/Profile 事务完整归并。",
        "aura_conclusion": "AURA-RSP：关联 AUC 接近随机猜测 0.5，未形成稳定跨 Profile 设备簇。",
        "paper_output": "论文图表",
        "full_result": "完整结果",
        "device_unit": "个 eUICC",
        "mno_unit": "个 MNO",
        "fixed_seed": "固定种子",
    },
    "en": {
        "experiment_title": "Experiment 1: Cross-Profile Linkability at a Shared SM-DP+",
        "figure_title": "Cross-Profile Linkability at a Shared SM-DP+",
        "figure_subtitle": "Standard RSP vs. AURA-RSP (higher values indicate greater linkability)",
        "metric_value": "Metric value",
        "pair_auc": "Pairwise ROC-AUC",
        "pair_accuracy": "Pairwise accuracy",
        "cluster_b3": "Direct clustering B3 F1",
        "cluster_ari": "Adjusted Rand Index",
        "exact_recovery": "Exact device recovery",
        "cross_profile": "Cross-profile direct link",
        "random_baseline": "Random-guess baseline: 0.5",
        "roc_title": "Pairwise Cross-Profile Linkability ROC Curves",
        "fpr": "False Positive Rate (FPR)",
        "tpr": "True Positive Rate (TPR)",
        "random_guess": "Random guess",
        "status": "Status",
        "scale": "Scale",
        "transactions": "transactions/protocol",
        "conclusion": "Plain-language conclusion",
        "standard_conclusion": "Standard RSP: stable EID/certificate/public-key values fully link profiles across MNOs.",
        "aura_conclusion": "AURA-RSP: AUC remains near random guessing (0.5), with no stable cross-profile device cluster.",
        "paper_output": "Paper figures",
        "full_result": "Full results",
        "device_unit": "eUICCs",
        "mno_unit": "MNOs",
        "fixed_seed": "fixed seed",
    },
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def display_ljust(value: str, width: int) -> str:
    display_width = sum(
        2 if unicodedata.east_asian_width(character) in ("W", "F") else 1
        for character in value
    )
    return value + " " * max(width - display_width, 1)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_records(records: list[dict[str, Any]]) -> str:
    return sha256_text("\n".join(canonical_json(row) for row in records))


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class DeterministicTokens:
    def __init__(self, seed: int):
        self.master = hashlib.sha256(f"experiment-01:{seed}".encode()).digest()

    def raw(self, domain: str, index: str, length: int = 32) -> bytes:
        material = hmac.new(
            self.master,
            f"{domain}:{index}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        if length <= len(material):
            return material[:length]
        output = bytearray(material)
        counter = 1
        while len(output) < length:
            output.extend(
                hmac.new(
                    self.master,
                    f"{domain}:{index}:{counter}".encode("utf-8"),
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
    if config["device_count"] < 2:
        raise ValueError("device_count must be at least 2")
    if len(config["mnos"]) < 2:
        raise ValueError("at least two MNOs are required")
    return config


def resolved_profile(config_path: Path, config: dict[str, Any]) -> bytes:
    path = (config_path.parent / config["profile_source"]).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"profile source not found: {path}")
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("profile source is too small")
    return data


def derived_profile(base_profile: bytes, tokens: DeterministicTokens, logical_id: str) -> bytes:
    """Make a distinct equal-size test profile artifact for each logical order."""
    marker = tokens.raw("profile-marker", logical_id, 32)
    return base_profile[:-32] + marker


def generate_dataset(
    config: dict[str, Any],
    base_profile: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    seed = int(config["seed"])
    rng = random.Random(seed)
    tokens = DeterministicTokens(seed)
    mnos = list(config["mnos"])
    count = int(config["device_count"])
    slots: list[dict[str, Any]] = []
    slot_index = 0

    for device_index in range(count):
        device_id = f"Device-{device_index + 1:02d}"
        eid = "89049032" + f"{device_index + 1:024d}"
        cert_fp = tokens.hex("standard-cert-fingerprint", device_id)
        pubkey_fp = tokens.hex("standard-pubkey-fingerprint", device_id)
        device_secret = tokens.raw("aura-hidden-x", device_id)
        for mno_index, mno in enumerate(mnos):
            logical_id = f"D{device_index + 1:02d}-M{mno_index + 1:02d}"
            profile = derived_profile(base_profile, tokens, logical_id)
            profile_hash = hashlib.sha256(profile).hexdigest()
            slots.append(
                {
                    "slot_index": slot_index,
                    "logical_download_id": logical_id,
                    "true_device_id": device_id,
                    "mno": mno,
                    "eid": eid,
                    "cert_fp": cert_fp,
                    "pubkey_fp": pubkey_fp,
                    "device_secret": device_secret,
                    "profile_hash": profile_hash,
                    "profile_size": len(profile),
                    "timestamp_offset": rng.randrange(int(config["time_window_seconds"])),
                }
            )
            slot_index += 1

    rng.shuffle(slots)
    standard: list[dict[str, Any]] = []
    aura: list[dict[str, Any]] = []
    truth: list[dict[str, Any]] = []
    base_timestamp = 1_800_000_000

    for event_index, slot in enumerate(slots):
        logical_id = slot["logical_download_id"]
        timestamp = base_timestamp + slot["timestamp_offset"]
        common = {
            "event_index": event_index,
            "timestamp_unix": timestamp,
            "mno": slot["mno"],
            "order_id": "ORDER-" + tokens.hex("order", logical_id, 12).upper(),
            "test_account_id": "ACCOUNT-" + tokens.hex("account", logical_id, 10),
            "profile_id": "PROFILE-" + tokens.hex("profile-id", logical_id, 10),
            "profile_hash": slot["profile_hash"],
            "profile_size": slot["profile_size"],
            "network_egress": config["shared_network_egress"],
            "smdpp": config["shared_smdpp"],
        }

        standard_tx = tokens.hex("standard-transaction", logical_id, 16).upper()
        standard_record = {
            "protocol_mode": "standard_rsp",
            "transaction_id": standard_tx,
            **common,
            "eid": slot["eid"],
            "euicc_certificate_fingerprint": slot["cert_fp"],
            "euicc_public_key_fingerprint": slot["pubkey_fp"],
            "euicc_signature_hash": tokens.hex("standard-signature", logical_id),
            "matching_id": "MID-" + tokens.hex("matching-id", logical_id, 12),
        }
        standard.append(standard_record)
        truth.append(
            {
                "protocol_mode": "standard_rsp",
                "transaction_id": standard_tx,
                "logical_download_id": logical_id,
                "true_device_id": slot["true_device_id"],
            }
        )

        aura_tx = tokens.hex("aura-transaction", logical_id, 16).upper()
        salt_p = tokens.raw("aura-profile-salt", logical_id)
        pid_h = slot["profile_hash"]
        lph = b64(
            hmac.new(
                slot["device_secret"],
                b"AURA-lph:" + bytes.fromhex(pid_h) + salt_p,
                hashlib.sha256,
            ).digest()
        )
        nu = tokens.b64("aura-ticket-nullifier", logical_id, 48)
        opid = tokens.b64("aura-opid", logical_id, 16)
        vk_t = tokens.b64("aura-vk-t", logical_id, 32)
        proof_seed = canonical_json(
            {
                "I_ac": "IAC-" + tokens.hex("aura-iac", logical_id, 16).upper(),
                "pid_h": pid_h,
                "nu": nu,
                "lph": lph,
                "opid": opid,
                "vk_t": vk_t,
            }
        )
        proof_hash = sha256_text(proof_seed + tokens.hex("aura-proof", logical_id))
        bind_hash = sha256_text(
            "AURA-RSP-v14:bind:" + proof_hash + aura_tx + pid_h
        )
        aura_record = {
            "protocol_mode": "aura_rsp",
            "transaction_id": aura_tx,
            **common,
            "I_ac": "IAC-" + tokens.hex("aura-iac", logical_id, 16).upper(),
            "I_t": tokens.b64("aura-I-t", logical_id, 16),
            "sid": config["aura_sid"],
            "pid_h": pid_h,
            "op": "download",
            "nu": nu,
            "lph": lph,
            "opid": opid,
            "vk_t": vk_t,
            "proof_hash": proof_hash,
            "Bind_t_hash": bind_hash,
            "session_public_key": tokens.b64("aura-session-pubkey", logical_id, 65),
            "N_U": tokens.b64("aura-N-U", logical_id, 16),
            "N_S": tokens.b64("aura-N-S", logical_id, 16),
            "serverOID": config["aura_server_oid"],
            "PRaddr": config["aura_praddr"],
            "cap": list(config["aura_capabilities"]),
        }
        aura.append(aura_record)
        truth.append(
            {
                "protocol_mode": "aura_rsp",
                "transaction_id": aura_tx,
                "logical_download_id": logical_id,
                "true_device_id": slot["true_device_id"],
            }
        )

    return standard, aura, truth


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


def nonempty_equal(a: dict[str, Any], b: dict[str, Any], key: str) -> float:
    left = a.get(key)
    right = b.get(key)
    return float(left not in (None, "") and right not in (None, "") and left == right)


def common_prefix_ratio(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    limit = min(len(left), len(right))
    match = 0
    for index in range(limit):
        if left[index] != right[index]:
            break
        match += 1
    return match / max(len(left), len(right))


def max_prefix(
    a: dict[str, Any],
    b: dict[str, Any],
    fields: list[str],
) -> float:
    return max(
        (common_prefix_ratio(str(a.get(key, "")), str(b.get(key, ""))) for key in fields),
        default=0.0,
    )


def pair_features(a: dict[str, Any], b: dict[str, Any]) -> list[float]:
    return [
        nonempty_equal(a, b, "eid"),
        nonempty_equal(a, b, "euicc_certificate_fingerprint"),
        nonempty_equal(a, b, "euicc_public_key_fingerprint"),
        max_prefix(a, b, STANDARD_STABLE_FIELDS),
        nonempty_equal(a, b, "I_ac"),
        nonempty_equal(a, b, "pid_h"),
        nonempty_equal(a, b, "nu"),
        nonempty_equal(a, b, "lph"),
        nonempty_equal(a, b, "opid"),
        nonempty_equal(a, b, "vk_t"),
        nonempty_equal(a, b, "proof_hash"),
        nonempty_equal(a, b, "Bind_t_hash"),
        nonempty_equal(a, b, "session_public_key"),
        max_prefix(a, b, AURA_PER_TRANSACTION_FIELDS),
        float(a["mno"] == b["mno"]),
        float(a["network_egress"] == b["network_egress"]),
        float(a["profile_size"] == b["profile_size"]),
        math.exp(-abs(a["timestamp_unix"] - b["timestamp_unix"]) / 86400.0),
    ]


def build_balanced_pairs(
    records: list[dict[str, Any]],
    truth_by_tx: dict[str, str],
    seed: int,
) -> list[dict[str, Any]]:
    positives: list[dict[str, Any]] = []
    negatives: list[dict[str, Any]] = []
    for left, right in itertools.combinations(records, 2):
        if left["mno"] == right["mno"]:
            continue
        label = int(
            truth_by_tx[left["transaction_id"]]
            == truth_by_tx[right["transaction_id"]]
        )
        pair = {
            "left_transaction_id": left["transaction_id"],
            "right_transaction_id": right["transaction_id"],
            "label_same_device": label,
            "features": pair_features(left, right),
        }
        (positives if label else negatives).append(pair)
    rng = random.Random(seed)
    rng.shuffle(positives)
    rng.shuffle(negatives)
    negatives = negatives[: len(positives)]
    pairs = positives + negatives
    rng.shuffle(pairs)
    return pairs


@dataclass
class Standardizer:
    means: list[float]
    scales: list[float]
    active: list[int]

    @classmethod
    def fit(cls, matrix: list[list[float]]) -> "Standardizer":
        columns = list(zip(*matrix))
        means = [statistics.fmean(column) for column in columns]
        scales: list[float] = []
        active: list[int] = []
        for index, (column, mean) in enumerate(zip(columns, means)):
            variance = statistics.fmean((value - mean) ** 2 for value in column)
            scale = math.sqrt(variance)
            scales.append(scale)
            if scale > 1e-12:
                active.append(index)
        return cls(means=means, scales=scales, active=active)

    def transform_one(self, row: list[float]) -> list[float]:
        return [(row[index] - self.means[index]) / self.scales[index] for index in self.active]


@dataclass
class LogisticModel:
    standardizer: Standardizer
    weights: list[float]
    bias: float

    def score(self, raw: list[float]) -> float:
        values = self.standardizer.transform_one(raw)
        z_value = self.bias + sum(weight * value for weight, value in zip(self.weights, values))
        if z_value >= 0:
            exp_value = math.exp(-z_value)
            return 1.0 / (1.0 + exp_value)
        exp_value = math.exp(z_value)
        return exp_value / (1.0 + exp_value)


def train_logistic(
    matrix: list[list[float]],
    labels: list[int],
    epochs: int = 1500,
    learning_rate: float = 0.08,
    l2: float = 0.002,
) -> LogisticModel:
    standardizer = Standardizer.fit(matrix)
    transformed = [standardizer.transform_one(row) for row in matrix]
    width = len(standardizer.active)
    weights = [0.0] * width
    bias = 0.0
    sample_count = len(labels)
    for _ in range(epochs):
        grad_w = [0.0] * width
        grad_b = 0.0
        for values, label in zip(transformed, labels):
            z_value = bias + sum(weight * value for weight, value in zip(weights, values))
            if z_value >= 0:
                probability = 1.0 / (1.0 + math.exp(-z_value))
            else:
                exp_value = math.exp(z_value)
                probability = exp_value / (1.0 + exp_value)
            error = probability - label
            grad_b += error
            for index, value in enumerate(values):
                grad_w[index] += error * value
        bias -= learning_rate * grad_b / sample_count
        for index in range(width):
            regularized = grad_w[index] / sample_count + l2 * weights[index]
            weights[index] -= learning_rate * regularized
    return LogisticModel(standardizer, weights, bias)


def stratified_folds(pairs: list[dict[str, Any]], folds: int, seed: int) -> list[list[int]]:
    by_label: dict[int, list[int]] = defaultdict(list)
    for index, pair in enumerate(pairs):
        by_label[pair["label_same_device"]].append(index)
    rng = random.Random(seed)
    output = [[] for _ in range(folds)]
    for indexes in by_label.values():
        rng.shuffle(indexes)
        for position, index in enumerate(indexes):
            output[position % folds].append(index)
    return output


def roc_auc(labels: list[int], scores: list[float]) -> float:
    positives = [score for label, score in zip(labels, scores) if label == 1]
    negatives = [score for label, score in zip(labels, scores) if label == 0]
    if not positives or not negatives:
        raise ValueError("ROC-AUC requires both classes")
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1.0
            elif positive == negative:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def binary_metrics(labels: list[int], scores: list[float], threshold: float = 0.5) -> dict[str, Any]:
    predicted = [int(score >= threshold) for score in scores]
    tp = sum(label == 1 and guess == 1 for label, guess in zip(labels, predicted))
    tn = sum(label == 0 and guess == 0 for label, guess in zip(labels, predicted))
    fp = sum(label == 0 and guess == 1 for label, guess in zip(labels, predicted))
    fn = sum(label == 1 and guess == 0 for label, guess in zip(labels, predicted))
    accuracy = (tp + tn) / len(labels)
    tpr = tp / (tp + fn) if tp + fn else 0.0
    tnr = tn / (tn + fp) if tn + fp else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "roc_auc": round(roc_auc(labels, scores), 6),
        "pairwise_accuracy": round(accuracy, 6),
        "balanced_accuracy": round((tpr + tnr) / 2, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "threshold": threshold,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "test_pairs": len(labels),
    }


def cross_validated_classifier(
    pairs: list[dict[str, Any]],
    folds: int,
    seed: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], LogisticModel]:
    fold_indexes = stratified_folds(pairs, folds, seed)
    all_labels: list[int] = []
    all_scores: list[float] = []
    predictions: list[dict[str, Any]] = []
    for fold_index, test_indexes in enumerate(fold_indexes):
        test_set = set(test_indexes)
        train = [pair for index, pair in enumerate(pairs) if index not in test_set]
        test = [pairs[index] for index in test_indexes]
        model = train_logistic(
            [pair["features"] for pair in train],
            [pair["label_same_device"] for pair in train],
        )
        for pair in test:
            score = model.score(pair["features"])
            label = pair["label_same_device"]
            all_labels.append(label)
            all_scores.append(score)
            predictions.append(
                {
                    "fold": fold_index,
                    "left_transaction_id": pair["left_transaction_id"],
                    "right_transaction_id": pair["right_transaction_id"],
                    "label_same_device": label,
                    "score_same_device": round(score, 9),
                    "predicted_same_device": int(score >= 0.5),
                }
            )
    metrics = binary_metrics(all_labels, all_scores)
    final_model = train_logistic(
        [pair["features"] for pair in pairs],
        [pair["label_same_device"] for pair in pairs],
    )
    metrics["cv_folds"] = folds
    metrics["balanced_pair_count"] = len(pairs)
    metrics["active_features"] = [
        PAIR_FEATURES[index] for index in final_model.standardizer.active
    ]
    metrics["dropped_constant_features"] = [
        name
        for index, name in enumerate(PAIR_FEATURES)
        if index not in final_model.standardizer.active
    ]
    metrics["final_model_coefficients"] = {
        PAIR_FEATURES[index]: round(weight, 6)
        for index, weight in zip(
            final_model.standardizer.active,
            final_model.weights,
        )
    }
    return metrics, predictions, final_model


class UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left != root_right:
            self.parent[root_right] = root_left

    def clusters(self) -> dict[str, str]:
        roots = sorted({self.find(item) for item in self.parent})
        labels = {root: f"Cluster-{index + 1:03d}" for index, root in enumerate(roots)}
        return {item: labels[self.find(item)] for item in self.parent}


def direct_clusters(records: list[dict[str, Any]], mode: str) -> dict[str, str]:
    transaction_ids = [row["transaction_id"] for row in records]
    union = UnionFind(transaction_ids)
    candidate_fields = (
        STANDARD_STABLE_FIELDS
        if mode == "standard_rsp"
        else ["nu", "lph", "opid", "vk_t", "proof_hash", "Bind_t_hash", "session_public_key"]
    )
    for field in candidate_fields:
        first_seen: dict[str, str] = {}
        for row in records:
            value = row.get(field)
            if value in (None, ""):
                continue
            if value in first_seen:
                union.union(first_seen[value], row["transaction_id"])
            else:
                first_seen[value] = row["transaction_id"]
    return union.clusters()


def learned_clusters(
    records: list[dict[str, Any]],
    model: LogisticModel,
    threshold: float = 0.5,
) -> dict[str, str]:
    transaction_ids = [row["transaction_id"] for row in records]
    union = UnionFind(transaction_ids)
    for left, right in itertools.combinations(records, 2):
        if left["mno"] == right["mno"]:
            continue
        if model.score(pair_features(left, right)) >= threshold:
            union.union(left["transaction_id"], right["transaction_id"])
    return union.clusters()


def choose2(value: int) -> int:
    return value * (value - 1) // 2


def adjusted_rand_index(true_labels: list[str], predicted_labels: list[str]) -> float:
    contingency: dict[tuple[str, str], int] = Counter(zip(true_labels, predicted_labels))
    true_counts = Counter(true_labels)
    pred_counts = Counter(predicted_labels)
    sum_comb = sum(choose2(value) for value in contingency.values())
    sum_true = sum(choose2(value) for value in true_counts.values())
    sum_pred = sum(choose2(value) for value in pred_counts.values())
    total_pairs = choose2(len(true_labels))
    if total_pairs == 0:
        return 1.0
    expected = sum_true * sum_pred / total_pairs
    maximum = (sum_true + sum_pred) / 2
    if maximum == expected:
        return 1.0
    return (sum_comb - expected) / (maximum - expected)


def cluster_metrics(
    records: list[dict[str, Any]],
    truth_by_tx: dict[str, str],
    cluster_by_tx: dict[str, str],
) -> dict[str, Any]:
    true_groups: dict[str, set[str]] = defaultdict(set)
    predicted_groups: dict[str, set[str]] = defaultdict(set)
    for row in records:
        tx = row["transaction_id"]
        true_groups[truth_by_tx[tx]].add(tx)
        predicted_groups[cluster_by_tx[tx]].add(tx)

    precisions: list[float] = []
    recalls: list[float] = []
    for row in records:
        tx = row["transaction_id"]
        truth_members = true_groups[truth_by_tx[tx]]
        predicted_members = predicted_groups[cluster_by_tx[tx]]
        overlap = len(truth_members & predicted_members)
        precisions.append(overlap / len(predicted_members))
        recalls.append(overlap / len(truth_members))
    precision = statistics.fmean(precisions)
    recall = statistics.fmean(recalls)
    b3_f1 = 2 * precision * recall / (precision + recall)

    exact = 0
    for device, truth_members in true_groups.items():
        labels = {cluster_by_tx[tx] for tx in truth_members}
        if len(labels) == 1:
            predicted_members = predicted_groups[next(iter(labels))]
            if predicted_members == truth_members:
                exact += 1

    positive_total = 0
    positive_linked = 0
    negative_total = 0
    negative_linked = 0
    for left, right in itertools.combinations(records, 2):
        if left["mno"] == right["mno"]:
            continue
        same_truth = truth_by_tx[left["transaction_id"]] == truth_by_tx[right["transaction_id"]]
        same_cluster = cluster_by_tx[left["transaction_id"]] == cluster_by_tx[right["transaction_id"]]
        if same_truth:
            positive_total += 1
            positive_linked += int(same_cluster)
        else:
            negative_total += 1
            negative_linked += int(same_cluster)

    true_labels = [truth_by_tx[row["transaction_id"]] for row in records]
    predicted_labels = [cluster_by_tx[row["transaction_id"]] for row in records]
    return {
        "cluster_count": len(predicted_groups),
        "b3_precision": round(precision, 6),
        "b3_recall": round(recall, 6),
        "cluster_accuracy_b3_f1": round(b3_f1, 6),
        "adjusted_rand_index": round(adjusted_rand_index(true_labels, predicted_labels), 6),
        "exact_device_recovery_rate": round(exact / len(true_groups), 6),
        "cross_profile_link_rate": round(
            positive_linked / positive_total if positive_total else 0.0,
            6,
        ),
        "false_link_rate": round(
            negative_linked / negative_total if negative_total else 0.0,
            6,
        ),
    }


def stable_identifier_groups(records: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    cluster_map = direct_clusters(records, mode)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        groups[cluster_map[row["transaction_id"]]].append(row)
    output = []
    for cluster_id, members in sorted(groups.items()):
        output.append(
            {
                "cluster_id": cluster_id,
                "transaction_count": len(members),
                "mnos": sorted({member["mno"] for member in members}),
                "profiles": sorted(member["profile_id"] for member in members),
                "link_basis": (
                    [
                        field
                        for field in STANDARD_STABLE_FIELDS
                        if len({member.get(field) for member in members}) == 1
                    ]
                    if mode == "standard_rsp" and len(members) > 1
                    else []
                ),
            }
        )
    return output


def escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_dot_and_svg(
    output_dir: Path,
    mode: str,
    records: list[dict[str, Any]],
    truth_by_tx: dict[str, str],
    graph_device_limit: int,
) -> None:
    allowed_devices = {
        f"Device-{index + 1:02d}" for index in range(graph_device_limit)
    }
    selected = [
        row
        for row in records
        if truth_by_tx[row["transaction_id"]] in allowed_devices
    ]
    selected.sort(key=lambda row: (truth_by_tx[row["transaction_id"]], row["mno"]))
    dot_lines = ["graph linkability {", "  rankdir=LR;"]
    if mode == "standard_rsp":
        for device in sorted(allowed_devices):
            device_records = [
                row
                for row in selected
                if truth_by_tx[row["transaction_id"]] == device
            ]
            observed = "Stable-" + device_records[0]["eid"][-4:]
            dot_lines.append(f'  "{observed}" [shape=box,style=filled,fillcolor="#ffd166"];')
        for row in selected:
            profile = row["profile_id"]
            device = "Stable-" + row["eid"][-4:]
            dot_lines.append(f'  "{profile}" [shape=ellipse,label="{row["mno"]}\\n{profile[-8:]}"];')
            dot_lines.append(f'  "{device}" -- "{profile}" [label="stable EID/cert/key"];')
    else:
        for row in selected:
            session = "Session-" + row["transaction_id"][:8]
            profile = row["profile_id"]
            dot_lines.append(f'  "{session}" [shape=box,style=filled,fillcolor="#8ecae6"];')
            dot_lines.append(f'  "{profile}" [shape=ellipse,label="{row["mno"]}\\n{profile[-8:]}"];')
            dot_lines.append(f'  "{session}" -- "{profile}" [label="current transaction only"];')
    dot_lines.append("}")
    (output_dir / f"{mode}_relationship.dot").write_text(
        "\n".join(dot_lines) + "\n",
        encoding="utf-8",
    )

    rows = len(selected)
    width = 1000
    height = 90 + rows * 50
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="30" y="35" font-family="sans-serif" font-size="22" font-weight="bold">{escape_xml(mode)}: SM-DP+ visible relationship</text>',
    ]
    for index, row in enumerate(selected):
        y = 75 + index * 50
        if mode == "standard_rsp":
            left = "Stable-" + row["eid"][-4:]
            link = "stable EID/certificate/public-key"
            color = "#ffd166"
        else:
            left = "Session-" + row["transaction_id"][:8]
            link = "fresh ticket/nullifier/key"
            color = "#8ecae6"
        right = f'{row["mno"]} / {row["profile_id"][-12:]}'
        svg.extend(
            [
                f'<rect x="30" y="{y - 24}" width="250" height="34" rx="6" fill="{color}" stroke="#333"/>',
                f'<text x="42" y="{y}" font-family="monospace" font-size="14">{escape_xml(left)}</text>',
                f'<line x1="280" y1="{y - 7}" x2="650" y2="{y - 7}" stroke="#555" stroke-width="2"/>',
                f'<text x="360" y="{y - 13}" font-family="sans-serif" font-size="12" fill="#555">{escape_xml(link)}</text>',
                f'<rect x="650" y="{y - 24}" width="310" height="34" rx="17" fill="#f4f4f4" stroke="#333"/>',
                f'<text x="665" y="{y}" font-family="monospace" font-size="14">{escape_xml(right)}</text>',
            ]
        )
    if mode == "aura_rsp":
        svg.append(
            f'<text x="30" y="{height - 15}" font-family="sans-serif" font-size="13" fill="#9b2226">'
            "Ground-truth device labels are intentionally absent from the SM-DP+ view.</text>"
        )
    svg.append("</svg>")
    (output_dir / f"{mode}_relationship.svg").write_text(
        "\n".join(svg) + "\n",
        encoding="utf-8",
    )


def roc_curve_points(predictions: list[dict[str, Any]]) -> list[tuple[float, float]]:
    grouped: dict[float, list[int]] = defaultdict(list)
    for row in predictions:
        grouped[float(row["score_same_device"])].append(
            int(row["label_same_device"])
        )
    positives = sum(sum(labels) for labels in grouped.values())
    negatives = sum(len(labels) - sum(labels) for labels in grouped.values())
    tp = 0
    fp = 0
    points = [(0.0, 0.0)]
    for score in sorted(grouped, reverse=True):
        labels = grouped[score]
        tp += sum(labels)
        fp += len(labels) - sum(labels)
        points.append((fp / negatives, tp / positives))
    if points[-1] != (1.0, 1.0):
        points.append((1.0, 1.0))
    return points


def roc_step_path(
    points: list[tuple[float, float]],
    x_left: float,
    y_bottom: float,
    width: float,
    height: float,
) -> str:
    first_x = x_left + points[0][0] * width
    first_y = y_bottom - points[0][1] * height
    commands = [f"M {first_x:.2f} {first_y:.2f}"]
    previous_y = first_y
    for fpr, tpr in points[1:]:
        x_value = x_left + fpr * width
        y_value = y_bottom - tpr * height
        commands.append(f"L {x_value:.2f} {previous_y:.2f}")
        commands.append(f"L {x_value:.2f} {y_value:.2f}")
        previous_y = y_value
    return " ".join(commands)


def write_paper_metric_figure(
    paper_dir: Path,
    report: dict[str, Any],
    language: str,
) -> None:
    text = LANG[language]
    std = report["modes"]["standard_rsp"]
    aura = report["modes"]["aura_rsp"]
    metrics = [
        (
            "ROC-AUC",
            "成对关联分类" if language == "zh" else "Pairwise linkability",
            std["pairwise_classifier"]["roc_auc"],
            aura["pairwise_classifier"]["roc_auc"],
        ),
        (
            text["pair_accuracy"],
            "",
            std["pairwise_classifier"]["pairwise_accuracy"],
            aura["pairwise_classifier"]["pairwise_accuracy"],
        ),
        (
            text["exact_recovery"],
            "",
            std["direct_stable_grouping"]["exact_device_recovery_rate"],
            aura["direct_stable_grouping"]["exact_device_recovery_rate"],
        ),
        (
            text["cross_profile"],
            "",
            std["direct_stable_grouping"]["cross_profile_link_rate"],
            aura["direct_stable_grouping"]["cross_profile_link_rate"],
        ),
    ]
    width = 1650
    height = 1020
    x_left = 135
    y_top = 145
    y_bottom = 780
    plot_height = y_bottom - y_top
    centers = [320, 700, 1080, 1460]
    bar_width = 96
    gap = 22
    blue = "#2F5597"
    orange = "#ED7D31"
    gray = "#666666"
    font = "Arial, Microsoft YaHei, sans-serif"
    title = text["figure_title"]
    subtitle = text["figure_subtitle"]
    description = (
        "Standard RSP reaches one on all four linkability metrics, while AURA-RSP remains near random guessing for pairwise classification and zero for direct device recovery."
        if language == "en"
        else "四项指标采用零到一量纲。Standard RSP 均为一；AURA-RSP 的成对分类接近随机猜测，设备恢复和直接关联为零。"
    )
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<title>{escape_xml(title)}</title>",
        f"<desc>{escape_xml(description)}</desc>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="58" text-anchor="middle" font-family="{font}" font-size="38" font-weight="600" fill="#222222">{escape_xml(title)}</text>',
        f'<text x="{width / 2}" y="105" text-anchor="middle" font-family="{font}" font-size="23" fill="{gray}">{escape_xml(subtitle)}</text>',
    ]
    for tick in range(6):
        value = tick / 5
        y_value = y_bottom - value * plot_height
        svg.extend(
            [
                f'<line x1="{x_left}" y1="{y_value:.1f}" x2="1435" y2="{y_value:.1f}" stroke="#dddddd" stroke-width="1"/>',
                f'<text x="{x_left - 20}" y="{y_value + 7:.1f}" text-anchor="end" font-family="{font}" font-size="20" fill="#444444">{value:.1f}</text>',
            ]
        )
    svg.extend(
        [
            f'<line x1="{x_left}" y1="{y_top}" x2="{x_left}" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<line x1="{x_left}" y1="{y_bottom}" x2="1605" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<text x="40" y="{(y_top + y_bottom) / 2}" transform="rotate(-90 40 {(y_top + y_bottom) / 2})" text-anchor="middle" font-family="{font}" font-size="24" fill="#222222">{escape_xml(text["metric_value"])}</text>',
        ]
    )
    for index, (english, chinese, std_value, aura_value) in enumerate(metrics):
        center = centers[index]
        for offset, value, color in (
            (-bar_width - gap / 2, std_value, blue),
            (gap / 2, aura_value, orange),
        ):
            x_value = center + offset
            bar_height = value * plot_height
            y_value = y_bottom - bar_height
            visible_height = max(bar_height, 2)
            svg.extend(
                [
                    f'<rect x="{x_value:.1f}" y="{y_bottom - visible_height:.1f}" width="{bar_width}" height="{visible_height:.1f}" fill="{color}"/>',
                    f'<text x="{x_value + bar_width / 2:.1f}" y="{max(y_value - 14, y_top - 6):.1f}" text-anchor="middle" font-family="{font}" font-size="23" font-weight="600" fill="#222222">{value:.3f}</text>',
                ]
            )
        svg.extend(
            [
                f'<text x="{center}" y="{y_bottom + 48}" text-anchor="middle" font-family="{font}" font-size="22" fill="#222222">{escape_xml(english)}</text>',
                f'<text x="{center}" y="{y_bottom + 81}" text-anchor="middle" font-family="{font}" font-size="20" fill="{gray}">{escape_xml(chinese)}</text>',
            ]
        )
    random_y = y_bottom - 0.5 * plot_height
    svg.extend(
        [
            f'<line x1="170" y1="{random_y:.1f}" x2="840" y2="{random_y:.1f}" stroke="#777777" stroke-width="2" stroke-dasharray="9,8"/>',
            f'<text x="535" y="{random_y - 14:.1f}" text-anchor="end" font-family="{font}" font-size="19" fill="#555555">{escape_xml(text["random_baseline"])}</text>',
            f'<rect x="545" y="910" width="30" height="22" fill="{blue}"/>',
            f'<text x="590" y="930" font-family="{font}" font-size="23" fill="#222222">Standard RSP</text>',
            f'<rect x="855" y="910" width="30" height="22" fill="{orange}"/>',
            f'<text x="900" y="930" font-family="{font}" font-size="23" fill="#222222">AURA-RSP</text>',
            f'<text x="{width - 40}" y="988" text-anchor="end" font-family="{font}" font-size="18" fill="{gray}">n={report["design"]["device_count"]} {escape_xml(text["device_unit"])} · {report["design"]["profiles_per_device"]} Profile/eUICC · {escape_xml(text["fixed_seed"])} {report["design"]["seed"]}</text>',
            "</svg>",
        ]
    )
    (paper_dir / f"figure-1-linkability-metrics-{language}.svg").write_text(
        "\n".join(svg) + "\n",
        encoding="utf-8",
    )


def write_paper_roc_figure(
    paper_dir: Path,
    report: dict[str, Any],
    std_predictions: list[dict[str, Any]],
    aura_predictions: list[dict[str, Any]],
    language: str,
) -> None:
    text = LANG[language]
    width = 1450
    height = 1050
    x_left = 165
    y_top = 125
    plot_width = 900
    plot_height = 790
    y_bottom = y_top + plot_height
    blue = "#2F5597"
    orange = "#ED7D31"
    font = "Arial, Microsoft YaHei, sans-serif"
    std_points = roc_curve_points(std_predictions)
    aura_points = roc_curve_points(aura_predictions)
    std_path = roc_step_path(std_points, x_left, y_bottom, plot_width, plot_height)
    aura_path = roc_step_path(aura_points, x_left, y_bottom, plot_width, plot_height)
    std_auc = report["modes"]["standard_rsp"]["pairwise_classifier"]["roc_auc"]
    aura_auc = report["modes"]["aura_rsp"]["pairwise_classifier"]["roc_auc"]
    description = (
        "The Standard RSP curve reaches the upper-left corner with AUC one, whereas the AURA-RSP curve remains close to the random-guess diagonal."
        if language == "en"
        else "Standard RSP 曲线到达左上角且 AUC 为一；AURA-RSP 曲线接近随机猜测对角线。"
    )
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<title>{escape_xml(text['roc_title'])}</title>",
        f"<desc>{escape_xml(description)}</desc>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="62" text-anchor="middle" font-family="{font}" font-size="39" font-weight="600" fill="#222222">{escape_xml(text["roc_title"])}</text>',
    ]
    for tick in range(6):
        value = tick / 5
        x_value = x_left + value * plot_width
        y_value = y_bottom - value * plot_height
        svg.extend(
            [
                f'<line x1="{x_value:.1f}" y1="{y_top}" x2="{x_value:.1f}" y2="{y_bottom}" stroke="#e1e1e1" stroke-width="1"/>',
                f'<line x1="{x_left}" y1="{y_value:.1f}" x2="{x_left + plot_width}" y2="{y_value:.1f}" stroke="#e1e1e1" stroke-width="1"/>',
                f'<text x="{x_value:.1f}" y="{y_bottom + 35}" text-anchor="middle" font-family="{font}" font-size="20" fill="#444444">{value:.1f}</text>',
                f'<text x="{x_left - 20}" y="{y_value + 7:.1f}" text-anchor="end" font-family="{font}" font-size="20" fill="#444444">{value:.1f}</text>',
            ]
        )
    svg.extend(
        [
            f'<line x1="{x_left}" y1="{y_bottom}" x2="{x_left + plot_width}" y2="{y_top}" stroke="#777777" stroke-width="2" stroke-dasharray="9,7"/>',
            f'<path d="{std_path}" fill="none" stroke="{blue}" stroke-width="5" stroke-linejoin="round"/>',
            f'<path d="{aura_path}" fill="none" stroke="{orange}" stroke-width="4" stroke-linejoin="round"/>',
            f'<line x1="{x_left}" y1="{y_top}" x2="{x_left}" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<line x1="{x_left}" y1="{y_bottom}" x2="{x_left + plot_width}" y2="{y_bottom}" stroke="#333333" stroke-width="2"/>',
            f'<text x="{x_left + plot_width / 2}" y="1000" text-anchor="middle" font-family="{font}" font-size="26" fill="#222222">{escape_xml(text["fpr"])}</text>',
            f'<text x="47" y="{y_top + plot_height / 2}" transform="rotate(-90 47 {y_top + plot_height / 2})" text-anchor="middle" font-family="{font}" font-size="26" fill="#222222">{escape_xml(text["tpr"])}</text>',
            f'<line x1="1140" y1="255" x2="1210" y2="255" stroke="{blue}" stroke-width="6"/>',
            f'<text x="1230" y="263" font-family="{font}" font-size="24" fill="#222222">Standard RSP</text>',
            f'<text x="1140" y="304" font-family="{font}" font-size="22" fill="#444444">AUC = {std_auc:.3f}</text>',
            f'<line x1="1140" y1="390" x2="1210" y2="390" stroke="{orange}" stroke-width="6"/>',
            f'<text x="1230" y="398" font-family="{font}" font-size="24" fill="#222222">AURA-RSP</text>',
            f'<text x="1140" y="439" font-family="{font}" font-size="22" fill="#444444">AUC = {aura_auc:.3f}</text>',
            '<line x1="1140" y1="545" x2="1210" y2="500" stroke="#777777" stroke-width="3" stroke-dasharray="10,8"/>',
            f'<text x="1230" y="532" font-family="{font}" font-size="24" fill="#222222">{escape_xml(text["random_guess"])}</text>',
            f'<text x="1140" y="578" font-family="{font}" font-size="22" fill="#444444">AUC = 0.500</text>',
            "</svg>",
        ]
    )
    (paper_dir / f"figure-2-roc-curve-{language}.svg").write_text(
        "\n".join(svg) + "\n",
        encoding="utf-8",
    )


def write_paper_artifacts(
    output: Path,
    report: dict[str, Any],
    std_predictions: list[dict[str, Any]],
    aura_predictions: list[dict[str, Any]],
) -> None:
    paper_dir = output / "paper"
    for language in ("zh", "en"):
        write_paper_metric_figure(paper_dir, report, language)
        write_paper_roc_figure(
            paper_dir,
            report,
            std_predictions,
            aura_predictions,
            language,
        )
    std = report["modes"]["standard_rsp"]
    aura = report["modes"]["aura_rsp"]
    rows_zh = [
        {
            "指标": "Pairwise ROC-AUC",
            "Standard RSP": f'{std["pairwise_classifier"]["roc_auc"]:.4f}',
            "AURA-RSP": f'{aura["pairwise_classifier"]["roc_auc"]:.4f}',
            "解释": "越高表示越容易判断两条事务属于同一设备",
        },
        {
            "指标": "Pairwise accuracy",
            "Standard RSP": f'{std["pairwise_classifier"]["pairwise_accuracy"]:.4f}',
            "AURA-RSP": f'{aura["pairwise_classifier"]["pairwise_accuracy"]:.4f}',
            "解释": "平衡正负样本上的成对分类准确率",
        },
        {
            "指标": "B³ F1（直接分组）",
            "Standard RSP": f'{std["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}',
            "解释": "设备聚类的精确率与召回率综合指标",
        },
        {
            "指标": "ARI（直接分组）",
            "Standard RSP": f'{std["direct_stable_grouping"]["adjusted_rand_index"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["adjusted_rand_index"]:.4f}',
            "解释": "校正随机一致性的聚类评价指标",
        },
        {
            "指标": "完整设备簇恢复率",
            "Standard RSP": f'{std["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}',
            "解释": "全部 Profile 被正确归入且无其他事务混入的设备比例",
        },
        {
            "指标": "跨 Profile 直接关联率",
            "Standard RSP": f'{std["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}',
            "解释": "同设备不同 MNO/Profile 事务被稳定标识直接归并的比例",
        },
    ]
    rows_en = [
        {
            "Metric": "Pairwise ROC-AUC",
            "Standard RSP": f'{std["pairwise_classifier"]["roc_auc"]:.4f}',
            "AURA-RSP": f'{aura["pairwise_classifier"]["roc_auc"]:.4f}',
            "Interpretation": "Ability to distinguish same-device from different-device transaction pairs",
        },
        {
            "Metric": "Pairwise accuracy",
            "Standard RSP": f'{std["pairwise_classifier"]["pairwise_accuracy"]:.4f}',
            "AURA-RSP": f'{aura["pairwise_classifier"]["pairwise_accuracy"]:.4f}',
            "Interpretation": "Accuracy on a balanced positive/negative pair set",
        },
        {
            "Metric": "Direct-clustering B³ F1",
            "Standard RSP": f'{std["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}',
            "Interpretation": "Harmonic mean of device-cluster precision and recall",
        },
        {
            "Metric": "Direct-clustering ARI",
            "Standard RSP": f'{std["direct_stable_grouping"]["adjusted_rand_index"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["adjusted_rand_index"]:.4f}',
            "Interpretation": "Clustering agreement corrected for chance",
        },
        {
            "Metric": "Exact device recovery",
            "Standard RSP": f'{std["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}',
            "Interpretation": "Devices whose profiles are recovered as one pure and complete cluster",
        },
        {
            "Metric": "Cross-profile direct link",
            "Standard RSP": f'{std["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}',
            "AURA-RSP": f'{aura["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}',
            "Interpretation": "Same-device cross-MNO/profile pairs linked by repeated visible identifiers",
        },
    ]
    write_csv(paper_dir / "table-1-linkability-results-zh.csv", rows_zh)
    write_csv(paper_dir / "table-1-linkability-results-en.csv", rows_en)
    markdown_zh = [
        "| 指标 | Standard RSP | AURA-RSP |",
        "|---|---:|---:|",
    ]
    markdown_zh.extend(
        f'| {row["指标"]} | {row["Standard RSP"]} | {row["AURA-RSP"]} |'
        for row in rows_zh
    )
    markdown_en = [
        "| Metric | Standard RSP | AURA-RSP |",
        "|---|---:|---:|",
    ]
    markdown_en.extend(
        f'| {row["Metric"]} | {row["Standard RSP"]} | {row["AURA-RSP"]} |'
        for row in rows_en
    )
    (paper_dir / "table-1-linkability-results-zh.md").write_text(
        "\n".join(markdown_zh) + "\n",
        encoding="utf-8",
    )
    (paper_dir / "table-1-linkability-results-en.md").write_text(
        "\n".join(markdown_en) + "\n",
        encoding="utf-8",
    )
    caption_zh = f"""图1 共享 SM-DP+ 跨 Profile 关联能力对比。实验包含 {report["design"]["device_count"]} 个模拟 eUICC，每个 eUICC 分别从 {report["design"]["profiles_per_device"]} 个 MNO 获取独立 Profile。Standard RSP 的稳定 EID、eUICC 证书及公钥使跨 Profile 关联和设备簇恢复率均达到 1；AURA-RSP 逐事务更新票据、nullifier、临时密钥和绑定材料，未形成可直接复用的设备标识。

图2 Standard RSP 与 AURA-RSP 的成对关联 ROC 曲线。Standard RSP 的 ROC-AUC 为 {std["pairwise_classifier"]["roc_auc"]:.3f}，共享 SM-DP+ 可准确关联同一 eUICC 的跨 MNO/Profile 事务；AURA-RSP 的 ROC-AUC 为 {aura["pairwise_classifier"]["roc_auc"]:.3f}，接近随机猜测基线 0.5，表明受控公开转录中未观察到有效的跨 Profile 设备关联信号。

表1 共享 SM-DP+ 跨 Profile 关联实验结果。AURA-RSP 的 ROC-AUC 接近而非必须等于 0.5；偏差来自有限样本和固定随机种子。该实验验证协议可见字段的不可链接性，不覆盖 PR 与 SM-DP+ 合谋、入口/出口流量同时观测或终端秘密泄露。
"""
    caption_en = f"""Figure 1. Cross-profile linkability at a shared SM-DP+. The experiment includes {report["design"]["device_count"]} simulated eUICCs, each obtaining an independent profile from {report["design"]["profiles_per_device"]} MNOs. Stable EID, eUICC-certificate, and public-key values make Standard RSP fully linkable across profiles. AURA-RSP refreshes the ticket, nullifier, temporary key, and binding material for each transaction and exposes no directly reusable device identifier.

Figure 2. Pairwise cross-profile linkability ROC curves. Standard RSP achieves an ROC-AUC of {std["pairwise_classifier"]["roc_auc"]:.3f}, allowing the shared SM-DP+ to link transactions belonging to the same eUICC. AURA-RSP achieves an ROC-AUC of {aura["pairwise_classifier"]["roc_auc"]:.3f}, close to the random-guess baseline of 0.5, indicating that no effective cross-profile device-linking signal was observed in the controlled public transcripts.

Table 1. Shared SM-DP+ cross-profile linkability results. The AURA-RSP ROC-AUC is expected to be near, rather than exactly equal to, 0.5 because of finite-sample variation under a fixed random seed. The experiment evaluates unlinkability of protocol-visible fields; it does not cover PR/SM-DP+ collusion, simultaneous observation of ingress and egress traffic, or compromise of endpoint secrets.
"""
    (paper_dir / "captions-and-analysis-zh.txt").write_text(
        caption_zh,
        encoding="utf-8",
    )
    (paper_dir / "captions-and-analysis-en.txt").write_text(
        caption_en,
        encoding="utf-8",
    )


def print_human_summary(
    report: dict[str, Any],
    output: Path,
    language: str,
) -> None:
    text = LANG[language]
    std = report["modes"]["standard_rsp"]
    aura = report["modes"]["aura_rsp"]
    rows = [
        (
            text["pair_auc"],
            std["pairwise_classifier"]["roc_auc"],
            aura["pairwise_classifier"]["roc_auc"],
        ),
        (
            text["pair_accuracy"],
            std["pairwise_classifier"]["pairwise_accuracy"],
            aura["pairwise_classifier"]["pairwise_accuracy"],
        ),
        (
            text["cluster_b3"],
            std["direct_stable_grouping"]["cluster_accuracy_b3_f1"],
            aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"],
        ),
        (
            text["cluster_ari"],
            std["direct_stable_grouping"]["adjusted_rand_index"],
            aura["direct_stable_grouping"]["adjusted_rand_index"],
        ),
        (
            text["exact_recovery"],
            std["direct_stable_grouping"]["exact_device_recovery_rate"],
            aura["direct_stable_grouping"]["exact_device_recovery_rate"],
        ),
        (
            text["cross_profile"],
            std["direct_stable_grouping"]["cross_profile_link_rate"],
            aura["direct_stable_grouping"]["cross_profile_link_rate"],
        ),
    ]
    line = "=" * 86
    print()
    print(line)
    print(text["experiment_title"])
    print(
        f'{text["status"]}: [{report["status"]}]    '
        f'{text["scale"]}: {report["design"]["device_count"]} {text["device_unit"]} × '
        f'{report["design"]["profiles_per_device"]} {text["mno_unit"]} = '
        f'{report["design"]["transaction_count_per_mode"]} {text["transactions"]}'
    )
    print(line)
    metric_heading = "指标" if language == "zh" else "Metric"
    print(f'{display_ljust(metric_heading, 44)} {"Standard RSP":>19} {"AURA-RSP":>19}')
    print("-" * 86)
    for name, std_value, aura_value in rows:
        print(
            f"{display_ljust(name, 44)} "
            f"{std_value:>19.4f} {aura_value:>19.4f}"
        )
    print("-" * 86)
    print(f'{text["conclusion"]}:')
    print(f'  {text["standard_conclusion"]}')
    print(f'  {text["aura_conclusion"]}')
    print(f'{text["paper_output"]}: {output / "paper"}')
    print(f'{text["full_result"]}: {output / "summary.md"}')
    print(line)


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


def analyze_mode(
    mode: str,
    records: list[dict[str, Any]],
    truth_by_tx: dict[str, str],
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str], dict[str, str]]:
    pairs = build_balanced_pairs(
        records,
        truth_by_tx,
        int(config["seed"]) + (1 if mode == "standard_rsp" else 2),
    )
    classifier, predictions, model = cross_validated_classifier(
        pairs,
        int(config["pair_cv_folds"]),
        int(config["seed"]) + (11 if mode == "standard_rsp" else 12),
    )
    direct = direct_clusters(records, mode)
    learned = learned_clusters(records, model)
    result = {
        "protocol_mode": mode,
        "transaction_count": len(records),
        "device_count": int(config["device_count"]),
        "profiles_per_device": len(config["mnos"]),
        "direct_stable_grouping": cluster_metrics(records, truth_by_tx, direct),
        "pairwise_classifier": classifier,
        "learned_connected_components": cluster_metrics(records, truth_by_tx, learned),
        "stable_identifier_groups": stable_identifier_groups(records, mode),
    }
    return result, predictions, direct, learned


def prepare_output(path: Path, experiment_root: Path) -> None:
    resolved = path.resolve()
    safe_parent = (experiment_root / "results").resolve()
    if resolved == safe_parent or safe_parent not in resolved.parents:
        raise ValueError(f"refusing to reset output outside {safe_parent}: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    (resolved / "raw").mkdir(parents=True)
    (resolved / "analysis").mkdir(parents=True)
    (resolved / "graphs").mkdir(parents=True)
    (resolved / "paper").mkdir(parents=True)


def summary_markdown(report: dict[str, Any]) -> str:
    std = report["modes"]["standard_rsp"]
    aura = report["modes"]["aura_rsp"]
    return f"""# 实验1：共享 SM-DP+ 跨 Profile 关联

状态：**{report["status"]}**

本结果来自受控协议可见转录实验，不代表执行了 {report["design"]["transaction_count_per_mode"]} 次完整网络下载。分类器没有读取真实设备标签；真实标签只在评估阶段使用。

| 指标 | Standard RSP | AURA-RSP |
|---|---:|---:|
| 事务数 | {std["transaction_count"]} | {aura["transaction_count"]} |
| Pairwise ROC-AUC | {std["pairwise_classifier"]["roc_auc"]:.3f} | {aura["pairwise_classifier"]["roc_auc"]:.3f} |
| Pairwise accuracy | {std["pairwise_classifier"]["pairwise_accuracy"]:.3f} | {aura["pairwise_classifier"]["pairwise_accuracy"]:.3f} |
| 直接分组 B³ F1 | {std["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.3f} | {aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.3f} |
| 直接分组 ARI | {std["direct_stable_grouping"]["adjusted_rand_index"]:.3f} | {aura["direct_stable_grouping"]["adjusted_rand_index"]:.3f} |
| 完整设备簇恢复率 | {std["direct_stable_grouping"]["exact_device_recovery_rate"]:.3f} | {aura["direct_stable_grouping"]["exact_device_recovery_rate"]:.3f} |
| 跨 Profile 直接关联率 | {std["direct_stable_grouping"]["cross_profile_link_rate"]:.3f} | {aura["direct_stable_grouping"]["cross_profile_link_rate"]:.3f} |
| 学习式聚类 B³ F1 | {std["learned_connected_components"]["cluster_accuracy_b3_f1"]:.3f} | {aura["learned_connected_components"]["cluster_accuracy_b3_f1"]:.3f} |
| 学习式聚类 ARI | {std["learned_connected_components"]["adjusted_rand_index"]:.3f} | {aura["learned_connected_components"]["adjusted_rand_index"]:.3f} |

## 解释

- Standard RSP 的共享 SM-DP+ 正常收到稳定 EID、eUICC 证书和证书公钥，因此无需篡改协议即可将不同 MNO、订单和 Profile 归并到同一硬件设备。
- AURA-RSP 的实验输入中，每个订单使用不同 `I_ac/pid_h/nu/lph/opid/vk_t`、证明摘要、`Bind_t` 摘要和会话公钥；分类器只能利用时间等受控公开特征。
- AURA 的期望是 ROC-AUC 接近 0.5，而不是固定等于 0.5。该数值是本次真实训练/交叉验证的输出。
- 这证明的是当前威胁模型下的协议字段不可链接性，不覆盖 PR 与 SM-DP+ 合谋、入口出口流量同时观测、终端秘密泄露或 MNO 主动植入额外标识。

## 论文可用产物

- `paper/figure-1-linkability-metrics-zh.svg` / `-en.svg`：中英文关键指标图。
- `paper/figure-2-roc-curve-zh.svg` / `-en.svg`：中英文 ROC 曲线。
- `paper/table-1-linkability-results-zh.csv` / `-en.csv`：中英文结果表。
- `paper/table-1-linkability-results-zh.md` / `-en.md`：中英文 Markdown 表。
- `paper/captions-and-analysis-zh.txt` / `-en.txt`：中英文图题、表题和边界说明。
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--devices", type=int, help="override device_count")
    parser.add_argument(
        "--machine-json",
        action="store_true",
        help="print only the compact machine-readable JSON result",
    )
    parser.add_argument(
        "--lang",
        choices=("zh", "en", "both"),
        default="both",
        help="human-readable terminal language; default: both",
    )
    args = parser.parse_args()

    started = time.perf_counter()
    config_path = args.config.resolve()
    experiment_root = Path(__file__).resolve().parent
    config = load_config(config_path)
    if args.devices is not None:
        config["device_count"] = args.devices
    profile = resolved_profile(config_path, config)
    prepare_output(args.output, experiment_root)
    output = args.output.resolve()

    standard, aura, truth = generate_dataset(config, profile)
    standard_again, aura_again, truth_again = generate_dataset(config, profile)
    reproducible = (
        sha256_records(standard) == sha256_records(standard_again)
        and sha256_records(aura) == sha256_records(aura_again)
        and sha256_records(truth) == sha256_records(truth_again)
    )

    public_fields = set().union(*(row.keys() for row in standard + aura))
    if "true_device_id" in public_fields:
        raise RuntimeError("ground-truth label leaked into public transcript")

    write_jsonl(output / "raw" / "standard_smdpp_view.jsonl", standard)
    write_jsonl(output / "raw" / "aura_smdpp_view.jsonl", aura)
    write_jsonl(output / "raw" / "ground_truth.jsonl", truth)
    write_csv(output / "raw" / "standard_smdpp_view.csv", standard)
    write_csv(output / "raw" / "aura_smdpp_view.csv", aura)
    write_csv(output / "raw" / "ground_truth.csv", truth)

    truth_by_mode: dict[str, dict[str, str]] = defaultdict(dict)
    for row in truth:
        truth_by_mode[row["protocol_mode"]][row["transaction_id"]] = row["true_device_id"]

    standard_result, std_predictions, std_direct, std_learned = analyze_mode(
        "standard_rsp",
        standard,
        truth_by_mode["standard_rsp"],
        config,
    )
    aura_result, aura_predictions, aura_direct, aura_learned = analyze_mode(
        "aura_rsp",
        aura,
        truth_by_mode["aura_rsp"],
        config,
    )
    for mode, predictions in (
        ("standard_rsp", std_predictions),
        ("aura_rsp", aura_predictions),
    ):
        write_csv(output / "analysis" / f"{mode}_pair_predictions.csv", predictions)
        write_jsonl(output / "analysis" / f"{mode}_pair_predictions.jsonl", predictions)

    assignment_rows = []
    for mode, records, direct_map, learned_map in (
        ("standard_rsp", standard, std_direct, std_learned),
        ("aura_rsp", aura, aura_direct, aura_learned),
    ):
        for row in records:
            assignment_rows.append(
                {
                    "protocol_mode": mode,
                    "transaction_id": row["transaction_id"],
                    "direct_cluster": direct_map[row["transaction_id"]],
                    "learned_cluster": learned_map[row["transaction_id"]],
                }
            )
    write_csv(output / "analysis" / "cluster_assignments.csv", assignment_rows)

    write_dot_and_svg(
        output / "graphs",
        "standard_rsp",
        standard,
        truth_by_mode["standard_rsp"],
        int(config["graph_device_limit"]),
    )
    write_dot_and_svg(
        output / "graphs",
        "aura_rsp",
        aura,
        truth_by_mode["aura_rsp"],
        int(config["graph_device_limit"]),
    )

    assertions: list[dict[str, Any]] = []
    expected_transactions = int(config["device_count"]) * len(config["mnos"])
    assertion(
        assertions,
        "transaction_count_per_mode",
        len(standard) == len(aura) == expected_transactions,
        {"standard": len(standard), "aura": len(aura)},
        f"both equal {expected_transactions}",
    )
    assertion(
        assertions,
        "generator_reproducible",
        reproducible,
        reproducible,
        "true",
    )
    assertion(
        assertions,
        "ground_truth_not_in_public_transcripts",
        "true_device_id" not in public_fields
        and "logical_download_id" not in public_fields,
        sorted(public_fields),
        "true_device_id and logical_download_id absent",
    )
    assertion(
        assertions,
        "all_orders_accounts_profiles_unique",
        all(
            len({row[field] for row in records}) == expected_transactions
            for records in (standard, aura)
            for field in ("order_id", "test_account_id", "profile_id", "profile_hash")
        ),
        True,
        "all unique in both modes",
    )
    assertion(
        assertions,
        "same_controlled_timing_size_and_egress",
        all(
            (
                std["timestamp_unix"],
                std["profile_size"],
                std["network_egress"],
            )
            == (
                aur["timestamp_unix"],
                aur["profile_size"],
                aur["network_egress"],
            )
            for std, aur in zip(
                sorted(standard, key=lambda row: row["order_id"]),
                sorted(aura, key=lambda row: row["order_id"]),
            )
        ),
        True,
        "matched across modes",
    )
    repeats = len(config["mnos"])
    standard_repeat_ok = all(
        all(count == repeats for count in Counter(row[field] for row in standard).values())
        for field in STANDARD_STABLE_FIELDS
    )
    assertion(
        assertions,
        "standard_stable_identifiers_repeat_per_device",
        standard_repeat_ok,
        standard_repeat_ok,
        f"each stable identifier appears {repeats} times",
    )
    aura_unique = {
        field: len({row[field] for row in aura}) for field in AURA_PER_TRANSACTION_FIELDS
    }
    assertion(
        assertions,
        "aura_transaction_fields_are_fresh",
        all(value == expected_transactions for value in aura_unique.values()),
        aura_unique,
        f"each field has {expected_transactions} unique values",
    )
    limits = config["assertions"]
    assertion(
        assertions,
        "standard_pairwise_auc_near_one",
        standard_result["pairwise_classifier"]["roc_auc"]
        >= float(limits["standard_min_roc_auc"]),
        standard_result["pairwise_classifier"]["roc_auc"],
        f'>= {limits["standard_min_roc_auc"]}',
    )
    aura_auc = aura_result["pairwise_classifier"]["roc_auc"]
    assertion(
        assertions,
        "aura_pairwise_auc_near_random",
        float(limits["aura_min_roc_auc"])
        <= aura_auc
        <= float(limits["aura_max_roc_auc"]),
        aura_auc,
        f'between {limits["aura_min_roc_auc"]} and {limits["aura_max_roc_auc"]}',
    )
    assertion(
        assertions,
        "standard_direct_clusters_recover_devices",
        standard_result["direct_stable_grouping"]["exact_device_recovery_rate"]
        >= float(limits["standard_min_exact_device_recovery"]),
        standard_result["direct_stable_grouping"]["exact_device_recovery_rate"],
        f'>= {limits["standard_min_exact_device_recovery"]}',
    )
    assertion(
        assertions,
        "aura_no_direct_cross_profile_link",
        aura_result["direct_stable_grouping"]["cross_profile_link_rate"]
        <= float(limits["aura_max_direct_cross_profile_link_rate"]),
        aura_result["direct_stable_grouping"]["cross_profile_link_rate"],
        f'<= {limits["aura_max_direct_cross_profile_link_rate"]}',
    )

    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    report = {
        "experiment": config["experiment_name"],
        "status": status,
        "method": "controlled_protocol_visible_transcript_experiment",
        "design": {
            "seed": config["seed"],
            "device_count": config["device_count"],
            "mnos": config["mnos"],
            "profiles_per_device": len(config["mnos"]),
            "transaction_count_per_mode": expected_transactions,
            "complete_network_downloads_executed": False,
            "classifier": "from-scratch pairwise logistic regression with stratified cross-validation",
            "pair_scope": "cross-MNO pairs only, balanced positive and negative classes",
            "profile_source_sha256": hashlib.sha256(profile).hexdigest(),
            "profile_bytes": len(profile),
            "same_network_egress": config["shared_network_egress"],
        },
        "reproducibility_hashes": {
            "standard_public_transcript_sha256": sha256_records(standard),
            "aura_public_transcript_sha256": sha256_records(aura),
            "ground_truth_sha256": sha256_records(truth),
        },
        "modes": {
            "standard_rsp": standard_result,
            "aura_rsp": aura_result,
        },
        "assertions": assertions,
        "execution_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    (output / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    flat_rows = []
    for mode in ("standard_rsp", "aura_rsp"):
        result = report["modes"][mode]
        flat_rows.append(
            {
                "protocol_mode": mode,
                "transactions": result["transaction_count"],
                "roc_auc": result["pairwise_classifier"]["roc_auc"],
                "pairwise_accuracy": result["pairwise_classifier"]["pairwise_accuracy"],
                "balanced_accuracy": result["pairwise_classifier"]["balanced_accuracy"],
                "direct_cluster_b3_f1": result["direct_stable_grouping"]["cluster_accuracy_b3_f1"],
                "direct_cluster_ari": result["direct_stable_grouping"]["adjusted_rand_index"],
                "exact_device_recovery_rate": result["direct_stable_grouping"]["exact_device_recovery_rate"],
                "direct_cross_profile_link_rate": result["direct_stable_grouping"]["cross_profile_link_rate"],
                "direct_false_link_rate": result["direct_stable_grouping"]["false_link_rate"],
            }
        )
    write_csv(output / "summary.csv", flat_rows)
    (output / "summary.md").write_text(summary_markdown(report), encoding="utf-8")
    write_paper_artifacts(output, report, std_predictions, aura_predictions)

    machine_result = {
        "status": status,
        "standard_roc_auc": standard_result["pairwise_classifier"]["roc_auc"],
        "aura_roc_auc": aura_result["pairwise_classifier"]["roc_auc"],
        "standard_exact_device_recovery": standard_result["direct_stable_grouping"]["exact_device_recovery_rate"],
        "aura_direct_cross_profile_link_rate": aura_result["direct_stable_grouping"]["cross_profile_link_rate"],
        "results": str(output),
    }
    if args.machine_json:
        print(canonical_json(machine_result))
    else:
        languages = ("zh", "en") if args.lang == "both" else (args.lang,)
        for language in languages:
            print_human_summary(report, output, language)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
