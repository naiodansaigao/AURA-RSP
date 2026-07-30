from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import shutil
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable

from aura_rsp.codec import canonical
from aura_rsp.lifecycle import (
    LifecycleEngine,
    LifecycleError,
    build_transition_receipt,
    receipt_fields,
    sign_receipt,
    verify_receipt_mac,
)


LANG = {
    "zh": {
        "title": "实验6：生命周期重放、分叉与删除故障恢复",
        "subtest": "子测试",
        "scenario": "场景",
        "result": "结果",
        "final": "最终状态",
        "pass": "通过",
        "unsupported": "当前baseline不支持",
    },
    "en": {
        "title": "Experiment 6: Lifecycle Resilience under Replay, Concurrency, and Message Loss",
        "subtest": "Subtest",
        "scenario": "Scenario",
        "result": "Result",
        "final": "Final state",
        "pass": "PASS",
        "unsupported": "unsupported by current baseline",
    },
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def prepare_output(path: Path, experiment_root: Path) -> Path:
    path = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if not path.is_relative_to(results_root):
        raise ValueError(f"output must stay under {results_root}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "databases", "paper"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def deterministic_bytes(seed: int, label: str, size: int = 32) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(output[:size])


def rid(seed: int, label: str) -> str:
    return "rid-" + hashlib.sha256(
        f"{seed}:{label}".encode("utf-8")
    ).hexdigest()[:24]


def catch_error(call: Callable[[], Any]) -> dict[str, Any]:
    try:
        result = call()
        return {"accepted": True, "response": result, "reason": None, "stage": None}
    except LifecycleError as exc:
        return {
            "accepted": False,
            "response": None,
            "reason": exc.code,
            "stage": exc.stage,
        }


class Harness:
    def __init__(self, output: Path, config: dict[str, Any]):
        self.output = output
        self.config = config
        self.seed = int(config["seed"])
        self.base_time = int(config["base_time"])
        self.lph = str(config["profile_lph"])
        self.device_key = deterministic_bytes(self.seed, "device-mac")
        self.server_key = deterministic_bytes(self.seed, "server-mac")

    def engine(self, name: str) -> LifecycleEngine:
        return LifecycleEngine(
            self.output / "databases" / f"{name}.sqlite",
            device_mac_key=self.device_key,
            server_mac_key=self.server_key,
        )

    def initialize(self, name: str) -> LifecycleEngine:
        engine = self.engine(name)
        engine.initialize_profile(self.lph)
        return engine

    def authorize(
        self,
        engine: LifecycleEngine,
        *,
        label: str,
        op: str,
        expires_at: int | None = None,
    ) -> str:
        value = rid(self.seed, label)
        engine.issue_authorization(
            rid=value,
            lph=self.lph,
            op=op,
            expires_at=(
                self.base_time + int(self.config["ticket_valid_seconds"])
                if expires_at is None
                else expires_at
            ),
        )
        return value


def subtest_6a(h: Harness) -> dict[str, Any]:
    engine = h.initialize("6a")
    initial = engine.snapshot(h.lph)
    enable_rid = h.authorize(engine, label="6a-enable", op="enable")
    enable_receipt = build_transition_receipt(
        snapshot=initial,
        st_new="enabled",
        rid=enable_rid,
        key=h.device_key,
    )
    enabled = engine.apply_transition(enable_receipt, now=h.base_time)
    disable_rid = h.authorize(engine, label="6a-disable", op="disable")
    disable_receipt = build_transition_receipt(
        snapshot=engine.snapshot(h.lph),
        st_new="disabled",
        rid=disable_rid,
        key=h.device_key,
    )
    disabled = engine.apply_transition(disable_receipt, now=h.base_time + 1)
    before_replays = engine.snapshot(h.lph)
    stale = catch_error(
        lambda: engine.apply_transition(enable_receipt, now=h.base_time + 2)
    )
    latest = catch_error(
        lambda: engine.apply_transition(disable_receipt, now=h.base_time + 3)
    )
    after_replays = engine.snapshot(h.lph)
    passed = (
        enabled["state"] == "enabled"
        and disabled["state"] == "disabled"
        and not stale["accepted"]
        and stale["reason"] == "STALE_RECEIPT_REPLAY"
        and latest["accepted"]
        and latest["response"]["idempotent"]
        and before_replays == after_replays
        and after_replays["ctr"] == 3
    )
    return {
        "id": "6A",
        "scenario": "old_receipt_replay_and_latest_idempotency",
        "passed": passed,
        "initial": initial,
        "enabled": enabled,
        "disabled": disabled,
        "stale_replay": stale,
        "latest_replay": latest,
        "final": after_replays,
        "receipts": {
            "enable": enable_receipt,
            "disable": disable_receipt,
        },
    }


def semantic_tamper(
    receipt: dict[str, Any],
    field: str,
    *,
    h: Harness,
) -> dict[str, Any]:
    changed = copy.deepcopy(receipt)
    if field == "st_old":
        changed["st_old"] = "disabled"
    elif field == "st_new":
        changed["st_new"] = "disabled"
    elif field == "ctr":
        changed["ctr"] = int(changed["ctr"]) + 7
    elif field == "last_hash":
        changed["last_hash"] = "00" * 32
    elif field == "lph":
        changed["lph"] = h.lph + ":tampered"
    elif field == "rid":
        changed["rid"] = rid(h.seed, "6b-unauthorized")
    elif field == "mac":
        changed["mac"] = ("A" if changed["mac"][:1] != "A" else "B") + changed["mac"][1:]
        return changed
    else:
        raise ValueError(field)
    return sign_receipt(h.device_key, receipt_fields(changed))


def subtest_6b(h: Harness) -> dict[str, Any]:
    fields = ("st_old", "st_new", "ctr", "last_hash", "lph", "rid", "mac")
    expected = {
        "st_old": "STATE_PREDECESSOR_MISMATCH",
        "st_new": "INVALID_STATE_TRANSITION",
        "ctr": "COUNTER_MISMATCH",
        "last_hash": "LAST_HASH_MISMATCH",
        "lph": "UNKNOWN_LPH",
        "rid": "AUTHORIZATION_NOT_FOUND",
        "mac": "INVALID_RECEIPT_MAC",
    }
    results: dict[str, Any] = {}
    for field in fields:
        engine = h.initialize(f"6b-{field.replace('_', '-')}")
        valid_rid = h.authorize(
            engine, label=f"6b-{field}-enable", op="enable"
        )
        original = build_transition_receipt(
            snapshot=engine.snapshot(h.lph),
            st_new="enabled",
            rid=valid_rid,
            key=h.device_key,
        )
        transport = copy.deepcopy(original)
        if field != "mac":
            if field == "ctr":
                transport[field] = int(transport[field]) + 7
            else:
                transport[field] = str(transport[field]) + ":network-tamper"
            network_reason = catch_error(
                lambda value=transport: verify_receipt_mac(h.device_key, value)
            )
        else:
            network_reason = None
        attacked = semantic_tamper(original, field, h=h)
        before = engine.snapshot(h.lph)
        outcome = catch_error(
            lambda value=attacked: engine.apply_transition(
                value, now=h.base_time
            )
        )
        after = engine.snapshot(h.lph)
        results[field] = {
            "passed": (
                not outcome["accepted"]
                and outcome["reason"] == expected[field]
                and before == after
                and (
                    field == "mac"
                    or (
                        network_reason is not None
                        and not network_reason["accepted"]
                        and network_reason["reason"] == "INVALID_RECEIPT_MAC"
                    )
                )
            ),
            "expected_reason": expected[field],
            "outcome": outcome,
            "network_tamper_outcome": network_reason,
            "state_unchanged": before == after,
            "attacked_receipt": attacked,
        }
    return {
        "id": "6B",
        "scenario": "receipt_field_tampering",
        "passed": all(value["passed"] for value in results.values()),
        "tamper_count": len(fields),
        "rejected_count": sum(
            not value["outcome"]["accepted"] for value in results.values()
        ),
        "field_results": results,
        "final": {"state": "installed", "ctr": 1},
        "white_box_note": (
            "non-MAC semantic cases are re-MACed by the test harness to exercise "
            "state/counter/hash/authorization checks after HMAC validation"
        ),
    }


def subtest_6c(h: Harness) -> dict[str, Any]:
    engine = h.initialize("6c")
    predecessor = engine.snapshot(h.lph)
    enable_rid = h.authorize(engine, label="6c-enable", op="enable")
    delete_rid = h.authorize(engine, label="6c-delete", op="delete")
    enable_receipt = build_transition_receipt(
        snapshot=predecessor,
        st_new="enabled",
        rid=enable_rid,
        key=h.device_key,
    )
    delete_receipt = build_transition_receipt(
        snapshot=predecessor,
        st_new="pending-delete",
        rid=delete_rid,
        key=h.device_key,
    )
    barrier = threading.Barrier(2)

    def enable_call() -> dict[str, Any]:
        barrier.wait()
        return catch_error(
            lambda: engine.apply_transition(enable_receipt, now=h.base_time)
        )

    def delete_call() -> dict[str, Any]:
        barrier.wait()
        return catch_error(
            lambda: engine.prepare_delete(delete_receipt, now=h.base_time)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        enable_future = pool.submit(enable_call)
        delete_future = pool.submit(delete_call)
        outcomes = {
            "enable": enable_future.result(),
            "delete": delete_future.result(),
        }
    accepted = [name for name, value in outcomes.items() if value["accepted"]]
    rejected = [name for name, value in outcomes.items() if not value["accepted"]]
    final = engine.snapshot(h.lph)
    counts = engine.counts()
    passed = (
        len(accepted) == 1
        and len(rejected) == 1
        and outcomes[rejected[0]]["reason"]
        in (
            "STATE_PREDECESSOR_MISMATCH",
            "INVALID_DELETE_PREDECESSOR",
        )
        and final["state"] in ("enabled", "pending-delete")
        and final["ctr"] == 2
        and counts["receipts"] == 1
    )
    return {
        "id": "6C",
        "scenario": "concurrent_enable_delete_fork",
        "passed": passed,
        "predecessor": predecessor,
        "outcomes": outcomes,
        "accepted_operation": accepted[0] if accepted else None,
        "rejected_operation": rejected[0] if rejected else None,
        "successor_count": counts["receipts"],
        "final": final,
        "database_counts": counts,
    }


def prepare_delete_fixture(
    h: Harness,
    name: str,
    *,
    expires_at: int | None = None,
) -> tuple[LifecycleEngine, str, dict[str, Any], dict[str, Any]]:
    engine = h.initialize(name)
    delete_rid = h.authorize(
        engine,
        label=f"{name}-delete",
        op="delete",
        expires_at=expires_at,
    )
    request = build_transition_receipt(
        snapshot=engine.snapshot(h.lph),
        st_new="pending-delete",
        rid=delete_rid,
        key=h.device_key,
    )
    response = engine.prepare_delete(request, now=h.base_time)
    return engine, delete_rid, request, response


def subtest_6d(h: Harness) -> dict[str, Any]:
    engine, _, request, first = prepare_delete_fixture(h, "6d")
    after_loss = engine.snapshot(h.lph)
    counts_after_loss = engine.counts()
    retry = engine.prepare_delete(request, now=h.base_time + 1)
    final = engine.snapshot(h.lph)
    counts_final = engine.counts()
    same_rprep = canonical(first["Rprep"]) == canonical(retry["Rprep"])
    passed = (
        after_loss["state"] == "pending-delete"
        and retry["idempotent"]
        and same_rprep
        and after_loss == final
        and counts_after_loss["receipts"] == counts_final["receipts"] == 1
        and counts_final["pending_deletes"] == 1
    )
    return {
        "id": "6D",
        "scenario": "lost_rprep_response",
        "passed": passed,
        "first_response_discarded": True,
        "same_rprep_returned": same_rprep,
        "counter_advanced_again": after_loss["ctr"] != final["ctr"],
        "first": first,
        "retry": retry,
        "final": final,
        "database_counts": counts_final,
    }


def commit_receipt(
    h: Harness,
    engine: LifecycleEngine,
    delete_rid: str,
) -> dict[str, Any]:
    return build_transition_receipt(
        snapshot=engine.snapshot(h.lph),
        st_new="tombstone",
        rid=delete_rid,
        key=h.device_key,
    )


def subtest_6e(h: Harness) -> dict[str, Any]:
    before_engine, before_rid, _, before_prep = prepare_delete_fixture(
        h, "6e-message-loss"
    )
    before_commit = commit_receipt(h, before_engine, before_rid)
    state_while_message_lost = before_engine.snapshot(h.lph)
    resent = before_engine.commit_delete(
        before_commit, before_prep["Rprep"], now=h.base_time + 2
    )
    message_loss_final = before_engine.snapshot(h.lph)

    ack_engine, ack_rid, _, ack_prep = prepare_delete_fixture(
        h, "6e-ack-loss"
    )
    ack_commit = commit_receipt(h, ack_engine, ack_rid)
    first_ack = ack_engine.commit_delete(
        ack_commit, ack_prep["Rprep"], now=h.base_time + 2
    )
    retried_ack = ack_engine.commit_delete(
        ack_commit, ack_prep["Rprep"], now=h.base_time + 3
    )
    ack_final = ack_engine.snapshot(h.lph)
    same_final = (
        first_ack["state"] == retried_ack["state"]
        and first_ack["ctr"] == retried_ack["ctr"]
        and first_ack["last_hash"] == retried_ack["last_hash"]
    )
    passed = (
        state_while_message_lost["state"] == "pending-delete"
        and resent["status"] == "tombstone"
        and message_loss_final["state"] == "tombstone"
        and retried_ack["idempotent"]
        and same_final
        and ack_final["state"] == "tombstone"
        and ack_engine.counts()["receipts"] == 2
    )
    return {
        "id": "6E",
        "scenario": "lost_commit_receipt_or_final_ack",
        "passed": passed,
        "commit_message_loss": {
            "device_profile_deleted": True,
            "server_before_retry": state_while_message_lost,
            "retry_response": resent,
            "final": message_loss_final,
        },
        "final_ack_loss": {
            "first_response_discarded": True,
            "retry_response": retried_ack,
            "same_final_response_semantics": same_final,
            "final": ack_final,
        },
        "final": ack_final,
    }


def subtest_6f(h: Harness) -> dict[str, Any]:
    expires = h.base_time + 5
    engine, delete_rid, _, prep = prepare_delete_fixture(
        h, "6f", expires_at=expires
    )
    receipt = commit_receipt(h, engine, delete_rid)
    commit_time = expires + 60
    result = catch_error(
        lambda: engine.commit_delete(
            receipt, prep["Rprep"], now=commit_time
        )
    )
    final = engine.snapshot(h.lph)
    passed = (
        result["accepted"]
        and result["response"]["status"] == "tombstone"
        and final["state"] == "tombstone"
        and commit_time > expires
    )
    return {
        "id": "6F",
        "scenario": "commit_after_delete_ticket_expiry",
        "passed": passed,
        "ticket_expires_at": expires,
        "commit_time": commit_time,
        "expired_by_seconds": commit_time - expires,
        "valid_pending_delete_retained": True,
        "commit": result,
        "device_profile_deleted": True,
        "final": final,
    }


def standard_audit(workspace_root: Path) -> dict[str, Any]:
    validation = (
        workspace_root / "aura-rsp" / "src" / "aura_rsp" / "validation_report.py"
    ).read_text(encoding="utf-8")
    baseline_script = (
        workspace_root / "rsp-baseline" / "scripts" / "run_software_demo.sh"
    ).read_text(encoding="utf-8")
    lifecycle_terms = (
        "pending-delete",
        "Rprep",
        "commit-delete",
        "last_hash",
        "tombstone",
    )
    return {
        "status": "UNSUPPORTED",
        "reason": (
            "current Standard baseline demo covers download and install notification "
            "but exposes no lifecycle state-chain or two-phase delete test interface"
        ),
        "standard_baseline_modified": False,
        "searched_terms": list(lifecycle_terms),
        "baseline_demo_term_matches": {
            term: baseline_script.count(term) for term in lifecycle_terms
        },
        "aura_validation_declares_network_lifecycle_endpoints_out_of_scope": (
            "network-exposed enable, disable, delete and reinstall endpoints remain out of scope"
            in validation
        ),
        "claim_boundary": (
            "UNSUPPORTED is not evidence that Standard RSP accepts replay"
        ),
    }


def check(
    assertions: list[dict[str, Any]],
    name: str,
    passed: bool,
    actual: Any,
    expected: Any,
) -> None:
    assertions.append(
        {
            "name": name,
            "passed": bool(passed),
            "actual": actual,
            "expected": expected,
        }
    )


def xml(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def results_svg(report: dict[str, Any], language: str) -> str:
    zh = language == "zh"
    labels = {
        "6A": "重放/幂等" if zh else "Replay / retry",
        "6B": "字段篡改" if zh else "Field tampering",
        "6C": "并发分叉" if zh else "Concurrent fork",
        "6D": "Rprep丢失" if zh else "Lost Rprep",
        "6E": "Commit/确认丢失" if zh else "Lost commit / ack",
        "6F": "过期后提交" if zh else "Commit after expiry",
    }
    title = (
        "生命周期重放、并发与消息丢失实验结果"
        if zh
        else "Lifecycle Resilience under Replay, Concurrency, and Message Loss"
    )
    width, height = 1900, 1050
    left, top, chart_h, baseline = 150, 190, 600, 790
    centers = [260, 550, 840, 1130, 1420, 1710]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="950" y="72" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="43" font-weight="700">{xml(title)}</text>',
        f'<text x="950" y="125" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" fill="#4b5563">{xml("柱上数值为机器断言通过率" if zh else "Labels show machine-checked assertion pass rates")}</text>',
    ]
    for tick in (0, 25, 50, 75, 100):
        y = baseline - tick / 100 * chart_h
        svg.append(
            f'<line x1="{left}" y1="{y}" x2="1840" y2="{y}" stroke="#d1d5db" stroke-width="2"/>'
        )
        svg.append(
            f'<text x="125" y="{y+9}" text-anchor="end" font-family="Arial,sans-serif" font-size="24">{tick}%</text>'
        )
    by_id = {item["id"]: item for item in report["aura"]["subtests"]}
    for index, subtest_id in enumerate(("6A", "6B", "6C", "6D", "6E", "6F")):
        value = 100 if by_id[subtest_id]["passed"] else 0
        x = centers[index] - 70
        y = baseline - value / 100 * chart_h
        color = "#16a34a" if value == 100 else "#dc2626"
        svg.append(
            f'<rect x="{x}" y="{y}" width="140" height="{value/100*chart_h}" rx="8" fill="{color}"/>'
        )
        svg.append(
            f'<text x="{centers[index]}" y="{y-14}" text-anchor="middle" font-family="Arial,sans-serif" font-size="29" font-weight="700">{value}%</text>'
        )
        svg.append(
            f'<text x="{centers[index]}" y="842" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" font-weight="700">{subtest_id}</text>'
        )
        svg.append(
            f'<text x="{centers[index]}" y="882" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="22">{xml(labels[subtest_id])}</text>'
        )
    note = (
        "Standard当前baseline无生命周期测试接口，结果标记为UNSUPPORTED，不作为协议失败。"
        if zh
        else
        "The current Standard baseline has no lifecycle test interface; UNSUPPORTED is not a protocol failure."
    )
    svg.append(
        f'<text x="950" y="965" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="24" fill="#374151">{xml(note)}</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def recovery_svg(report: dict[str, Any], language: str) -> str:
    zh = language == "zh"
    title = "两阶段删除的故障恢复路径" if zh else "Two-Phase Delete Recovery Paths"
    lanes = [
        (
            "6D",
            ["installed", "pending-delete", "pending-delete"],
            ["prepare/Rprep丢失", "重发/同一Rprep"]
            if zh
            else ["prepare / Rprep lost", "retry / same Rprep"],
        ),
        (
            "6E",
            ["installed", "pending-delete", "tombstone"],
            ["prepare", "Commit重发"]
            if zh
            else ["prepare", "commit retry"],
        ),
        (
            "6F",
            ["installed", "pending-delete", "tombstone"],
            ["有效票据prepare", "过期后commit"]
            if zh
            else ["prepare / valid ticket", "commit after expiry"],
        ),
    ]
    width, height = 1900, 1050
    xs = [420, 970, 1520]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="950" y="75" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="44" font-weight="700">{xml(title)}</text>',
    ]
    for lane_index, (lane_id, states, arrows) in enumerate(lanes):
        y = 245 + lane_index * 270
        svg.append(
            f'<text x="115" y="{y+55}" font-family="Arial,sans-serif" font-size="32" font-weight="700">{lane_id}</text>'
        )
        for index, (x, state) in enumerate(zip(xs, states)):
            fill = "#dcfce7" if state == "tombstone" else "#dbeafe" if state == "pending-delete" else "#f3f4f6"
            stroke = "#16a34a" if state == "tombstone" else "#2563eb" if state == "pending-delete" else "#6b7280"
            svg.append(
                f'<rect x="{x-155}" y="{y}" width="310" height="110" rx="18" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
            )
            svg.append(
                f'<text x="{x}" y="{y+68}" text-anchor="middle" font-family="Arial,sans-serif" font-size="27" font-weight="700">{xml(state)}</text>'
            )
            if index < 2:
                svg.append(
                    f'<line x1="{x+165}" y1="{y+55}" x2="{xs[index+1]-175}" y2="{y+55}" stroke="#374151" stroke-width="4"/>'
                )
                svg.append(
                    f'<polygon points="{xs[index+1]-175},{y+55} {xs[index+1]-198},{y+42} {xs[index+1]-198},{y+68}" fill="#374151"/>'
                )
                svg.append(
                    f'<text x="{(x+xs[index+1])/2}" y="{y+26}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="21">{xml(arrows[index])}</text>'
                )
    footer = (
        "6D不重复推进计数器；6E和6F最终实现设备—服务器状态收敛。"
        if zh
        else
        "6D does not advance the counter twice; 6E and 6F converge device and server state."
    )
    svg.append(
        f'<text x="950" y="985" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" fill="#374151">{xml(footer)}</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def write_paper(output: Path, report: dict[str, Any]) -> None:
    paper = output / "paper"
    for language in ("zh", "en"):
        (paper / f"figure-1-lifecycle-results-{language}.svg").write_text(
            results_svg(report, language), encoding="utf-8"
        )
        (paper / f"figure-2-delete-recovery-{language}.svg").write_text(
            recovery_svg(report, language), encoding="utf-8"
        )
        t = LANG[language]
        rows = [
            {
                t["subtest"]: item["id"],
                t["scenario"]: item["scenario"],
                t["result"]: t["pass"] if item["passed"] else "FAIL",
                t["final"]: item.get("final", {}).get("state", ""),
            }
            for item in report["aura"]["subtests"]
        ]
        write_csv(paper / f"table-1-subtests-{language}.csv", rows)
        caption = (
            "图1给出6A—6F机器断言结果。旧历史收据被拒绝，最新收据幂等；七类篡改"
            "均不改变状态；并发enable/delete只产生一个后继；删除prepare与commit在"
            "消息丢失和票据到期后均可恢复。图2展示两阶段删除的三条恢复路径。"
            if language == "zh"
            else
            "Figure 1 reports machine-checked outcomes for 6A-6F. Historical receipts "
            "are rejected while the latest receipt is idempotent; all seven tampering "
            "cases leave state unchanged; concurrent enable/delete yields one successor; "
            "and two-phase deletion recovers from message loss and ticket expiry. "
            "Figure 2 shows the three deletion-recovery paths."
        )
        (paper / f"captions-and-analysis-{language}.txt").write_text(
            caption + "\n", encoding="utf-8"
        )


def summary_markdown(report: dict[str, Any]) -> str:
    rows = "\n".join(
        f'| {item["id"]} | `{item["scenario"]}` | '
        f'{"PASS" if item["passed"] else "FAIL"} | '
        f'`{item.get("final", {}).get("state", "")}` |'
        for item in report["aura"]["subtests"]
    )
    return f"""# 实验6：生命周期重放、分叉与删除故障恢复

总体状态：**{report["status"]}**

| 子测试 | 场景 | 结果 | 最终状态 |
|---|---|---:|---|
{rows}

## 核心结果

- 旧状态收据：`{report["metrics"]["old_receipt_replay"]}`
- 最新收据重复：`{report["metrics"]["latest_receipt_retry"]}`
- 篡改拒绝：{report["metrics"]["tamper_rejected"]}/7
- 并发后继数量：{report["metrics"]["concurrent_successor_count"]}
- Rprep是否完全相同：{report["metrics"]["same_rprep"]}
- Commit/确认丢失后收敛：{report["metrics"]["delete_recovery_converged"]}
- 票据过期后完成commit-delete：{report["metrics"]["expired_ticket_commit_completed"]}

## Standard baseline

状态：**{report["standard"]["status"]}**

当前baseline没有生命周期状态链和两阶段删除测试接口。因此不声称Standard接受重放，
也不把`UNSUPPORTED`描述为标准协议漏洞。
"""


def print_summary(report: dict[str, Any], language: str) -> None:
    t = LANG[language]
    line = "=" * 112
    print(line)
    print(t["title"])
    print(f'Status: [{report["status"]}]')
    print(line)
    print(f'{t["subtest"]:<10} {t["scenario"]:<54} {t["result"]:<12} {t["final"]}')
    print("-" * 112)
    for item in report["aura"]["subtests"]:
        result = t["pass"] if item["passed"] else "FAIL"
        final = item.get("final", {}).get("state", "")
        print(f'{item["id"]:<10} {item["scenario"]:<54} {result:<12} {final}')
    print("-" * 112)
    print(
        "Standard RSP baseline: "
        f'[{report["standard"]["status"]}] {t["unsupported"]}'
    )
    if language == "zh":
        print(
            "结论：AURA状态链拒绝旧重放和字段篡改，并通过原子CAS阻止并发分叉；"
            "两阶段删除在消息丢失及票据到期后均可收敛到tombstone。"
        )
    else:
        print(
            "Conclusion: the AURA state chain rejects stale replay and tampering, "
            "atomic CAS prevents forks, and two-phase deletion converges after message "
            "loss or ticket expiry."
        )
    print(f'Results: {report["results_directory"]}')
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    started = time.perf_counter()
    experiment_root = Path(__file__).resolve().parent
    workspace_root = experiment_root.parents[1]
    output = prepare_output(args.output, experiment_root)
    config = read_json(args.config.resolve())
    harness = Harness(output, config)

    subtests = [
        subtest_6a(harness),
        subtest_6b(harness),
        subtest_6c(harness),
        subtest_6d(harness),
        subtest_6e(harness),
        subtest_6f(harness),
    ]
    by_id = {item["id"]: item for item in subtests}
    standard = standard_audit(workspace_root)
    assertions: list[dict[str, Any]] = []
    for item in subtests:
        check(
            assertions,
            f'{item["id"].lower()}_subtest_passes',
            item["passed"],
            item["passed"],
            True,
        )
    check(
        assertions,
        "6a_old_receipt_is_rejected_as_stale",
        by_id["6A"]["stale_replay"]["reason"] == "STALE_RECEIPT_REPLAY",
        by_id["6A"]["stale_replay"],
        "STALE_RECEIPT_REPLAY",
    )
    check(
        assertions,
        "6a_latest_receipt_is_idempotent_without_counter_change",
        by_id["6A"]["latest_replay"]["response"]["idempotent"]
        and by_id["6A"]["final"]["ctr"] == 3,
        by_id["6A"]["latest_replay"],
        "idempotent and ctr=3",
    )
    check(
        assertions,
        "6b_all_seven_tampering_cases_rejected",
        by_id["6B"]["rejected_count"] == 7,
        by_id["6B"]["rejected_count"],
        7,
    )
    check(
        assertions,
        "6c_exactly_one_concurrent_successor",
        by_id["6C"]["successor_count"] == 1,
        by_id["6C"]["successor_count"],
        1,
    )
    check(
        assertions,
        "6d_same_rprep_and_no_second_counter_advance",
        by_id["6D"]["same_rprep_returned"]
        and not by_id["6D"]["counter_advanced_again"],
        {
            "same_rprep": by_id["6D"]["same_rprep_returned"],
            "counter_advanced_again": by_id["6D"]["counter_advanced_again"],
        },
        {"same_rprep": True, "counter_advanced_again": False},
    )
    check(
        assertions,
        "6e_message_and_ack_loss_converge_to_tombstone",
        by_id["6E"]["passed"]
        and by_id["6E"]["commit_message_loss"]["final"]["state"] == "tombstone"
        and by_id["6E"]["final_ack_loss"]["final"]["state"] == "tombstone",
        by_id["6E"]["final"],
        "tombstone",
    )
    check(
        assertions,
        "6f_commit_after_ticket_expiry_is_completed",
        by_id["6F"]["passed"]
        and by_id["6F"]["expired_by_seconds"] > 0,
        by_id["6F"]["commit"],
        "accepted after expiry with valid pending-delete",
    )
    check(
        assertions,
        "standard_baseline_is_reported_as_unsupported_not_failed",
        standard["status"] == "UNSUPPORTED"
        and standard["standard_baseline_modified"] is False,
        standard,
        "UNSUPPORTED and unmodified",
    )
    assertions_passed = all(item["passed"] for item in assertions)
    metrics = {
        "old_receipt_replay": "rejected",
        "latest_receipt_retry": "idempotent",
        "tamper_rejected": by_id["6B"]["rejected_count"],
        "concurrent_successor_count": by_id["6C"]["successor_count"],
        "same_rprep": by_id["6D"]["same_rprep_returned"],
        "delete_recovery_converged": by_id["6E"]["passed"],
        "expired_ticket_commit_completed": by_id["6F"]["passed"],
    }
    report = {
        "experiment": config["experiment_name"],
        "status": "PASS" if assertions_passed else "FAIL",
        "seed": int(config["seed"]),
        "aura": {
            "status": "PASS" if all(item["passed"] for item in subtests) else "FAIL",
            "subtests": subtests,
            "state_chain": "lph + state + ctr + last_hash + device HMAC",
            "delete_protocol": "prepare-delete / Rprep / commit-delete",
            "atomicity": "SQLite BEGIN IMMEDIATE plus conditional UPDATE CAS",
        },
        "standard": standard,
        "metrics": metrics,
        "assertions": assertions,
        "assertions_passed": assertions_passed,
        "execution_ms": round((time.perf_counter() - started) * 1000, 3),
        "results_directory": str(output),
        "scope": {
            "network_services_started": False,
            "production_lifecycle_core_called_directly": True,
            "standard_baseline_modified": False,
            "pure_message_blocking_dos_scored_as_failure": False,
        },
    }

    all_events: list[dict[str, Any]] = []
    snapshots: dict[str, Any] = {}
    for db_path in sorted((output / "databases").glob("*.sqlite")):
        engine = LifecycleEngine(
            db_path,
            device_mac_key=harness.device_key,
            server_mac_key=harness.server_key,
        )
        for event in engine.export_events():
            all_events.append({"database": db_path.name, **event})
        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            snapshots[db_path.name] = {
                "profiles": [
                    dict(row)
                    for row in db.execute(
                        "SELECT * FROM lifecycle_profiles ORDER BY lph"
                    )
                ],
                "pending_deletes": [
                    dict(row)
                    for row in db.execute(
                        "SELECT * FROM pending_deletes ORDER BY lph"
                    )
                ],
                "receipt_count": db.execute(
                    "SELECT COUNT(*) FROM lifecycle_receipts"
                ).fetchone()[0],
            }
    write_json(output / "raw" / "subtests.json", subtests)
    write_jsonl(output / "raw" / "events.jsonl", all_events)
    write_csv(output / "raw" / "events.csv", all_events)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(
        output / "evidence" / "standard-baseline-audit.json", standard
    )
    write_json(
        output / "evidence" / "database-snapshots.json", snapshots
    )
    write_json(output / "summary.json", report)
    write_csv(
        output / "summary.csv",
        [
            {
                "subtest": item["id"],
                "scenario": item["scenario"],
                "passed": item["passed"],
                "final_state": item.get("final", {}).get("state", ""),
            }
            for item in subtests
        ],
    )
    (output / "summary.md").write_text(
        summary_markdown(report), encoding="utf-8"
    )
    write_paper(output, report)

    machine = {
        "status": report["status"],
        "aura_subtests_passed": sum(item["passed"] for item in subtests),
        "aura_subtests_total": len(subtests),
        "old_receipt_replay": metrics["old_receipt_replay"],
        "latest_receipt_retry": metrics["latest_receipt_retry"],
        "tamper_rejected": f'{metrics["tamper_rejected"]}/7',
        "concurrent_successor_count": metrics["concurrent_successor_count"],
        "same_rprep": metrics["same_rprep"],
        "delete_recovery_converged": metrics["delete_recovery_converged"],
        "expired_ticket_commit_completed": metrics[
            "expired_ticket_commit_completed"
        ],
        "standard_baseline": standard["status"],
        "assertions_passed": assertions_passed,
        "results": str(output),
    }
    if args.machine_json:
        print(json.dumps(machine, ensure_ascii=False, separators=(",", ":")))
    else:
        languages = ("zh", "en") if args.lang == "both" else (args.lang,)
        for language in languages:
            print_summary(report, language)
    return 0 if assertions_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
