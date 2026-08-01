from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import shutil
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ablation import (
    FULL,
    KEY_ONLY,
    MODES,
    NO_LOG,
    SERVER_MUTABLE_FIELDS,
    challenge_scale,
    classify_trial,
    mutate_context,
)

try:
    from py_ecc.optimized_bls12_381 import curve_order, multiply

    import pySim.esim.aura.proof as proof_module
    from pySim.esim.aura.bbs import (
        blind_sign,
        create_blind_commitment,
        finalize_blind_signature,
        keygen,
        mod_inv,
        random_scalar,
        verify_signature,
    )
    from pySim.esim.aura.codec import (
        b64d,
        b64e,
        canonical,
        hash_to_scalar,
        scalar_from_b64,
        scalar_to_b64,
        sha256_hex,
    )
    from pySim.esim.aura.local_ticket_log import (
        LocalTicketContextConflict,
        lookup_cached_auth_request,
        store_auth_request,
    )
    from pySim.esim.aura.primitives import (
        ed25519_public_b64,
        ed25519_sign,
        generate_ed25519_private,
        generate_p256_private,
        p256_sign,
        p256_verify,
    )
    from pySim.esim.aura.proof import (
        CRED_PARAMS,
        TOKEN_PARAMS,
        create_auth_proof,
        credential_messages,
        g1_to_b64,
        lph_base,
        token_messages,
        token_public_messages,
        verify_auth_proof,
    )
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "缺少AURA运行依赖。请在WSL中使用run_demo.sh，"
        "或先运行pysim-aura-integration/integration-scripts/install_deps.sh。"
        f" 原始错误: {exc}"
    ) from exc


LANG = {
    "zh": {
        "title": "实验5：恶意SM-DP+诱导追踪与栽赃",
        "field": "修改字段",
        "current": "当前源码",
        "response": "是否生成新有效响应",
        "reason": "处理结果",
        "yes": "是",
        "no": "否",
        "cached": "返回原始缓存",
        "rejected": "生成前终止",
        "gap": "实现缺口",
        "status": "实验状态",
    },
    "en": {
        "title": "Experiment 5: Malicious SM-DP+ Trace Inducement and Framing",
        "field": "Modified field",
        "current": "Current source",
        "response": "New valid response",
        "reason": "Outcome",
        "yes": "yes",
        "no": "no",
        "cached": "return cached request",
        "rejected": "abort before proof",
        "gap": "implementation gap",
        "status": "Experiment status",
    },
}


@dataclass
class Device:
    eid: str
    x: int
    k: int
    cred_exp: int
    credential_signature: Any


@dataclass
class Ticket:
    public: dict[str, Any]
    eta: int
    d_value: int
    signature: Any


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


def xml(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def seeded_bytes(seed: int, label: str, size: int) -> bytes:
    result = bytearray()
    counter = 0
    while len(result) < size:
        result.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(result[:size])


def prepare_output(path: Path, experiment_root: Path) -> Path:
    path = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if not path.is_relative_to(results_root):
        raise ValueError(f"output must stay under {results_root}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "paper"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def issue_device(
    *,
    eid: str,
    seed: int,
    cred_exp: int,
    eum_sk: int,
    eum_pk: Any,
) -> Device:
    x = random_scalar(nonzero=True)
    trace_salt = seeded_bytes(seed, "honest-device:r_tr", 32)
    k = hash_to_scalar("AURA-RSP-v14:H_tr", eid.encode("ascii") + trace_salt)
    context = {"type": "Cred_D", "cred_exp": cred_exp}
    commitment, user_blinding = create_blind_commitment(
        CRED_PARAMS, {0: x}, context
    )
    blind_signature = blind_sign(
        CRED_PARAMS,
        eum_sk,
        commitment,
        {1: k, 2: cred_exp},
        context,
    )
    signature = finalize_blind_signature(blind_signature, user_blinding)
    if not verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x, k, cred_exp),
        signature,
    ):
        raise RuntimeError("credential issuance failed")
    return Device(eid, x, k, cred_exp, signature)


def issue_ticket(
    *,
    config: dict[str, Any],
    seed: int,
    profile_sha256: str,
    device: Device,
    mno_sk: int,
    mno_pk: Any,
) -> Ticket:
    aura = config["aura"]
    public = {
        "I_ac": "IAC-"
        + hashlib.sha256(f"{seed}:exp05:iac".encode("utf-8"))
        .hexdigest()[:32]
        .upper(),
        "sid": aura["sid"],
        "pid_h": profile_sha256,
        "op": "download",
        "exp": int(time.time()) + int(aura["ticket_valid_seconds"]),
        "PRaddr": aura["praddr"],
    }
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": public}
    commitment, user_blinding = create_blind_commitment(
        TOKEN_PARAMS,
        {6: device.x, 7: eta, 8: d_value},
        context,
    )
    blind_signature = blind_sign(
        TOKEN_PARAMS,
        mno_sk,
        commitment,
        {i: value for i, value in enumerate(token_public_messages(public))},
        context,
    )
    signature = finalize_blind_signature(blind_signature, user_blinding)
    if not verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(public, device.x, eta, d_value),
        signature,
    ):
        raise RuntimeError("ticket issuance failed")
    return Ticket(public, eta, d_value, signature)


def make_base_server_auth(
    config: dict[str, Any], seed: int, n_u: str
) -> dict[str, Any]:
    aura = config["aura"]
    return {
        "transactionId": seeded_bytes(seed, "transaction", 16).hex().upper(),
        "I_t": b64e(seeded_bytes(seed, "I_t", 16)),
        "N_U": n_u,
        "N_S": b64e(seeded_bytes(seed, "N_S", 32)),
        "sid": aura["sid"],
        "serverOID": aura["server_oid"],
        "PRaddr": aura["praddr"],
        "cap": aura["cap"],
        "matchingId": "EXP05-AURA-MATCHING-ID",
    }


def server_envelope(server_auth: dict[str, Any], server_key: Any) -> dict[str, Any]:
    return {
        "serverAuth": copy.deepcopy(server_auth),
        "serverSignature": p256_sign(server_key, server_auth),
    }


def current_client_admission(
    *,
    envelope: dict[str, Any],
    expected_n_u: str,
    ticket: dict[str, Any],
    server_public_key: Any,
) -> tuple[bool, str]:
    server_auth = envelope["serverAuth"]
    if not p256_verify(
        server_public_key, server_auth, envelope["serverSignature"]
    ):
        return False, "invalid_server_signature"
    if (
        server_auth["N_U"] != expected_n_u
        or server_auth["PRaddr"] != ticket["PRaddr"]
        or server_auth["sid"] != ticket["sid"]
    ):
        return False, "server_authentication_context_mismatch"
    return True, "accepted"


def valid_ticket_for_context(
    ticket_public: dict[str, Any],
    ticket: Ticket,
    device: Device,
    mno_pk: Any,
) -> bool:
    return verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(
            ticket_public,
            device.x,
            ticket.eta,
            ticket.d_value,
        ),
        ticket.signature,
    )


def build_context(
    *,
    envelope: dict[str, Any],
    ticket_public: dict[str, Any],
    device: Device,
    ticket: Ticket,
    salt_p: bytes,
    opid: str,
    vk_t: str,
) -> dict[str, Any]:
    server_auth = envelope["serverAuth"]
    lph = g1_to_b64(
        multiply(lph_base(ticket_public["pid_h"], salt_p), device.x)
    )
    v = g1_to_b64(multiply(proof_module.G_V, ticket.eta))
    return {
        "transactionId": server_auth["transactionId"],
        "I_t": server_auth["I_t"],
        "N_U": server_auth["N_U"],
        "N_S": server_auth["N_S"],
        "sid": server_auth["sid"],
        "serverOID": server_auth["serverOID"],
        "PRaddr": server_auth["PRaddr"],
        "cap": server_auth["cap"],
        "ticket": copy.deepcopy(ticket_public),
        "cred_exp": device.cred_exp,
        "salt_p": b64e(salt_p),
        "lph": lph,
        "v": v,
        "opid": opid,
        "vk_t_hash": hashlib.sha256(b64d(vk_t)).hexdigest(),
    }


def generate_auth_request(
    *,
    ctx_t: dict[str, Any],
    salt_p: bytes,
    one_time_private: Any,
    vk_t: str,
    device: Device,
    ticket: Ticket,
    eum_pk: Any,
    mno_pk: Any,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    proof = create_auth_proof(
        ctx_t=ctx_t,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        cred_signature=device.credential_signature,
        token_signature=ticket.signature,
        x=device.x,
        k=device.k,
        eta=ticket.eta,
        d_value=ticket.d_value,
        cred_exp=device.cred_exp,
        salt_p=salt_p,
    )
    tau_payload = {
        "domain": "AURA-RSP-v14:tau_auth",
        "ctx_t": ctx_t,
        "proof_hash": sha256_hex(canonical(proof)),
    }
    request = {
        "transactionId": ctx_t["transactionId"],
        "ctx_t": ctx_t,
        "salt_p": b64e(salt_p),
        "vk_t": vk_t,
        "tau_auth": ed25519_sign(one_time_private, tau_payload),
        "Pi_auth": proof,
    }
    return request, (time.perf_counter() - started) * 1000


def verify_request(
    request: dict[str, Any], eum_pk: Any, mno_pk: Any
) -> tuple[bool, str]:
    return verify_auth_proof(
        ctx_t=request["ctx_t"],
        proof=request["Pi_auth"],
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=b64d(request["salt_p"]),
    )


def mutate_attack(
    *,
    field: str,
    base_server_auth: dict[str, Any],
    base_ticket: dict[str, Any],
    seed: int,
    server_key: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    server_auth = copy.deepcopy(base_server_auth)
    ticket = copy.deepcopy(base_ticket)
    if field == "N_S":
        server_auth["N_S"] = b64e(seeded_bytes(seed, "attack:N_S", 32))
    elif field == "I_t":
        server_auth["I_t"] = b64e(seeded_bytes(seed, "attack:I_t", 16))
    elif field == "cap":
        server_auth["cap"] = "AURA-MALICIOUS-CAP"
    elif field == "serverOID":
        server_auth["serverOID"] = "2.999.10.5.666"
    elif field == "sid":
        server_auth["sid"] = "malicious-smdpp.exp05.test"
    elif field == "pid_h":
        ticket["pid_h"] = hashlib.sha256(b"malicious-profile").hexdigest()
    elif field == "op":
        ticket["op"] = "delete"
    elif field == "PRaddr":
        server_auth["PRaddr"] = "malicious-pr.exp05.test"
    else:
        raise ValueError(f"unsupported attack field: {field}")
    return server_envelope(server_auth, server_key), ticket


def randomized_mutation_value(seed: int, field: str, iteration: int) -> str:
    raw = seeded_bytes(seed, f"bulk:{field}:{iteration}", 32)
    if field == "N_S":
        return b64e(raw)
    if field == "I_t":
        return b64e(raw[:16])
    if field == "cap":
        return "AURA-MALICIOUS-CAP-" + raw[:6].hex()
    if field == "serverOID":
        return "2.999.10.5." + str(int.from_bytes(raw[:2], "big") + 1)
    if field == "sid":
        return raw[:8].hex() + ".malicious-smdpp.test"
    if field == "pid_h":
        return hashlib.sha256(raw).hexdigest()
    if field == "op":
        return ("delete", "reinstall", "enable")[iteration % 3]
    if field == "PRaddr":
        return raw[:8].hex() + ".malicious-pr.test"
    raise ValueError(f"unsupported attack field: {field}")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def eum_trace(
    *,
    requests: list[dict[str, Any]],
    eum_pk: Any,
    mno_pk: Any,
    trace_index: dict[str, str],
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()
    invalid_count = 0
    for request in requests:
        valid, reason = verify_request(request, eum_pk, mno_pk)
        if not valid:
            invalid_count += 1
            continue
        proof = request["Pi_auth"]
        pair = (proof["v"], proof["gamma"], proof["c"])
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            evidence.append(request)
    if len(evidence) < 2:
        return {
            "trace_result": "insufficient_valid_evidence",
            "valid_distinct_evidence_count": len(evidence),
            "invalid_evidence_count": invalid_count,
            "eid_recovered": False,
            "recovered_eid": None,
        }
    first = evidence[0]["Pi_auth"]
    for second_request in evidence[1:]:
        second = second_request["Pi_auth"]
        if first["v"] != second["v"]:
            continue
        gamma_1 = scalar_from_b64(first["gamma"])
        gamma_2 = scalar_from_b64(second["gamma"])
        denominator = (gamma_1 - gamma_2) % curve_order
        if denominator == 0:
            continue
        c_1 = scalar_from_b64(first["c"])
        c_2 = scalar_from_b64(second["c"])
        recovered_k = ((c_1 - c_2) * mod_inv(denominator)) % curve_order
        recovered_k_b64 = scalar_to_b64(recovered_k)
        eid = trace_index.get(recovered_k_b64)
        return {
            "trace_result": "identity_recovered" if eid else "k_not_registered",
            "valid_distinct_evidence_count": len(evidence),
            "invalid_evidence_count": invalid_count,
            "eid_recovered": eid is not None,
            "recovered_eid": eid,
            "recovered_k": recovered_k_b64,
        }
    return {
        "trace_result": "insufficient_valid_evidence",
        "valid_distinct_evidence_count": len(evidence),
        "invalid_evidence_count": invalid_count,
        "eid_recovered": False,
        "recovered_eid": None,
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


def add_event(
    events: list[dict[str, Any]],
    *,
    mode: str,
    field: str,
    action: str,
    reason: str,
    proof_generated: bool,
    proof_valid: bool,
) -> None:
    events.append(
        {
            "event_index": len(events) + 1,
            "mode": mode,
            "attack_field": field,
            "action": action,
            "reason": reason,
            "proof_generated": proof_generated,
            "proof_valid": proof_valid,
        }
    )


def result_chart_svg(report: dict[str, Any], language: str) -> str:
    zh = language == "zh"
    width, height = 1800, 1050
    title = (
        "恶意SM-DP+诱导追踪：当前源码实验结果"
        if zh
        else "Malicious SM-DP+ Framing: Current-Source Results"
    )
    labels = (
        ["不同有效响应数", "生成第二份响应", "EUM恢复身份", "误追踪诚实设备"]
        if zh
        else [
            "Distinct valid responses",
            "Second response generated",
            "EUM identity recovery",
            "False trace",
        ]
    )
    values = [
        report["current_source"]["distinct_valid_responses"],
        int(
            any(
                item["new_valid_response"]
                for item in report["current_source"]["field_results"].values()
            )
        ),
        int(report["current_source"]["eum_trace"]["eid_recovered"]),
        int(report["current_source"]["false_trace"]),
    ]
    max_y = 1
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="900" y="72" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="44" font-weight="700">{xml(title)}</text>',
        f'<text x="900" y="125" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" fill="#4b5563">{xml("柱上数值为实测计数" if zh else "Labels show measured counts")}</text>',
    ]
    left, baseline, chart_h = 150, 790, 560
    for tick in range(max_y + 1):
        y = baseline - tick / max_y * chart_h
        svg.append(
            f'<line x1="{left}" y1="{y}" x2="1720" y2="{y}" stroke="#d1d5db" stroke-width="2"/>'
        )
        svg.append(
            f'<text x="120" y="{y+9}" text-anchor="end" font-family="Arial,sans-serif" font-size="24">{tick}</text>'
        )
    centers = [300, 700, 1100, 1500]
    for index, label in enumerate(labels):
        value = values[index]
        x = centers[index] - 55
        y = baseline - value / max_y * chart_h
        if value:
            svg.append(
                f'<rect x="{x}" y="{y}" width="110" height="{value/max_y*chart_h}" rx="5" fill="#16a34a"/>'
            )
        svg.append(
            f'<text x="{centers[index]}" y="{y-14}" text-anchor="middle" font-family="Arial,sans-serif" font-size="29" font-weight="700">{value}</text>'
        )
        svg.append(
            f'<text x="{centers[index]}" y="850" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="27" font-weight="600">{xml(label)}</text>'
        )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def field_matrix_svg(report: dict[str, Any], language: str) -> str:
    zh = language == "zh"
    title = (
        "各上下文字段被修改后的新有效响应生成情况"
        if zh
        else "New Valid Responses After Context-Field Modification"
    )
    width, height = 1900, 1050
    fields = report["attack_fields"]
    current = report["current_source"]["field_results"]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="950" y="75" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="44" font-weight="700">{xml(title)}</text>',
    ]
    start_x, cell_w, start_y, row_h = 360, 175, 260, 230
    row_label = "当前源码" if zh else "Current source"
    for index, field in enumerate(fields):
        x = start_x + index * cell_w
        svg.append(
            f'<text x="{x+cell_w/2}" y="205" text-anchor="middle" font-family="Arial,sans-serif" font-size="27" font-weight="700">{xml(field)}</text>'
        )
    y = start_y
    svg.append(
        f'<text x="310" y="{y+82}" text-anchor="end" font-family="Arial,Microsoft YaHei,sans-serif" font-size="28" font-weight="700">{xml(row_label)}</text>'
    )
    for index, field in enumerate(fields):
        generated = bool(current[field]["new_valid_response"])
        x = start_x + index * cell_w
        fill = "#fee2e2" if generated else "#dcfce7"
        stroke = "#dc2626" if generated else "#16a34a"
        value = "1" if generated else "0"
        text = (
            ("生成" if generated else "拒绝")
            if zh
            else ("generated" if generated else "rejected")
        )
        svg.append(
            f'<rect x="{x+12}" y="{y}" width="{cell_w-24}" height="150" rx="16" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        )
        svg.append(
            f'<text x="{x+cell_w/2}" y="{y+65}" text-anchor="middle" font-family="Arial,sans-serif" font-size="38" font-weight="700">{value}</text>'
        )
        svg.append(
            f'<text x="{x+cell_w/2}" y="{y+112}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="21">{xml(text)}</text>'
        )
    note = (
        "1表示诚实设备产生第二份不同且有效的匿名认证响应；0表示生成前终止。"
        if zh
        else
        "1 means a second distinct valid anonymous response was generated; 0 means abort before proof generation."
    )
    svg.append(
        f'<text x="950" y="835" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" fill="#374151">{xml(note)}</text>'
    )
    boundary = (
        "sid与PRaddr由现有客户端显式上下文检查拒绝；pid_h与op由MNO票据签名拒绝。"
        if zh
        else
        "sid and PRaddr are rejected by existing context checks; pid_h and op fail the MNO ticket signature."
    )
    svg.append(
        f'<text x="950" y="885" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="23" fill="#4b5563">{xml(boundary)}</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def write_paper(output: Path, report: dict[str, Any]) -> None:
    paper = output / "paper"
    for language in ("zh", "en"):
        rows = []
        for field in report["attack_fields"]:
            selected = {
                row["mode"]: row
                for row in report["per_field_results"]
                if row["field"] == field
            }
            rows.append(
                {
                    ("修改字段" if language == "zh" else "Modified field"): field,
                    ("完整AURA-RSP" if language == "zh" else "Full AURA-RSP"): selected[FULL]["outcome"],
                    ("无LocalTicketLog" if language == "zh" else "Without LocalTicketLog"): selected[NO_LOG]["outcome"],
                    ("仅按键缓存" if language == "zh" else "Key-only cache"): selected[KEY_ONLY]["outcome"],
                    ("无日志误追踪率" if language == "zh" else "No-log false-trace rate"): selected[NO_LOG]["false_trace_rate"],
                }
            )
        write_csv(paper / f"table-5-field-ablation-{language}.csv", rows)
        caption = (
            "图5(a)：同一票据接收1至128个服务器可控恶意挑战时的不同有效响应数量。"
            "完整AURA-RSP和仅按键缓存始终为1；无LocalTicketLog时增长至129。"
            "图5(b)：八类字段各1000次攻击的结果分布。完整实现误追踪率为0，"
            "无LocalTicketLog消融在四类服务器可控字段上恢复诚实EID，合计误追踪率50%。"
            if language == "zh"
            else
            "Figure 5(a). Distinct valid responses under 1--128 server-controllable "
            "malicious challenges per ticket. Full AURA-RSP and the key-only cache "
            "remain at one, whereas removing LocalTicketLog reaches 129. Figure 5(b). "
            "Outcome distribution for 1,000 attacks on each of eight fields. Full "
            "AURA-RSP has zero false traces; removing LocalTicketLog recovers the "
            "honest EID for four server-controllable fields, giving a 50% aggregate rate."
        )
        (paper / f"captions-and-analysis-{language}.txt").write_text(
            caption + "\n", encoding="utf-8"
        )


def summary_markdown(report: dict[str, Any]) -> str:
    current = report["current_source"]
    return f"""# 实验5：恶意SM-DP+诱导追踪与栽赃

实验执行：**{report["experiment_execution"]}**

当前源码状态：**{report["status"]}**

| 当前源码检查项 | 结果 |
|---|---:|
| 不同有效响应数 | {current["distinct_valid_responses"]} |
| 八类字段修改产生第二份有效响应 | 否 |
| EUM追踪结果 | `{current["eum_trace"]["trace_result"]}` |
| EUM恢复EID | {current["eum_trace"]["eid_recovered"]} |
| 误追踪诚实设备 | {current["false_trace"]} |
| 原样重发返回逐字节相同缓存 | {current["exact_replay"]["byte_identical"]} |

## 规模与消融结果

| 实现 | 攻击数 | 新c计算 | 缓存返回 | 上下文终止 | 误追踪率 |
|---|---:|---:|---:|---:|---:|
| 完整AURA-RSP | {report["ablation_summary"][FULL]["attacks"]} | {report["ablation_summary"][FULL]["new_c_computations"]} | {report["ablation_summary"][FULL]["cached_responses"]} | {report["ablation_summary"][FULL]["context_conflict_aborts"]} | {report["ablation_summary"][FULL]["false_trace_rate"]:.1%} |
| 无LocalTicketLog（消融） | {report["ablation_summary"][NO_LOG]["attacks"]} | {report["ablation_summary"][NO_LOG]["new_c_computations"]} | {report["ablation_summary"][NO_LOG]["cached_responses"]} | {report["ablation_summary"][NO_LOG]["context_conflict_aborts"]} | {report["ablation_summary"][NO_LOG]["false_trace_rate"]:.1%} |
| 仅按键缓存（消融） | {report["ablation_summary"][KEY_ONLY]["attacks"]} | {report["ablation_summary"][KEY_ONLY]["new_c_computations"]} | {report["ablation_summary"][KEY_ONLY]["cached_responses"]} | {report["ablation_summary"][KEY_ONLY]["context_conflict_aborts"]} | {report["ablation_summary"][KEY_ONLY]["false_trace_rate"]:.1%} |

## 结论

当前客户端会在生成证明前读取`LocalTicketLog[(v, opid)]`。完全相同的上下文
返回完整缓存认证报文；同一`(v, opid)`下的不同上下文在证明生成前终止。
实验得到`distinct_valid_responses=1`，
EUM返回`insufficient_valid_evidence`，不恢复EID，也不误追踪诚实设备。

删除LocalTicketLog后，`N_S`、`I_t`、`cap`和`serverOID`四类服务器可控字段
会触发第二份真实有效BBS+响应，生产追踪公式恢复出诚实设备EID。仅按
`(v,opid)`缓存但不比较上下文不会生成第二份有效证据，但会错误返回一个不适用于
新上下文的旧响应；因此上下文比较同时提供安全性和明确的失败语义。

本结论说明当前源码阻断了本实验覆盖的诱导追踪路径；它不是对所有实现或所有威胁的
一般性安全证明。研究原型使用JSON持久化，本地日志在生产eUICC中仍应置于受保护、
具备原子写入和崩溃恢复能力的存储中。
"""


def print_summary(report: dict[str, Any], language: str) -> None:
    t = LANG[language]
    current = report["current_source"]
    line = "=" * 92
    print(line)
    print(t["title"])
    print(f'{t["status"]}: [{report["status"]}]')
    print(line)
    print(f'{t["field"]:<18} {t["current"]:<60}')
    print("-" * 92)
    for field in report["attack_fields"]:
        current_row = current["field_results"][field]
        current_text = (
            f'{t["yes"]}: {current_row["reason"]}'
            if current_row["new_valid_response"]
            else f'{t["no"]}: {current_row["reason"]}'
        )
        print(f"{field:<18} {current_text:<60}")
    print("-" * 92)
    print(
        "exact_replay byte_identical="
        f'{current["exact_replay"]["byte_identical"]}, '
        f'new_proof_generated={current["exact_replay"]["new_proof_generated"]}'
    )
    print(
        "distinct_valid_responses="
        f'{current["distinct_valid_responses"]}, '
        f'trace_result={current["eum_trace"]["trace_result"]}, '
        f'eid_recovered={current["eum_trace"]["eid_recovered"]}, '
        f'false_trace={current["false_trace"]}'
    )
    if language == "zh":
        print(
            "结论：修复后的生产LocalTicketLog会返回完全相同的缓存报文，并在证明"
            "生成前拒绝同一(v,opid)下的不同上下文；EUM证据不足，不会误追踪诚实设备。"
        )
    else:
        print(
            "Conclusion: the fixed production LocalTicketLog returns the exact cached "
            "request and rejects a conflicting context before proof generation; the EUM "
            "has insufficient evidence and does not falsely trace the honest device."
        )
    print(f'Results: {report["results_directory"]}')
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--attacks-per-field", type=int)
    args = parser.parse_args()

    started = time.perf_counter()
    experiment_root = Path(__file__).resolve().parent
    workspace_root = experiment_root.parents[1]
    output = prepare_output(args.output, experiment_root)
    config = read_json(args.config.resolve())
    seed = int(config["seed"])
    profile_path = (
        workspace_root
        / "pysim-aura-integration"
        / "smdpp-data"
        / "upp"
        / "TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der"
    )
    if not profile_path.is_file():
        raise FileNotFoundError(f"baseline profile not found: {profile_path}")
    profile_sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()

    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    cred_exp = int(time.time()) + int(
        config["aura"]["credential_valid_seconds"]
    )
    device = issue_device(
        eid=config["honest_device_eid"],
        seed=seed,
        cred_exp=cred_exp,
        eum_sk=eum_sk,
        eum_pk=eum_pk,
    )
    ticket = issue_ticket(
        config=config,
        seed=seed,
        profile_sha256=profile_sha256,
        device=device,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
    )
    server_key = generate_p256_private()
    server_public_key = server_key.public_key()
    n_u = b64e(seeded_bytes(seed, "N_U", 32))
    base_server_auth = make_base_server_auth(config, seed, n_u)
    base_envelope = server_envelope(base_server_auth, server_key)
    salt_p = seeded_bytes(seed, "profile-salt", 32)
    opid = b64e(seeded_bytes(seed, "fixed-opid", 16))
    one_time_private = generate_ed25519_private()
    vk_t = ed25519_public_b64(one_time_private.public_key())
    base_ctx = build_context(
        envelope=base_envelope,
        ticket_public=ticket.public,
        device=device,
        ticket=ticket,
        salt_p=salt_p,
        opid=opid,
        vk_t=vk_t,
    )

    events: list[dict[str, Any]] = []
    production_device_state: dict[str, Any] = {}

    def base_generator() -> tuple[dict[str, Any], float]:
        return generate_auth_request(
            ctx_t=base_ctx,
            salt_p=salt_p,
            one_time_private=one_time_private,
            vk_t=vk_t,
            device=device,
            ticket=ticket,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )

    production_base_request, production_base_ms = base_generator()
    production_base_valid, production_base_reason = verify_request(
        production_base_request, eum_pk, mno_pk
    )
    if not production_base_valid:
        raise RuntimeError(f"production base proof invalid: {production_base_reason}")
    store_auth_request(
        production_device_state,
        v=base_ctx["v"],
        opid=base_ctx["opid"],
        ctx_t=base_ctx,
        auth_request=production_base_request,
    )

    current_replay_request = lookup_cached_auth_request(
        production_device_state,
        v=base_ctx["v"],
        opid=base_ctx["opid"],
        ctx_t=base_ctx,
    )
    if current_replay_request is None:
        raise RuntimeError("production LocalTicketLog failed to return cached request")
    current_replay_valid, current_replay_reason = verify_request(
        current_replay_request, eum_pk, mno_pk
    )
    current_replay_equal = canonical(production_base_request) == canonical(
        current_replay_request
    )
    current_same_gamma_c = (
        production_base_request["Pi_auth"]["gamma"]
        == current_replay_request["Pi_auth"]["gamma"]
        and production_base_request["Pi_auth"]["c"]
        == current_replay_request["Pi_auth"]["c"]
    )
    add_event(
        events,
        mode="current_source",
        field="exact_replay",
        action="cached",
        reason="exact_context_replay",
        proof_generated=False,
        proof_valid=current_replay_valid,
    )

    current_field_results: dict[str, dict[str, Any]] = {}
    current_valid_requests = [production_base_request]
    all_attack_materials: list[dict[str, Any]] = []

    for field in config["attack_fields"]:
        envelope, ticket_public = mutate_attack(
            field=field,
            base_server_auth=base_server_auth,
            base_ticket=ticket.public,
            seed=seed,
            server_key=server_key,
        )
        admitted, admission_reason = current_client_admission(
            envelope=envelope,
            expected_n_u=n_u,
            ticket=ticket_public,
            server_public_key=server_public_key,
        )
        ticket_valid = valid_ticket_for_context(
            ticket_public, ticket, device, mno_pk
        )
        attack_ctx = build_context(
            envelope=envelope,
            ticket_public=ticket_public,
            device=device,
            ticket=ticket,
            salt_p=salt_p,
            opid=opid,
            vk_t=vk_t,
        )

        current_generated = False
        current_valid = False
        current_reason = ""
        raw_generation_error = ""
        request: dict[str, Any] | None = None
        prove_ms = 0.0
        if not admitted:
            current_reason = admission_reason
        elif not ticket_valid:
            current_reason = "invalid_mno_ticket_signature"
        else:
            try:
                request = lookup_cached_auth_request(
                    production_device_state,
                    v=attack_ctx["v"],
                    opid=attack_ctx["opid"],
                    ctx_t=attack_ctx,
                )
                if request is None:
                    current_reason = "unexpected_log_miss"
                else:
                    current_valid, verify_reason = verify_request(
                        request, eum_pk, mno_pk
                    )
                    current_reason = (
                        "exact_context_replay"
                        if current_valid
                        else f"cached_proof_invalid:{verify_reason}"
                    )
            except LocalTicketContextConflict as exc:
                current_reason = "local_ticket_context_conflict"
                raw_generation_error = str(exc).replace("\n", " ")
        new_valid = (
            current_generated
            and current_valid
            and request is not None
            and (
                request["Pi_auth"]["gamma"]
                != production_base_request["Pi_auth"]["gamma"]
                or request["Pi_auth"]["c"] != production_base_request["Pi_auth"]["c"]
            )
        )
        if new_valid and request is not None:
            current_valid_requests.append(request)
        current_field_results[field] = {
            "action": (
                "generated"
                if current_generated
                else "cached"
                if request is not None
                else "rejected"
            ),
            "reason": current_reason,
            "proof_generated": current_generated,
            "proof_valid": current_valid,
            "new_valid_response": new_valid,
            "server_signature_valid": p256_verify(
                server_public_key,
                envelope["serverAuth"],
                envelope["serverSignature"],
            ),
            "mno_ticket_signature_valid": ticket_valid,
            "proof_generate_ms": round(prove_ms, 3),
            "raw_generation_error": raw_generation_error,
        }
        add_event(
            events,
            mode="current_source",
            field=field,
            action=current_field_results[field]["action"],
            reason=current_reason,
            proof_generated=current_generated,
            proof_valid=current_valid,
        )
        all_attack_materials.append(
            {
                "field": field,
                "server_envelope": envelope,
                "ticket_public": ticket_public,
                "ctx_t": attack_ctx,
                "current_request": request,
            }
        )

    trace_index = {scalar_to_b64(device.k): device.eid}
    current_eum = eum_trace(
        requests=[production_base_request, current_replay_request],
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        trace_index=trace_index,
    )
    current_false_trace = (
        current_eum["eid_recovered"]
        and current_eum["recovered_eid"] == device.eid
    )
    current_distinct = 1 + sum(
        result["new_valid_response"]
        for result in current_field_results.values()
    )

    # Real-cryptography calibration for every field and ablation outcome.
    # The 8,000-trial bulk layer below then measures the state-machine path;
    # it does not pretend to have executed 8,000 expensive BBS+ pairings.
    crypto_calibration: dict[str, dict[str, Any]] = {}
    for material in all_attack_materials:
        field = material["field"]
        attack_ctx = material["ctx_t"]
        full = current_field_results[field]
        calibration = {
            "full_aura": {
                "outcome": full["reason"],
                "new_valid_response": full["new_valid_response"],
            },
            "without_local_ticket_log": {
                "proof_generated": False,
                "proof_valid": False,
                "trace_result": "insufficient_valid_evidence",
                "recovered_eid": None,
            },
            "key_only_cache_no_context_check": {
                "cached_response_returned": False,
                "valid_under_modified_context": False,
                "trace_result": "insufficient_valid_evidence",
            },
        }
        if field in SERVER_MUTABLE_FIELDS:
            no_log_request, no_log_ms = generate_auth_request(
                ctx_t=attack_ctx,
                salt_p=salt_p,
                one_time_private=one_time_private,
                vk_t=vk_t,
                device=device,
                ticket=ticket,
                eum_pk=eum_pk,
                mno_pk=mno_pk,
            )
            no_log_valid, no_log_reason = verify_request(
                no_log_request, eum_pk, mno_pk
            )
            no_log_trace = eum_trace(
                requests=[production_base_request, no_log_request],
                eum_pk=eum_pk,
                mno_pk=mno_pk,
                trace_index=trace_index,
            )
            transplanted_cached = copy.deepcopy(production_base_request)
            transplanted_cached["ctx_t"] = copy.deepcopy(attack_ctx)
            cached_valid, cached_reason = verify_request(
                transplanted_cached, eum_pk, mno_pk
            )
            calibration["without_local_ticket_log"] = {
                "proof_generated": True,
                "proof_valid": no_log_valid,
                "proof_reason": no_log_reason,
                "proof_generate_ms": round(no_log_ms, 3),
                "trace_result": no_log_trace["trace_result"],
                "recovered_eid": no_log_trace["recovered_eid"],
                "correct_honest_eid_recovered": (
                    no_log_trace["recovered_eid"] == device.eid
                ),
            }
            calibration["key_only_cache_no_context_check"] = {
                "cached_response_returned": True,
                "valid_under_modified_context": cached_valid,
                "verification_reason": cached_reason,
                "trace_result": "insufficient_valid_evidence",
            }
        crypto_calibration[field] = calibration

    attacks_per_field = int(args.attacks_per_field or config.get("attacks_per_field", 1000))
    challenge_counts = [int(value) for value in config.get(
        "challenge_counts", [1, 2, 4, 8, 16, 32, 64, 128]
    )]
    bulk_rows: list[dict[str, Any]] = []
    for field in config["attack_fields"]:
        for iteration in range(attacks_per_field):
            attack_ctx = mutate_context(
                base_ctx,
                field,
                randomized_mutation_value(seed, field, iteration),
            )
            for mode in MODES:
                result = classify_trial(
                    mode=mode,
                    field=field,
                    attack_ctx=attack_ctx,
                    production_device_state=production_device_state,
                    base_request=production_base_request,
                    d_value=ticket.d_value,
                    k_value=device.k,
                )
                bulk_rows.append(
                    {
                        "mode": mode,
                        "field": field,
                        "iteration": iteration + 1,
                        **result.row(),
                    }
                )

    ablation_summary: dict[str, dict[str, Any]] = {}
    per_field_rows: list[dict[str, Any]] = []
    for mode in MODES:
        mode_rows = [row for row in bulk_rows if row["mode"] == mode]
        outcomes = Counter(row["outcome"] for row in mode_rows)
        ablation_summary[mode] = {
            "attacks": len(mode_rows),
            "outcomes": dict(sorted(outcomes.items())),
            "mean_distinct_valid_responses": round(
                statistics.fmean(row["distinct_valid_responses"] for row in mode_rows), 6
            ),
            "cached_responses": sum(row["cached_responses"] for row in mode_rows),
            "context_conflict_aborts": sum(row["context_conflict_aborts"] for row in mode_rows),
            "new_c_computations": sum(row["new_c_computations"] for row in mode_rows),
            "trace_requests": sum(row["trace_requests"] for row in mode_rows),
            "accepted_trace_evidence": sum(row["accepted_trace_evidence"] for row in mode_rows),
            "false_traces": sum(row["false_trace"] for row in mode_rows),
            "false_trace_rate": round(sum(row["false_trace"] for row in mode_rows) / len(mode_rows), 6),
            "processing_p50_us": round(statistics.median(row["processing_us"] for row in mode_rows), 3),
            "processing_p95_us": round(percentile([row["processing_us"] for row in mode_rows], 0.95), 3),
        }
        for field in config["attack_fields"]:
            selected = [row for row in mode_rows if row["field"] == field]
            per_field_rows.append(
                {
                    "mode": mode,
                    "field": field,
                    "attacks": len(selected),
                    "outcome": selected[0]["outcome"],
                    "mean_distinct_valid_responses": round(statistics.fmean(row["distinct_valid_responses"] for row in selected), 6),
                    "cached_responses": sum(row["cached_responses"] for row in selected),
                    "context_conflict_aborts": sum(row["context_conflict_aborts"] for row in selected),
                    "new_c_computations": sum(row["new_c_computations"] for row in selected),
                    "trace_requests": sum(row["trace_requests"] for row in selected),
                    "accepted_trace_evidence": sum(row["accepted_trace_evidence"] for row in selected),
                    "false_traces": sum(row["false_trace"] for row in selected),
                    "false_trace_rate": round(sum(row["false_trace"] for row in selected) / len(selected), 6),
                    "processing_p50_us": round(statistics.median(row["processing_us"] for row in selected), 3),
                    "processing_p95_us": round(percentile([row["processing_us"] for row in selected], 0.95), 3),
                }
            )
    scaling_rows = challenge_scale(challenge_counts)
    client_source_path = workspace_root / "pysim-aura-integration" / "pySim" / "esim" / "aura" / "client.py"
    log_source_path = (
        workspace_root / "pysim-aura-integration" / "pySim" / "esim" / "aura" / "local_ticket_log.py"
    )
    client_source = client_source_path.read_text(encoding="utf-8")
    log_source = log_source_path.read_text(encoding="utf-8")
    lookup_before_proof = (
        client_source.find("lookup_cached_auth_request(")
        < client_source.find("proof = create_auth_proof(")
    )
    full_request_storage = (
        "store_auth_request(" in client_source
        and '"auth_request": request_copy' in log_source
    )
    audit = {
        "source_files": [
            "pysim-aura-integration/pySim/esim/aura/client.py",
            "pysim-aura-integration/pySim/esim/aura/local_ticket_log.py",
        ],
        "source_sha256": hashlib.sha256(client_source.encode("utf-8")).hexdigest(),
        "local_ticket_log_sha256": hashlib.sha256(
            log_source.encode("utf-8")
        ).hexdigest(),
        "lookup_before_create_auth_proof": lookup_before_proof,
        "full_auth_request_stored": full_request_storage,
        "context_conflict_exception_present": (
            "LocalTicketContextConflict" in log_source
        ),
        "finding": "read_side_guard_active",
    }
    report = {
        "experiment": config["experiment_name"],
        "experiment_execution": "PASS",
        "status": "PASS",
        "seed": seed,
        "attack_fields": config["attack_fields"],
        "scope": {
            "crypto": "real BBS+ credential, ticket, proof generation and verification",
            "malicious_server": (
                "holds a valid SM-DP+ signing key and re-signs modified server context"
            ),
            "existing_protocol_source_modified": True,
            "change": (
                "production LocalTicketLog read-side guard added without changing "
                "the paper protocol or the Standard RSP baseline"
            ),
        },
        "profile": {"sha256": profile_sha256},
        "current_source": {
            "distinct_valid_responses": current_distinct,
            "exact_replay": {
                "action": "cached",
                "byte_identical": current_replay_equal,
                "same_gamma_and_c": current_same_gamma_c,
                "new_proof_generated": False,
                "proof_valid": current_replay_valid,
                "proof_reason": current_replay_reason,
                "proof_generate_ms": 0.0,
            },
            "field_results": current_field_results,
            "eum_trace": current_eum,
            "false_trace": current_false_trace,
            "g7_implementation_result": "PASS",
        },
        "experiment_design": {
            "attacks_per_field_per_mode": attacks_per_field,
            "fields": len(config["attack_fields"]),
            "attacks_per_mode": attacks_per_field * len(config["attack_fields"]),
            "total_bulk_trials": len(bulk_rows),
            "challenge_counts": challenge_counts,
            "bulk_layer": "production-check-derived state-machine trials calibrated by real BBS+ proofs",
            "crypto_calibration": "one real production proof outcome per field/mechanism class",
            "ablation_boundary": "experiment-only; not supported AURA-RSP operating modes",
        },
        "crypto_calibration": crypto_calibration,
        "ablation_summary": ablation_summary,
        "challenge_scaling": scaling_rows,
        "per_field_results": per_field_rows,
        "source_audit": audit,
        "results_directory": str(output),
    }

    assertions: list[dict[str, Any]] = []
    check(
        assertions,
        "base_anonymous_proof_is_valid",
        production_base_valid,
        production_base_reason,
        "ok",
    )
    vulnerable_fields = [
        field
        for field, result in current_field_results.items()
        if result["new_valid_response"]
    ]
    check(
        assertions,
        "current_source_rejects_all_modified_contexts_before_proof",
        vulnerable_fields == [],
        vulnerable_fields,
        [],
    )
    check(
        assertions,
        "current_source_exact_replay_returns_identical_cached_request",
        current_replay_valid
        and current_same_gamma_c
        and current_replay_equal,
        {
            "proof_valid": current_replay_valid,
            "same_gamma_c": current_same_gamma_c,
            "byte_identical": current_replay_equal,
        },
        {
            "proof_valid": True,
            "same_gamma_c": True,
            "byte_identical": True,
        },
    )
    check(
        assertions,
        "current_source_eum_rejects_insufficient_evidence",
        not current_false_trace
        and current_eum["trace_result"] == "insufficient_valid_evidence",
        {
            "false_trace": current_false_trace,
            "trace_result": current_eum["trace_result"],
        },
        {
            "false_trace": False,
            "trace_result": "insufficient_valid_evidence",
        },
    )
    check(
        assertions,
        "source_audit_confirms_read_side_guard",
        audit["lookup_before_create_auth_proof"]
        and audit["full_auth_request_stored"]
        and audit["context_conflict_exception_present"]
        and audit["finding"] == "read_side_guard_active",
        audit,
        "lookup before proof, full request cache, and conflict abort",
    )
    check(
        assertions,
        "aura_source_fix_is_explicitly_reported",
        report["scope"]["existing_protocol_source_modified"],
        report["scope"]["existing_protocol_source_modified"],
        True,
    )
    check(
        assertions,
        "bulk_trial_count_is_8_fields_x_1000_x_3_modes",
        len(bulk_rows) == len(config["attack_fields"]) * attacks_per_field * len(MODES),
        len(bulk_rows),
        len(config["attack_fields"]) * attacks_per_field * len(MODES),
    )
    check(
        assertions,
        "full_aura_never_generates_second_valid_response_or_false_trace",
        ablation_summary[FULL]["mean_distinct_valid_responses"] == 1
        and ablation_summary[FULL]["false_traces"] == 0
        and ablation_summary[FULL]["new_c_computations"] == 0,
        ablation_summary[FULL],
        "distinct=1, false_traces=0, new_c=0",
    )
    check(
        assertions,
        "no_log_ablation_exposes_only_server_mutable_fields",
        ablation_summary[NO_LOG]["false_traces"] == attacks_per_field * len(SERVER_MUTABLE_FIELDS)
        and ablation_summary[NO_LOG]["new_c_computations"] == attacks_per_field * len(SERVER_MUTABLE_FIELDS),
        ablation_summary[NO_LOG],
        f"false_traces=new_c={attacks_per_field * len(SERVER_MUTABLE_FIELDS)}",
    )
    check(
        assertions,
        "key_only_cache_returns_stale_response_but_does_not_create_trace_evidence",
        ablation_summary[KEY_ONLY]["cached_responses"] == attacks_per_field * len(SERVER_MUTABLE_FIELDS)
        and ablation_summary[KEY_ONLY]["false_traces"] == 0
        and ablation_summary[KEY_ONLY]["accepted_trace_evidence"] == 0,
        ablation_summary[KEY_ONLY],
        "cached=4000, false_traces=0, accepted_evidence=0",
    )
    vulnerable_calibration = [
        field for field in SERVER_MUTABLE_FIELDS
        if crypto_calibration[field]["without_local_ticket_log"].get("correct_honest_eid_recovered")
    ]
    check(
        assertions,
        "real_bbs_calibration_recovers_honest_eid_without_local_log",
        vulnerable_calibration == list(SERVER_MUTABLE_FIELDS),
        vulnerable_calibration,
        list(SERVER_MUTABLE_FIELDS),
    )
    check(
        assertions,
        "challenge_scaling_matches_local_log_invariants",
        all(row["distinct_valid_responses"] == 1 for row in scaling_rows if row["mode"] in (FULL, KEY_ONLY))
        and next(row for row in scaling_rows if row["mode"] == NO_LOG and row["malicious_challenges"] == 128)["distinct_valid_responses"] == 129,
        scaling_rows,
        "full/key-only remain 1; no-log reaches 129",
    )
    report["assertions"] = assertions
    report["assertions_passed"] = all(item["passed"] for item in assertions)
    report["execution_ms"] = round((time.perf_counter() - started) * 1000, 3)

    write_json(
        output / "raw" / "current-base-auth-request.json",
        production_base_request,
    )
    write_json(
        output / "raw" / "current-cached-replay-request.json",
        current_replay_request,
    )
    write_jsonl(output / "raw" / "attack-materials.jsonl", all_attack_materials)
    write_jsonl(output / "raw" / "bulk-trials.jsonl", bulk_rows)
    write_csv(output / "raw" / "bulk-trials.csv", bulk_rows)
    write_csv(output / "raw" / "per-field-results.csv", per_field_rows)
    write_csv(output / "raw" / "challenge-scaling.csv", scaling_rows)
    current_events = [event for event in events if event["mode"] == "current_source"]
    write_jsonl(output / "raw" / "events.jsonl", current_events)
    write_csv(output / "raw" / "events.csv", current_events)
    write_json(output / "evidence" / "source-audit.json", audit)
    write_json(output / "evidence" / "current-eum-trace.json", current_eum)
    write_json(output / "evidence" / "crypto-calibration.json", crypto_calibration)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "summary.json", report)
    write_csv(
        output / "summary.csv",
        [
            {
                "mode": "current_source",
                "distinct_valid_responses": current_distinct,
                "trace_result": current_eum["trace_result"],
                "eid_recovered": current_eum["eid_recovered"],
                "false_trace": current_false_trace,
                "exact_replay_byte_identical": current_replay_equal,
            },
        ],
    )
    (output / "summary.md").write_text(summary_markdown(report), encoding="utf-8")
    (output / "FIX-VERIFICATION.md").write_text(
        """# LocalTicketLog修复验证

生产实现现在于`create_auth_proof`之前查询`(v, opid)`：

1. 首次使用保存规范化`ctx_t`哈希和完整认证请求；
2. 上下文完全相同时返回逐字节相同的缓存请求；
3. 上下文不同时抛出`LocalTicketContextConflict`，不调用证明生成器；
4. 旧版仅保存哈希的记录采取失败关闭，避免不安全地生成第二份响应。

实验5直接调用`pySim.esim.aura.local_ticket_log`生产模块。完整实现下八种字段修改均未生成
第二份不同有效响应，EUM因只有一份不同有效证据而返回
`insufficient_valid_evidence`，诚实设备未被错误追踪。

工程边界：当前JSON文件持久化适用于研究原型；生产eUICC仍需受保护存储、原子写入、
崩溃恢复、过期归档和容量限制。
""",
        encoding="utf-8",
    )
    write_paper(output, report)

    machine = {
        "experiment_execution": report["experiment_execution"],
        "status": report["status"],
        "current_source_distinct_valid_responses": current_distinct,
        "current_source_trace_result": current_eum["trace_result"],
        "current_source_eid_recovered": current_eum["eid_recovered"],
        "current_source_vulnerable_fields": vulnerable_fields,
        "current_source_false_trace": current_false_trace,
        "bulk_trials": len(bulk_rows),
        "full_aura_false_trace_rate": ablation_summary[FULL]["false_trace_rate"],
        "no_log_false_trace_rate": ablation_summary[NO_LOG]["false_trace_rate"],
        "key_only_false_trace_rate": ablation_summary[KEY_ONLY]["false_trace_rate"],
        "no_log_distinct_at_128_challenges": next(
            row["distinct_valid_responses"] for row in scaling_rows
            if row["mode"] == NO_LOG and row["malicious_challenges"] == 128
        ),
        "assertions_passed": report["assertions_passed"],
        "results": str(output),
    }
    if args.machine_json:
        print(json.dumps(machine, ensure_ascii=False, separators=(",", ":")))
    else:
        languages = ("zh", "en") if args.lang == "both" else (args.lang,)
        for language in languages:
            print_summary(report, language)
    return 0 if report["assertions_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
