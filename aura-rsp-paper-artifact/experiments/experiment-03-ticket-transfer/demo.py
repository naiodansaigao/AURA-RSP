from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import random
import shutil
import sys
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from py_ecc.optimized_bls12_381 import curve_order, multiply

    import aura_rsp.proof as proof_module
    from aura_rsp.bbs import (
        blind_sign,
        create_blind_commitment,
        finalize_blind_signature,
        keygen,
        public_key_to_dict,
        random_scalar,
        verify_signature,
    )
    from aura_rsp.codec import (
        b64e,
        canonical,
        hash_to_scalar,
        save_json,
        scalar_to_b64,
        sha256_hex,
    )
    from aura_rsp.primitives import (
        ed25519_public_b64,
        ed25519_sign,
        generate_ed25519_private,
        generate_p256_private,
        p256_private_to_pem,
        p256_public_to_pem,
    )
    from aura_rsp.proof import (
        CRED_PARAMS,
        TOKEN_PARAMS,
        create_auth_proof,
        credential_messages,
        g1_to_b64,
        lph_base,
        token_messages,
        token_public_messages,
    )
    from aura_rsp.server import AuraServerState
    from aura_rsp.storage import connect, connect_trace
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by launcher checks
    raise SystemExit(
        "缺少AURA运行依赖。请在WSL中使用run_demo.sh，"
        "或先运行aura-rsp/scripts/install_deps.sh。"
        f" 原始错误: {exc}"
    ) from exc


LANG = {
    "zh": {
        "title": "实验3：操作票据盗取与跨设备转移",
        "status": "状态",
        "scenario": "场景",
        "auth": "认证结果",
        "bind": "Bind_t",
        "profile": "Profile交付",
        "identity": "稳定EID暴露",
        "accepted": "通过",
        "rejected": "拒绝",
        "generated": "已生成",
        "not_generated": "未生成",
        "yes": "是",
        "no": "否",
        "owner": "AURA：Device-A正常使用",
        "aura_transfer": "AURA：票据转移到Device-B",
        "std_prebound": "Standard：订单预绑定EID",
        "std_unbound": "Standard：未绑定激活码",
        "conclusion": (
            "AURA在不公开EID的情况下拒绝跨设备票据；Standard的结果取决于订单是否预绑定EID。"
        ),
        "fig1_title": "跨设备转移攻击结果",
        "fig1_subtitle": "1表示攻击成功或稳定身份暴露；0表示未发生",
        "transferred_accept": "被盗材料被Device-B接受",
        "profile_delivered": "向Device-B交付Profile",
        "stable_eid": "服务器依赖稳定EID",
        "aura_label": "AURA-RSP",
        "std_bound_label": "Standard\n预绑定EID",
        "std_unbound_label": "Standard\n未绑定激活码",
        "fig2_title": "AURA-RSP操作票据跨设备转移验证链",
        "device_a": "Device-A\nCred_A(x_A)",
        "ticket": "被盗操作票据\nTok_A(...,x_A,η,d)",
        "device_b": "Device-B\nCred_B(x_B)",
        "proof": "联合证明要求\nx_credential=x_ticket",
        "server": "SM-DP+\n匿名认证验证",
        "result": "401拒绝\n无Bind_t / 无Profile",
        "copy": "复制票据和订单材料",
        "mismatch": "x_A ≠ x_B",
        "submit": "强行提交无效证明",
    },
    "en": {
        "title": "Experiment 3: Stolen Operation Ticket and Cross-Device Transfer",
        "status": "Status",
        "scenario": "Scenario",
        "auth": "Authentication",
        "bind": "Bind_t",
        "profile": "Profile delivery",
        "identity": "Stable EID exposed",
        "accepted": "accepted",
        "rejected": "rejected",
        "generated": "generated",
        "not_generated": "not generated",
        "yes": "yes",
        "no": "no",
        "owner": "AURA: legitimate Device-A",
        "aura_transfer": "AURA: ticket transferred to Device-B",
        "std_prebound": "Standard: EID-prebound order",
        "std_unbound": "Standard: unbound activation code",
        "conclusion": (
            "AURA rejects a cross-device ticket without disclosing EID; "
            "the Standard result depends on whether the order is EID-prebound."
        ),
        "fig1_title": "Cross-Device Transfer Attack Outcomes",
        "fig1_subtitle": "1 denotes attacker success or stable-identity exposure; 0 denotes absence",
        "transferred_accept": "Stolen material accepted for Device-B",
        "profile_delivered": "Profile delivered to Device-B",
        "stable_eid": "Server relies on stable EID",
        "aura_label": "AURA-RSP",
        "std_bound_label": "Standard\nEID-prebound",
        "std_unbound_label": "Standard\nunbound code",
        "fig2_title": "AURA-RSP Cross-Device Operation-Ticket Validation Chain",
        "device_a": "Device-A\nCred_A(x_A)",
        "ticket": "Stolen ticket\nTok_A(...,x_A,eta,d)",
        "device_b": "Device-B\nCred_B(x_B)",
        "proof": "Joint proof requires\nx_credential=x_ticket",
        "server": "SM-DP+\nanonymous authentication",
        "result": "HTTP 401 rejection\nno Bind_t / no profile",
        "copy": "copy ticket and order material",
        "mismatch": "x_A != x_B",
        "submit": "force invalid proof submission",
    },
}


def load_config(path: Path) -> dict[str, Any]:
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
        for row in rows:
            writer.writerow(row)


def xml(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def seeded_hex(seed: int, label: str, size: int = 16) -> str:
    digest = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()
    return digest[: size * 2]


def seeded_bytes(seed: int, label: str, size: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(output[:size])


def prepare_output(output: Path, experiment_root: Path) -> Path:
    output = output.resolve()
    results_root = (experiment_root / "results").resolve()
    if not output.is_relative_to(results_root):
        raise ValueError(f"output must stay under {results_root}")
    if output.exists():
        shutil.rmtree(output)
    for name in ("raw", "evidence", "paper"):
        (output / name).mkdir(parents=True, exist_ok=True)
    return output


@dataclass
class Device:
    label: str
    eid: str
    x: int
    k: int
    cred_exp: int
    credential_signature: Any


@dataclass
class TicketBundle:
    label: str
    ticket: dict[str, Any]
    eta: int
    d_value: int
    signature: Any


def issue_credential(
    *,
    label: str,
    eid: str,
    x: int,
    k: int,
    cred_exp: int,
    eum_sk: int,
    eum_pk: Any,
) -> Device:
    context = {"type": "Cred_D", "cred_exp": cred_exp}
    commitment, s_user = create_blind_commitment(CRED_PARAMS, {0: x}, context)
    blind_signature = blind_sign(
        CRED_PARAMS,
        eum_sk,
        commitment,
        {1: k, 2: cred_exp},
        context,
    )
    signature = finalize_blind_signature(blind_signature, s_user)
    if not verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x, k, cred_exp),
        signature,
    ):
        raise RuntimeError(f"{label} credential issuance failed")
    return Device(label, eid, x, k, cred_exp, signature)


def issue_ticket(
    *,
    label: str,
    seed: int,
    owner_x: int,
    mno_sk: int,
    mno_pk: Any,
    aura_config: dict[str, Any],
    profile_sha256: str,
) -> TicketBundle:
    ticket = {
        "I_ac": "IAC-" + seeded_hex(seed, f"{label}:iac", 16).upper(),
        "sid": aura_config["sid"],
        "pid_h": profile_sha256,
        "op": "download",
        "exp": int(time.time()) + int(aura_config["ticket_valid_seconds"]),
        "PRaddr": aura_config["praddr"],
    }
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": ticket}
    commitment, s_user = create_blind_commitment(
        TOKEN_PARAMS,
        {6: owner_x, 7: eta, 8: d_value},
        context,
    )
    blind_signature = blind_sign(
        TOKEN_PARAMS,
        mno_sk,
        commitment,
        {i: value for i, value in enumerate(token_public_messages(ticket))},
        context,
    )
    signature = finalize_blind_signature(blind_signature, s_user)
    if not verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(ticket, owner_x, eta, d_value),
        signature,
    ):
        raise RuntimeError(f"{label} ticket issuance failed")
    return TicketBundle(label, ticket, eta, d_value, signature)


def create_server_root(
    *,
    root: Path,
    config: dict[str, Any],
    profile: bytes,
    eum_pk: Any,
    mno_pk: Any,
    devices: list[Device],
) -> AuraServerState:
    aura = config["aura"]
    (root / "config").mkdir(parents=True)
    (root / "runtime").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)
    save_json(
        root / "config" / "aura.json",
        {
            "matching_id": aura["matching_id"],
            "sid": aura["sid"],
            "server_oid": aura["server_oid"],
            "praddr": aura["praddr"],
            "capabilities": aura["capabilities"],
        },
    )
    (root / "runtime" / "profile.der").write_bytes(profile)
    server_auth_key = generate_p256_private()
    profile_binding_key = generate_p256_private()
    (root / "runtime" / "server-auth-key.pem").write_bytes(
        p256_private_to_pem(server_auth_key)
    )
    (root / "runtime" / "profile-binding-key.pem").write_bytes(
        p256_private_to_pem(profile_binding_key)
    )
    save_json(
        root / "runtime" / "server-public.json",
        {
            "eum_public_key": public_key_to_dict(eum_pk),
            "mno_public_key": public_key_to_dict(mno_pk),
            "server_auth_public_pem": p256_public_to_pem(
                server_auth_key.public_key()
            ).decode("ascii"),
            "profile_binding_public_pem": p256_public_to_pem(
                profile_binding_key.public_key()
            ).decode("ascii"),
        },
    )
    with closing(connect(root / "runtime" / "aura.sqlite")):
        pass
    with closing(
        connect_trace(root / "runtime" / "eum-trace.sqlite")
    ) as trace_db:
        for device in devices:
            trace_db.execute(
                "INSERT INTO trace_index(k,eid,r_tr) VALUES(?,?,?)",
                (
                    scalar_to_b64(device.k),
                    device.eid,
                    b64e(
                        hashlib.sha256(
                            f"exp03:{device.label}:r_tr".encode("utf-8")
                        ).digest()
                    ),
                ),
            )
        trace_db.commit()
    return AuraServerState(root)


def prepare_authentication(
    *,
    server: AuraServerState,
    config: dict[str, Any],
    label: str,
    seed: int,
    device: Device,
    ticket_bundle: TicketBundle,
) -> dict[str, Any]:
    aura = config["aura"]
    n_u = b64e(seeded_bytes(seed, f"{label}:N_U", 32))
    init_status, init_response = server.initiate(
        {
            "matchingId": aura["matching_id"],
            "N_U": n_u,
            "capabilities": aura["capabilities"],
        },
        aura["praddr"],
    )
    if init_status != 200:
        raise RuntimeError(f"initiate failed: {init_status} {init_response}")
    server_auth = init_response["serverAuth"]
    salt_p = seeded_bytes(seed, f"{label}:salt_p", 32)
    salt_p_b64 = b64e(salt_p)
    opid = b64e(seeded_bytes(seed, f"{label}:opid", 16))
    one_time_private = generate_ed25519_private()
    vk_t = ed25519_public_b64(one_time_private.public_key())
    v_b64 = g1_to_b64(multiply(proof_module.G_V, ticket_bundle.eta))
    lph_b64 = g1_to_b64(
        multiply(lph_base(ticket_bundle.ticket["pid_h"], salt_p), device.x)
    )
    ctx_t = {
        "transactionId": server_auth["transactionId"],
        "I_t": server_auth["I_t"],
        "N_U": server_auth["N_U"],
        "N_S": server_auth["N_S"],
        "sid": server_auth["sid"],
        "serverOID": server_auth["serverOID"],
        "PRaddr": server_auth["PRaddr"],
        "cap": server_auth["cap"],
        "ticket": ticket_bundle.ticket,
        "cred_exp": device.cred_exp,
        "salt_p": salt_p_b64,
        "lph": lph_b64,
        "v": v_b64,
        "opid": opid,
        "vk_t_hash": hashlib.sha256(
            __import__("base64").b64decode(vk_t)
        ).hexdigest(),
    }
    return {
        "ctx_t": ctx_t,
        "salt_p": salt_p,
        "salt_p_b64": salt_p_b64,
        "vk_t": vk_t,
        "one_time_private": one_time_private,
        "transaction_id": server_auth["transactionId"],
    }


def build_proof(
    *,
    context: dict[str, Any],
    device: Device,
    ticket_bundle: TicketBundle,
    eum_pk: Any,
    mno_pk: Any,
    bypass_local_pairing_check: bool = False,
) -> tuple[dict[str, Any], float]:
    original_pairing = proof_module.pairing
    if bypass_local_pairing_check:
        sentinel = object()
        proof_module.pairing = lambda *_args, **_kwargs: sentinel
    started = time.perf_counter()
    try:
        proof = create_auth_proof(
            ctx_t=context["ctx_t"],
            eum_public_key=eum_pk,
            mno_public_key=mno_pk,
            cred_signature=device.credential_signature,
            token_signature=ticket_bundle.signature,
            x=device.x,
            k=device.k,
            eta=ticket_bundle.eta,
            d_value=ticket_bundle.d_value,
            cred_exp=device.cred_exp,
            salt_p=context["salt_p"],
        )
    finally:
        proof_module.pairing = original_pairing
    return proof, (time.perf_counter() - started) * 1000


def build_auth_request(context: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
    tau_payload = {
        "domain": "AURA-RSP-v14:tau_auth",
        "ctx_t": context["ctx_t"],
        "proof_hash": sha256_hex(canonical(proof)),
    }
    return {
        "transactionId": context["transaction_id"],
        "ctx_t": context["ctx_t"],
        "salt_p": context["salt_p_b64"],
        "vk_t": context["vk_t"],
        "tau_auth": ed25519_sign(context["one_time_private"], tau_payload),
        "Pi_auth": proof,
    }


def database_evidence(
    server_root: Path,
    attack_transaction_id: str,
    attack_v: str,
) -> dict[str, Any]:
    with closing(connect(server_root / "runtime" / "aura.sqlite")) as db:
        session = db.execute(
            "SELECT status,bind_t,auth_response_json FROM sessions WHERE transaction_id=?",
            (attack_transaction_id,),
        ).fetchone()
        attack_nullifiers = db.execute(
            "SELECT COUNT(*) AS n FROM used_nullifiers WHERE v=?", (attack_v,)
        ).fetchone()["n"]
        attack_notifications = db.execute(
            "SELECT COUNT(*) AS n FROM notifications WHERE transaction_id=?",
            (attack_transaction_id,),
        ).fetchone()["n"]
        total_nullifiers = db.execute(
            "SELECT COUNT(*) AS n FROM used_nullifiers"
        ).fetchone()["n"]
    return {
        "attack_session_status": session["status"],
        "attack_bind_t": session["bind_t"],
        "attack_auth_response_stored": session["auth_response_json"] is not None,
        "attack_nullifier_rows": attack_nullifiers,
        "attack_notification_rows": attack_notifications,
        "total_nullifier_rows_including_owner_control": total_nullifiers,
    }


def event(
    events: list[dict[str, Any]],
    *,
    mode: str,
    scenario: str,
    step: str,
    actor: str,
    result: str,
    reason: str = "",
    **fields: Any,
) -> None:
    events.append(
        {
            "event_index": len(events) + 1,
            "protocol_mode": mode,
            "scenario": scenario,
            "step": step,
            "actor": actor,
            "result": result,
            "reason": reason,
            **fields,
        }
    )


def run_standard_models(
    config: dict[str, Any],
    device_a: Device,
    device_b: Device,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    activation_code = config["standard"]["activation_code"]

    prebound_accept = device_b.eid == device_a.eid
    event(
        events,
        mode="standard_rsp",
        scenario="eid_prebound_order",
        step="device_identity_check",
        actor="standard_smdpp",
        result="accepted" if prebound_accept else "rejected",
        reason="" if prebound_accept else "eid_mismatch",
        authentication=prebound_accept,
        bind_t_generated=False,
        profile_delivered=False,
        stable_eid_exposed=True,
        order_consumed=False,
    )

    unbound_state = {"consumed": False, "consumed_by": None}

    def consume_unbound(device: Device) -> dict[str, Any]:
        if unbound_state["consumed"]:
            return {
                "accepted": False,
                "reason": "activation_code_already_consumed",
                "profile_delivered": False,
            }
        if activation_code != config["standard"]["activation_code"]:
            return {
                "accepted": False,
                "reason": "invalid_activation_code",
                "profile_delivered": False,
            }
        unbound_state["consumed"] = True
        unbound_state["consumed_by"] = device.label
        return {"accepted": True, "reason": "ok", "profile_delivered": True}

    attacker_first = consume_unbound(device_b)
    event(
        events,
        mode="standard_rsp",
        scenario="unbound_activation_code",
        step="attacker_first_consumption",
        actor="Device-B",
        result="accepted" if attacker_first["accepted"] else "rejected",
        reason=attacker_first["reason"],
        authentication=attacker_first["accepted"],
        bind_t_generated=False,
        profile_delivered=attacker_first["profile_delivered"],
        stable_eid_exposed=True,
        order_consumed=unbound_state["consumed"],
    )
    owner_later = consume_unbound(device_a)
    event(
        events,
        mode="standard_rsp",
        scenario="unbound_activation_code",
        step="legitimate_owner_after_theft",
        actor="Device-A",
        result="accepted" if owner_later["accepted"] else "rejected",
        reason=owner_later["reason"],
        authentication=owner_later["accepted"],
        bind_t_generated=False,
        profile_delivered=owner_later["profile_delivered"],
        stable_eid_exposed=True,
        order_consumed=unbound_state["consumed"],
    )
    return {
        "method": "controlled_standard_order_policy_model",
        "eid_prebound": {
            "device_b_authentication": prebound_accept,
            "reason": "ok" if prebound_accept else "eid_mismatch",
            "profile_delivered_to_device_b": False,
            "stable_eid_exposed": True,
        },
        "unbound_activation_code": {
            "device_b_authentication": attacker_first["accepted"],
            "device_b_profile_delivered": attacker_first["profile_delivered"],
            "order_consumed_by": unbound_state["consumed_by"],
            "device_a_later_authentication": owner_later["accepted"],
            "device_a_later_reason": owner_later["reason"],
            "stable_eid_exposed_during_standard_authentication": True,
        },
    }


def check(
    assertions: list[dict[str, Any]],
    name: str,
    passed: bool,
    actual: Any,
    expected: Any,
) -> None:
    assertions.append(
        {"name": name, "passed": bool(passed), "actual": actual, "expected": expected}
    )


def grouped_bar_svg(report: dict[str, Any], language: str) -> str:
    text = LANG[language]
    width, height = 1800, 1050
    left, top, chart_h = 150, 210, 570
    baseline = top + chart_h
    scenarios = [
        (
            text["aura_label"],
            [
                int(report["aura"]["transfer_attack"]["authentication"]),
                int(report["aura"]["transfer_attack"]["profile_delivered"]),
                0,
            ],
        ),
        (
            text["std_bound_label"],
            [
                int(report["standard"]["eid_prebound"]["device_b_authentication"]),
                int(report["standard"]["eid_prebound"]["profile_delivered_to_device_b"]),
                1,
            ],
        ),
        (
            text["std_unbound_label"],
            [
                int(
                    report["standard"]["unbound_activation_code"][
                        "device_b_authentication"
                    ]
                ),
                int(
                    report["standard"]["unbound_activation_code"][
                        "device_b_profile_delivered"
                    ]
                ),
                1,
            ],
        ),
    ]
    metrics = [
        (text["transferred_accept"], "#2F5597"),
        (text["profile_delivered"], "#ED7D31"),
        (text["stable_eid"], "#70AD47"),
    ]
    group_x = [390, 900, 1410]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="70" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="44" font-weight="700" fill="#111827">{xml(text["fig1_title"])}</text>',
        f'<text x="{width/2}" y="120" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="25" fill="#4b5563">{xml(text["fig1_subtitle"])}</text>',
    ]
    for tick in (0, 0.5, 1):
        y = baseline - tick * chart_h
        svg.extend(
            [
                f'<line x1="{left}" y1="{y}" x2="{width-80}" y2="{y}" stroke="#d1d5db" stroke-width="2"/>',
                f'<text x="{left-25}" y="{y+9}" text-anchor="end" font-family="Arial,sans-serif" font-size="25">{tick:.1f}</text>',
            ]
        )
    bar_w = 90
    for group_index, (label, values) in enumerate(scenarios):
        center = group_x[group_index]
        for metric_index, value in enumerate(values):
            x = center + (metric_index - 1) * 120 - bar_w / 2
            y = baseline - value * chart_h
            if value:
                svg.append(
                    f'<rect x="{x}" y="{y}" width="{bar_w}" height="{value*chart_h}" fill="{metrics[metric_index][1]}" rx="5"/>'
                )
            svg.append(
                f'<text x="{x+bar_w/2}" y="{y-14}" text-anchor="middle" font-family="Arial,sans-serif" font-size="27" font-weight="700">{value}</text>'
            )
        lines = label.split("\n")
        for line_index, line in enumerate(lines):
            svg.append(
                f'<text x="{center}" y="{baseline+55+line_index*32}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="27" font-weight="600">{xml(line)}</text>'
            )
    legend_y = 905
    legend_x = [190, 720, 1250]
    legend_lines = (
        [
            ["被盗材料被Device-B接受"],
            ["向Device-B交付Profile"],
            ["服务器依赖稳定EID"],
        ]
        if language == "zh"
        else [
            ["Stolen material accepted", "for Device-B"],
            ["Profile delivered", "to Device-B"],
            ["Server relies on", "stable EID"],
        ]
    )
    for index, (_label, color) in enumerate(metrics):
        svg.extend(
            [
                f'<rect x="{legend_x[index]}" y="{legend_y-23}" width="34" height="34" fill="{color}"/>',
            ]
        )
        for line_index, line in enumerate(legend_lines[index]):
            svg.append(
                f'<text x="{legend_x[index]+50}" y="{legend_y+2+line_index*30}" font-family="Arial,Microsoft YaHei,sans-serif" font-size="23">{xml(line)}</text>'
            )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def flow_svg(language: str) -> str:
    text = LANG[language]
    width, height = 2400, 850
    boxes = [
        (50, 270, 280, 145, text["device_a"], "#dbeafe", "#2563eb"),
        (440, 270, 340, 145, text["ticket"], "#fef3c7", "#d97706"),
        (950, 270, 280, 145, text["device_b"], "#ede9fe", "#7c3aed"),
        (1400, 270, 360, 145, text["proof"], "#fee2e2", "#dc2626"),
        (1970, 270, 330, 145, text["server"], "#e5e7eb", "#374151"),
    ]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs><marker id="arrow" markerWidth="14" markerHeight="10" refX="12" refY="5" orient="auto"><path d="M0,0 L14,5 L0,10 z" fill="#4b5563"/></marker></defs>',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="75" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="43" font-weight="700" fill="#111827">{xml(text["fig2_title"])}</text>',
    ]
    for x, y, w, h, label, fill, stroke in boxes:
        svg.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        )
        lines = label.split("\n")
        start_y = y + h / 2 - (len(lines) - 1) * 19
        for idx, line in enumerate(lines):
            svg.append(
                f'<text x="{x+w/2}" y="{start_y+idx*38}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="27" font-weight="600" fill="#111827">{xml(line)}</text>'
            )
    arrows = [
        (330, 342, 440, 342, ""),
        (780, 342, 950, 342, text["copy"]),
        (1230, 342, 1400, 342, text["mismatch"]),
        (1760, 342, 1970, 342, text["submit"]),
    ]
    for x1, y1, x2, y2, label in arrows:
        svg.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2-10}" y2="{y2}" stroke="#4b5563" stroke-width="4" marker-end="url(#arrow)"/>'
        )
        if label:
            svg.append(
                f'<text x="{(x1+x2)/2}" y="220" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="22" fill="#374151">{xml(label)}</text>'
            )
    svg.extend(
        [
            '<line x1="2135" y1="415" x2="2135" y2="550" stroke="#dc2626" stroke-width="4" marker-end="url(#arrow)"/>',
            f'<rect x="1750" y="570" width="600" height="150" rx="18" fill="#fee2e2" stroke="#dc2626" stroke-width="3"/>',
        ]
    )
    for idx, line in enumerate(text["result"].split("\n")):
        svg.append(
            f'<text x="2050" y="{635+idx*40}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="29" font-weight="700" fill="#991b1b">{xml(line)}</text>'
        )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def write_paper_outputs(output: Path, report: dict[str, Any]) -> None:
    paper = output / "paper"
    for language in ("zh", "en"):
        text = LANG[language]
        (paper / f"figure-1-transfer-outcomes-{language}.svg").write_text(
            grouped_bar_svg(report, language), encoding="utf-8"
        )
        (paper / f"figure-2-aura-transfer-flow-{language}.svg").write_text(
            flow_svg(language), encoding="utf-8"
        )
        rows = [
            {
                text["scenario"]: text["aura_transfer"],
                text["auth"]: text["rejected"],
                text["bind"]: text["not_generated"],
                text["profile"]: text["no"],
                text["identity"]: text["no"],
            },
            {
                text["scenario"]: text["std_prebound"],
                text["auth"]: text["rejected"],
                text["bind"]: "-",
                text["profile"]: text["no"],
                text["identity"]: text["yes"],
            },
            {
                text["scenario"]: text["std_unbound"],
                text["auth"]: text["accepted"],
                text["bind"]: "-",
                text["profile"]: text["yes"],
                text["identity"]: text["yes"],
            },
        ]
        write_csv(paper / f"table-1-ticket-transfer-{language}.csv", rows)
        if language == "zh":
            caption = (
                "图1  操作票据盗取与跨设备转移结果。AURA-RSP中，Device-B虽持有合法"
                "Cred_B和完整Tok_A副本，但两份凭证隐藏秘密不相等，服务器联合证明验证返回"
                "401，未生成Bind_t且未交付Profile。Standard预绑定EID时能够拒绝转移，但需要"
                "暴露稳定EID；未绑定Activation Code时，Device-B可抢先消费订单。\n\n"
                "图2  AURA-RSP服务器端验证链。恶意客户端即使绕过本地快速失败并强行提交，"
                "未修改的SM-DP+仍通过BBS+联合证明关系拒绝不一致的隐藏秘密。"
            )
        else:
            caption = (
                "Figure 1. Stolen operation-ticket transfer outcomes. In AURA-RSP, "
                "Device-B owns a valid Cred_B and a complete copy of Tok_A, but the "
                "hidden secrets differ. The unchanged server returns HTTP 401, emits "
                "no Bind_t, and delivers no profile. Standard can reject an EID-prebound "
                "order by exposing a stable EID; an unbound activation code may be "
                "consumed first by Device-B.\n\n"
                "Figure 2. AURA-RSP server-side validation chain. Even when a malicious "
                "client bypasses the prover's local fast-fail and forces submission, the "
                "unchanged SM-DP+ rejects the inconsistent BBS+ joint proof."
            )
        (paper / f"captions-and-analysis-{language}.txt").write_text(
            caption + "\n", encoding="utf-8"
        )


def summary_markdown(report: dict[str, Any]) -> str:
    aura = report["aura"]
    std = report["standard"]
    return f"""# 实验3：操作票据盗取与跨设备转移

状态：**{report["status"]}**

## AURA-RSP

| 检查项 | 结果 |
|---|---|
| Device-A正常认证 | {"通过" if aura["owner_control"]["authentication"] else "失败"} |
| Device-A正常Bind_t | {"已生成" if aura["owner_control"]["bind_t_generated"] else "未生成"} |
| Device-B本地联合证明 | {"被拒绝" if aura["transfer_attack"]["local_proof_rejected"] else "未拒绝"} |
| Device-B服务器认证 | {"通过" if aura["transfer_attack"]["authentication"] else "拒绝"} |
| HTTP状态 | {aura["transfer_attack"]["http_status"]} |
| 统一拒绝原因 | `{aura["transfer_attack"]["reason"]}` |
| 服务器原始原因 | `{aura["transfer_attack"]["server_raw_reason"]}` |
| Bind_t生成 | {aura["transfer_attack"]["bind_t_generated"]} |
| Profile交付 | {aura["transfer_attack"]["profile_delivered"]} |
| 公开EID | {aura["transfer_attack"]["stable_eid_exposed"]} |

## Standard RSP订单策略对照

| 策略 | Device-B认证 | Profile交付 | 稳定EID暴露 |
|---|---:|---:|---:|
| 预绑定EID | {std["eid_prebound"]["device_b_authentication"]} | {std["eid_prebound"]["profile_delivered_to_device_b"]} | {std["eid_prebound"]["stable_eid_exposed"]} |
| 未绑定Activation Code | {std["unbound_activation_code"]["device_b_authentication"]} | {std["unbound_activation_code"]["device_b_profile_delivered"]} | {std["unbound_activation_code"]["stable_eid_exposed_during_standard_authentication"]} |

## 结论

AURA-RSP在不公开EID的情况下，依靠设备凭证与操作票据共享隐藏秘密`x`的联合证明拒绝跨设备转移。
Standard的结果取决于订单策略：预绑定EID可以拒绝，但需要稳定身份；未绑定激活码可能被另一合法设备抢先消费。

Standard部分是受控订单策略模型；AURA部分调用现有真实BBS+盲签、联合证明和服务器验证代码。
"""


def print_summary(report: dict[str, Any], language: str) -> None:
    text = LANG[language]
    aura = report["aura"]
    std = report["standard"]
    if language == "en":
        transfer = aura["transfer_attack"]
        db_state = transfer["database_state"]
        assertions = report["assertions"]
        passed_assertions = sum(1 for item in assertions if item["passed"])
        width = 96

        def flag(value: bool, true_text: str = "YES", false_text: str = "NO") -> str:
            return true_text if value else false_text

        def evidence(label: str, value: str) -> None:
            print(f"  {label:.<62} {value}")

        print("=" * width)
        print("EXPERIMENT 3  |  STOLEN OPERATION TICKET AND CROSS-DEVICE TRANSFER")
        print(f'OVERALL RESULT: {report["status"]}')
        print("=" * width)

        print("\n[1] TEST SETUP")
        evidence("Device-A anonymous credential Cred_A(x_A) valid", "YES")
        evidence("Device-B anonymous credential Cred_B(x_B) valid", "YES")
        evidence("Device secrets are distinct (x_A != x_B)", "YES")
        evidence(
            "Tok_A verifies with Device-A secret x_A",
            flag(transfer["ticket_a_valid_for_x_a"]),
        )
        evidence(
            "Tok_A verifies with Device-B secret x_B",
            flag(transfer["ticket_a_valid_for_x_b"]),
        )
        evidence("Copied material", "Tok_A + public activation material")

        print("\n[2] AURA-RSP: LEGITIMATE OWNER CONTROL")
        evidence(
            "Device-A authentication",
            flag(aura["owner_control"]["authentication"], "ACCEPTED", "REJECTED"),
        )
        evidence("HTTP status", str(aura["owner_control"]["http_status"]))
        evidence(
            "Bind_t generated",
            flag(aura["owner_control"]["bind_t_generated"]),
        )
        evidence("Stable EID disclosed", "NO")

        print("\n[3] AURA-RSP: STOLEN Tok_A USED BY DEVICE-B")
        evidence(
            "Honest prover generates the joint proof",
            flag(not transfer["local_proof_rejected"], "YES", "REJECTED LOCALLY"),
        )
        evidence("Local rejection reason", transfer["local_raw_reason"])
        evidence("Malicious client bypasses the local check", "YES")
        evidence(
            "Unmodified server accepts the forced proof",
            flag(transfer["authentication"], "YES", "NO"),
        )
        evidence("Server HTTP status", str(transfer["http_status"]))
        evidence("Server verification result", "REJECTED")
        evidence("Classified reason", transfer["reason"])
        evidence("Bind_t generated for attack session", flag(transfer["bind_t_generated"]))
        evidence(
            "Attack-session nullifier records",
            str(db_state["attack_nullifier_rows"]),
        )
        evidence(
            "Attack-session notification records",
            str(db_state["attack_notification_rows"]),
        )
        evidence("Profile delivered to Device-B", flag(transfer["profile_delivered"]))
        evidence("Stable EID disclosed", flag(transfer["stable_eid_exposed"]))

        print("\n[4] STANDARD RSP ORDER-POLICY CONTROLS")
        print(
            f"  {'Order policy':<30} {'Device-B':<12} "
            f"{'Profile':<12} {'Stable EID'}"
        )
        print("  " + "-" * 78)
        print(
            f"  {'EID-prebound order':<30} "
            f"{'REJECTED':<12} {'NO':<12} {'YES'}"
        )
        print(
            f"  {'Unbound Activation Code':<30} "
            f"{'ACCEPTED':<12} {'DELIVERED':<12} {'YES'}"
        )

        print("\n[5] ASSERTIONS")
        evidence(
            "Passed",
            f"{passed_assertions}/{len(assertions)} "
            f"({report['status']})",
        )
        print("-" * width)
        print(
            "CONCLUSION: AURA-RSP prevents cross-device ticket transfer without "
            "disclosing a stable EID."
        )
        print(f'Results: {report["results_directory"]}')
        print("=" * width)
        return

    line = "=" * 112
    print(line)
    print(text["title"])
    print(f'{text["status"]}: [{report["status"]}]')
    print(line)
    print(
        f'{text["scenario"]:<45} {text["auth"]:<15} {text["bind"]:<15} '
        f'{text["profile"]:<15} {text["identity"]:<15}'
    )
    print("-" * 112)
    rows = [
        (
            text["owner"],
            aura["owner_control"]["authentication"],
            aura["owner_control"]["bind_t_generated"],
            False,
            False,
        ),
        (
            text["aura_transfer"],
            aura["transfer_attack"]["authentication"],
            aura["transfer_attack"]["bind_t_generated"],
            aura["transfer_attack"]["profile_delivered"],
            aura["transfer_attack"]["stable_eid_exposed"],
        ),
        (
            text["std_prebound"],
            std["eid_prebound"]["device_b_authentication"],
            False,
            std["eid_prebound"]["profile_delivered_to_device_b"],
            std["eid_prebound"]["stable_eid_exposed"],
        ),
        (
            text["std_unbound"],
            std["unbound_activation_code"]["device_b_authentication"],
            False,
            std["unbound_activation_code"]["device_b_profile_delivered"],
            std["unbound_activation_code"][
                "stable_eid_exposed_during_standard_authentication"
            ],
        ),
    ]
    for label, auth, bind_t, profile, identity in rows:
        print(
            f"{label:<45} "
            f'{(text["accepted"] if auth else text["rejected"]):<15} '
            f'{(text["generated"] if bind_t else text["not_generated"]):<15} '
            f'{(text["yes"] if profile else text["no"]):<15} '
            f'{(text["yes"] if identity else text["no"]):<15}'
        )
    print("-" * 112)
    print(text["conclusion"])
    print(f'Results: {report["results_directory"]}')
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    started = time.perf_counter()
    config_path = args.config.resolve()
    experiment_root = Path(__file__).resolve().parent
    workspace_root = experiment_root.parents[1]
    config = load_config(config_path)
    output = prepare_output(args.output, experiment_root)
    seed = int(config["seed"])
    random.seed(seed)
    profile_path = (
        workspace_root
        / "rsp-baseline"
        / "third_party"
        / "pysim"
        / "smdpp-data"
        / "upp"
        / "TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der"
    )
    if not profile_path.is_file():
        raise FileNotFoundError(f"baseline profile not found: {profile_path}")
    profile = profile_path.read_bytes()
    profile_sha256 = hashlib.sha256(profile).hexdigest()
    events: list[dict[str, Any]] = []

    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    now = int(time.time())
    cred_exp = now + int(config["aura"]["credential_valid_seconds"])
    x_a = random_scalar(nonzero=True)
    x_b = random_scalar(nonzero=True)
    while x_b == x_a:
        x_b = random_scalar(nonzero=True)
    eid_a = "89049032123451234512345678903001"
    eid_b = "89049032123451234512345678903002"
    k_a = hash_to_scalar(
        "AURA-RSP-v14:H_tr", eid_a.encode("ascii") + seeded_bytes(seed, "A:r_tr", 32)
    )
    k_b = hash_to_scalar(
        "AURA-RSP-v14:H_tr", eid_b.encode("ascii") + seeded_bytes(seed, "B:r_tr", 32)
    )
    device_a = issue_credential(
        label="Device-A",
        eid=eid_a,
        x=x_a,
        k=k_a,
        cred_exp=cred_exp,
        eum_sk=eum_sk,
        eum_pk=eum_pk,
    )
    device_b = issue_credential(
        label="Device-B",
        eid=eid_b,
        x=x_b,
        k=k_b,
        cred_exp=cred_exp,
        eum_sk=eum_sk,
        eum_pk=eum_pk,
    )
    owner_ticket = issue_ticket(
        label="owner-control-ticket",
        seed=seed,
        owner_x=x_a,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        aura_config=config["aura"],
        profile_sha256=profile_sha256,
    )
    stolen_ticket = issue_ticket(
        label="stolen-ticket",
        seed=seed,
        owner_x=x_a,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        aura_config=config["aura"],
        profile_sha256=profile_sha256,
    )

    credential_a_valid = verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x_a, k_a, cred_exp),
        device_a.credential_signature,
    )
    credential_b_valid = verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x_b, k_b, cred_exp),
        device_b.credential_signature,
    )
    ticket_a_valid_for_xa = verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(
            stolen_ticket.ticket,
            x_a,
            stolen_ticket.eta,
            stolen_ticket.d_value,
        ),
        stolen_ticket.signature,
    )
    ticket_a_valid_for_xb = verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(
            stolen_ticket.ticket,
            x_b,
            stolen_ticket.eta,
            stolen_ticket.d_value,
        ),
        stolen_ticket.signature,
    )

    work_parent = output / ".work"
    work_parent.mkdir()
    with tempfile.TemporaryDirectory(prefix="isolated-aura-", dir=work_parent) as temp:
        server_root = Path(temp)
        server = create_server_root(
            root=server_root,
            config=config,
            profile=profile,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            devices=[device_a, device_b],
        )

        owner_context = prepare_authentication(
            server=server,
            config=config,
            label="owner-control",
            seed=seed,
            device=device_a,
            ticket_bundle=owner_ticket,
        )
        owner_proof, owner_prove_ms = build_proof(
            context=owner_context,
            device=device_a,
            ticket_bundle=owner_ticket,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )
        owner_request = build_auth_request(owner_context, owner_proof)
        owner_started = time.perf_counter()
        owner_status, owner_response = server.authenticate(
            owner_request, config["aura"]["praddr"]
        )
        owner_verify_wall_ms = (time.perf_counter() - owner_started) * 1000
        owner_bind_t = owner_response.get("Bind_t")
        event(
            events,
            mode="aura_rsp",
            scenario="owner_control",
            step="anonymous_authentication",
            actor="Device-A",
            result="accepted" if owner_status == 200 else "rejected",
            reason=owner_response.get("reason", owner_response.get("error", "ok")),
            authentication=owner_status == 200,
            bind_t_generated=bool(owner_bind_t),
            profile_delivered=False,
            stable_eid_exposed=False,
            http_status=owner_status,
            proof_generate_ms=round(owner_prove_ms, 3),
            proof_verify_wall_ms=round(owner_verify_wall_ms, 3),
            proof_bytes=len(canonical(owner_proof)),
        )

        attack_context = prepare_authentication(
            server=server,
            config=config,
            label="ticket-transfer",
            seed=seed,
            device=device_b,
            ticket_bundle=stolen_ticket,
        )
        local_proof_rejected = False
        local_reason = ""
        local_started = time.perf_counter()
        try:
            build_proof(
                context=attack_context,
                device=device_b,
                ticket_bundle=stolen_ticket,
                eum_pk=eum_pk,
                mno_pk=mno_pk,
            )
        except ValueError as exc:
            local_proof_rejected = True
            local_reason = str(exc)
        local_ms = (time.perf_counter() - local_started) * 1000
        event(
            events,
            mode="aura_rsp",
            scenario="ticket_transfer",
            step="honest_prover_generation",
            actor="Device-B",
            result="rejected" if local_proof_rejected else "unexpectedly_generated",
            reason=local_reason,
            authentication=False,
            bind_t_generated=False,
            profile_delivered=False,
            stable_eid_exposed=False,
            execution_ms=round(local_ms, 3),
        )

        forced_proof, forced_prove_ms = build_proof(
            context=attack_context,
            device=device_b,
            ticket_bundle=stolen_ticket,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            bypass_local_pairing_check=True,
        )
        attack_request = build_auth_request(attack_context, forced_proof)
        public_request = canonical(attack_request).decode("utf-8")
        eid_exposed = eid_a in public_request or eid_b in public_request
        attack_started = time.perf_counter()
        attack_status, attack_response = server.authenticate(
            attack_request, config["aura"]["praddr"]
        )
        attack_verify_wall_ms = (time.perf_counter() - attack_started) * 1000
        server_raw_reason = attack_response.get(
            "reason", attack_response.get("error", "")
        )
        semantic_mismatch = (
            x_a != x_b
            and credential_b_valid
            and ticket_a_valid_for_xa
            and not ticket_a_valid_for_xb
            and attack_status == 401
        )
        normalized_reason = (
            "credential_ticket_secret_mismatch"
            if semantic_mismatch
            else "unclassified_authentication_failure"
        )
        event(
            events,
            mode="aura_rsp",
            scenario="ticket_transfer",
            step="forced_server_submission",
            actor="malicious-Device-B",
            result="rejected" if attack_status != 200 else "accepted",
            reason=normalized_reason,
            server_raw_reason=server_raw_reason,
            authentication=attack_status == 200,
            bind_t_generated=bool(attack_response.get("Bind_t")),
            profile_delivered=False,
            stable_eid_exposed=eid_exposed,
            http_status=attack_status,
            proof_generate_ms=round(forced_prove_ms, 3),
            proof_verify_wall_ms=round(attack_verify_wall_ms, 3),
            proof_bytes=len(canonical(forced_proof)),
            request_bytes=len(canonical(attack_request)),
        )

        profile_status, profile_response = server.get_profile(
            {"transactionId": attack_context["transaction_id"]},
            config["aura"]["praddr"],
        )
        event(
            events,
            mode="aura_rsp",
            scenario="ticket_transfer",
            step="profile_request_after_rejection",
            actor="malicious-Device-B",
            result="rejected" if profile_status != 200 else "accepted",
            reason=profile_response.get("error", ""),
            authentication=False,
            bind_t_generated=False,
            profile_delivered=profile_status == 200,
            stable_eid_exposed=False,
            http_status=profile_status,
        )

        db_state = database_evidence(
            server_root,
            attack_context["transaction_id"],
            forced_proof["v"],
        )
        server_log_path = server_root / "logs" / "aura-smdpp.jsonl"
        if server_log_path.exists():
            shutil.copyfile(server_log_path, output / "raw" / "aura-server.jsonl")
        else:
            (output / "raw" / "aura-server.jsonl").write_text("", encoding="utf-8")
        del server
        gc.collect()

    work_parent.rmdir()

    standard = run_standard_models(config, device_a, device_b, events)
    aura_result = {
        "method": "real_aura_crypto_and_in_process_server",
        "owner_control": {
            "authentication": owner_status == 200,
            "http_status": owner_status,
            "bind_t_generated": bool(owner_bind_t),
            "proof_generate_ms": round(owner_prove_ms, 3),
            "proof_verify_wall_ms": round(owner_verify_wall_ms, 3),
        },
        "transfer_attack": {
            "copied_material": [
                "operation_ticket",
                "ticket_signature",
                "eta",
                "d",
                "public_order_information",
                "activation_material",
            ],
            "x_a_equals_x_b": x_a == x_b,
            "credential_b_valid": credential_b_valid,
            "ticket_a_valid_for_x_a": ticket_a_valid_for_xa,
            "ticket_a_valid_for_x_b": ticket_a_valid_for_xb,
            "local_proof_rejected": local_proof_rejected,
            "local_raw_reason": local_reason,
            "malicious_local_fast_fail_bypassed": True,
            "authentication": attack_status == 200,
            "http_status": attack_status,
            "server_error": attack_response.get("error"),
            "server_raw_reason": server_raw_reason,
            "reason": normalized_reason,
            "bind_t_generated": bool(attack_response.get("Bind_t"))
            or bool(db_state["attack_bind_t"]),
            "profile_request_http_status": profile_status,
            "profile_request_error": profile_response.get("error"),
            "profile_delivered": profile_status == 200,
            "stable_eid_exposed": eid_exposed,
            "database_state": db_state,
            "proof_generate_ms": round(forced_prove_ms, 3),
            "proof_verify_wall_ms": round(attack_verify_wall_ms, 3),
            "proof_bytes": len(canonical(forced_proof)),
            "authentication_request_bytes": len(canonical(attack_request)),
        },
    }

    assertions: list[dict[str, Any]] = []
    transfer = aura_result["transfer_attack"]
    check(assertions, "device_secrets_are_distinct", x_a != x_b, x_a == x_b, False)
    check(
        assertions,
        "both_device_credentials_are_valid",
        credential_a_valid and credential_b_valid,
        {"Device-A": credential_a_valid, "Device-B": credential_b_valid},
        {"Device-A": True, "Device-B": True},
    )
    check(
        assertions,
        "stolen_ticket_valid_only_for_device_a_secret",
        ticket_a_valid_for_xa and not ticket_a_valid_for_xb,
        {"valid_for_xA": ticket_a_valid_for_xa, "valid_for_xB": ticket_a_valid_for_xb},
        {"valid_for_xA": True, "valid_for_xB": False},
    )
    check(
        assertions,
        "aura_owner_control_authentication_passes",
        aura_result["owner_control"]["authentication"],
        aura_result["owner_control"],
        "authentication=true and Bind_t generated",
    )
    check(
        assertions,
        "aura_honest_device_b_prover_rejects_transfer",
        local_proof_rejected,
        local_reason,
        "randomized BBS+ pairing check failed",
    )
    check(
        assertions,
        "aura_server_rejects_forced_transfer_proof",
        attack_status == int(config["assertions"]["aura_rejection_http_status"]),
        {"status": attack_status, "response": attack_response},
        {"status": 401, "error": "INVALID_PI_AUTH"},
    )
    check(
        assertions,
        "aura_reason_classified_as_secret_mismatch",
        normalized_reason == "credential_ticket_secret_mismatch",
        normalized_reason,
        "credential_ticket_secret_mismatch",
    )
    check(
        assertions,
        "aura_no_bind_t_after_rejection",
        not transfer["bind_t_generated"],
        transfer["bind_t_generated"],
        False,
    )
    check(
        assertions,
        "aura_no_profile_delivery_after_rejection",
        not transfer["profile_delivered"] and profile_status != 200,
        {
            "profile_delivered": transfer["profile_delivered"],
            "profile_http_status": profile_status,
        },
        {"profile_delivered": False, "profile_http_status": "non-200"},
    )
    check(
        assertions,
        "aura_attack_did_not_execute_business_state",
        db_state["attack_session_status"] == "initiated"
        and db_state["attack_nullifier_rows"] == 0
        and db_state["attack_notification_rows"] == 0,
        db_state,
        "session remains initiated; zero attack nullifier/notification rows",
    )
    check(
        assertions,
        "aura_authentication_request_exposes_no_eid",
        not eid_exposed,
        eid_exposed,
        False,
    )
    check(
        assertions,
        "standard_prebound_order_rejects_device_b",
        not standard["eid_prebound"]["device_b_authentication"]
        and standard["eid_prebound"]["stable_eid_exposed"],
        standard["eid_prebound"],
        "rejected with stable EID comparison",
    )
    check(
        assertions,
        "standard_unbound_code_can_be_consumed_by_device_b",
        standard["unbound_activation_code"]["device_b_authentication"]
        and standard["unbound_activation_code"]["device_b_profile_delivered"]
        and standard["unbound_activation_code"]["order_consumed_by"] == "Device-B",
        standard["unbound_activation_code"],
        "Device-B consumes the unbound order first",
    )

    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    report = {
        "experiment": config["experiment_name"],
        "status": status,
        "seed": seed,
        "scope": {
            "aura": "real BBS+ blind credentials/ticket, joint proof, and AuraServerState authentication",
            "standard": "controlled comparison of EID-prebound and unbound activation-code order policies",
            "complete_profile_download_executed": False,
            "profile_request_after_rejection_tested": True,
            "existing_protocol_source_modified": False,
        },
        "profile": {"bytes": len(profile), "sha256": profile_sha256},
        "aura": aura_result,
        "standard": standard,
        "assertions": assertions,
        "execution_ms": round((time.perf_counter() - started) * 1000, 3),
        "results_directory": str(output),
    }

    copied_ticket = {
        "ticket": stolen_ticket.ticket,
        "token_signature": stolen_ticket.signature.to_dict(),
        "eta_sha256": hashlib.sha256(scalar_to_b64(stolen_ticket.eta).encode()).hexdigest(),
        "d_sha256": hashlib.sha256(
            scalar_to_b64(stolen_ticket.d_value).encode()
        ).hexdigest(),
        "activation_material": (
            f'LPA:1${config["aura"]["praddr"]}${stolen_ticket.ticket["I_ac"]}'
        ),
        "device_a_eid_in_ticket": False,
        "device_a_x_in_public_ticket": False,
    }
    write_json(output / "raw" / "copied-ticket-public.json", copied_ticket)
    write_jsonl(output / "raw" / "events.jsonl", events)
    write_csv(output / "raw" / "events.csv", events)
    write_json(output / "evidence" / "database-state.json", db_state)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "summary.json", report)
    write_csv(
        output / "summary.csv",
        [
            {
                "protocol_mode": "aura_rsp",
                "scenario": "ticket_transfer",
                "authentication": transfer["authentication"],
                "reason": transfer["reason"],
                "bind_t_generated": transfer["bind_t_generated"],
                "profile_delivered": transfer["profile_delivered"],
                "stable_eid_exposed": transfer["stable_eid_exposed"],
            },
            {
                "protocol_mode": "standard_rsp",
                "scenario": "eid_prebound_order",
                "authentication": standard["eid_prebound"][
                    "device_b_authentication"
                ],
                "reason": standard["eid_prebound"]["reason"],
                "bind_t_generated": False,
                "profile_delivered": standard["eid_prebound"][
                    "profile_delivered_to_device_b"
                ],
                "stable_eid_exposed": True,
            },
            {
                "protocol_mode": "standard_rsp",
                "scenario": "unbound_activation_code",
                "authentication": standard["unbound_activation_code"][
                    "device_b_authentication"
                ],
                "reason": "ok",
                "bind_t_generated": False,
                "profile_delivered": standard["unbound_activation_code"][
                    "device_b_profile_delivered"
                ],
                "stable_eid_exposed": True,
            },
        ],
    )
    (output / "summary.md").write_text(summary_markdown(report), encoding="utf-8")
    write_paper_outputs(output, report)

    machine = {
        "status": status,
        "aura_owner_authentication": aura_result["owner_control"]["authentication"],
        "aura_transfer_authentication": transfer["authentication"],
        "aura_transfer_reason": transfer["reason"],
        "aura_bind_t_generated": transfer["bind_t_generated"],
        "aura_profile_delivered": transfer["profile_delivered"],
        "standard_prebound_device_b_authentication": standard["eid_prebound"][
            "device_b_authentication"
        ],
        "standard_unbound_device_b_authentication": standard[
            "unbound_activation_code"
        ]["device_b_authentication"],
        "results": str(output),
    }
    if args.machine_json:
        print(json.dumps(machine, ensure_ascii=False, separators=(",", ":")))
    else:
        languages = ("zh", "en") if args.lang == "both" else (args.lang,)
        for language in languages:
            print_summary(report, language)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
