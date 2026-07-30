from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import shutil
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
        mod_inv,
        public_key_to_dict,
        random_scalar,
        verify_signature,
    )
    from aura_rsp.codec import (
        b64d,
        b64e,
        canonical,
        hash_to_scalar,
        save_json,
        scalar_from_b64,
        scalar_to_b64,
        sha256_hex,
    )
    from aura_rsp.primitives import (
        decrypt_profile,
        derive_session_keys,
        ed25519_public_b64,
        ed25519_sign,
        generate_ed25519_private,
        generate_p256_private,
        p256_private_to_pem,
        p256_public_b64,
        p256_public_to_pem,
        p256_verify,
        receipt_mac,
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
        verify_auth_proof,
    )
    from aura_rsp.server import AuraServerState
    from aura_rsp.storage import connect, connect_trace
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "缺少 AURA 运行依赖。请在 WSL 中使用 run_demo.sh，"
        "或先运行 aura-rsp/scripts/install_deps.sh。"
        f" 原始错误: {exc}"
    ) from exc


LANG = {
    "zh": {
        "title": "实验4：票据双花、重放识别与条件追踪",
        "scenario": "场景",
        "auth": "认证结果",
        "profile": "Profile安装",
        "second": "第二次业务执行",
        "trace": "触发追踪",
        "identity": "身份结果",
        "single": "4A 正常单次使用",
        "replay": "4B 完全相同报文重传",
        "double": "4C 两个不同有效转录",
        "accepted": "通过",
        "rejected": "拒绝",
        "installed": "已安装",
        "first_installed": "首笔已安装",
        "yes": "是",
        "no": "否",
        "anonymous": "保持匿名",
        "correct": "恢复正确EID",
        "cached": "缓存/幂等",
        "conclusion": (
            "正常使用保持匿名；逐字节重传被幂等处理；只有同一 nu 下的第二份不同有效转录"
            "才触发追踪，且第二次业务执行被拒绝。"
        ),
    },
    "en": {
        "title": "Experiment 4: Ticket Double Spending, Replay, and Conditional Tracing",
        "scenario": "Scenario",
        "auth": "Authentication",
        "profile": "Profile install",
        "second": "Second execution",
        "trace": "Tracing",
        "identity": "Identity outcome",
        "single": "4A Normal single use",
        "replay": "4B Exact message replay",
        "double": "4C Two distinct valid transcripts",
        "accepted": "accepted",
        "rejected": "rejected",
        "installed": "installed",
        "first_installed": "first installed",
        "yes": "yes",
        "no": "no",
        "anonymous": "anonymous",
        "correct": "correct EID recovered",
        "cached": "cached/idempotent",
        "conclusion": (
            "Normal use remains anonymous; a byte-identical replay is idempotent; only a "
            "second distinct valid transcript under the same nu triggers tracing, while "
            "the second business execution is rejected."
        ),
    },
}


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
    ticket: dict[str, Any]
    eta: int
    d_value: int
    signature: Any


def load_json(path: Path) -> dict[str, Any]:
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
        raise ValueError(f"output must remain under {results_root}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "paper"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def issue_credential(
    *,
    eid: str,
    x: int,
    k: int,
    cred_exp: int,
    eum_sk: int,
    eum_pk: Any,
) -> Device:
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
        raise RuntimeError("device credential issuance failed")
    return Device("malicious-eUICC", eid, x, k, cred_exp, signature)


def issue_ticket(
    *,
    seed: int,
    label: str,
    owner_x: int,
    mno_sk: int,
    mno_pk: Any,
    aura: dict[str, Any],
    profile_sha256: str,
) -> TicketBundle:
    ticket = {
        "I_ac": "IAC-" + hashlib.sha256(
            f"{seed}:{label}:iac".encode("utf-8")
        ).hexdigest()[:32].upper(),
        "sid": aura["sid"],
        "pid_h": profile_sha256,
        "op": "download",
        "exp": int(time.time()) + int(aura["ticket_valid_seconds"]),
        "PRaddr": aura["praddr"],
    }
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": ticket}
    commitment, user_blinding = create_blind_commitment(
        TOKEN_PARAMS, {6: owner_x, 7: eta, 8: d_value}, context
    )
    blind_signature = blind_sign(
        TOKEN_PARAMS,
        mno_sk,
        commitment,
        {i: value for i, value in enumerate(token_public_messages(ticket))},
        context,
    )
    signature = finalize_blind_signature(blind_signature, user_blinding)
    if not verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(ticket, owner_x, eta, d_value),
        signature,
    ):
        raise RuntimeError("operation-ticket issuance failed")
    return TicketBundle(ticket, eta, d_value, signature)


def create_server(
    *,
    root: Path,
    config: dict[str, Any],
    profile: bytes,
    eum_pk: Any,
    mno_pk: Any,
    device: Device,
    trace_salt: bytes,
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
    with closing(connect_trace(root / "runtime" / "eum-trace.sqlite")) as trace_db:
        trace_db.execute(
            "INSERT INTO trace_index(k,eid,r_tr) VALUES(?,?,?)",
            (scalar_to_b64(device.k), device.eid, b64e(trace_salt)),
        )
        trace_db.commit()
    return AuraServerState(root)


def prepare_auth(
    *,
    server: AuraServerState,
    config: dict[str, Any],
    seed: int,
    context_label: str,
    salt_label: str,
    device: Device,
    ticket: TicketBundle,
) -> dict[str, Any]:
    aura = config["aura"]
    init_status, init_response = server.initiate(
        {
            "matchingId": aura["matching_id"],
            "N_U": b64e(seeded_bytes(seed, f"{context_label}:N_U", 32)),
            "capabilities": aura["capabilities"],
        },
        aura["praddr"],
    )
    if init_status != 200:
        raise RuntimeError(f"initiate failed: {init_status} {init_response}")
    server_auth = init_response["serverAuth"]
    salt_p = seeded_bytes(seed, salt_label, 32)
    salt_p_b64 = b64e(salt_p)
    one_time_private = generate_ed25519_private()
    vk_t = ed25519_public_b64(one_time_private.public_key())
    v = g1_to_b64(multiply(proof_module.G_V, ticket.eta))
    lph = g1_to_b64(
        multiply(lph_base(ticket.ticket["pid_h"], salt_p), device.x)
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
        "ticket": ticket.ticket,
        "cred_exp": device.cred_exp,
        "salt_p": salt_p_b64,
        "lph": lph,
        "v": v,
        "opid": b64e(seeded_bytes(seed, f"{context_label}:opid", 16)),
        "vk_t_hash": hashlib.sha256(b64d(vk_t)).hexdigest(),
    }
    return {
        "ctx_t": ctx_t,
        "salt_p": salt_p,
        "salt_p_b64": salt_p_b64,
        "transaction_id": server_auth["transactionId"],
        "vk_t": vk_t,
        "one_time_private": one_time_private,
        "server_auth": server_auth,
    }


def build_auth(
    *,
    context: dict[str, Any],
    device: Device,
    ticket: TicketBundle,
    eum_pk: Any,
    mno_pk: Any,
) -> tuple[dict[str, Any], dict[str, Any], float]:
    started = time.perf_counter()
    proof = create_auth_proof(
        ctx_t=context["ctx_t"],
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        cred_signature=device.credential_signature,
        token_signature=ticket.signature,
        x=device.x,
        k=device.k,
        eta=ticket.eta,
        d_value=ticket.d_value,
        cred_exp=device.cred_exp,
        salt_p=context["salt_p"],
    )
    prove_ms = (time.perf_counter() - started) * 1000
    tau_payload = {
        "domain": "AURA-RSP-v14:tau_auth",
        "ctx_t": context["ctx_t"],
        "proof_hash": sha256_hex(canonical(proof)),
    }
    request = {
        "transactionId": context["transaction_id"],
        "ctx_t": context["ctx_t"],
        "salt_p": context["salt_p_b64"],
        "vk_t": context["vk_t"],
        "tau_auth": ed25519_sign(context["one_time_private"], tau_payload),
        "Pi_auth": proof,
    }
    return proof, request, prove_ms


def independently_verify(
    context: dict[str, Any],
    proof: dict[str, Any],
    eum_pk: Any,
    mno_pk: Any,
) -> tuple[bool, str]:
    return verify_auth_proof(
        ctx_t=context["ctx_t"],
        proof=proof,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=context["salt_p"],
    )


def complete_profile(
    *,
    server: AuraServerState,
    config: dict[str, Any],
    context: dict[str, Any],
    auth_response: dict[str, Any],
    expected_profile_sha256: str,
) -> dict[str, Any]:
    client_ephemeral = generate_p256_private()
    key_request = {
        "transactionId": context["transaction_id"],
        "Bind_t": auth_response["Bind_t"],
        "ctx_bind": auth_response["ctx_bind"],
        "clientEphemeral": p256_public_b64(client_ephemeral.public_key()),
        "cap": context["server_auth"]["cap"],
        "vk_t": context["vk_t"],
    }
    key_request["clientSignature"] = ed25519_sign(
        context["one_time_private"], dict(key_request)
    )
    profile_status, profile_response = server.get_profile(
        key_request, config["aura"]["praddr"]
    )
    if profile_status != 200:
        raise RuntimeError(f"profile delivery failed: {profile_status} {profile_response}")
    ctx_k = profile_response["ctx_K"]
    signed_response = {
        "ctx_K": ctx_k,
        "nonce": profile_response["nonce"],
        "ciphertext_hash": hashlib.sha256(
            b64d(profile_response["ciphertext"])
        ).hexdigest(),
        "profile_sha256": profile_response["profileSha256"],
    }
    server_signature_valid = p256_verify(
        server.profile_binding_key.public_key(),
        signed_response,
        profile_response["serverSignature"],
    )
    k_enc, k_mac = derive_session_keys(
        client_ephemeral, ctx_k["serverEphemeral"], ctx_k
    )
    aad = {
        "ctx_K": ctx_k,
        "profile_sha256": profile_response["profileSha256"],
    }
    profile = decrypt_profile(
        k_enc,
        profile_response["nonce"],
        profile_response["ciphertext"],
        aad,
    )
    profile_sha256 = hashlib.sha256(profile).hexdigest()
    receipt_fields = {
        "transactionId": context["transaction_id"],
        "profileSha256": profile_sha256,
        "status": "installed",
        "counter": 1,
    }
    notification_status, notification_response = server.notification(
        {**receipt_fields, "mac": receipt_mac(k_mac, receipt_fields)},
        config["aura"]["praddr"],
    )
    return {
        "profile_status": profile_status,
        "profile_bytes": len(profile),
        "profile_sha256": profile_sha256,
        "profile_digest_matches_order": profile_sha256 == expected_profile_sha256,
        "server_signature_valid": server_signature_valid,
        "notification_status": notification_status,
        "notification_response": notification_response,
        "installed": notification_status == 204,
        "profile": profile,
    }


def read_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def database_snapshot(root: Path) -> dict[str, Any]:
    with closing(connect(root / "runtime" / "aura.sqlite")) as db:
        sessions = [
            dict(row)
            for row in db.execute(
                "SELECT transaction_id,status,bind_t,profile_sha256 FROM sessions "
                "ORDER BY created_at,transaction_id"
            ).fetchall()
        ]
        nullifiers = [
            dict(row)
            for row in db.execute(
                "SELECT v,auth_hash,gamma,c_value,transaction_id FROM used_nullifiers"
            ).fetchall()
        ]
        traces = [
            dict(row)
            for row in db.execute(
                "SELECT v,recovered_k,eid,first_transaction_id,"
                "second_transaction_id FROM traces ORDER BY id"
            ).fetchall()
        ]
        notifications = [
            dict(row)
            for row in db.execute(
                "SELECT transaction_id,receipt_json FROM notifications"
            ).fetchall()
        ]
    return {
        "sessions": sessions,
        "used_nullifiers": nullifiers,
        "traces": traces,
        "notifications": notifications,
        "counts": {
            "sessions": len(sessions),
            "used_nullifiers": len(nullifiers),
            "traces": len(traces),
            "notifications": len(notifications),
            "business_execution_count": sum(
                row["status"] in ("authenticated", "downloaded", "installed")
                for row in sessions
            ),
        },
    }


def add_event(
    events: list[dict[str, Any]],
    *,
    scenario: str,
    step: str,
    result: str,
    reason: str,
    **fields: Any,
) -> None:
    events.append(
        {
            "event_index": len(events) + 1,
            "protocol_mode": "aura_rsp",
            "scenario": scenario,
            "step": step,
            "result": result,
            "reason": reason,
            **fields,
        }
    )


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


def run_experiment(
    *,
    config: dict[str, Any],
    output: Path,
    profile: bytes,
    eum_sk: int,
    eum_pk: Any,
    mno_sk: int,
    mno_pk: Any,
    device: Device,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    seed = int(config["seed"])
    profile_sha256 = hashlib.sha256(profile).hexdigest()
    trace_salt = seeded_bytes(seed, "malicious-device:r_tr", 32)
    roots: dict[str, Path] = {}
    server_logs: dict[str, list[dict[str, Any]]] = {}

    work_parent = output / ".work"
    work_parent.mkdir()
    with tempfile.TemporaryDirectory(prefix="exp04-", dir=work_parent) as temporary:
        temporary_root = Path(temporary)

        # 4A: one new nullifier, one complete profile execution, no trace.
        roots["4a"] = temporary_root / "4a"
        server_4a = create_server(
            root=roots["4a"],
            config=config,
            profile=profile,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            device=device,
            trace_salt=trace_salt,
        )
        ticket_4a = issue_ticket(
            seed=seed,
            label="4a",
            owner_x=device.x,
            mno_sk=mno_sk,
            mno_pk=mno_pk,
            aura=config["aura"],
            profile_sha256=profile_sha256,
        )
        context_4a = prepare_auth(
            server=server_4a,
            config=config,
            seed=seed,
            context_label="4a-single",
            salt_label="4a-profile-salt",
            device=device,
            ticket=ticket_4a,
        )
        proof_4a, request_4a, prove_4a_ms = build_auth(
            context=context_4a,
            device=device,
            ticket=ticket_4a,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )
        proof_4a_valid, proof_4a_reason = independently_verify(
            context_4a, proof_4a, eum_pk, mno_pk
        )
        auth_4a_started = time.perf_counter()
        status_4a, response_4a = server_4a.authenticate(
            request_4a, config["aura"]["praddr"]
        )
        auth_4a_ms = (time.perf_counter() - auth_4a_started) * 1000
        profile_4a = complete_profile(
            server=server_4a,
            config=config,
            context=context_4a,
            auth_response=response_4a,
            expected_profile_sha256=profile_sha256,
        )
        (output / "evidence" / "4a-downloaded-profile.der").write_bytes(
            profile_4a.pop("profile")
        )
        snapshot_4a = database_snapshot(roots["4a"])
        server_logs["4a"] = read_log(roots["4a"] / "logs" / "aura-smdpp.jsonl")
        public_4a = canonical(
            {"request": request_4a, "response": response_4a}
        ).decode("utf-8")
        eid_visible_4a = device.eid in public_4a
        add_event(
            events,
            scenario="4A_normal_single_use",
            step="authenticate_download_install",
            result="accepted" if status_4a == 200 and profile_4a["installed"] else "failed",
            reason="ok" if status_4a == 200 else response_4a.get("error", ""),
            http_status=status_4a,
            proof_valid=proof_4a_valid,
            proof_reason=proof_4a_reason,
            profile_installed=profile_4a["installed"],
            trace_triggered=False,
            stable_eid_exposed=eid_visible_4a,
            business_execution_count=snapshot_4a["counts"]["business_execution_count"],
        )

        # 4B: byte-identical request replay after the original business completes.
        roots["4b"] = temporary_root / "4b"
        server_4b = create_server(
            root=roots["4b"],
            config=config,
            profile=profile,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            device=device,
            trace_salt=trace_salt,
        )
        ticket_4b = issue_ticket(
            seed=seed,
            label="4b",
            owner_x=device.x,
            mno_sk=mno_sk,
            mno_pk=mno_pk,
            aura=config["aura"],
            profile_sha256=profile_sha256,
        )
        context_4b = prepare_auth(
            server=server_4b,
            config=config,
            seed=seed,
            context_label="4b-replay",
            salt_label="4b-profile-salt",
            device=device,
            ticket=ticket_4b,
        )
        proof_4b, request_4b, prove_4b_ms = build_auth(
            context=context_4b,
            device=device,
            ticket=ticket_4b,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )
        proof_4b_valid, proof_4b_reason = independently_verify(
            context_4b, proof_4b, eum_pk, mno_pk
        )
        status_4b_first, response_4b_first = server_4b.authenticate(
            request_4b, config["aura"]["praddr"]
        )
        profile_4b = complete_profile(
            server=server_4b,
            config=config,
            context=context_4b,
            auth_response=response_4b_first,
            expected_profile_sha256=profile_sha256,
        )
        profile_4b.pop("profile")
        original_bytes = canonical(request_4b)
        replay_bytes = bytes(original_bytes)
        replay_request = json.loads(replay_bytes.decode("utf-8"))
        replay_started = time.perf_counter()
        status_4b_replay, response_4b_replay = server_4b.authenticate(
            replay_request, config["aura"]["praddr"]
        )
        replay_ms = (time.perf_counter() - replay_started) * 1000
        snapshot_4b = database_snapshot(roots["4b"])
        server_logs["4b"] = read_log(roots["4b"] / "logs" / "aura-smdpp.jsonl")
        add_event(
            events,
            scenario="4B_exact_auth_replay",
            step="byte_identical_replay",
            result="cached" if response_4b_replay.get("replayed") else "failed",
            reason="exact_replay_idempotent"
            if response_4b_replay.get("replayed")
            else response_4b_replay.get("error", ""),
            http_status=status_4b_replay,
            exact_request_bytes_equal=original_bytes == replay_bytes,
            proof_valid=proof_4b_valid,
            proof_reason=proof_4b_reason,
            same_bind_t=response_4b_first.get("Bind_t")
            == response_4b_replay.get("Bind_t"),
            second_business_execution=False,
            trace_triggered=False,
            business_execution_count=snapshot_4b["counts"]["business_execution_count"],
        )

        # 4C: malicious client bypasses LocalTicketLog and uses one ticket in two contexts.
        roots["4c"] = temporary_root / "4c"
        server_4c = create_server(
            root=roots["4c"],
            config=config,
            profile=profile,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            device=device,
            trace_salt=trace_salt,
        )
        ticket_4c = issue_ticket(
            seed=seed,
            label="4c",
            owner_x=device.x,
            mno_sk=mno_sk,
            mno_pk=mno_pk,
            aura=config["aura"],
            profile_sha256=profile_sha256,
        )
        context_4c_first = prepare_auth(
            server=server_4c,
            config=config,
            seed=seed,
            context_label="4c-first",
            salt_label="4c-shared-profile-salt",
            device=device,
            ticket=ticket_4c,
        )
        context_4c_second = prepare_auth(
            server=server_4c,
            config=config,
            seed=seed,
            context_label="4c-second",
            salt_label="4c-shared-profile-salt",
            device=device,
            ticket=ticket_4c,
        )
        proof_4c_first, request_4c_first, prove_4c_first_ms = build_auth(
            context=context_4c_first,
            device=device,
            ticket=ticket_4c,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )
        proof_4c_second, request_4c_second, prove_4c_second_ms = build_auth(
            context=context_4c_second,
            device=device,
            ticket=ticket_4c,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
        )
        valid_4c_first, reason_4c_first = independently_verify(
            context_4c_first, proof_4c_first, eum_pk, mno_pk
        )
        valid_4c_second, reason_4c_second = independently_verify(
            context_4c_second, proof_4c_second, eum_pk, mno_pk
        )
        status_4c_first, response_4c_first = server_4c.authenticate(
            request_4c_first, config["aura"]["praddr"]
        )
        profile_4c = complete_profile(
            server=server_4c,
            config=config,
            context=context_4c_first,
            auth_response=response_4c_first,
            expected_profile_sha256=profile_sha256,
        )
        profile_4c.pop("profile")
        second_started = time.perf_counter()
        status_4c_second, response_4c_second = server_4c.authenticate(
            request_4c_second, config["aura"]["praddr"]
        )
        second_ms = (time.perf_counter() - second_started) * 1000
        gamma_first = scalar_from_b64(proof_4c_first["gamma"])
        gamma_second = scalar_from_b64(proof_4c_second["gamma"])
        c_first = scalar_from_b64(proof_4c_first["c"])
        c_second = scalar_from_b64(proof_4c_second["c"])
        denominator = (gamma_first - gamma_second) % curve_order
        recovered_k_formula = (
            (c_first - c_second) * mod_inv(denominator)
        ) % curve_order
        snapshot_4c = database_snapshot(roots["4c"])
        server_logs["4c"] = read_log(roots["4c"] / "logs" / "aura-smdpp.jsonl")
        public_before_trace = canonical(
            {
                "first_request": request_4c_first,
                "first_response": response_4c_first,
                "second_request": request_4c_second,
            }
        ).decode("utf-8")
        eid_visible_before_trace = device.eid in public_before_trace
        add_event(
            events,
            scenario="4C_true_double_spend",
            step="second_distinct_valid_transcript",
            result="rejected_and_traced"
            if status_4c_second == 409 and response_4c_second.get("traceRecovered")
            else "failed",
            reason=response_4c_second.get("error", ""),
            http_status=status_4c_second,
            local_ticket_log_bypassed=True,
            same_nullifier=proof_4c_first["v"] == proof_4c_second["v"],
            different_context=context_4c_first["ctx_t"] != context_4c_second["ctx_t"],
            different_gamma=gamma_first != gamma_second,
            both_proofs_valid=valid_4c_first and valid_4c_second,
            second_business_execution=False,
            trace_triggered=response_4c_second.get("traceRecovered", False),
            recovered_eid_correct=response_4c_second.get("traceEid") == device.eid,
            stable_eid_exposed_before_trace=eid_visible_before_trace,
            business_execution_count=snapshot_4c["counts"]["business_execution_count"],
        )

        for label, rows in server_logs.items():
            write_jsonl(output / "raw" / f"aura-server-{label}.jsonl", rows)
        write_json(
            output / "raw" / "4a-auth-request.json",
            request_4a,
        )
        (output / "raw" / "4b-auth-original.canonical.json").write_bytes(
            original_bytes
        )
        (output / "raw" / "4b-auth-replay.canonical.json").write_bytes(
            replay_bytes
        )
        write_json(output / "raw" / "4c-first-auth.json", request_4c_first)
        write_json(output / "raw" / "4c-second-auth.json", request_4c_second)
        write_json(output / "evidence" / "database-4a.json", snapshot_4a)
        write_json(output / "evidence" / "database-4b.json", snapshot_4b)
        write_json(output / "evidence" / "database-4c.json", snapshot_4c)

        result = {
            "4A_normal_single_use": {
                "authentication": status_4a == 200,
                "http_status": status_4a,
                "proof_valid": proof_4a_valid,
                "proof_reason": proof_4a_reason,
                "used_nullifier_count": snapshot_4a["counts"]["used_nullifiers"],
                "trace_request_count": snapshot_4a["counts"]["traces"],
                "eum_trace_requested": snapshot_4a["counts"]["traces"] > 0,
                "smdpp_knows_eid": eid_visible_4a,
                "profile_installed": profile_4a["installed"],
                "profile": profile_4a,
                "business_execution_count": snapshot_4a["counts"][
                    "business_execution_count"
                ],
                "proof_generate_ms": round(prove_4a_ms, 3),
                "authentication_wall_ms": round(auth_4a_ms, 3),
            },
            "4B_exact_replay": {
                "first_authentication": status_4b_first == 200,
                "replay_http_status": status_4b_replay,
                "exact_request_bytes_equal": original_bytes == replay_bytes,
                "request_sha256_original": hashlib.sha256(original_bytes).hexdigest(),
                "request_sha256_replay": hashlib.sha256(replay_bytes).hexdigest(),
                "replayed_flag": response_4b_replay.get("replayed", False),
                "same_cached_bind_t": response_4b_first.get("Bind_t")
                == response_4b_replay.get("Bind_t"),
                "proof_valid": proof_4b_valid,
                "proof_reason": proof_4b_reason,
                "used_nullifier_count": snapshot_4b["counts"]["used_nullifiers"],
                "trace_request_count": snapshot_4b["counts"]["traces"],
                "eum_trace_requested": snapshot_4b["counts"]["traces"] > 0,
                "profile_installed_once": profile_4b["installed"],
                "profile_delivery_count": sum(
                    row["event"] == "getBoundProfilePackage"
                    for row in server_logs["4b"]
                ),
                "second_business_execution": False,
                "business_execution_count": snapshot_4b["counts"][
                    "business_execution_count"
                ],
                "proof_generate_ms": round(prove_4b_ms, 3),
                "replay_wall_ms": round(replay_ms, 3),
            },
            "4C_true_double_spend": {
                "local_ticket_log_bypassed": True,
                "same_ticket_eta_and_d": True,
                "same_nullifier": proof_4c_first["v"] == proof_4c_second["v"],
                "different_context": context_4c_first["ctx_t"]
                != context_4c_second["ctx_t"],
                "different_opid": context_4c_first["ctx_t"]["opid"]
                != context_4c_second["ctx_t"]["opid"],
                "different_gamma": gamma_first != gamma_second,
                "different_c": c_first != c_second,
                "first_proof_valid": valid_4c_first,
                "first_proof_reason": reason_4c_first,
                "second_proof_valid": valid_4c_second,
                "second_proof_reason": reason_4c_second,
                "first_authentication": status_4c_first == 200,
                "first_profile_installed": profile_4c["installed"],
                "second_http_status": status_4c_second,
                "second_error": response_4c_second.get("error"),
                "second_business_execution": False,
                "business_execution_count": snapshot_4c["counts"][
                    "business_execution_count"
                ],
                "used_nullifier_count": snapshot_4c["counts"]["used_nullifiers"],
                "duplicate_nu_detected": snapshot_4c["counts"]["traces"] == 1,
                "trace_request_count": snapshot_4c["counts"]["traces"],
                "trace_success": response_4c_second.get("traceRecovered", False),
                "recovered_eid": response_4c_second.get("traceEid"),
                "recovered_eid_matches_malicious_device": response_4c_second.get(
                    "traceEid"
                )
                == device.eid,
                "recovered_k_formula": scalar_to_b64(recovered_k_formula),
                "recovered_k_server": response_4c_second.get("recoveredK"),
                "recovered_k_matches_formula": response_4c_second.get("recoveredK")
                == scalar_to_b64(recovered_k_formula),
                "recovered_k_matches_device": recovered_k_formula == device.k,
                "smdpp_knows_eid_before_trace": eid_visible_before_trace,
                "proof_generate_first_ms": round(prove_4c_first_ms, 3),
                "proof_generate_second_ms": round(prove_4c_second_ms, 3),
                "second_authentication_wall_ms": round(second_ms, 3),
            },
        }

        del server_4a, server_4b, server_4c
        gc.collect()

    work_parent.rmdir()
    return result


def standard_comparison(device_eid: str) -> dict[str, Any]:
    return {
        "method": "controlled_standard_protocol_visibility_comparison",
        "authentication_log_fields": [
            "EID",
            "eUICC_certificate",
            "certificate_fingerprint",
            "public_key_fingerprint",
        ],
        "identity_known_from_first_transaction": True,
        "stable_eid_or_certificate_exposed": True,
        "normal_anonymity_then_conditional_trace_distinction": False,
        "server_observed_eid": device_eid,
        "security_interpretation": (
            "This is expected stable-identity authentication behavior, not a "
            "Standard RSP message-integrity vulnerability."
        ),
    }


def outcomes_svg(report: dict[str, Any], language: str) -> str:
    t = LANG[language]
    width, height = 1800, 1080
    scenarios = [
        (t["single"], [0, 0, 0, 0]),
        (t["replay"], [0, 0, 0, 0]),
        (t["double"], [0, 1, 1, 0]),
    ]
    metric_labels = (
        ["第二次业务执行", "触发条件追踪", "正确EID恢复", "误追踪"]
        if language == "zh"
        else ["Second execution", "Conditional trace", "Correct EID recovery", "False trace"]
    )
    colors = ["#dc2626", "#2563eb", "#16a34a", "#f59e0b"]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="900" y="72" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="44" font-weight="700">{xml(t["title"])}</text>',
        f'<text x="900" y="125" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="26" fill="#4b5563">{xml("1 = 是，0 = 否" if language == "zh" else "1 = yes, 0 = no")}</text>',
    ]
    left, top, chart_h, baseline = 150, 220, 560, 780
    for tick in (0, 0.5, 1):
        y = baseline - tick * chart_h
        svg.append(
            f'<line x1="{left}" y1="{y}" x2="1730" y2="{y}" stroke="#d1d5db" stroke-width="2"/>'
        )
        svg.append(
            f'<text x="120" y="{y+9}" text-anchor="end" font-family="Arial,sans-serif" font-size="25">{tick:.1f}</text>'
        )
    centers = [400, 900, 1400]
    for scenario_index, (label, values) in enumerate(scenarios):
        center = centers[scenario_index]
        for metric_index, value in enumerate(values):
            x = center + (metric_index - 1.5) * 90 - 34
            y = baseline - value * chart_h
            if value:
                svg.append(
                    f'<rect x="{x}" y="{y}" width="68" height="{value*chart_h}" rx="5" fill="{colors[metric_index]}"/>'
                )
            svg.append(
                f'<text x="{x+34}" y="{y-13}" text-anchor="middle" font-family="Arial,sans-serif" font-size="27" font-weight="700">{value}</text>'
            )
        svg.append(
            f'<text x="{center}" y="840" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="27" font-weight="600">{xml(label)}</text>'
        )
    for index, label in enumerate(metric_labels):
        x = 135 + index * 410
        svg.append(
            f'<rect x="{x}" y="930" width="34" height="34" fill="{colors[index]}"/>'
        )
        svg.append(
            f'<text x="{x+50}" y="957" font-family="Arial,Microsoft YaHei,sans-serif" font-size="24">{xml(label)}</text>'
        )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def trace_flow_svg(language: str) -> str:
    zh = language == "zh"
    title = (
        "AURA-RSP：精确重传与真双花的分流"
        if zh
        else "AURA-RSP: Exact Replay vs. True Double Spend"
    )
    labels = (
        {
            "first": "首次有效转录\n(nu, gamma, c, proof)",
            "store": "写入UsedNullifier\n业务执行一次",
            "replay": "相同auth_hash\n返回缓存结果\n不追踪",
            "double": "同nu、不同有效转录\n恢复 k",
            "formula": "k=(c-c')/(gamma-gamma') mod q\nEUM查询 L_tr[k]",
            "result": "拒绝第二次执行\n恢复违规EID",
            "same": "逐字节相同",
            "different": "上下文不同且证明有效",
        }
        if zh
        else {
            "first": "First valid transcript\n(nu, gamma, c, proof)",
            "store": "Store UsedNullifier\nexecute business once",
            "replay": "Same auth_hash\nreturn cached result\nno tracing",
            "double": "Same nu, distinct valid transcript\nrecover k",
            "formula": "k=(c-c')/(gamma-gamma') mod q\nEUM lookup L_tr[k]",
            "result": "Reject second execution\nrecover offending EID",
            "same": "byte-identical",
            "different": "different context, valid proof",
        }
    )
    width, height = 2300, 1100
    boxes = [
        (80, 390, 360, 150, labels["first"], "#dbeafe", "#2563eb"),
        (610, 390, 360, 150, labels["store"], "#dcfce7", "#16a34a"),
        (1160, 180, 400, 170, labels["replay"], "#f3f4f6", "#4b5563"),
        (1160, 620, 430, 170, labels["double"], "#fef3c7", "#d97706"),
        (1720, 620, 500, 170, labels["formula"], "#fee2e2", "#dc2626"),
        (1720, 860, 500, 150, labels["result"], "#ede9fe", "#7c3aed"),
    ]
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs><marker id="arrow" markerWidth="14" markerHeight="10" refX="12" refY="5" orient="auto"><path d="M0,0 L14,5 L0,10 z" fill="#4b5563"/></marker></defs>',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="1150" y="80" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="45" font-weight="700">{xml(title)}</text>',
    ]
    for x, y, w, h, label, fill, stroke in boxes:
        svg.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        )
        lines = label.split("\n")
        start = y + h / 2 - (len(lines) - 1) * 20
        for i, line in enumerate(lines):
            svg.append(
                f'<text x="{x+w/2}" y="{start+i*40}" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="27" font-weight="600">{xml(line)}</text>'
            )
    arrows = [
        (440, 465, 610, 465),
        (970, 435, 1160, 265),
        (970, 505, 1160, 705),
        (1590, 705, 1720, 705),
        (1970, 790, 1970, 860),
    ]
    for x1, y1, x2, y2 in arrows:
        svg.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2-8 if x1 != x2 else x2}" y2="{y2-8 if x1 == x2 else y2}" stroke="#4b5563" stroke-width="4" marker-end="url(#arrow)"/>'
        )
    svg.append(
        f'<text x="1060" y="300" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="23" fill="#374151">{xml(labels["same"])}</text>'
    )
    svg.append(
        f'<text x="1050" y="620" text-anchor="middle" font-family="Arial,Microsoft YaHei,sans-serif" font-size="23" fill="#374151">{xml(labels["different"])}</text>'
    )
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def write_paper_outputs(output: Path, report: dict[str, Any]) -> None:
    paper = output / "paper"
    for language in ("zh", "en"):
        t = LANG[language]
        (paper / f"figure-1-scenario-outcomes-{language}.svg").write_text(
            outcomes_svg(report, language), encoding="utf-8"
        )
        (paper / f"figure-2-replay-double-spend-flow-{language}.svg").write_text(
            trace_flow_svg(language), encoding="utf-8"
        )
        rows = [
            {
                t["scenario"]: t["single"],
                t["auth"]: t["accepted"],
                t["profile"]: t["installed"],
                t["second"]: t["no"],
                t["trace"]: t["no"],
                t["identity"]: t["anonymous"],
            },
            {
                t["scenario"]: t["replay"],
                t["auth"]: t["cached"],
                t["profile"]: t["installed"],
                t["second"]: t["no"],
                t["trace"]: t["no"],
                t["identity"]: t["anonymous"],
            },
            {
                t["scenario"]: t["double"],
                t["auth"]: t["rejected"],
                t["profile"]: t["first_installed"],
                t["second"]: t["no"],
                t["trace"]: t["yes"],
                t["identity"]: t["correct"],
            },
        ]
        write_csv(paper / f"table-1-double-spend-results-{language}.csv", rows)
        caption = (
            "图1  AURA-RSP三种票据使用场景。正常使用只执行一次业务且不暴露EID；"
            "完全相同认证报文重传返回缓存结果，不重复下载、不触发追踪；同一nu下第二份"
            "不同且有效的转录被拒绝，服务器仅在此时通过EUM恢复正确EID。图2给出服务端"
            "基于auth_hash和nu的分流以及条件追踪公式。"
            if language == "zh"
            else
            "Figure 1. Three AURA-RSP ticket-use cases. Normal use executes the "
            "business once without revealing EID. A byte-identical authentication "
            "replay returns a cached result without another download or trace. A "
            "second distinct valid transcript under the same nu is rejected and only "
            "then causes the EUM lookup to recover the correct EID. Figure 2 shows the "
            "auth_hash/nu branch and conditional tracing equation."
        )
        (paper / f"captions-and-analysis-{language}.txt").write_text(
            caption + "\n", encoding="utf-8"
        )


def summary_markdown(report: dict[str, Any]) -> str:
    a = report["aura"]
    return f"""# 实验4：票据双花、重放识别与条件追踪

状态：**{report["status"]}**

| 场景 | 第二次业务执行 | 追踪 | 身份结果 | business_execution_count |
|---|---:|---:|---|---:|
| 4A 正常单次使用 | 否 | 否 | SM-DP+不知道EID | {a["4A_normal_single_use"]["business_execution_count"]} |
| 4B 完全相同报文重传 | 否 | 否 | SM-DP+不知道EID | {a["4B_exact_replay"]["business_execution_count"]} |
| 4C 两个不同有效转录 | 否 | 是 | 恢复正确EID | {a["4C_true_double_spend"]["business_execution_count"]} |

## 核心结果

- `trace_success = {str(a["4C_true_double_spend"]["trace_success"]).lower()}`
- `recovered_eid == malicious_device_eid = {str(a["4C_true_double_spend"]["recovered_eid_matches_malicious_device"]).lower()}`
- `false_trace_count = {report["metrics"]["false_trace_count"]}`
- `business_execution_count = {a["4C_true_double_spend"]["business_execution_count"]}`
- `k`公式恢复与设备追踪标量一致：{a["4C_true_double_spend"]["recovered_k_matches_device"]}

## 解释边界

AURA部分真实调用当前BBS+凭证/票据、匿名证明、nullifier数据库、条件追踪、
P-256 ECDHE、HKDF、AES-GCM和安装通知代码。EUM查询由隔离的本地追踪数据库模拟。
Standard对照只说明服务器从首次标准认证即能看到稳定EID/证书，这是预期身份认证行为，
不是Standard RSP消息完整性漏洞。
"""


def print_summary(report: dict[str, Any], language: str) -> None:
    t = LANG[language]
    a = report["aura"]
    line = "=" * 118
    print(line)
    print(t["title"])
    print(f'Status / 状态: [{report["status"]}]')
    print(line)
    print(
        f'{t["scenario"]:<38} {t["auth"]:<18} {t["profile"]:<18} '
        f'{t["second"]:<20} {t["trace"]:<14} {t["identity"]:<22}'
    )
    print("-" * 118)
    rows = [
        (t["single"], t["accepted"], t["installed"], t["no"], t["no"], t["anonymous"]),
        (t["replay"], t["cached"], t["installed"], t["no"], t["no"], t["anonymous"]),
        (
            t["double"],
            t["rejected"],
            t["first_installed"],
            t["no"],
            t["yes"],
            t["correct"],
        ),
    ]
    for row in rows:
        print(
            f"{row[0]:<38} {row[1]:<18} {row[2]:<18} "
            f"{row[3]:<20} {row[4]:<14} {row[5]:<22}"
        )
    print("-" * 118)
    print(f'trace_success: {a["4C_true_double_spend"]["trace_success"]}')
    print(
        "recovered_eid == malicious_device_eid: "
        f'{a["4C_true_double_spend"]["recovered_eid_matches_malicious_device"]}'
    )
    print(f'false_trace_count: {report["metrics"]["false_trace_count"]}')
    print(
        "business_execution_count (4C): "
        f'{a["4C_true_double_spend"]["business_execution_count"]}'
    )
    print(t["conclusion"])
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
    experiment_root = Path(__file__).resolve().parent
    workspace_root = experiment_root.parents[1]
    output = prepare_output(args.output, experiment_root)
    config = load_json(args.config.resolve())
    seed = int(config["seed"])
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

    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    x = random_scalar(nonzero=True)
    eid = config["malicious_device_eid"]
    trace_salt = seeded_bytes(seed, "malicious-device:r_tr", 32)
    k = hash_to_scalar("AURA-RSP-v14:H_tr", eid.encode("ascii") + trace_salt)
    device = issue_credential(
        eid=eid,
        x=x,
        k=k,
        cred_exp=int(time.time()) + int(config["aura"]["credential_valid_seconds"]),
        eum_sk=eum_sk,
        eum_pk=eum_pk,
    )
    events: list[dict[str, Any]] = []
    aura = run_experiment(
        config=config,
        output=output,
        profile=profile,
        eum_sk=eum_sk,
        eum_pk=eum_pk,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        device=device,
        events=events,
    )
    standard = standard_comparison(eid)
    false_trace_count = (
        aura["4A_normal_single_use"]["trace_request_count"]
        + aura["4B_exact_replay"]["trace_request_count"]
        + int(
            aura["4C_true_double_spend"]["trace_success"]
            and not aura["4C_true_double_spend"][
                "recovered_eid_matches_malicious_device"
            ]
        )
    )

    assertions: list[dict[str, Any]] = []
    a4 = aura["4A_normal_single_use"]
    b4 = aura["4B_exact_replay"]
    c4 = aura["4C_true_double_spend"]
    check(assertions, "4a_proof_is_valid", a4["proof_valid"], a4["proof_reason"], "ok")
    check(
        assertions,
        "4a_single_use_authenticates_and_installs_profile",
        a4["authentication"] and a4["profile_installed"],
        {"auth": a4["authentication"], "installed": a4["profile_installed"]},
        {"auth": True, "installed": True},
    )
    check(
        assertions,
        "4a_used_nullifier_once_without_trace",
        a4["used_nullifier_count"] == 1 and a4["trace_request_count"] == 0,
        {"used": a4["used_nullifier_count"], "trace": a4["trace_request_count"]},
        {"used": 1, "trace": 0},
    )
    check(
        assertions,
        "4a_smdpp_does_not_see_eid",
        not a4["smdpp_knows_eid"],
        a4["smdpp_knows_eid"],
        False,
    )
    check(
        assertions,
        "4b_attack_proxy_replays_identical_bytes",
        b4["exact_request_bytes_equal"]
        and b4["request_sha256_original"] == b4["request_sha256_replay"],
        {
            "equal": b4["exact_request_bytes_equal"],
            "original": b4["request_sha256_original"],
            "replay": b4["request_sha256_replay"],
        },
        "identical canonical bytes and SHA-256",
    )
    check(
        assertions,
        "4b_exact_replay_returns_cached_bind_t",
        b4["replay_http_status"] == 200
        and b4["replayed_flag"]
        and b4["same_cached_bind_t"],
        {
            "http": b4["replay_http_status"],
            "replayed": b4["replayed_flag"],
            "same_bind_t": b4["same_cached_bind_t"],
        },
        {"http": 200, "replayed": True, "same_bind_t": True},
    )
    check(
        assertions,
        "4b_no_second_download_or_business_execution",
        b4["profile_delivery_count"] == 1
        and not b4["second_business_execution"]
        and b4["business_execution_count"] == 1,
        {
            "profile_delivery_count": b4["profile_delivery_count"],
            "second_business_execution": b4["second_business_execution"],
            "business_execution_count": b4["business_execution_count"],
        },
        {"profile_delivery_count": 1, "business_execution_count": 1},
    )
    check(
        assertions,
        "4b_exact_replay_does_not_trace",
        b4["trace_request_count"] == 0,
        b4["trace_request_count"],
        0,
    )
    check(
        assertions,
        "4c_same_ticket_produces_same_nullifier",
        c4["same_ticket_eta_and_d"] and c4["same_nullifier"],
        {
            "same_ticket_eta_and_d": c4["same_ticket_eta_and_d"],
            "same_nullifier": c4["same_nullifier"],
        },
        True,
    )
    check(
        assertions,
        "4c_transcripts_are_distinct",
        c4["different_context"]
        and c4["different_opid"]
        and c4["different_gamma"]
        and c4["different_c"],
        {
            "context": c4["different_context"],
            "opid": c4["different_opid"],
            "gamma": c4["different_gamma"],
            "c": c4["different_c"],
        },
        "all distinct",
    )
    check(
        assertions,
        "4c_both_anonymous_proofs_are_valid",
        c4["first_proof_valid"] and c4["second_proof_valid"],
        {
            "first": c4["first_proof_reason"],
            "second": c4["second_proof_reason"],
        },
        {"first": "ok", "second": "ok"},
    )
    check(
        assertions,
        "4c_second_execution_is_rejected",
        c4["second_http_status"] == 409
        and c4["second_error"] == "DOUBLE_SPEND_DETECTED"
        and not c4["second_business_execution"]
        and c4["business_execution_count"] == 1,
        {
            "http": c4["second_http_status"],
            "error": c4["second_error"],
            "second_execution": c4["second_business_execution"],
            "business_execution_count": c4["business_execution_count"],
        },
        {
            "http": 409,
            "error": "DOUBLE_SPEND_DETECTED",
            "second_execution": False,
            "business_execution_count": 1,
        },
    )
    check(
        assertions,
        "4c_formula_recovers_device_trace_scalar",
        c4["recovered_k_matches_formula"] and c4["recovered_k_matches_device"],
        {
            "formula": c4["recovered_k_formula"],
            "server": c4["recovered_k_server"],
            "matches_device": c4["recovered_k_matches_device"],
        },
        "formula == server == device k",
    )
    check(
        assertions,
        "4c_eum_recovers_correct_malicious_eid",
        c4["trace_success"] and c4["recovered_eid_matches_malicious_device"],
        {
            "trace_success": c4["trace_success"],
            "recovered_eid_matches": c4[
                "recovered_eid_matches_malicious_device"
            ],
        },
        {"trace_success": True, "recovered_eid_matches": True},
    )
    check(
        assertions,
        "no_eid_before_conditional_trace",
        not c4["smdpp_knows_eid_before_trace"],
        c4["smdpp_knows_eid_before_trace"],
        False,
    )
    check(
        assertions,
        "false_trace_count_is_zero",
        false_trace_count == 0,
        false_trace_count,
        0,
    )
    check(
        assertions,
        "standard_identity_is_known_from_first_transaction",
        standard["identity_known_from_first_transaction"]
        and not standard["normal_anonymity_then_conditional_trace_distinction"],
        standard,
        "stable identity known from first transaction",
    )

    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    report = {
        "experiment": config["experiment_name"],
        "status": status,
        "seed": seed,
        "scope": {
            "aura": (
                "real BBS+ credential/ticket proofs, UsedNullifier replay branch, "
                "double-spend tracing, ECDHE/HKDF/AEAD profile install"
            ),
            "standard": "controlled stable-identity visibility comparison",
            "eum_trace_deployment": "isolated in-process SQLite lookup for research demo",
            "existing_protocol_source_modified": False,
        },
        "profile": {"bytes": len(profile), "sha256": profile_sha256},
        "aura": aura,
        "standard": standard,
        "metrics": {
            "trace_success": c4["trace_success"],
            "recovered_eid_equals_malicious_device_eid": c4[
                "recovered_eid_matches_malicious_device"
            ],
            "false_trace_count": false_trace_count,
            "business_execution_count": c4["business_execution_count"],
        },
        "assertions": assertions,
        "execution_ms": round((time.perf_counter() - started) * 1000, 3),
        "results_directory": str(output),
    }
    write_jsonl(output / "raw" / "events.jsonl", events)
    write_csv(output / "raw" / "events.csv", events)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "summary.json", report)
    write_csv(
        output / "summary.csv",
        [
            {
                "scenario": "4A_normal_single_use",
                "second_business_execution": False,
                "trace_success": False,
                "false_trace_count": 0,
                "business_execution_count": a4["business_execution_count"],
                "profile_installed": a4["profile_installed"],
                "eid_exposed": a4["smdpp_knows_eid"],
            },
            {
                "scenario": "4B_exact_replay",
                "second_business_execution": b4["second_business_execution"],
                "trace_success": False,
                "false_trace_count": 0,
                "business_execution_count": b4["business_execution_count"],
                "profile_installed": b4["profile_installed_once"],
                "eid_exposed": False,
            },
            {
                "scenario": "4C_true_double_spend",
                "second_business_execution": c4["second_business_execution"],
                "trace_success": c4["trace_success"],
                "false_trace_count": false_trace_count,
                "business_execution_count": c4["business_execution_count"],
                "profile_installed": c4["first_profile_installed"],
                "eid_exposed": c4["trace_success"],
            },
        ],
    )
    (output / "summary.md").write_text(summary_markdown(report), encoding="utf-8")
    write_paper_outputs(output, report)

    machine = {
        "status": status,
        "normal_used_nullifier_count": a4["used_nullifier_count"],
        "exact_replay_idempotent": b4["replayed_flag"],
        "double_spend_detected": c4["duplicate_nu_detected"],
        "trace_success": c4["trace_success"],
        "recovered_eid_matches_malicious_device": c4[
            "recovered_eid_matches_malicious_device"
        ],
        "false_trace_count": false_trace_count,
        "business_execution_count": c4["business_execution_count"],
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
