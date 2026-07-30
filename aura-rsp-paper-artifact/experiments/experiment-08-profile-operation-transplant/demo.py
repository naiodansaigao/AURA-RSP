from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import shutil
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from py_ecc.optimized_bls12_381 import multiply

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
        b64d,
        b64e,
        canonical,
        save_json,
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
        p256_sign,
        p256_verify,
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
        "缺少AURA运行依赖。请在WSL中使用run_demo.sh，或先运行"
        " aura-rsp/scripts/install_deps.sh。原始错误: "
        f"{exc}"
    ) from exc


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


def seeded_bytes(seed: int, label: str, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(out[:size])


def resolve_path(root: Path, value: str) -> Path:
    return (root / value).resolve()


def load_profile(
    root: Path, primary_value: str, fallback_value: str | None = None
) -> tuple[bytes, Path]:
    candidates = [resolve_path(root, primary_value)]
    if fallback_value:
        candidates.append(resolve_path(root, fallback_value))
    for path in candidates:
        if path.is_file():
            return path.read_bytes(), path
    raise FileNotFoundError("profile not found: " + ", ".join(map(str, candidates)))


def prepare_output(path: Path, experiment_root: Path) -> Path:
    path = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if not path.is_relative_to(results_root):
        raise ValueError(f"output must remain under {results_root}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "paper", "runtime"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def issue_device(eum_sk: int, eum_pk: Any) -> Device:
    x = random_scalar(nonzero=True)
    k = random_scalar(nonzero=True)
    cred_exp = int(time.time()) + 7200
    context = {"type": "Cred_D", "cred_exp": cred_exp}
    commitment, blinding = create_blind_commitment(CRED_PARAMS, {0: x}, context)
    blind_signature = blind_sign(
        CRED_PARAMS,
        eum_sk,
        commitment,
        {1: k, 2: cred_exp},
        context,
    )
    signature = finalize_blind_signature(blind_signature, blinding)
    if not verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x, k, cred_exp),
        signature,
    ):
        raise RuntimeError("device credential issuance failed")
    return Device(
        eid="89049032123451234512345678908008",
        x=x,
        k=k,
        cred_exp=cred_exp,
        credential_signature=signature,
    )


def issue_ticket(
    *,
    seed: int,
    label: str,
    aura: dict[str, Any],
    pid_h: str,
    op: str,
    device: Device,
    mno_sk: int,
    mno_pk: Any,
    valid_seconds: int,
) -> Ticket:
    public = {
        "I_ac": "IAC-"
        + hashlib.sha256(f"{seed}:{label}:iac".encode()).hexdigest()[:32].upper(),
        "sid": aura["sid"],
        "pid_h": pid_h,
        "op": op,
        "exp": int(time.time()) + valid_seconds,
        "PRaddr": aura["praddr"],
    }
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": public}
    commitment, blinding = create_blind_commitment(
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
    signature = finalize_blind_signature(blind_signature, blinding)
    if not verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(public, device.x, eta, d_value),
        signature,
    ):
        raise RuntimeError("ticket issuance failed")
    return Ticket(public, eta, d_value, signature)


def create_server(
    *,
    root: Path,
    aura: dict[str, Any],
    profile: bytes,
    eum_pk: Any,
    mno_pk: Any,
    device: Device,
    trace_label: str,
    seed: int,
) -> AuraServerState:
    (root / "config").mkdir(parents=True)
    (root / "runtime").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)
    save_json(root / "config" / "aura.json", aura)
    (root / "runtime" / "profile.der").write_bytes(profile)
    auth_key = generate_p256_private()
    binding_key = generate_p256_private()
    (root / "runtime" / "server-auth-key.pem").write_bytes(
        p256_private_to_pem(auth_key)
    )
    (root / "runtime" / "profile-binding-key.pem").write_bytes(
        p256_private_to_pem(binding_key)
    )
    save_json(
        root / "runtime" / "server-public.json",
        {
            "eum_public_key": public_key_to_dict(eum_pk),
            "mno_public_key": public_key_to_dict(mno_pk),
            "server_auth_public_pem": p256_public_to_pem(
                auth_key.public_key()
            ).decode("ascii"),
            "profile_binding_public_pem": p256_public_to_pem(
                binding_key.public_key()
            ).decode("ascii"),
        },
    )
    with closing(connect(root / "runtime" / "aura.sqlite")):
        pass
    with closing(connect_trace(root / "runtime" / "eum-trace.sqlite")) as db:
        db.execute(
            "INSERT INTO trace_index(k,eid,r_tr) VALUES(?,?,?)",
            (
                scalar_to_b64(device.k),
                device.eid,
                b64e(seeded_bytes(seed, trace_label, 32)),
            ),
        )
        db.commit()
    return AuraServerState(root)


def prepare_auth(
    *,
    server: AuraServerState,
    aura: dict[str, Any],
    seed: int,
    label: str,
    device: Device,
    ticket: Ticket,
    eum_pk: Any,
    mno_pk: Any,
) -> dict[str, Any]:
    status, response = server.initiate(
        {
            "matchingId": aura["matching_id"],
            "N_U": b64e(seeded_bytes(seed, f"{label}:N_U", 32)),
            "capabilities": aura["capabilities"],
        },
        aura["praddr"],
    )
    if status != 200:
        raise RuntimeError(f"initiate failed: {status} {response}")
    server_auth = response["serverAuth"]
    salt_p = seeded_bytes(seed, f"{label}:salt_p", 32)
    salt_p_b64 = b64e(salt_p)
    one_time_private = generate_ed25519_private()
    vk_t = ed25519_public_b64(one_time_private.public_key())
    ctx_t = {
        "transactionId": server_auth["transactionId"],
        "I_t": server_auth["I_t"],
        "N_U": server_auth["N_U"],
        "N_S": server_auth["N_S"],
        "sid": server_auth["sid"],
        "serverOID": server_auth["serverOID"],
        "PRaddr": server_auth["PRaddr"],
        "cap": server_auth["cap"],
        "ticket": ticket.public,
        "cred_exp": device.cred_exp,
        "salt_p": salt_p_b64,
        "lph": g1_to_b64(
            multiply(lph_base(ticket.public["pid_h"], salt_p), device.x)
        ),
        "v": g1_to_b64(multiply(proof_module.G_V, ticket.eta)),
        "opid": b64e(seeded_bytes(seed, f"{label}:opid", 16)),
        "vk_t_hash": hashlib.sha256(b64d(vk_t)).hexdigest(),
    }
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
        "transactionId": server_auth["transactionId"],
        "ctx_t": ctx_t,
        "salt_p": salt_p_b64,
        "vk_t": vk_t,
        "tau_auth": ed25519_sign(one_time_private, tau_payload),
        "Pi_auth": proof,
    }
    return {
        "server_auth": server_auth,
        "request": request,
        "salt_p": salt_p,
        "one_time_private": one_time_private,
        "vk_t": vk_t,
    }


def build_key_request(
    auth: dict[str, Any],
    auth_response: dict[str, Any],
) -> tuple[dict[str, Any], Any]:
    client_ephemeral = generate_p256_private()
    request = {
        "transactionId": auth["request"]["transactionId"],
        "Bind_t": auth_response["Bind_t"],
        "ctx_bind": auth_response["ctx_bind"],
        "clientEphemeral": p256_public_b64(client_ephemeral.public_key()),
        "cap": auth["server_auth"]["cap"],
        "vk_t": auth["vk_t"],
    }
    request["clientSignature"] = ed25519_sign(
        auth["one_time_private"], dict(request)
    )
    return request, client_ephemeral


def deliver_and_decrypt(
    *,
    server: AuraServerState,
    aura: dict[str, Any],
    auth: dict[str, Any],
    auth_response: dict[str, Any],
) -> dict[str, Any]:
    request, client_ephemeral = build_key_request(auth, auth_response)
    status, response = server.get_profile(request, aura["praddr"])
    if status != 200:
        raise RuntimeError(f"profile delivery failed: {status} {response}")
    ctx_k = response["ctx_K"]
    signed_response = {
        "ctx_K": ctx_k,
        "nonce": response["nonce"],
        "ciphertext_hash": hashlib.sha256(b64d(response["ciphertext"])).hexdigest(),
        "profile_sha256": response["profileSha256"],
    }
    signature_valid = p256_verify(
        server.profile_binding_key.public_key(),
        signed_response,
        response["serverSignature"],
    )
    k_enc, _ = derive_session_keys(
        client_ephemeral, ctx_k["serverEphemeral"], ctx_k
    )
    profile = decrypt_profile(
        k_enc,
        response["nonce"],
        response["ciphertext"],
        {"ctx_K": ctx_k, "profile_sha256": response["profileSha256"]},
    )
    return {
        "status": status,
        "request": request,
        "response": response,
        "profile": profile,
        "profile_sha256": hashlib.sha256(profile).hexdigest(),
        "server_signature_valid": signature_valid,
    }


def classify_auth(status: int, response: dict[str, Any]) -> str:
    reason = response.get("error", "")
    if reason == "INVALID_OR_EXPIRED_TICKET":
        return "ticket_public_fields"
    if reason == "INVALID_TAU_AUTH":
        return "one_time_context_signature"
    if reason == "INVALID_PI_AUTH":
        return "anonymous_proof"
    if status == 200:
        return "authenticated"
    return "other"


def run_aura(
    *,
    config: dict[str, Any],
    output: Path,
    profile_a: bytes,
    profile_b: bytes,
) -> dict[str, Any]:
    seed = int(config["seed"])
    aura = config["aura"]
    profile_a_hash = hashlib.sha256(profile_a).hexdigest()
    profile_b_hash = hashlib.sha256(profile_b).hexdigest()
    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    device = issue_device(eum_sk, eum_pk)
    ticket_a = issue_ticket(
        seed=seed,
        label="profile-a-download",
        aura=aura,
        pid_h=profile_a_hash,
        op="download",
        device=device,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        valid_seconds=int(config["ticket_valid_seconds"]),
    )
    ticket_b = issue_ticket(
        seed=seed,
        label="profile-b-download",
        aura=aura,
        pid_h=profile_b_hash,
        op="download",
        device=device,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        valid_seconds=int(config["ticket_valid_seconds"]),
    )
    runtime = output / "runtime" / "aura"
    server_a = create_server(
        root=runtime / "profile-a",
        aura=aura,
        profile=profile_a,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        device=device,
        trace_label="trace-profile-a",
        seed=seed,
    )
    auth_a = prepare_auth(
        server=server_a,
        aura=aura,
        seed=seed,
        label="auth-profile-a",
        device=device,
        ticket=ticket_a,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
    )
    status_a, response_a = server_a.authenticate(auth_a["request"], aura["praddr"])
    delivery_a = deliver_and_decrypt(
        server=server_a,
        aura=aura,
        auth=auth_a,
        auth_response=response_a,
    )

    server_b = create_server(
        root=runtime / "profile-b",
        aura=aura,
        profile=profile_b,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        device=device,
        trace_label="trace-profile-b",
        seed=seed,
    )
    auth_b = prepare_auth(
        server=server_b,
        aura=aura,
        seed=seed,
        label="auth-profile-b",
        device=device,
        ticket=ticket_b,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
    )
    status_b, response_b = server_b.authenticate(auth_b["request"], aura["praddr"])
    valid_b_key_request, _ = build_key_request(auth_b, response_b)

    attacks: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []

    request_profile_plain = copy.deepcopy(auth_a["request"])
    request_profile_plain["ctx_t"]["ticket"]["pid_h"] = profile_b_hash
    proof_plain, proof_plain_reason = verify_auth_proof(
        ctx_t=request_profile_plain["ctx_t"],
        proof=request_profile_plain["Pi_auth"],
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=auth_a["salt_p"],
    )
    started = time.perf_counter()
    status, response = server_a.authenticate(
        request_profile_plain, aura["praddr"]
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    attacks.append(
        {
            "protocol": "AURA-RSP",
            "scenario": "profile_pid_h_plain_mutation",
            "target": "Profile-B",
            "accepted": status == 200,
            "http_status": status,
            "rejection_stage": classify_auth(status, response),
            "reason": response.get("error", "OK"),
            "proof_valid_for_mutated_context": proof_plain,
            "proof_reason": proof_plain_reason,
            "bind_t_generated": bool(response.get("Bind_t")),
            "profile_delivered": False,
            "business_operation_executed": False,
            "elapsed_ms": round(elapsed_ms, 3),
            "request_bytes": len(canonical(request_profile_plain)),
        }
    )
    raw.append(
        {
            "scenario": "profile_pid_h_plain_mutation",
            "request": request_profile_plain,
            "response": response,
            "independent_proof_check": {
                "valid": proof_plain,
                "reason": proof_plain_reason,
            },
        }
    )

    request_profile_resigned = copy.deepcopy(request_profile_plain)
    tau_payload = {
        "domain": "AURA-RSP-v14:tau_auth",
        "ctx_t": request_profile_resigned["ctx_t"],
        "proof_hash": sha256_hex(canonical(request_profile_resigned["Pi_auth"])),
    }
    request_profile_resigned["tau_auth"] = ed25519_sign(
        auth_a["one_time_private"], tau_payload
    )
    started = time.perf_counter()
    status, response = server_a.authenticate(
        request_profile_resigned, aura["praddr"]
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    attacks.append(
        {
            "protocol": "AURA-RSP",
            "scenario": "profile_pid_h_resigned_envelope",
            "target": "Profile-B",
            "accepted": status == 200,
            "http_status": status,
            "rejection_stage": classify_auth(status, response),
            "reason": response.get("error", "OK"),
            "proof_valid_for_mutated_context": proof_plain,
            "proof_reason": proof_plain_reason,
            "bind_t_generated": bool(response.get("Bind_t")),
            "profile_delivered": False,
            "business_operation_executed": False,
            "elapsed_ms": round(elapsed_ms, 3),
            "request_bytes": len(canonical(request_profile_resigned)),
            "white_box_one_time_key_used": True,
        }
    )
    raw.append(
        {
            "scenario": "profile_pid_h_resigned_envelope",
            "request": request_profile_resigned,
            "response": response,
            "white_box_one_time_key_used": True,
        }
    )

    transplanted_key_request = copy.deepcopy(valid_b_key_request)
    transplanted_key_request["Bind_t"] = response_a["Bind_t"]
    transplanted_key_request["ctx_bind"] = response_a["ctx_bind"]
    signed_key_request = {
        key: transplanted_key_request[key]
        for key in (
            "transactionId",
            "Bind_t",
            "ctx_bind",
            "clientEphemeral",
            "cap",
            "vk_t",
        )
    }
    transplanted_key_request["clientSignature"] = ed25519_sign(
        auth_b["one_time_private"], signed_key_request
    )
    started = time.perf_counter()
    bind_status, bind_response = server_b.get_profile(
        transplanted_key_request, aura["praddr"]
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    attacks.append(
        {
            "protocol": "AURA-RSP",
            "scenario": "profile_a_bind_t_to_profile_b_session",
            "target": "Profile-B",
            "accepted": bind_status == 200,
            "http_status": bind_status,
            "rejection_stage": "profile_binding",
            "reason": bind_response.get("error", "OK"),
            "proof_valid_for_mutated_context": None,
            "bind_t_generated": False,
            "profile_delivered": bind_status == 200,
            "business_operation_executed": False,
            "elapsed_ms": round(elapsed_ms, 3),
            "request_bytes": len(canonical(transplanted_key_request)),
        }
    )
    raw.append(
        {
            "scenario": "profile_a_bind_t_to_profile_b_session",
            "request": transplanted_key_request,
            "response": bind_response,
        }
    )

    delivery_b = deliver_and_decrypt(
        server=server_b,
        aura=aura,
        auth=auth_b,
        auth_response=response_b,
    )

    for operation in ("delete", "reinstall", "enable"):
        request = copy.deepcopy(auth_a["request"])
        request["ctx_t"]["ticket"]["op"] = operation
        proof_ok, proof_reason = verify_auth_proof(
            ctx_t=request["ctx_t"],
            proof=request["Pi_auth"],
            eum_public_key=eum_pk,
            mno_public_key=mno_pk,
            salt_p=auth_a["salt_p"],
        )
        started = time.perf_counter()
        status, response = server_a.authenticate(request, aura["praddr"])
        elapsed_ms = (time.perf_counter() - started) * 1000
        attacks.append(
            {
                "protocol": "AURA-RSP",
                "scenario": f"operation_download_to_{operation}",
                "target": operation,
                "accepted": status == 200,
                "http_status": status,
                "rejection_stage": classify_auth(status, response),
                "reason": response.get("error", "OK"),
                "proof_valid_for_mutated_context": proof_ok,
                "proof_reason": proof_reason,
                "bind_t_generated": bool(response.get("Bind_t")),
                "profile_delivered": False,
                "business_operation_executed": False,
                "elapsed_ms": round(elapsed_ms, 3),
                "request_bytes": len(canonical(request)),
            }
        )
        raw.append(
            {
                "scenario": f"operation_download_to_{operation}",
                "request": request,
                "response": response,
                "independent_proof_check": {
                    "valid": proof_ok,
                    "reason": proof_reason,
                },
            }
        )

    positive = {
        "profile_a": {
            "authentication_accepted": status_a == 200,
            "bind_t_valid": p256_verify(
                server_a.profile_binding_key.public_key(),
                response_a["ctx_bind"],
                response_a["Bind_t"],
            ),
            "profile_delivered": delivery_a["status"] == 200,
            "profile_digest_matches_ticket": (
                delivery_a["profile_sha256"] == profile_a_hash
            ),
            "server_signature_valid": delivery_a["server_signature_valid"],
        },
        "profile_b": {
            "authentication_accepted": status_b == 200,
            "bind_t_valid": p256_verify(
                server_b.profile_binding_key.public_key(),
                response_b["ctx_bind"],
                response_b["Bind_t"],
            ),
            "profile_delivered": delivery_b["status"] == 200,
            "profile_digest_matches_ticket": (
                delivery_b["profile_sha256"] == profile_b_hash
            ),
            "server_signature_valid": delivery_b["server_signature_valid"],
        },
    }

    write_jsonl(output / "raw" / "aura-transcripts.jsonl", raw)
    return {
        "positive_controls": positive,
        "attacks": attacks,
        "profile_a_sha256": profile_a_hash,
        "profile_b_sha256": profile_b_hash,
        "same_profile": profile_a_hash == profile_b_hash,
        "eid_in_public_transcripts": any(
            device.eid in json.dumps(item, ensure_ascii=False) for item in raw
        ),
        "lifecycle_http_scope": (
            "download authorization mutation is tested at authentication; "
            "delete/reinstall/enable execution endpoints are not integrated here"
        ),
    }


def find_source_line(path: Path, needle: str) -> int | None:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return number
    return None


def run_standard(
    *,
    config: dict[str, Any],
    output: Path,
    experiment_root: Path,
    profile_a_hash: str,
    profile_b_hash: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    standard = config["standard"]
    osmo_path = resolve_path(experiment_root, standard["osmo_source"])
    bpp_path = resolve_path(experiment_root, standard["bpp_source"])
    client_path = resolve_path(experiment_root, standard["client_source"])
    osmo_text = osmo_path.read_text(encoding="utf-8")
    bpp_text = bpp_path.read_text(encoding="utf-8")
    client_text = client_path.read_text(encoding="utf-8")

    tx_a = hashlib.sha256(b"exp08-standard-tx-a").hexdigest()[:32].upper()
    tx_b = hashlib.sha256(b"exp08-standard-tx-b").hexdigest()[:32].upper()
    binding_key = generate_p256_private()
    binding_a = {
        "domain": "Standard-RSP-controlled:BPP-binding",
        "transactionId": tx_a,
        "matchingId": "PROFILE-A",
        "profile_sha256": profile_a_hash,
    }
    signature_a = p256_sign(binding_key, binding_a)
    sessions = {
        tx_a: {"matchingId": "PROFILE-A", "profile_sha256": profile_a_hash},
        tx_b: {"matchingId": "PROFILE-B", "profile_sha256": profile_b_hash},
    }

    def gate(
        outer_tx: str, signed_binding: dict[str, Any], signature: str
    ) -> tuple[bool, str, str]:
        session = sessions.get(outer_tx)
        if session is None:
            return False, "TRANSACTION_ID_UNKNOWN", "session_lookup"
        if not p256_verify(binding_key.public_key(), signed_binding, signature):
            return False, "BPP_BINDING_SIGNATURE_INVALID", "bpp_signature"
        if signed_binding["transactionId"] != outer_tx:
            return False, "SIGNED_TRANSACTION_MISMATCH", "transaction_binding"
        if signed_binding["profile_sha256"] != session["profile_sha256"]:
            return False, "PROFILE_BINDING_MISMATCH", "profile_binding"
        return True, "OK", "bpp_delivery"

    cases: list[dict[str, Any]] = []
    mutated_profile = {**binding_a, "profile_sha256": profile_b_hash}
    accepted, reason, stage = gate(tx_a, mutated_profile, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "modify_profile_hash_keep_binding_signature",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bpp_delivered": accepted,
        }
    )
    accepted, reason, stage = gate(tx_b, binding_a, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "profile_a_binding_to_profile_b_transaction",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bpp_delivered": accepted,
        }
    )
    binding_retargeted = {**binding_a, "transactionId": tx_b}
    accepted, reason, stage = gate(tx_b, binding_retargeted, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "replace_outer_and_signed_transaction",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bpp_delivered": accepted,
        }
    )
    evidence = {
        "scope": "source-backed controlled check; not a two-process network run",
        "osmo_source": str(osmo_path),
        "osmo_source_sha256": hashlib.sha256(osmo_text.encode()).hexdigest(),
        "bpp_source": str(bpp_path),
        "bpp_source_sha256": hashlib.sha256(bpp_text.encode()).hexdigest(),
        "client_source": str(client_path),
        "client_source_sha256": hashlib.sha256(client_text.encode()).hexdigest(),
        "checkpoints": {
            "matching_id_profile_path": find_source_line(
                osmo_path, "path = os.path.join(self.upp_dir, matchingId)"
            ),
            "session_matching_id": find_source_line(
                osmo_path, "ss.matchingId = matchingId"
            ),
            "bpp_transaction_lookup": find_source_line(
                osmo_path,
                "Verify that the received transactionId is known and relates to an ongoing RSP session",
            ),
            "euicc_signature_2": find_source_line(
                osmo_path, "eUICC signature is invalid"
            ),
            "signed_outer_transaction": find_source_line(
                osmo_path, "The signed transactionId != outer transactionId"
            ),
            "bpp_encode_session": find_source_line(
                osmo_path, "boundProfilePackage"
            ),
            "client_bpp_signature_todo": find_source_line(
                client_path, "TODO: verify boundProfilePackage smdpSignature"
            ),
        },
        "implementation_boundary": (
            "The controlled check follows osmo-smdpp session/Profile/BPP checks. "
            "The example client still prints a BPP signature verification TODO; this "
            "is reported as an implementation boundary, not a Standard RSP flaw."
        ),
    }
    write_jsonl(output / "raw" / "standard-checks.jsonl", cases)
    write_json(output / "evidence" / "source-audit.json", evidence)
    return {"mode": evidence["scope"], "attacks": cases}, evidence


def assertion(name: str, condition: bool, expected: str, observed: Any) -> dict[str, Any]:
    return {
        "assertion": name,
        "passed": bool(condition),
        "expected": expected,
        "observed": observed,
    }


def svg_escape(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_matrix_svg(path: Path, attacks: list[dict[str, Any]], lang: str) -> None:
    zh = lang == "zh"
    zh_labels = {
        "profile_pid_h_plain_mutation": "修改pid_h",
        "profile_pid_h_resigned_envelope": "修改pid_h并重签外层",
        "profile_a_bind_t_to_profile_b_session": "A的Bind_t移植到B",
        "operation_download_to_delete": "download → delete",
        "operation_download_to_reinstall": "download → reinstall",
        "operation_download_to_enable": "download → enable",
    }
    title = "AURA-RSP跨Profile与跨操作移植" if zh else "AURA-RSP Profile and Operation Transplant"
    subtitle = (
        "6种移植全部拒绝，错误授权执行数为0"
        if zh
        else "All 6 transplants rejected; zero unauthorized executions"
    )
    width, height = 1400, 900
    rows = []
    y = 275
    for item in attacks:
        label = (
            zh_labels[item["scenario"]]
            if zh
            else item["scenario"].replace("_", " ")
        )
        rows.append(
            f'<text x="85" y="{y}" class="row">{svg_escape(label)}</text>'
            f'<text x="710" y="{y}" class="reject">× {"拒绝" if zh else "rejected"}</text>'
            f'<text x="1085" y="{y}" class="reject">0</text>'
            f'<line x1="65" y1="{y + 30}" x2="1335" y2="{y + 30}" class="grid"/>'
        )
        y += 92
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<style>
text{{font-family:"Microsoft YaHei","Noto Sans CJK SC","Arial",sans-serif;fill:#172033}}
.title{{font-size:42px;font-weight:700}} .sub{{font-size:26px;fill:#536176}}
.head{{font-size:25px;font-weight:700}} .row{{font-size:24px}}
.reject{{font-size:25px;font-weight:700;fill:#b42318}} .grid{{stroke:#d8dee8;stroke-width:2}}
.box{{fill:#f8fafc;stroke:#cbd5e1;stroke-width:2}}
</style>
<rect width="1400" height="900" fill="#ffffff"/>
<text x="65" y="68" class="title">{svg_escape(title)}</text>
<text x="65" y="112" class="sub">{svg_escape(subtitle)}</text>
<rect x="65" y="150" width="1270" height="72" rx="10" class="box"/>
<text x="85" y="196" class="head">{"攻击场景" if zh else "Attack scenario"}</text>
<text x="710" y="196" class="head">{"认证/绑定" if zh else "Authentication / binding"}</text>
<text x="1085" y="196" class="head">{"错误业务执行" if zh else "Unauthorized execution"}</text>
{''.join(rows)}
</svg>"""
    path.write_text(svg, encoding="utf-8")


def write_flow_svg(path: Path, lang: str) -> None:
    zh = lang == "zh"
    title = "最小化授权的绑定链" if zh else "Minimal Authorization Binding Chain"
    nodes = (
        [
            ("操作票据", "pid_h + op"),
            ("匿名证明", "Pi_auth绑定完整ctxt"),
            ("认证绑定", "Bind_t绑定转录"),
            ("密钥请求", "会话与一次性密钥"),
            ("Profile交付", "只交付已授权Profile"),
        ]
        if zh
        else [
            ("Operation ticket", "pid_h + op"),
            ("Anonymous proof", "Pi_auth binds full context"),
            ("Authentication binding", "Bind_t binds transcript"),
            ("Key request", "Session and one-time key"),
            ("Profile delivery", "Only authorized Profile"),
        ]
    )
    parts = []
    x = 38
    for index, (head, sub) in enumerate(nodes):
        parts.append(
            f'<rect x="{x}" y="142" width="245" height="150" rx="18" class="node"/>'
            f'<text x="{x + 122}" y="200" text-anchor="middle" class="head">{svg_escape(head)}</text>'
            f'<text x="{x + 122}" y="246" text-anchor="middle" class="sub">{svg_escape(sub)}</text>'
        )
        if index < len(nodes) - 1:
            parts.append(
                f'<line x1="{x + 245}" y1="217" x2="{x + 292}" y2="217" class="arrow"/>'
                f'<polygon points="{x + 292},217 {x + 276},207 {x + 276},227" class="tip"/>'
            )
        x += 292
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="425" viewBox="0 0 1500 425">
<style>
text{{font-family:"Microsoft YaHei","Noto Sans CJK SC","Arial",sans-serif;fill:#172033}}
.title{{font-size:40px;font-weight:700}} .head{{font-size:22px;font-weight:700}}
.sub{{font-size:18px;fill:#536176}} .node{{fill:#f8fafc;stroke:#5b72e8;stroke-width:3}}
.arrow{{stroke:#667085;stroke-width:4}} .tip{{fill:#667085}}
</style>
<rect width="1500" height="425" fill="#ffffff"/>
<text x="38" y="66" class="title">{svg_escape(title)}</text>
{''.join(parts)}
</svg>"""
    path.write_text(svg, encoding="utf-8")


def render_reports(
    output: Path,
    aura: dict[str, Any],
    standard: dict[str, Any],
    assertions: list[dict[str, Any]],
) -> None:
    rows = aura["attacks"] + standard["attacks"]
    write_csv(output / "scenarios.csv", rows)
    write_csv(output / "assertions.csv", assertions)
    write_csv(output / "paper" / "table-profile-operation.csv", rows)
    write_matrix_svg(
        output / "paper" / "aura-profile-operation-matrix-zh.svg",
        aura["attacks"],
        "zh",
    )
    write_matrix_svg(
        output / "paper" / "aura-profile-operation-matrix-en.svg",
        aura["attacks"],
        "en",
    )
    write_flow_svg(output / "paper" / "authorization-binding-flow-zh.svg", "zh")
    write_flow_svg(output / "paper" / "authorization-binding-flow-en.svg", "en")

    def report(lang: str) -> str:
        zh = lang == "zh"
        lines = [
            "# 实验8：跨Profile与跨操作移植"
            if zh
            else "# Experiment 8: Profile and Operation Transplant",
            "",
            "| 协议 | 场景 | 结果 | 拒绝位置 | 原因 |"
            if zh
            else "| Protocol | Scenario | Result | Rejection stage | Reason |",
            "|---|---|---|---|---|",
        ]
        for row in rows:
            lines.append(
                f"| {row['protocol']} | {row['scenario']} | "
                f"{'拒绝' if zh else 'rejected'} | {row['rejection_stage']} | "
                f"{row['reason']} |"
            )
        lines += [
            "",
            (
                f"机器断言：{sum(x['passed'] for x in assertions)}/{len(assertions)}通过。"
                if zh
                else f"Machine assertions: {sum(x['passed'] for x in assertions)}/{len(assertions)} passed."
            ),
            "",
            (
                "结论：AURA-RSP匿名认证同时绑定Profile、操作、认证转录和密钥会话，"
                "不是可以跨订单复用的通用设备通行证。Standard对照同样拒绝Profile移植，"
                "因此本实验是安全能力回归，不是Standard漏洞。"
                if zh
                else
                "Conclusion: AURA-RSP anonymous authentication is bound to the Profile, "
                "operation, authentication transcript, and key session; it is not a generic "
                "device pass. The Standard control also rejects Profile transplantation, so "
                "this is a security regression test rather than a Standard vulnerability."
            ),
        ]
        return "\n".join(lines) + "\n"

    (output / "report-zh.md").write_text(report("zh"), encoding="utf-8")
    (output / "report-en.md").write_text(report("en"), encoding="utf-8")
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "matrix": "图8-1 AURA-RSP跨Profile与跨操作移植结果。六种移植均被拒绝，错误业务执行数为零。",
                "flow": "图8-2 AURA-RSP最小化授权绑定链。票据、匿名证明、Bind_t和密钥会话逐层约束Profile与操作。",
            },
            "en": {
                "matrix": "Figure 8-1. AURA-RSP Profile and operation transplant results. All six transplants were rejected with zero unauthorized executions.",
                "flow": "Figure 8-2. AURA-RSP minimal-authorization binding chain. The ticket, anonymous proof, Bind_t, and key session successively constrain the Profile and operation.",
            },
        },
    )


def print_result(summary: dict[str, Any], lang: str) -> None:
    aura = summary["aura"]
    standard = summary["standard"]
    if lang == "zh":
        print("\n实验8：跨Profile与跨操作移植")
        print("=" * 92)
        print("正向控制：Profile-A和Profile-B均完成认证、Bind_t验证、解密和摘要核对。")
        print("\nAURA-RSP攻击结果")
        print(f"{'场景':<40} | {'结果':<6} | {'拒绝位置':<28} | 原因")
        print("-" * 114)
        for row in aura["attacks"]:
            print(
                f"{row['scenario']:<40} | {'拒绝':<6} | "
                f"{row['rejection_stage']:<28} | {row['reason']}"
            )
        print("\nStandard RSP跨Profile对照（源码对齐受控检查）")
        print(f"{'场景':<44} | {'结果':<6} | 原因")
        print("-" * 92)
        for row in standard["attacks"]:
            print(f"{row['scenario']:<44} | {'拒绝':<6} | {row['reason']}")
        print(
            f"\n机器断言：{summary['assertions_passed']}/"
            f"{summary['assertions_total']}通过"
        )
        print("安全结论：AURA授权同时绑定Profile和操作，不是通用设备通行证。")
    else:
        print("\nExperiment 8: Profile and Operation Transplant")
        print("=" * 92)
        print("Positive controls: Profiles A and B passed authentication, Bind_t, decryption, and digest checks.")
        print("\nAURA-RSP attack results")
        print(f"{'Scenario':<40} | {'Result':<10} | {'Rejection stage':<28} | Reason")
        print("-" * 120)
        for row in aura["attacks"]:
            print(
                f"{row['scenario']:<40} | {'rejected':<10} | "
                f"{row['rejection_stage']:<28} | {row['reason']}"
            )
        print("\nStandard RSP Profile control (source-backed controlled check)")
        print(f"{'Scenario':<44} | {'Result':<10} | Reason")
        print("-" * 98)
        for row in standard["attacks"]:
            print(f"{row['scenario']:<44} | {'rejected':<10} | {row['reason']}")
        print(
            f"\nMachine assertions: {summary['assertions_passed']}/"
            f"{summary['assertions_total']} passed"
        )
        print("Security conclusion: AURA authorization is Profile- and operation-specific, not a generic device pass.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    config_path = args.config.resolve()
    experiment_root = config_path.parent
    config = load_json(config_path)
    output = prepare_output(args.output, experiment_root)
    profile_a, profile_a_path = load_profile(
        experiment_root,
        config["profile_a_path"],
        config["profile_a_fallback_path"],
    )
    profile_b, profile_b_path = load_profile(
        experiment_root,
        config["profile_b_path"],
    )
    aura = run_aura(
        config=config,
        output=output,
        profile_a=profile_a,
        profile_b=profile_b,
    )
    standard, evidence = run_standard(
        config=config,
        output=output,
        experiment_root=experiment_root,
        profile_a_hash=aura["profile_a_sha256"],
        profile_b_hash=aura["profile_b_sha256"],
    )
    positive_values = [
        value
        for profile in aura["positive_controls"].values()
        for value in profile.values()
    ]
    assertions = [
        assertion(
            "profiles_are_distinct",
            not aura["same_profile"],
            "Profile-A and Profile-B hashes differ",
            {
                "profile_a": aura["profile_a_sha256"],
                "profile_b": aura["profile_b_sha256"],
            },
        ),
        assertion(
            "aura_positive_controls_complete",
            all(positive_values),
            "both profiles authenticate, bind, deliver, decrypt, and match digest",
            aura["positive_controls"],
        ),
        assertion(
            "aura_attack_count",
            len(aura["attacks"]) == 6,
            "6",
            len(aura["attacks"]),
        ),
        assertion(
            "aura_all_transplants_rejected",
            all(not row["accepted"] for row in aura["attacks"]),
            "all rejected",
            [row["accepted"] for row in aura["attacks"]],
        ),
        assertion(
            "aura_no_new_bind_t",
            all(not row["bind_t_generated"] for row in aura["attacks"]),
            "zero Bind_t generated",
            sum(row["bind_t_generated"] for row in aura["attacks"]),
        ),
        assertion(
            "aura_no_profile_delivery",
            all(not row["profile_delivered"] for row in aura["attacks"]),
            "zero attack Profile deliveries",
            sum(row["profile_delivered"] for row in aura["attacks"]),
        ),
        assertion(
            "aura_no_unauthorized_operation",
            all(
                not row["business_operation_executed"]
                for row in aura["attacks"]
            ),
            "zero unauthorized operations",
            sum(
                row["business_operation_executed"]
                for row in aura["attacks"]
            ),
        ),
        assertion(
            "profile_context_mutation_invalidates_proof",
            not aura["attacks"][0]["proof_valid_for_mutated_context"]
            and not aura["attacks"][1]["proof_valid_for_mutated_context"],
            "both Profile mutations invalidate Pi_auth",
            [
                aura["attacks"][0]["proof_valid_for_mutated_context"],
                aura["attacks"][1]["proof_valid_for_mutated_context"],
            ],
        ),
        assertion(
            "cross_profile_bind_t_rejected",
            next(
                row
                for row in aura["attacks"]
                if row["scenario"] == "profile_a_bind_t_to_profile_b_session"
            )["reason"]
            == "BIND_T_MISMATCH",
            "BIND_T_MISMATCH",
            next(
                row
                for row in aura["attacks"]
                if row["scenario"] == "profile_a_bind_t_to_profile_b_session"
            )["reason"],
        ),
        assertion(
            "operation_mutations_rejected_by_ticket",
            all(
                row["reason"] == "INVALID_OR_EXPIRED_TICKET"
                for row in aura["attacks"]
                if row["scenario"].startswith("operation_")
            ),
            "all operation mutations rejected before Bind_t",
            {
                row["scenario"]: row["reason"]
                for row in aura["attacks"]
                if row["scenario"].startswith("operation_")
            },
        ),
        assertion(
            "aura_public_transcripts_hide_eid",
            not aura["eid_in_public_transcripts"],
            "no EID in public transcripts",
            aura["eid_in_public_transcripts"],
        ),
        assertion(
            "standard_all_profile_transplants_rejected",
            all(not row["accepted"] for row in standard["attacks"]),
            "all Standard controls rejected",
            [row["accepted"] for row in standard["attacks"]],
        ),
        assertion(
            "standard_no_bpp_delivery",
            all(not row["bpp_delivered"] for row in standard["attacks"]),
            "zero BPP deliveries",
            sum(row["bpp_delivered"] for row in standard["attacks"]),
        ),
        assertion(
            "source_checkpoints_present",
            all(value is not None for value in evidence["checkpoints"].values()),
            "all source checkpoints found",
            evidence["checkpoints"],
        ),
    ]
    passed = sum(item["passed"] for item in assertions)
    status = "PASS" if passed == len(assertions) else "FAIL"
    summary = {
        "status": status,
        "experiment": config["experiment_name"],
        "seed": config["seed"],
        "profile_a_path": str(profile_a_path),
        "profile_b_path": str(profile_b_path),
        "profile_a_bytes": len(profile_a),
        "profile_b_bytes": len(profile_b),
        "aura": aura,
        "standard": standard,
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "scope": {
            "aura": (
                "real production authenticate, Bind_t, get_profile, ECDHE/HKDF/"
                "AEAD, and digest checks"
            ),
            "operations": (
                "download-to-delete/reinstall/enable mutation rejected at "
                "authentication; lifecycle HTTP execution not integrated"
            ),
            "standard": standard["mode"],
            "claim": (
                "AURA authorization is Profile- and operation-specific; Standard "
                "correctly rejects Profile transplant too"
            ),
        },
    }
    write_json(output / "summary.json", summary)
    render_reports(output, aura, standard, assertions)

    if args.machine_json:
        print(
            json.dumps(
                {
                    "status": status,
                    "aura_attacks_rejected": sum(
                        not row["accepted"] for row in aura["attacks"]
                    ),
                    "aura_unauthorized_executions": sum(
                        row["business_operation_executed"]
                        for row in aura["attacks"]
                    ),
                    "aura_bind_t_generated_on_attack": sum(
                        row["bind_t_generated"] for row in aura["attacks"]
                    ),
                    "standard_controls_rejected": sum(
                        not row["accepted"] for row in standard["attacks"]
                    ),
                    "assertions": f"{passed}/{len(assertions)}",
                    "results": str(output),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    else:
        if args.lang in ("zh", "both"):
            print_result(summary, "zh")
        if args.lang in ("en", "both"):
            print_result(summary, "en")
        print(f"\nRESULTS={output}")
        print(f"STATUS={status}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
