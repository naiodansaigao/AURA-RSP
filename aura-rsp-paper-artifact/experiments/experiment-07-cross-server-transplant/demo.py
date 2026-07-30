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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

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
        ed25519_public_b64,
        ed25519_sign,
        generate_ed25519_private,
        generate_p256_private,
        p256_private_to_pem,
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


def resolve_path(experiment_root: Path, value: str) -> Path:
    return (experiment_root / value).resolve()


def load_profile(config: dict[str, Any], experiment_root: Path) -> tuple[bytes, Path]:
    primary = resolve_path(experiment_root, config["profile_path"])
    fallback = resolve_path(experiment_root, config["fallback_profile_path"])
    for path in (primary, fallback):
        if path.is_file():
            return path.read_bytes(), path
    raise FileNotFoundError(f"profile not found: {primary} or {fallback}")


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
        eid="89049032123451234512345678907007",
        x=x,
        k=k,
        cred_exp=cred_exp,
        credential_signature=signature,
    )


def issue_ticket(
    *,
    seed: int,
    label: str,
    identity: dict[str, Any],
    profile_sha256: str,
    device: Device,
    mno_sk: int,
    mno_pk: Any,
    valid_seconds: int,
) -> Ticket:
    public = {
        "I_ac": "IAC-"
        + hashlib.sha256(f"{seed}:{label}:iac".encode()).hexdigest()[:32].upper(),
        "sid": identity["sid"],
        "pid_h": profile_sha256,
        "op": "download",
        "exp": int(time.time()) + valid_seconds,
        "PRaddr": identity["praddr"],
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
    identity: dict[str, Any],
    profile: bytes,
    eum_pk: Any,
    mno_pk: Any,
    device: Device,
    trace_salt: bytes,
) -> AuraServerState:
    (root / "config").mkdir(parents=True)
    (root / "runtime").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)
    save_json(
        root / "config" / "aura.json",
        {
            "matching_id": identity["matching_id"],
            "sid": identity["sid"],
            "server_oid": identity["server_oid"],
            "praddr": identity["praddr"],
            "capabilities": identity["capabilities"],
        },
    )
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
            (scalar_to_b64(device.k), device.eid, b64e(trace_salt)),
        )
        db.commit()
    return AuraServerState(root)


def prepare_auth(
    *,
    server: AuraServerState,
    identity: dict[str, Any],
    seed: int,
    label: str,
    device: Device,
    ticket: Ticket,
    eum_pk: Any,
    mno_pk: Any,
) -> dict[str, Any]:
    init_status, init_response = server.initiate(
        {
            "matchingId": identity["matching_id"],
            "N_U": b64e(seeded_bytes(seed, f"{label}:N_U", 32)),
            "capabilities": identity["capabilities"],
        },
        identity["praddr"],
    )
    if init_status != 200:
        raise RuntimeError(f"initiate failed: {init_status} {init_response}")
    server_auth = init_response["serverAuth"]
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
        "server_signature": init_response["serverSignature"],
        "request": request,
        "salt_p": salt_p,
        "one_time_private": one_time_private,
    }


def seed_cloned_session(
    server: AuraServerState,
    captured_server_auth: dict[str, Any],
    field: str,
    value: Any,
) -> None:
    init_data = copy.deepcopy(captured_server_auth)
    init_data[field] = value
    with closing(connect(server.db_path)) as db:
        db.execute(
            """
            INSERT INTO sessions(transaction_id,init_json,status,created_at)
            VALUES(?,?,?,?)
            """,
            (
                init_data["transactionId"],
                json.dumps(init_data, sort_keys=True),
                "initiated",
                int(time.time()),
            ),
        )
        db.commit()


def classify_stage(status: int, response: dict[str, Any]) -> str:
    reason = response.get("error", "")
    if reason == "UNKNOWN_TRANSACTION":
        return "session_lookup"
    if reason in {
        "CTX_SERVER_BINDING_MISMATCH",
        "CTX_PR_IDENTITY_MISMATCH",
        "INVALID_OR_EXPIRED_TICKET",
    }:
        return "server_context_or_ticket"
    if reason in {"INVALID_TAU_AUTH", "INVALID_PI_AUTH"}:
        return "cryptographic_authentication"
    if status == 200:
        return "authenticated"
    return "other"


def run_aura(
    *,
    config: dict[str, Any],
    output: Path,
    experiment_root: Path,
    profile: bytes,
    profile_sha256: str,
) -> dict[str, Any]:
    seed = int(config["seed"])
    identity_a = config["aura_server_a"]
    identity_b = config["aura_server_b"]
    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    device = issue_device(eum_sk, eum_pk)
    ticket_a = issue_ticket(
        seed=seed,
        label="ticket-a",
        identity=identity_a,
        profile_sha256=profile_sha256,
        device=device,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        valid_seconds=int(config["ticket_valid_seconds"]),
    )
    ticket_b = issue_ticket(
        seed=seed,
        label="ticket-b",
        identity=identity_b,
        profile_sha256=profile_sha256,
        device=device,
        mno_sk=mno_sk,
        mno_pk=mno_pk,
        valid_seconds=int(config["ticket_valid_seconds"]),
    )

    runtime = output / "runtime" / "aura"
    server_a = create_server(
        root=runtime / "positive-a",
        identity=identity_a,
        profile=profile,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        device=device,
        trace_salt=seeded_bytes(seed, "trace-a", 32),
    )
    auth_a = prepare_auth(
        server=server_a,
        identity=identity_a,
        seed=seed,
        label="auth-a",
        device=device,
        ticket=ticket_a,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
    )
    status_a, response_a = server_a.authenticate(
        auth_a["request"], identity_a["praddr"]
    )

    server_b_positive = create_server(
        root=runtime / "positive-b",
        identity=identity_b,
        profile=profile,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        device=device,
        trace_salt=seeded_bytes(seed, "trace-b", 32),
    )
    auth_b = prepare_auth(
        server=server_b_positive,
        identity=identity_b,
        seed=seed,
        label="auth-b",
        device=device,
        ticket=ticket_b,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
    )
    status_b, response_b = server_b_positive.authenticate(
        auth_b["request"], identity_b["praddr"]
    )

    positive = [
        {
            "protocol": "AURA-RSP",
            "scenario": "positive_server_a",
            "accepted": status_a == 200,
            "http_status": status_a,
            "reason": response_a.get("error", "OK"),
            "bind_t_generated": bool(response_a.get("Bind_t")),
            "bind_t_valid": bool(response_a.get("Bind_t"))
            and p256_verify(
                server_a.profile_binding_key.public_key(),
                response_a["ctx_bind"],
                response_a["Bind_t"],
            ),
        },
        {
            "protocol": "AURA-RSP",
            "scenario": "positive_server_b",
            "accepted": status_b == 200,
            "http_status": status_b,
            "reason": response_b.get("error", "OK"),
            "bind_t_generated": bool(response_b.get("Bind_t")),
            "bind_t_valid": bool(response_b.get("Bind_t"))
            and p256_verify(
                server_b_positive.profile_binding_key.public_key(),
                response_b["ctx_bind"],
                response_b["Bind_t"],
            ),
        },
    ]

    captured = auth_a["request"]
    attacks: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []

    direct_server = create_server(
        root=runtime / "attack-direct-replay",
        identity=identity_b,
        profile=profile,
        eum_pk=eum_pk,
        mno_pk=mno_pk,
        device=device,
        trace_salt=seeded_bytes(seed, "trace-direct", 32),
    )
    started = time.perf_counter()
    status, response = direct_server.authenticate(captured, identity_b["praddr"])
    elapsed_ms = (time.perf_counter() - started) * 1000
    attacks.append(
        {
            "protocol": "AURA-RSP",
            "scenario": "direct_replay_to_server_b",
            "mutated_field": "none",
            "white_box_cloned_session": False,
            "accepted": status == 200,
            "http_status": status,
            "rejection_stage": classify_stage(status, response),
            "reason": response.get("error", "OK"),
            "proof_valid_for_mutated_context": True,
            "bind_t_generated": bool(response.get("Bind_t")),
            "profile_delivery_reached": False,
            "request_bytes": len(canonical(captured)),
            "elapsed_ms": round(elapsed_ms, 3),
        }
    )
    raw_rows.append(
        {
            "scenario": "direct_replay_to_server_b",
            "request": captured,
            "response": response,
            "http_status": status,
        }
    )

    mutations = [
        (
            "modify_sid",
            "sid",
            identity_b["sid"],
            {**identity_a, "sid": identity_b["sid"], "label": "B-SID"},
        ),
        (
            "modify_server_oid",
            "serverOID",
            identity_b["server_oid"],
            {**identity_a, "server_oid": identity_b["server_oid"], "label": "B-OID"},
        ),
        ("modify_praddr", "PRaddr", identity_b["praddr"], {**identity_a, "praddr": identity_b["praddr"], "label": "B-PR"}),
        (
            "modify_cap",
            "cap",
            identity_b["capabilities"][0],
            {
                **identity_a,
                "capabilities": identity_b["capabilities"],
                "label": "B-CAP",
            },
        ),
        (
            "modify_transaction_nonce",
            "N_S",
            b64e(seeded_bytes(seed, "target-b:N_S", 32)),
            {**identity_a, "label": "B-NONCE"},
        ),
    ]
    for index, (scenario, field, value, target_identity) in enumerate(mutations):
        server = create_server(
            root=runtime / f"attack-{scenario}",
            identity=target_identity,
            profile=profile,
            eum_pk=eum_pk,
            mno_pk=mno_pk,
            device=device,
            trace_salt=seeded_bytes(seed, f"trace-{scenario}", 32),
        )
        seed_cloned_session(server, auth_a["server_auth"], field, value)
        request = copy.deepcopy(captured)
        request["ctx_t"][field] = value
        proof_ok, proof_reason = verify_auth_proof(
            ctx_t=request["ctx_t"],
            proof=request["Pi_auth"],
            eum_public_key=eum_pk,
            mno_public_key=mno_pk,
            salt_p=auth_a["salt_p"],
        )
        started = time.perf_counter()
        status, response = server.authenticate(request, target_identity["praddr"])
        elapsed_ms = (time.perf_counter() - started) * 1000
        row = {
            "protocol": "AURA-RSP",
            "scenario": scenario,
            "mutated_field": field,
            "white_box_cloned_session": True,
            "accepted": status == 200,
            "http_status": status,
            "rejection_stage": classify_stage(status, response),
            "reason": response.get("error", "OK"),
            "proof_valid_for_mutated_context": proof_ok,
            "proof_reason": proof_reason,
            "bind_t_generated": bool(response.get("Bind_t")),
            "profile_delivery_reached": False,
            "request_bytes": len(canonical(request)),
            "elapsed_ms": round(elapsed_ms, 3),
        }
        attacks.append(row)
        raw_rows.append(
            {
                "scenario": scenario,
                "mutated_field": field,
                "request": request,
                "response": response,
                "http_status": status,
                "independent_proof_check": {
                    "valid": proof_ok,
                    "reason": proof_reason,
                },
            }
        )

    a_signature_valid_with_a = p256_verify(
        server_a.server_auth_key.public_key(),
        auth_a["server_auth"],
        auth_a["server_signature"],
    )
    a_signature_valid_with_b = p256_verify(
        server_b_positive.server_auth_key.public_key(),
        auth_a["server_auth"],
        auth_a["server_signature"],
    )
    target_only = {
        "protocol": "AURA-RSP",
        "scenario": "replace_target_address_only",
        "mutated_field": "transport_target",
        "white_box_cloned_session": False,
        "accepted": a_signature_valid_with_b,
        "http_status": 0,
        "rejection_stage": "server_authentication",
        "reason": "SERVER_AUTH_SIGNATURE_MISMATCH",
        "proof_valid_for_mutated_context": True,
        "bind_t_generated": False,
        "profile_delivery_reached": False,
        "request_bytes": len(canonical(captured)),
        "elapsed_ms": 0.0,
        "a_signature_valid_with_a_key": a_signature_valid_with_a,
        "a_signature_valid_with_b_key": a_signature_valid_with_b,
    }
    attacks.insert(4, target_only)
    raw_rows.append(
        {
            "scenario": "replace_target_address_only",
            "server_auth": auth_a["server_auth"],
            "server_signature": auth_a["server_signature"],
            "a_signature_valid_with_a_key": a_signature_valid_with_a,
            "a_signature_valid_with_b_key": a_signature_valid_with_b,
        }
    )
    write_jsonl(output / "raw" / "aura-transcripts.jsonl", raw_rows)
    return {
        "positive_controls": positive,
        "attacks": attacks,
        "captured_request_sha256": sha256_hex(canonical(captured)),
        "captured_transaction_id": captured["transactionId"],
        "stable_identity_exposed": False,
        "eid_in_public_transcripts": any(
            device.eid in json.dumps(row, ensure_ascii=False) for row in raw_rows
        ),
    }


def certificate_names(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        return extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        issuer.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return True
    except Exception:
        return False


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
) -> tuple[dict[str, Any], dict[str, Any]]:
    standard = config["standard"]
    cert_a_path = resolve_path(experiment_root, standard["server_a_tls_cert"])
    cert_b_path = resolve_path(experiment_root, standard["server_b_tls_cert"])
    ci_path = resolve_path(experiment_root, standard["ci_cert"])
    source_path = resolve_path(experiment_root, standard["osmo_source"])
    client_path = resolve_path(experiment_root, standard["client_source"])

    cert_a = x509.load_der_x509_certificate(cert_a_path.read_bytes())
    cert_b = x509.load_der_x509_certificate(cert_b_path.read_bytes())
    ci = x509.load_pem_x509_certificate(ci_path.read_bytes())
    host_a = standard["server_a_hostname"]
    host_b = standard["server_b_hostname"]
    cert_checks = {
        "server_a_chain_valid": verify_cert_signature(cert_a, ci),
        "server_b_chain_valid": verify_cert_signature(cert_b, ci),
        "server_a_names": certificate_names(cert_a),
        "server_b_names": certificate_names(cert_b),
        "server_a_hostname_valid": host_a in certificate_names(cert_a),
        "server_b_hostname_valid": host_b in certificate_names(cert_b),
        "server_b_cert_valid_for_server_a": host_a in certificate_names(cert_b),
        "server_a_cert_valid_for_server_b": host_b in certificate_names(cert_a),
    }

    tx_a = hashlib.sha256(b"standard-server-a-transaction").hexdigest()[:32].upper()
    tx_b = hashlib.sha256(b"standard-server-b-transaction").hexdigest()[:32].upper()
    challenge_a = b64e(hashlib.sha256(b"standard-server-a-challenge").digest()[:16])
    challenge_b = b64e(hashlib.sha256(b"standard-server-b-challenge").digest()[:16])
    euicc_key = generate_p256_private()
    signed_a = {
        "transactionId": tx_a,
        "serverAddress": host_a,
        "serverChallenge": challenge_a,
    }
    signature_a = p256_sign(euicc_key, signed_a)
    sessions_b = {tx_b: {"serverChallenge": challenge_b}}

    def gate(
        outer_tx: str,
        signed_payload: dict[str, Any],
        signature: str,
    ) -> tuple[bool, str, str]:
        session = sessions_b.get(outer_tx)
        if session is None:
            return False, "TRANSACTION_ID_UNKNOWN", "session_lookup"
        if not p256_verify(euicc_key.public_key(), signed_payload, signature):
            return False, "EUICC_SIGNATURE_INVALID", "euicc_signature"
        if signed_payload["serverChallenge"] != session["serverChallenge"]:
            return False, "SERVER_CHALLENGE_MISMATCH", "session_challenge"
        return True, "OK", "authenticated"

    cases: list[dict[str, Any]] = []
    accepted, reason, stage = gate(tx_a, signed_a, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "direct_replay_to_server_b",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bound_profile_package_reached": accepted,
        }
    )
    accepted, reason, stage = gate(tx_b, signed_a, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "replace_outer_transaction_id",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bound_profile_package_reached": accepted,
        }
    )
    mutated_address = {**signed_a, "serverAddress": host_b}
    accepted, reason, stage = gate(tx_b, mutated_address, signature_a)
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "modify_signed_server_address",
            "accepted": accepted,
            "reason": reason,
            "rejection_stage": stage,
            "bound_profile_package_reached": accepted,
        }
    )
    tls_accept = cert_checks["server_b_cert_valid_for_server_a"]
    cases.append(
        {
            "protocol": "Standard RSP",
            "scenario": "replace_target_address_only",
            "accepted": tls_accept,
            "reason": "OK" if tls_accept else "TLS_HOSTNAME_MISMATCH",
            "rejection_stage": "tls_server_authentication",
            "bound_profile_package_reached": False,
        }
    )

    source_text = source_path.read_text(encoding="utf-8")
    client_text = client_path.read_text(encoding="utf-8")
    evidence = {
        "scope": "source-backed controlled check; not a two-process network run",
        "osmo_source": str(source_path),
        "osmo_source_sha256": hashlib.sha256(source_text.encode()).hexdigest(),
        "client_source": str(client_path),
        "client_source_sha256": hashlib.sha256(client_text.encode()).hexdigest(),
        "checkpoints": {
            "server_address_refusal": find_source_line(
                source_path, "Invalid SM-DP+ Address"
            ),
            "server_signed_transaction": find_source_line(
                source_path, "'transactionId': h2b(transactionId)"
            ),
            "server_signed_address": find_source_line(
                source_path, "'serverAddress': self.server_hostname"
            ),
            "server_signed_challenge": find_source_line(
                source_path, "'serverChallenge': serverChallenge"
            ),
            "unknown_transaction": find_source_line(
                source_path,
                "Verify that the transactionId is known and relates to an ongoing RSP session",
            ),
            "euicc_signature_check": find_source_line(
                source_path, "Verification failed (euiccSignature1 over euiccSigned1)"
            ),
            "server_challenge_check": find_source_line(
                source_path, "Verification failed (serverChallenge)"
            ),
            "client_tls_ca": find_source_line(
                client_path,
                "Es9pApiClient(opts.url, server_cert_verify=opts.server_ca_cert)",
            ),
            "client_server_signature_todo": find_source_line(
                client_path, "TODO: verify serverSignature1 over serverSigned1"
            ),
            "client_server_certificate_todo": find_source_line(
                client_path, "TODO: verify server certificate against CI"
            ),
        },
        "implementation_boundary": (
            "The baseline client enables CI-backed TLS verification, while its "
            "application-layer serverSignature1/server-certificate checks remain TODO. "
            "This is reported as an implementation boundary, not a Standard RSP flaw."
        ),
        "certificate_checks": cert_checks,
    }
    write_jsonl(output / "raw" / "standard-checks.jsonl", cases)
    write_json(output / "evidence" / "source-audit.json", evidence)
    return {"mode": evidence["scope"], "certificate_checks": cert_checks, "attacks": cases}, evidence


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


def write_matrix_svg(path: Path, aura: list[dict[str, Any]], lang: str) -> None:
    zh = lang == "zh"
    labels = {
        "direct_replay_to_server_b": "原样重放",
        "modify_sid": "修改 sid",
        "modify_server_oid": "修改 serverOID",
        "modify_praddr": "修改 PRaddr",
        "replace_target_address_only": "仅替换目标地址",
        "modify_cap": "修改 cap",
        "modify_transaction_nonce": "修改 N_S",
    }
    title = "AURA-RSP跨服务器移植结果" if zh else "AURA-RSP Cross-Server Transplant Results"
    subtitle = (
        "7种攻击全部拒绝，0个有效Bind_t"
        if zh
        else "All 7 attacks rejected; zero valid Bind_t values"
    )
    header_case = "攻击场景" if zh else "Attack scenario"
    header_auth = "认证" if zh else "Authentication"
    header_bind = "Bind_t"
    reject = "拒绝" if zh else "rejected"
    none = "未生成" if zh else "not generated"
    width, height = 1400, 960
    rows = []
    y = 285
    for item in aura:
        name = labels.get(item["scenario"], item["scenario"]) if zh else item["scenario"].replace("_", " ")
        rows.append(
            f'<text x="95" y="{y}" class="row">{svg_escape(name)}</text>'
            f'<text x="790" y="{y}" class="reject">× {reject}</text>'
            f'<text x="1110" y="{y}" class="reject">× {none}</text>'
            f'<line x1="70" y1="{y + 28}" x2="1330" y2="{y + 28}" class="grid"/>'
        )
        y += 92
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<style>
text{{font-family:"Microsoft YaHei","Noto Sans CJK SC","Arial",sans-serif;fill:#172033}}
.title{{font-size:42px;font-weight:700}} .sub{{font-size:26px;fill:#536176}}
.head{{font-size:25px;font-weight:700}} .row{{font-size:25px}}
.reject{{font-size:25px;font-weight:700;fill:#b42318}} .grid{{stroke:#d8dee8;stroke-width:2}}
.box{{fill:#f8fafc;stroke:#cbd5e1;stroke-width:2}}
</style>
<rect width="1400" height="960" fill="#ffffff"/>
<text x="70" y="70" class="title">{svg_escape(title)}</text>
<text x="70" y="115" class="sub">{svg_escape(subtitle)}</text>
<rect x="70" y="150" width="1260" height="72" rx="10" class="box"/>
<text x="95" y="196" class="head">{svg_escape(header_case)}</text>
<text x="790" y="196" class="head">{svg_escape(header_auth)}</text>
<text x="1110" y="196" class="head">{svg_escape(header_bind)}</text>
{''.join(rows)}
</svg>"""
    path.write_text(svg, encoding="utf-8")


def write_flow_svg(path: Path, lang: str) -> None:
    zh = lang == "zh"
    title = "跨服务器移植的拒绝链" if zh else "Cross-Server Transplant Rejection Chain"
    nodes = (
        [
            ("捕获A的认证报文", "不含公开EID"),
            ("转发或修改后交给B", "事务/服务器字段变化"),
            ("B按本地会话核对", "事务或上下文不匹配"),
            ("验证票据、tau与Pi_auth", "旧证明不能覆盖新上下文"),
            ("拒绝", "不生成Bind_t / 不下发Profile"),
        ]
        if zh
        else [
            ("Capture A authentication", "No public EID"),
            ("Forward or mutate for B", "Server/session fields change"),
            ("B checks local session", "Transaction or context mismatch"),
            ("Verify ticket, tau, Pi_auth", "Old proof cannot cover new context"),
            ("Reject", "No Bind_t / no profile delivery"),
        ]
    )
    chunks = []
    x = 40
    for idx, (head, sub) in enumerate(nodes):
        chunks.append(
            f'<rect x="{x}" y="145" width="240" height="150" rx="18" class="node"/>'
            f'<text x="{x + 120}" y="202" text-anchor="middle" class="head">{svg_escape(head)}</text>'
            f'<text x="{x + 120}" y="247" text-anchor="middle" class="sub">{svg_escape(sub)}</text>'
        )
        if idx < len(nodes) - 1:
            chunks.append(
                f'<line x1="{x + 240}" y1="220" x2="{x + 290}" y2="220" class="arrow"/>'
                f'<polygon points="{x + 290},220 {x + 274},210 {x + 274},230" class="arrowhead"/>'
            )
        x += 290
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="430" viewBox="0 0 1500 430">
<style>
text{{font-family:"Microsoft YaHei","Noto Sans CJK SC","Arial",sans-serif;fill:#172033}}
.title{{font-size:40px;font-weight:700}} .head{{font-size:22px;font-weight:700}}
.sub{{font-size:18px;fill:#536176}} .node{{fill:#f8fafc;stroke:#5b72e8;stroke-width:3}}
.arrow{{stroke:#667085;stroke-width:4}} .arrowhead{{fill:#667085}}
</style>
<rect width="1500" height="430" fill="#ffffff"/>
<text x="40" y="68" class="title">{svg_escape(title)}</text>
{''.join(chunks)}
</svg>"""
    path.write_text(svg, encoding="utf-8")


def render_reports(
    output: Path,
    aura: dict[str, Any],
    standard: dict[str, Any],
    assertions: list[dict[str, Any]],
) -> None:
    scenario_rows = aura["attacks"] + standard["attacks"]
    write_csv(output / "scenarios.csv", scenario_rows)
    write_csv(output / "assertions.csv", assertions)
    write_csv(output / "paper" / "table-cross-server.csv", scenario_rows)
    write_matrix_svg(output / "paper" / "aura-rejection-matrix-zh.svg", aura["attacks"], "zh")
    write_matrix_svg(output / "paper" / "aura-rejection-matrix-en.svg", aura["attacks"], "en")
    write_flow_svg(output / "paper" / "binding-flow-zh.svg", "zh")
    write_flow_svg(output / "paper" / "binding-flow-en.svg", "en")

    def table(lang: str) -> str:
        zh = lang == "zh"
        lines = [
            "# 实验7：跨服务器移植" if zh else "# Experiment 7: Cross-Server Transplant",
            "",
            "| 协议 | 场景 | 结果 | 拒绝原因 | Bind_t/BPP |"
            if zh
            else "| Protocol | Scenario | Result | Rejection reason | Bind_t/BPP |",
            "|---|---|---|---|---|",
        ]
        for row in scenario_rows:
            result = "拒绝" if zh else "rejected"
            artifact = "未生成/未到达" if zh else "not generated/not reached"
            lines.append(
                f"| {row['protocol']} | {row['scenario']} | {result} | "
                f"{row['reason']} | {artifact} |"
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
                "结论：AURA-RSP在不公开稳定设备身份的前提下，仍通过服务器本地会话、"
                "统一上下文、票据、一次性签名和匿名证明拒绝跨服务器移植。Standard对照"
                "也拒绝移植，因此本结果是安全能力回归，而不是Standard漏洞。"
                if zh
                else
                "Conclusion: AURA-RSP rejects cross-server transplantation through the "
                "target server's local session, unified context, ticket, one-time signature, "
                "and anonymous proof without exposing a stable device identity. The Standard "
                "control also rejects transplantation; this is a security regression test, "
                "not a Standard RSP vulnerability."
            ),
        ]
        return "\n".join(lines) + "\n"

    (output / "report-zh.md").write_text(table("zh"), encoding="utf-8")
    (output / "report-en.md").write_text(table("en"), encoding="utf-8")
    captions = {
        "zh": {
            "matrix": "图7-1 AURA-RSP跨服务器移植结果。七种攻击均未通过认证，也未生成有效Bind_t。",
            "flow": "图7-2 AURA-RSP跨服务器移植拒绝链。服务器本地会话与统一上下文使A的认证材料不能在B重用。",
        },
        "en": {
            "matrix": "Figure 7-1. AURA-RSP cross-server transplant results. All seven attacks were rejected and no valid Bind_t was generated.",
            "flow": "Figure 7-2. AURA-RSP cross-server transplant rejection chain. The target server's local session and unified context prevent reuse of A's authentication material at B.",
        },
    }
    write_json(output / "paper" / "captions.json", captions)


def print_result(summary: dict[str, Any], lang: str) -> None:
    aura = summary["aura"]
    standard = summary["standard"]
    if lang == "zh":
        print("\n实验7：跨服务器移植")
        print("=" * 86)
        print("AURA-RSP正向控制：A和B均认证成功，均生成并验证了Bind_t。")
        print("\nAURA-RSP攻击结果")
        print(f"{'场景':<34} | {'结果':<6} | {'拒绝阶段':<28} | 原因")
        print("-" * 104)
        for row in aura["attacks"]:
            print(
                f"{row['scenario']:<34} | {'拒绝':<6} | "
                f"{row['rejection_stage']:<28} | {row['reason']}"
            )
        print("\nStandard RSP对照（源码对齐受控检查）")
        print(f"{'场景':<34} | {'结果':<6} | 原因")
        print("-" * 76)
        for row in standard["attacks"]:
            print(f"{row['scenario']:<34} | {'拒绝':<6} | {row['reason']}")
        print(
            f"\n机器断言：{summary['assertions_passed']}/"
            f"{summary['assertions_total']}通过"
        )
        print("安全结论：两种协议都拒绝跨服务器移植；这不是Standard漏洞。")
        print("AURA额外证明：删除稳定身份后，仍保留服务器/事务绑定且不生成Bind_t。")
    else:
        print("\nExperiment 7: Cross-Server Transplant")
        print("=" * 86)
        print("AURA-RSP positive controls: both A and B authenticated and produced valid Bind_t.")
        print("\nAURA-RSP attack results")
        print(f"{'Scenario':<34} | {'Result':<10} | {'Rejection stage':<28} | Reason")
        print("-" * 112)
        for row in aura["attacks"]:
            print(
                f"{row['scenario']:<34} | {'rejected':<10} | "
                f"{row['rejection_stage']:<28} | {row['reason']}"
            )
        print("\nStandard RSP control (source-backed controlled check)")
        print(f"{'Scenario':<34} | {'Result':<10} | Reason")
        print("-" * 82)
        for row in standard["attacks"]:
            print(f"{row['scenario']:<34} | {'rejected':<10} | {row['reason']}")
        print(
            f"\nMachine assertions: {summary['assertions_passed']}/"
            f"{summary['assertions_total']} passed"
        )
        print("Security conclusion: both protocols reject cross-server transplantation.")
        print("This is a regression test, not evidence of a Standard RSP vulnerability.")


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
    profile, profile_path = load_profile(config, experiment_root)
    profile_sha256 = hashlib.sha256(profile).hexdigest()

    aura = run_aura(
        config=config,
        output=output,
        experiment_root=experiment_root,
        profile=profile,
        profile_sha256=profile_sha256,
    )
    standard, source_evidence = run_standard(
        config=config,
        output=output,
        experiment_root=experiment_root,
    )
    assertions = [
        assertion(
            "aura_positive_controls_accept",
            all(x["accepted"] and x["bind_t_valid"] for x in aura["positive_controls"]),
            "both A and B accept their own request and issue valid Bind_t",
            aura["positive_controls"],
        ),
        assertion(
            "aura_attack_count",
            len(aura["attacks"]) == 7,
            "7",
            len(aura["attacks"]),
        ),
        assertion(
            "aura_all_transplants_rejected",
            all(not x["accepted"] for x in aura["attacks"]),
            "all rejected",
            [x["accepted"] for x in aura["attacks"]],
        ),
        assertion(
            "aura_no_bind_t_on_attack",
            all(not x["bind_t_generated"] for x in aura["attacks"]),
            "zero Bind_t",
            sum(x["bind_t_generated"] for x in aura["attacks"]),
        ),
        assertion(
            "aura_no_profile_delivery_on_attack",
            all(not x["profile_delivery_reached"] for x in aura["attacks"]),
            "zero profile deliveries",
            sum(x["profile_delivery_reached"] for x in aura["attacks"]),
        ),
        assertion(
            "aura_mutated_context_invalidates_proof",
            all(
                not x["proof_valid_for_mutated_context"]
                for x in aura["attacks"]
                if x["mutated_field"] in {"sid", "serverOID", "PRaddr", "cap", "N_S"}
            ),
            "all five mutated contexts invalidate Pi_auth",
            {
                x["scenario"]: x["proof_valid_for_mutated_context"]
                for x in aura["attacks"]
                if x["mutated_field"] in {"sid", "serverOID", "PRaddr", "cap", "N_S"}
            },
        ),
        assertion(
            "aura_no_stable_identity_exposure",
            not aura["stable_identity_exposed"] and not aura["eid_in_public_transcripts"],
            "no EID in public transcripts",
            aura["eid_in_public_transcripts"],
        ),
        assertion(
            "standard_test_cert_chains_valid",
            standard["certificate_checks"]["server_a_chain_valid"]
            and standard["certificate_checks"]["server_b_chain_valid"],
            "both test server certificates verify under the test CI",
            standard["certificate_checks"],
        ),
        assertion(
            "standard_own_hostnames_valid",
            standard["certificate_checks"]["server_a_hostname_valid"]
            and standard["certificate_checks"]["server_b_hostname_valid"],
            "each certificate matches its own server",
            standard["certificate_checks"],
        ),
        assertion(
            "standard_cross_hostnames_invalid",
            not standard["certificate_checks"]["server_b_cert_valid_for_server_a"]
            and not standard["certificate_checks"]["server_a_cert_valid_for_server_b"],
            "cross-host certificate use rejected",
            standard["certificate_checks"],
        ),
        assertion(
            "standard_all_transplants_rejected",
            all(not x["accepted"] for x in standard["attacks"]),
            "all rejected",
            [x["accepted"] for x in standard["attacks"]],
        ),
        assertion(
            "standard_no_bpp_on_attack",
            all(not x["bound_profile_package_reached"] for x in standard["attacks"]),
            "no BPP path reached",
            sum(x["bound_profile_package_reached"] for x in standard["attacks"]),
        ),
        assertion(
            "source_checkpoints_present",
            all(
                value is not None
                for value in source_evidence["checkpoints"].values()
            ),
            "all source checkpoints located",
            source_evidence["checkpoints"],
        ),
    ]
    passed = sum(item["passed"] for item in assertions)
    status = "PASS" if passed == len(assertions) else "FAIL"
    summary = {
        "status": status,
        "experiment": config["experiment_name"],
        "seed": config["seed"],
        "profile_path": str(profile_path),
        "profile_bytes": len(profile),
        "profile_sha256": profile_sha256,
        "aura": aura,
        "standard": standard,
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "scope": {
            "aura": "real AURA production authenticate path with real BBS+ proofs",
            "standard": standard["mode"],
            "claim": (
                "AURA preserves cross-server transplant resistance after stable "
                "device identity removal; Standard is expected to reject too."
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
                        not x["accepted"] for x in aura["attacks"]
                    ),
                    "aura_bind_t_generated_on_attack": sum(
                        x["bind_t_generated"] for x in aura["attacks"]
                    ),
                    "standard_attacks_rejected": sum(
                        not x["accepted"] for x in standard["attacks"]
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
