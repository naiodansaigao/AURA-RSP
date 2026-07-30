from __future__ import annotations

import argparse
import base64
import copy
import csv
import hashlib
import hmac
import json
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "缺少AURA密码依赖。请在WSL中运行 bash ./run_demo.sh；"
        f"原始错误: {exc}"
    ) from exc


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


@dataclass
class Session:
    label: str
    transaction_id: str
    ticket_pid_h: str
    client_private: ec.EllipticCurvePrivateKey
    ctx_k: dict[str, Any]
    bind_t: str
    k_enc: bytes
    k_mac: bytes
    response: dict[str, Any]


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def sha256_hex_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def deterministic_p256(seed: int, label: str) -> ec.EllipticCurvePrivateKey:
    value = int.from_bytes(seeded_bytes(seed, label, 32), "big")
    value = (value % (P256_ORDER - 1)) + 1
    return ec.derive_private_key(value, ec.SECP256R1())


def p256_public_b64(public_key) -> str:
    return b64e(
        public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def p256_public_from_b64(value: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b64d(value)
    )


def p256_sign(private_key, value: dict[str, Any]) -> str:
    return b64e(
        private_key.sign(canonical(value), ec.ECDSA(hashes.SHA256()))
    )


def p256_verify(public_key, value: dict[str, Any], signature_b64: str) -> bool:
    try:
        public_key.verify(
            b64d(signature_b64),
            canonical(value),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


def derive_session_keys(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_b64: str,
    ctx_k: dict[str, Any],
) -> tuple[bytes, bytes]:
    peer_public = p256_public_from_b64(peer_public_b64)
    shared = private_key.exchange(ec.ECDH(), peer_public)
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(canonical(ctx_k)).digest(),
        info=b"AURA-RSP-v14:profile-download-keys",
    ).derive(shared)
    return material[:32], material[32:]


def receipt_mac(key: bytes, fields: dict[str, Any]) -> str:
    return b64e(hmac.new(key, canonical(fields), hashlib.sha256).digest())


def signed_profile_response(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "ctx_K": response["ctx_K"],
        "nonce": response["nonce"],
        "ciphertext_hash": hashlib.sha256(
            b64d(response["ciphertext"])
        ).hexdigest(),
        "profile_sha256": response["profileSha256"],
    }


def resolve_path(root: Path, value: str) -> Path:
    return (root / value).resolve()


def load_profile(
    root: Path, primary: str, fallback: str | None = None
) -> tuple[bytes, Path]:
    candidates = [resolve_path(root, primary)]
    if fallback:
        candidates.append(resolve_path(root, fallback))
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
    for name in ("raw", "evidence", "paper"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


class ProfileDeliveryFixture:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.seed = int(config["seed"])
        self.binding_key = deterministic_p256(self.seed, "profile-binding-key")
        self.binding_public = self.binding_key.public_key()

    def create_session(
        self,
        *,
        label: str,
        ticket_pid_h: str,
        delivered_profile: bytes,
        declared_profile_hash: str | None = None,
    ) -> Session:
        transaction_id = hashlib.sha256(
            f"{self.seed}:{label}:transaction".encode("utf-8")
        ).hexdigest()[:32].upper()
        client_private = deterministic_p256(
            self.seed, f"{label}:client-ephemeral"
        )
        server_private = deterministic_p256(
            self.seed, f"{label}:server-ephemeral"
        )
        ctx_bind = {
            "domain": "AURA-RSP-v14:bind",
            "transactionId": transaction_id,
            "ticket_pid_h": ticket_pid_h,
        }
        bind_t = p256_sign(self.binding_key, ctx_bind)
        ctx_k = {
            "domain": "AURA-RSP-v14:ctx_K",
            "transactionId": transaction_id,
            "Bind_t": bind_t,
            "clientEphemeral": p256_public_b64(client_private.public_key()),
            "serverEphemeral": p256_public_b64(server_private.public_key()),
            "cap": self.config["capability"],
        }
        k_enc, k_mac = derive_session_keys(
            server_private, ctx_k["clientEphemeral"], ctx_k
        )
        declared = declared_profile_hash or sha256_hex_bytes(delivered_profile)
        aad = {"ctx_K": ctx_k, "profile_sha256": declared}
        nonce = seeded_bytes(self.seed, f"{label}:nonce", 12)
        ciphertext = AESGCM(k_enc).encrypt(
            nonce, delivered_profile, canonical(aad)
        )
        response = {
            "transactionId": transaction_id,
            "ctx_K": ctx_k,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "profileSha256": declared,
        }
        response["serverSignature"] = p256_sign(
            self.binding_key, signed_profile_response(response)
        )
        return Session(
            label=label,
            transaction_id=transaction_id,
            ticket_pid_h=ticket_pid_h,
            client_private=client_private,
            ctx_k=ctx_k,
            bind_t=bind_t,
            k_enc=k_enc,
            k_mac=k_mac,
            response=response,
        )

    def resign(self, response: dict[str, Any]) -> None:
        response["serverSignature"] = p256_sign(
            self.binding_key, signed_profile_response(response)
        )


def base_result(
    scenario: str,
    category: str,
    threat_model: str,
    white_box: bool,
) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "category": category,
        "threat_model": threat_model,
        "white_box": white_box,
        "accepted": False,
        "server_signature_verified": False,
        "ctx_k_verified": False,
        "aead_verified": False,
        "server_declared_digest_verified": False,
        "order_digest_checked": False,
        "order_digest_match": None,
        "installed": False,
        "receipt_generated": False,
        "receipt_mac_valid": False,
        "profile_hash": None,
        "ticket_pid_h": None,
        "reason": "UNPROCESSED",
        "rejection_stage": "none",
        "elapsed_ms": 0.0,
        "wire_bytes": 0,
    }


def process_current_client(
    *,
    scenario: str,
    category: str,
    threat_model: str,
    white_box: bool,
    session: Session,
    response: dict[str, Any],
    binding_public,
    enforce_order_digest: bool,
) -> dict[str, Any]:
    result = base_result(scenario, category, threat_model, white_box)
    result["ticket_pid_h"] = session.ticket_pid_h
    result["wire_bytes"] = len(canonical(response))
    started = time.perf_counter()
    ctx_k = response.get("ctx_K", {})
    expected_ctx = {
        "clientEphemeral": session.ctx_k["clientEphemeral"],
        "Bind_t": session.bind_t,
        "transactionId": session.transaction_id,
    }
    if any(ctx_k.get(key) != value for key, value in expected_ctx.items()):
        result.update(
            reason="CTX_K_MISMATCH",
            rejection_stage="ctx_k_binding",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result
    result["ctx_k_verified"] = True
    try:
        signed = signed_profile_response(response)
    except Exception:
        result.update(
            reason="INVALID_SERVER_KEY_EXCHANGE_RESPONSE",
            rejection_stage="server_signature",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result
    if not p256_verify(
        binding_public, signed, response.get("serverSignature", "")
    ):
        result.update(
            reason="INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
            rejection_stage="server_signature",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result
    result["server_signature_verified"] = True
    k_enc, k_mac = derive_session_keys(
        session.client_private, ctx_k["serverEphemeral"], ctx_k
    )
    aad = {
        "ctx_K": ctx_k,
        "profile_sha256": response["profileSha256"],
    }
    try:
        plaintext = AESGCM(k_enc).decrypt(
            b64d(response["nonce"]),
            b64d(response["ciphertext"]),
            canonical(aad),
        )
    except (InvalidTag, ValueError):
        result.update(
            reason="PROFILE_AEAD_AUTHENTICATION_FAILED",
            rejection_stage="aead",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result
    result["aead_verified"] = True
    profile_hash = sha256_hex_bytes(plaintext)
    result["profile_hash"] = profile_hash
    if profile_hash != response["profileSha256"]:
        result.update(
            reason="DECRYPTED_PROFILE_HASH_MISMATCH",
            rejection_stage="server_declared_digest",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result
    result["server_declared_digest_verified"] = True
    result["order_digest_match"] = profile_hash == session.ticket_pid_h
    if enforce_order_digest:
        result["order_digest_checked"] = True
        if not result["order_digest_match"]:
            result.update(
                reason="PROFILE_ORDER_DIGEST_MISMATCH",
                rejection_stage="order_pid_h",
                elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            return result

    receipt_fields = {
        "transactionId": session.transaction_id,
        "profileSha256": profile_hash,
        "status": "installed",
        "counter": 1,
    }
    receipt = {
        **receipt_fields,
        "mac": receipt_mac(k_mac, receipt_fields),
    }
    expected_mac = receipt_mac(k_mac, receipt_fields)
    result.update(
        accepted=True,
        installed=True,
        receipt_generated=True,
        receipt_mac_valid=hmac.compare_digest(receipt["mac"], expected_mac),
        reason="PROFILE_ACCEPTED",
        rejection_stage="none",
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )
    return result


def flip_ciphertext_byte(response: dict[str, Any], index: int) -> None:
    value = bytearray(b64d(response["ciphertext"]))
    value[index] ^= 1
    response["ciphertext"] = b64e(bytes(value))


def run_experiment(
    config: dict[str, Any],
    profile_a: bytes,
    profile_b: bytes,
    enforce_current_order_digest: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fixture = ProfileDeliveryFixture(config)
    pid_a = sha256_hex_bytes(profile_a)
    pid_b = sha256_hex_bytes(profile_b)

    session_a = fixture.create_session(
        label="session-a",
        ticket_pid_h=pid_a,
        delivered_profile=profile_a,
    )
    session_b = fixture.create_session(
        label="session-b",
        ticket_pid_h=pid_a,
        delivered_profile=profile_a,
    )
    honest_a = process_current_client(
        scenario="honest_session_a",
        category="positive_control",
        threat_model="honest",
        white_box=False,
        session=session_a,
        response=copy.deepcopy(session_a.response),
        binding_public=fixture.binding_public,
        enforce_order_digest=enforce_current_order_digest,
    )
    honest_b = process_current_client(
        scenario="honest_session_b",
        category="positive_control",
        threat_model="honest",
        white_box=False,
        session=session_b,
        response=copy.deepcopy(session_b.response),
        binding_public=fixture.binding_public,
        enforce_order_digest=enforce_current_order_digest,
    )

    attacks: list[dict[str, Any]] = []

    response = copy.deepcopy(session_a.response)
    flip_ciphertext_byte(response, 0)
    attacks.append(
        process_current_client(
            scenario="10a_ciphertext_flip_network",
            category="10A",
            threat_model="network_mitm",
            white_box=False,
            session=session_a,
            response=response,
            binding_public=fixture.binding_public,
            enforce_order_digest=enforce_current_order_digest,
        )
    )

    response = copy.deepcopy(session_a.response)
    flip_ciphertext_byte(response, 0)
    fixture.resign(response)
    attacks.append(
        process_current_client(
            scenario="10a_ciphertext_flip_resigned",
            category="10A",
            threat_model="white_box_defense_depth",
            white_box=True,
            session=session_a,
            response=response,
            binding_public=fixture.binding_public,
            enforce_order_digest=enforce_current_order_digest,
        )
    )

    response = copy.deepcopy(session_a.response)
    flip_ciphertext_byte(response, -1)
    fixture.resign(response)
    attacks.append(
        process_current_client(
            scenario="10a_tag_flip_resigned",
            category="10A",
            threat_model="white_box_defense_depth",
            white_box=True,
            session=session_a,
            response=response,
            binding_public=fixture.binding_public,
            enforce_order_digest=enforce_current_order_digest,
        )
    )

    attacks.append(
        process_current_client(
            scenario="10b_whole_package_a_to_b",
            category="10B",
            threat_model="network_mitm",
            white_box=False,
            session=session_b,
            response=copy.deepcopy(session_a.response),
            binding_public=fixture.binding_public,
            enforce_order_digest=enforce_current_order_digest,
        )
    )

    response = copy.deepcopy(session_b.response)
    response["nonce"] = session_a.response["nonce"]
    response["ciphertext"] = session_a.response["ciphertext"]
    fixture.resign(response)
    attacks.append(
        process_current_client(
            scenario="10b_ciphertext_a_in_b_resigned",
            category="10B",
            threat_model="white_box_defense_depth",
            white_box=True,
            session=session_b,
            response=response,
            binding_public=fixture.binding_public,
            enforce_order_digest=enforce_current_order_digest,
        )
    )

    malicious_session = fixture.create_session(
        label="session-c-malicious-server",
        ticket_pid_h=pid_a,
        delivered_profile=profile_b,
        declared_profile_hash=pid_b,
    )
    current_10c = process_current_client(
        scenario="10c_current_client_wrong_profile",
        category="10C",
        threat_model="malicious_smdpp_valid_keys",
        white_box=False,
        session=malicious_session,
        response=copy.deepcopy(malicious_session.response),
        binding_public=fixture.binding_public,
        enforce_order_digest=enforce_current_order_digest,
    )
    without_order_check = process_current_client(
        scenario="10c_without_order_check_control",
        category="negative_control",
        threat_model="fault_injection_order_check_removed",
        white_box=False,
        session=malicious_session,
        response=copy.deepcopy(malicious_session.response),
        binding_public=fixture.binding_public,
        enforce_order_digest=False,
    )
    boundary_session = fixture.create_session(
        label="business-boundary",
        ticket_pid_h=pid_b,
        delivered_profile=profile_b,
        declared_profile_hash=pid_b,
    )
    boundary = process_current_client(
        scenario="business_boundary_joint_wrong_authorization",
        category="trust_boundary",
        threat_model="mno_and_smdpp_joint_authorization",
        white_box=False,
        session=boundary_session,
        response=copy.deepcopy(boundary_session.response),
        binding_public=fixture.binding_public,
        enforce_order_digest=enforce_current_order_digest,
    )
    scenarios = [
        honest_a,
        honest_b,
        *attacks,
        current_10c,
        without_order_check,
        boundary,
    ]
    session_evidence = {
        "session_a": {
            "transaction_id": session_a.transaction_id,
            "ctx_k_sha256": sha256_hex_bytes(canonical(session_a.ctx_k)),
            "k_enc_sha256": sha256_hex_bytes(session_a.k_enc),
        },
        "session_b": {
            "transaction_id": session_b.transaction_id,
            "ctx_k_sha256": sha256_hex_bytes(canonical(session_b.ctx_k)),
            "k_enc_sha256": sha256_hex_bytes(session_b.k_enc),
        },
        "sessions_are_distinct": (
            session_a.transaction_id != session_b.transaction_id
            and session_a.ctx_k != session_b.ctx_k
            and session_a.k_enc != session_b.k_enc
        ),
        "profile_a_sha256": pid_a,
        "profile_b_sha256": pid_b,
        "profiles_are_distinct": pid_a != pid_b,
    }
    return session_evidence, scenarios


def find_line(path: Path, pattern: str) -> int | None:
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if pattern in line:
            return number
    return None


def build_source_audit(
    experiment_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    paths = {
        name: resolve_path(experiment_root, value)
        for name, value in config["aura_source"].items()
    }
    patterns = {
        "ticket_pid_h_commitment": (
            "ticket",
            '"pid_h": hashlib.sha256(profile).hexdigest()',
        ),
        "server_aad_ctx_k": ("server", '"ctx_K": ctx_k'),
        "server_aad_profile_hash": (
            "server",
            '"profile_sha256": self.profile_sha256',
        ),
        "server_encrypt_profile": (
            "server",
            "nonce, ciphertext = encrypt_profile(k_enc, self.profile, aad)",
        ),
        "client_signed_ciphertext_hash": (
            "client",
            'b64d(profile_response["ciphertext"])',
        ),
        "client_decrypt_profile": ("client", "profile = decrypt_profile("),
        "client_hashes_plaintext": (
            "client",
            "profile_hash = hashlib.sha256(profile).hexdigest()",
        ),
        "client_compares_server_hash_only": (
            "client",
            'if profile_hash != profile_response["profileSha256"]',
        ),
        "client_compares_ticket_pid_h": (
            "client",
            'if profile_hash != ticket["pid_h"]',
        ),
        "client_writes_profile": (
            "client",
            "output_path.write_bytes(profile)",
        ),
        "client_generates_receipt": (
            "client",
            "receipt = {**receipt_fields, \"mac\": receipt_mac",
        ),
    }
    checkpoints = {
        name: {
            "file": str(paths[file_key]),
            "line": find_line(paths[file_key], pattern),
            "pattern": pattern,
        }
        for name, (file_key, pattern) in patterns.items()
    }
    client_lines = paths["client"].read_text(encoding="utf-8").splitlines()
    decrypt_line = checkpoints["client_decrypt_profile"]["line"] or 0
    post_decrypt_pid_h_lines = [
        index
        for index, line in enumerate(client_lines, start=1)
        if index >= decrypt_line and "pid_h" in line
    ]
    order_check_present = (
        checkpoints["client_compares_ticket_pid_h"]["line"] is not None
        and checkpoints["client_compares_ticket_pid_h"]["line"] in
        post_decrypt_pid_h_lines
    )
    return {
        "source_sha256": {
            name: sha256_hex_bytes(path.read_bytes())
            for name, path in paths.items()
        },
        "checkpoints": checkpoints,
        "all_checkpoints_found": all(
            item["line"] is not None for item in checkpoints.values()
        ),
        "post_decrypt_pid_h_lines": post_decrypt_pid_h_lines,
        "current_client_checks_order_pid_h_after_decrypt": order_check_present,
        "implementation_gap": (
            None
            if order_check_present
            else (
                "client validates H(P) against server-declared profileSha256 "
                "but not against ticket.pid_h"
            )
        ),
        "fix_status": (
            "ENFORCED_BEFORE_INSTALL_AND_RECEIPT"
            if order_check_present
            else "MISSING"
        ),
        "recommended_fix": (
            "after decryption and before any file write or receipt creation, "
            "reject unless SHA256(profile) == ticket['pid_h']"
        ),
    }


def make_assertion(
    name: str,
    expected: Any,
    observed: Any,
    passed: bool,
    assertion_class: str,
) -> dict[str, Any]:
    return {
        "assertion": name,
        "class": assertion_class,
        "expected": expected,
        "observed": observed,
        "passed": bool(passed),
    }


def by_name(scenarios: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["scenario"]: row for row in scenarios}


def build_assertions(
    sessions: dict[str, Any],
    scenarios: list[dict[str, Any]],
    audit: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = by_name(scenarios)
    a_net = rows["10a_ciphertext_flip_network"]
    a_cipher = rows["10a_ciphertext_flip_resigned"]
    a_tag = rows["10a_tag_flip_resigned"]
    b_whole = rows["10b_whole_package_a_to_b"]
    b_cipher = rows["10b_ciphertext_a_in_b_resigned"]
    current = rows["10c_current_client_wrong_profile"]
    without_check = rows["10c_without_order_check_control"]
    boundary = rows["business_boundary_joint_wrong_authorization"]
    return [
        make_assertion(
            "profiles_are_distinct",
            True,
            sessions["profiles_are_distinct"],
            sessions["profiles_are_distinct"],
            "harness",
        ),
        make_assertion(
            "sessions_are_distinct",
            True,
            sessions["sessions_are_distinct"],
            sessions["sessions_are_distinct"],
            "harness",
        ),
        make_assertion(
            "honest_session_a_installs_and_receipts",
            "accepted, installed, receipt",
            rows["honest_session_a"],
            rows["honest_session_a"]["accepted"]
            and rows["honest_session_a"]["installed"]
            and rows["honest_session_a"]["receipt_generated"],
            "harness",
        ),
        make_assertion(
            "honest_session_b_installs_and_receipts",
            "accepted, installed, receipt",
            rows["honest_session_b"],
            rows["honest_session_b"]["accepted"]
            and rows["honest_session_b"]["installed"]
            and rows["honest_session_b"]["receipt_generated"],
            "harness",
        ),
        make_assertion(
            "10a_network_flip_rejected_by_signature",
            "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
            a_net["reason"],
            a_net["reason"] == "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE"
            and not a_net["installed"]
            and not a_net["receipt_generated"],
            "security",
        ),
        make_assertion(
            "10a_resigned_ciphertext_rejected_by_aead",
            "PROFILE_AEAD_AUTHENTICATION_FAILED",
            a_cipher["reason"],
            a_cipher["server_signature_verified"]
            and not a_cipher["aead_verified"]
            and not a_cipher["installed"]
            and not a_cipher["receipt_generated"],
            "security",
        ),
        make_assertion(
            "10a_resigned_tag_rejected_by_aead",
            "PROFILE_AEAD_AUTHENTICATION_FAILED",
            a_tag["reason"],
            a_tag["server_signature_verified"]
            and not a_tag["aead_verified"]
            and not a_tag["installed"]
            and not a_tag["receipt_generated"],
            "security",
        ),
        make_assertion(
            "10b_whole_package_replay_rejected",
            "CTX_K_MISMATCH",
            b_whole["reason"],
            b_whole["reason"] == "CTX_K_MISMATCH"
            and not b_whole["installed"],
            "security",
        ),
        make_assertion(
            "10b_resigned_ciphertext_replay_rejected_by_aead",
            "PROFILE_AEAD_AUTHENTICATION_FAILED",
            b_cipher["reason"],
            b_cipher["server_signature_verified"]
            and not b_cipher["aead_verified"]
            and not b_cipher["installed"],
            "security",
        ),
        make_assertion(
            "10c_malicious_package_is_cryptographically_valid",
            "signature, ctx_K, AEAD, and server digest all pass",
            current,
            current["server_signature_verified"]
            and current["ctx_k_verified"]
            and current["aead_verified"]
            and current["server_declared_digest_verified"],
            "harness",
        ),
        make_assertion(
            "10c_wrong_profile_must_not_install",
            "rejected before install and receipt",
            {
                "accepted": current["accepted"],
                "installed": current["installed"],
                "receipt_generated": current["receipt_generated"],
                "order_digest_match": current["order_digest_match"],
            },
            not current["accepted"]
            and not current["installed"]
            and not current["receipt_generated"],
            "security_property",
        ),
        make_assertion(
            "10c_order_digest_check_enforced",
            "current client rejects before install and receipt",
            current,
            not current["accepted"]
            and not current["installed"]
            and not current["receipt_generated"]
            and current["order_digest_match"] is False
            and current["order_digest_checked"]
            and audit["current_client_checks_order_pid_h_after_decrypt"],
            "security",
        ),
        make_assertion(
            "negative_control_reproduces_original_gap",
            "accepts only when the order digest check is deliberately removed",
            without_check,
            without_check["accepted"]
            and without_check["installed"]
            and without_check["receipt_generated"]
            and without_check["order_digest_match"] is False
            and not without_check["order_digest_checked"],
            "negative_control",
        ),
        make_assertion(
            "joint_authorization_boundary_accepts",
            "accepted because ticket.pid_h equals delivered Profile",
            boundary,
            boundary["accepted"]
            and boundary["order_digest_checked"]
            and boundary["order_digest_match"],
            "trust_boundary",
        ),
        make_assertion(
            "source_checkpoints_present",
            True,
            audit["all_checkpoints_found"],
            audit["all_checkpoints_found"],
            "source_audit",
        ),
        make_assertion(
            "source_confirms_order_check",
            True,
            audit["current_client_checks_order_pid_h_after_decrypt"],
            audit["current_client_checks_order_pid_h_after_decrypt"],
            "source_audit",
        ),
        make_assertion(
            "public_rows_hide_eid",
            False,
            any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
            not any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
            "privacy_regression",
        ),
    ]


ZH_NAMES = {
    "honest_session_a": "正常会话A",
    "honest_session_b": "正常会话B",
    "10a_ciphertext_flip_network": "10A 密文字节翻转",
    "10a_ciphertext_flip_resigned": "10A 密文翻转+白盒重签",
    "10a_tag_flip_resigned": "10A Tag翻转+白盒重签",
    "10b_whole_package_a_to_b": "10B A整包重放到B",
    "10b_ciphertext_a_in_b_resigned": "10B A密文放入B+白盒重签",
    "10c_current_client_wrong_profile": "10C 修复后客户端/错误Profile",
    "10c_without_order_check_control": "10C 移除pid_h检查/负向控制",
    "business_boundary_joint_wrong_authorization": "MNO+SM-DP+共同错误授权",
}

EN_NAMES = {
    "honest_session_a": "Honest Session A",
    "honest_session_b": "Honest Session B",
    "10a_ciphertext_flip_network": "10A Ciphertext byte flip",
    "10a_ciphertext_flip_resigned": "10A Cipher flip + white-box resign",
    "10a_tag_flip_resigned": "10A Tag flip + white-box resign",
    "10b_whole_package_a_to_b": "10B Replay whole A package to B",
    "10b_ciphertext_a_in_b_resigned": "10B A ciphertext in B + resign",
    "10c_current_client_wrong_profile": "10C Fixed client / wrong Profile",
    "10c_without_order_check_control": "10C Remove pid_h check / negative control",
    "business_boundary_joint_wrong_authorization": "MNO + SM-DP+ joint authorization",
}


def status_cell(value: bool | None, checked: bool = True) -> str:
    if not checked:
        return "N/C"
    if value is None:
        return "—"
    return "PASS" if value else "FAIL"


def render_terminal(
    summary: dict[str, Any], lang: str, machine_json: bool
) -> None:
    if machine_json:
        compact = {
            "status": summary["status"],
            "security_properties": (
                f"{summary['security_properties_passed']}/"
                f"{summary['security_properties_total']}"
            ),
            "assertions": (
                f"{summary['assertions_passed']}/{summary['assertions_total']}"
            ),
            "10a_rejected": summary["metrics"]["10a_rejected"],
            "10b_rejected": summary["metrics"]["10b_rejected"],
            "10c_current_client_accepted_wrong_profile": summary["metrics"][
                "10c_current_client_accepted_wrong_profile"
            ],
            "10c_wrong_profile_installed": summary["metrics"][
                "10c_wrong_profile_installed"
            ],
            "10c_receipt_generated": summary["metrics"][
                "10c_receipt_generated"
            ],
            "10c_order_digest_checked": summary["metrics"][
                "10c_order_digest_checked"
            ],
            "results": summary["results_dir"],
        }
        print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")))
        return
    rows = [
        row
        for row in summary["scenarios"]
        if row["category"] != "positive_control"
    ]
    if lang in ("zh", "both"):
        print("\n实验10：Profile密文篡改、重放与明文替换")
        print("=" * 118)
        print(
            f"{'场景':<34} {'响应签名':<10} {'AEAD':<8} "
            f"{'订单pid_h':<11} {'安装':<6} {'收据':<6} {'结果'}"
        )
        print("-" * 118)
        for row in rows:
            order = status_cell(
                row["order_digest_match"], row["order_digest_checked"]
            )
            outcome = (
                "接受"
                if row["accepted"]
                else f"拒绝/{row['reason']}"
            )
            print(
                f"{ZH_NAMES[row['scenario']]:<34} "
                f"{status_cell(row['server_signature_verified']):<10} "
                f"{status_cell(row['aead_verified']):<8} "
                f"{order:<11} "
                f"{('是' if row['installed'] else '否'):<6} "
                f"{('是' if row['receipt_generated'] else '否'):<6} "
                f"{outcome}"
            )
        print("-" * 118)
        print(
            f"安全属性：{summary['security_properties_passed']}/"
            f"{summary['security_properties_total']}；机器断言："
            f"{summary['assertions_passed']}/{summary['assertions_total']}"
        )
        if summary["status"] == "PASS":
            print(
                "关键结果：修复后客户端在10C中通过订单pid_h检查拒绝错误Profile，"
                "未安装且未生成收据；状态=PASS"
            )
        else:
            print(
                "关键发现：当前客户端在10C中接受错误Profile、执行安装并生成收据；"
                "状态=IMPLEMENTATION_GAP_DETECTED"
            )
    if lang in ("en", "both"):
        print("\nExperiment 10: Profile Ciphertext Tamper, Replay, and Plaintext Replacement")
        print("=" * 132)
        print(
            f"{'Scenario':<43} {'Signature':<10} {'AEAD':<8} "
            f"{'Order pid_h':<12} {'Install':<8} {'Receipt':<8} {'Outcome'}"
        )
        print("-" * 132)
        for row in rows:
            order = status_cell(
                row["order_digest_match"], row["order_digest_checked"]
            )
            outcome = (
                "ACCEPT"
                if row["accepted"]
                else f"REJECT/{row['reason']}"
            )
            print(
                f"{EN_NAMES[row['scenario']]:<43} "
                f"{status_cell(row['server_signature_verified']):<10} "
                f"{status_cell(row['aead_verified']):<8} "
                f"{order:<12} "
                f"{('YES' if row['installed'] else 'NO'):<8} "
                f"{('YES' if row['receipt_generated'] else 'NO'):<8} "
                f"{outcome}"
            )
        print("-" * 132)
        print(
            f"Security properties: {summary['security_properties_passed']}/"
            f"{summary['security_properties_total']}; machine assertions: "
            f"{summary['assertions_passed']}/{summary['assertions_total']}"
        )
        if summary["status"] == "PASS":
            print(
                "Key result: the fixed client rejects the wrong Profile through "
                "the order pid_h check, with no installation or receipt; status=PASS"
            )
        else:
            print(
                "Key finding: the current client accepts, installs, and receipts the "
                "wrong Profile in 10C; status=IMPLEMENTATION_GAP_DETECTED"
            )


def render_report(
    output: Path,
    summary: dict[str, Any],
    language: str,
) -> None:
    zh = language == "zh"
    fixed_client = summary["status"] == "PASS"
    names = ZH_NAMES if zh else EN_NAMES
    title = (
        "# 实验10：Profile密文篡改、重放与明文替换"
        if zh
        else "# Experiment 10: Profile Ciphertext Tamper, Replay, and Plaintext Replacement"
    )
    lines = [title, ""]
    if zh:
        lines += [
            f"- 实验状态：**{summary['status']}**",
            (
                f"- 安全属性：{summary['security_properties_passed']}/"
                f"{summary['security_properties_total']}"
            ),
            (
                f"- 机器断言：{summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "- 10A与10B：全部拒绝且未安装、未生成收据",
            (
                "- 10C修复后客户端：错误Profile在安装和收据生成前被订单pid_h检查拒绝"
                if fixed_client
                else "- 10C当前客户端：错误Profile被接受、安装并生成收据"
            ),
            "",
            "## 场景结果",
            "",
            "| 场景 | 签名 | AEAD | 订单pid_h | 安装 | 收据 | 结果 |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    else:
        lines += [
            f"- Experiment status: **{summary['status']}**",
            (
                f"- Security properties: {summary['security_properties_passed']}/"
                f"{summary['security_properties_total']}"
            ),
            (
                f"- Machine assertions: {summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "- 10A and 10B: all rejected, with no installation or receipt",
            (
                "- 10C fixed client: wrong Profile rejected by the order pid_h "
                "check before installation and receipt"
                if fixed_client
                else "- 10C current client: wrong Profile accepted, installed, and receipted"
            ),
            "",
            "## Scenario results",
            "",
            "| Scenario | Signature | AEAD | Order pid_h | Install | Receipt | Outcome |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    for row in summary["scenarios"]:
        order = status_cell(
            row["order_digest_match"], row["order_digest_checked"]
        )
        outcome = (
            ("接受" if zh else "ACCEPT")
            if row["accepted"]
            else f"{'拒绝' if zh else 'REJECT'} / `{row['reason']}`"
        )
        lines.append(
            f"| {names[row['scenario']]} | "
            f"{status_cell(row['server_signature_verified'])} | "
            f"{status_cell(row['aead_verified'])} | {order} | "
            f"{int(row['installed'])} | {int(row['receipt_generated'])} | "
            f"{outcome} |"
        )
    if zh and fixed_client:
        lines += [
            "",
            "## 10C修复验证",
            "",
            (
                "恶意SM-DP+仍使用当前合法会话密钥加密Profile-B，并以Profile-B自身摘要"
                "构造AAD和合法服务器签名。因此服务器签名、ctx_K、AEAD以及服务端自报"
                "摘要检查仍全部通过，证明攻击包在密码学上自洽。"
            ),
            (
                "修复后的客户端继续比较`H(Profile-B)`与订单`ticket.pid_h`中承诺的"
                "`H(Profile-A)`，返回`PROFILE_ORDER_DIGEST_MISMATCH`，没有写入错误"
                "Profile，也没有生成安装收据。"
            ),
            (
                "移除订单摘要检查的负向控制仍会接受、安装并生成收据，说明10C通过确实"
                "来自新增检查，而不是攻击夹具失效。"
            ),
            "",
            "## 边界",
            "",
            (
                "若MNO与SM-DP+共同把Profile-B摘要写入订单，则订单承诺与交付明文一致，"
                "修复后的检查也会通过；这是业务授权信任边界，不是AEAD或Profile "
                "Binding可以判断的恶意业务决策。"
            ),
        ]
    elif zh:
        lines += [
            "",
            "## 10C实现缺口",
            "",
            (
                "恶意SM-DP+使用当前合法会话密钥加密Profile-B，并以Profile-B自身摘要"
                "构造AAD和合法服务器签名。服务器签名、ctx_K、AEAD以及服务端自报摘要"
                "检查全部通过。"
            ),
            (
                "当前客户端没有把解密后的Profile摘要与订单`ticket.pid_h`比较，因此"
                "继续安装错误Profile并生成安装收据。参考修复在文件写入和收据生成前"
                "执行该比较后，返回`PROFILE_ORDER_DIGEST_MISMATCH`。"
            ),
            "",
            "## 边界",
            "",
            (
                "若MNO与SM-DP+共同把Profile-B摘要写入订单，则参考检查也会通过；这是"
                "业务授权信任边界，不是AEAD或Profile Binding可以判断的恶意业务决策。"
            ),
        ]
    elif fixed_client:
        lines += [
            "",
            "## 10C fix validation",
            "",
            (
                "The malicious SM-DP+ still encrypts Profile-B with the valid current "
                "session key and supplies Profile-B's own digest in the AAD and valid "
                "server signature. The signature, ctx_K, AEAD, and server-declared "
                "digest checks therefore all pass."
            ),
            (
                "The fixed client then compares `H(Profile-B)` with the order "
                "commitment `ticket.pid_h = H(Profile-A)` and rejects with "
                "`PROFILE_ORDER_DIGEST_MISMATCH` before any file write or receipt."
            ),
            (
                "The negative control with the order check deliberately removed still "
                "accepts, installs, and receipts Profile-B, confirming that the new "
                "check—not a broken attack fixture—causes the rejection."
            ),
            "",
            "## Boundary",
            "",
            (
                "If the MNO and SM-DP+ jointly place Profile-B's digest in the order, "
                "the order commitment and delivered plaintext agree, so the fixed "
                "check also passes. This remains a business authorization trust boundary."
            ),
        ]
    else:
        lines += [
            "",
            "## 10C implementation gap",
            "",
            (
                "A malicious SM-DP+ used the valid current session key to encrypt "
                "Profile-B and supplied Profile-B's own digest in the AAD and valid "
                "server signature. The signature, ctx_K, AEAD, and server-declared "
                "digest checks all passed."
            ),
            (
                "The current client does not compare the decrypted Profile digest "
                "with `ticket.pid_h`, so it installs the wrong Profile and creates an "
                "installation receipt. The reference check rejects with "
                "`PROFILE_ORDER_DIGEST_MISMATCH` before any file write or receipt."
            ),
            "",
            "## Boundary",
            "",
            (
                "If the MNO and SM-DP+ jointly place Profile-B's digest in the order, "
                "the reference check also passes. This is a business authorization "
                "trust boundary, not a decision AEAD or Profile Binding can make."
            ),
        ]
    (output / f"report-{language}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def svg_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_matrix_svg(
    path: Path,
    scenarios: list[dict[str, Any]],
    language: str,
) -> None:
    zh = language == "zh"
    names = ZH_NAMES if zh else EN_NAMES
    rows = [
        row
        for row in scenarios
        if row["category"] != "positive_control"
    ]
    title = (
        "实验10：Profile交付检查结果"
        if zh
        else "Experiment 10: Profile Delivery Checks"
    )
    headers = (
        ("场景", "签名", "AEAD", "订单pid_h", "安装", "收据")
        if zh
        else ("Scenario", "Signature", "AEAD", "Order pid_h", "Install", "Receipt")
    )
    width, row_h = 1540, 72
    height = 150 + row_h * len(rows)
    xs = (45, 790, 930, 1070, 1240, 1380)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".head{font-size:21px;font-weight:700}",
        ".cell{font-size:20px}",
        ".safe{fill:#15803d}",
        ".danger{fill:#b42318}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="48" text-anchor="middle" class="title">{svg_escape(title)}</text>',
        '<rect x="25" y="78" width="1490" height="54" rx="8" fill="#e8eef8"/>',
    ]
    for x, label in zip(xs, headers):
        anchor = "middle" if x != 45 else "start"
        parts.append(
            f'<text x="{x}" y="113" text-anchor="{anchor}" class="head">{svg_escape(label)}</text>'
        )
    for index, row in enumerate(rows):
        y = 132 + index * row_h
        fill = "#f7f9fc" if index % 2 == 0 else "#ffffff"
        order = status_cell(
            row["order_digest_match"], row["order_digest_checked"]
        )
        values = (
            names[row["scenario"]],
            status_cell(row["server_signature_verified"]),
            status_cell(row["aead_verified"]),
            order,
            "YES" if row["installed"] else "NO",
            "YES" if row["receipt_generated"] else "NO",
        )
        parts.append(
            f'<rect x="25" y="{y}" width="1490" height="{row_h}" fill="{fill}"/>'
        )
        for col, (x, value) in enumerate(zip(xs, values)):
            anchor = "start" if col == 0 else "middle"
            cell_class = "cell"
            if row["scenario"] == "10c_current_client_wrong_profile" and col == 3:
                cell_class = "cell safe"
            if row["scenario"] == "10c_without_order_check_control" and col in (4, 5):
                cell_class = "cell danger"
            parts.append(
                f'<text x="{x}" y="{y + 45}" text-anchor="{anchor}" '
                f'class="{cell_class}">{svg_escape(value)}</text>'
            )
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_flow_svg(path: Path, language: str, order_check_present: bool) -> None:
    zh = language == "zh"
    title = (
        (
            "修复后AURA Profile交付检查链"
            if order_check_present
            else "当前AURA Profile交付检查链与10C缺口"
        )
        if zh
        else (
            "Fixed AURA Profile Delivery Verification Chain"
            if order_check_present
            else "Current AURA Profile Delivery Chain and the 10C Gap"
        )
    )
    labels = (
        [
            ("响应签名", "ctx_K + ciphertext hash"),
            ("会话与AEAD", "K_enc + AAD(ctx_K)"),
            ("服务端自报摘要", "H(P) = response hash"),
            ("订单摘要", "H(P) = ticket.pid_h"),
            ("安装与收据", "install + receipt"),
        ]
        if zh
        else [
            ("Response signature", "ctx_K + ciphertext hash"),
            ("Session and AEAD", "K_enc + AAD(ctx_K)"),
            ("Server-declared digest", "H(P) = response hash"),
            ("Order digest", "H(P) = ticket.pid_h"),
            ("Install and receipt", "install + receipt"),
        ]
    )
    width, height = 1580, 400
    box_w, box_h, gap = 265, 132, 42
    start_x, y = 28, 132
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<defs>",
        '<marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 z" fill="#486581"/>',
        "</marker>",
        "</defs>",
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".main{font-size:23px;font-weight:700}",
        ".sub{font-size:18px}",
        ".check{font-size:19px;font-weight:700;fill:#15803d}",
        ".gap{font-size:19px;font-weight:700;fill:#b42318}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="50" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for index, (main, sub) in enumerate(labels):
        x = start_x + index * (box_w + gap)
        if index:
            previous_end = x - gap
            parts.append(
                f'<line x1="{previous_end + 5}" y1="{y + box_h/2}" '
                f'x2="{x - 10}" y2="{y + box_h/2}" stroke="#486581" '
                'stroke-width="4" marker-end="url(#arrow)"/>'
            )
        is_gap = index == 3
        fill = (
            "#eaf7ee"
            if is_gap and order_check_present
            else "#fdecec"
            if is_gap
            else "#e8f2ff"
        )
        stroke = (
            "#15803d"
            if is_gap and order_check_present
            else "#d92d20"
            if is_gap
            else "#9fb3c8"
        )
        parts += [
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="16" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="3"/>',
            f'<text x="{x + box_w/2}" y="{y + 48}" text-anchor="middle" '
            f'class="main">{svg_escape(main)}</text>',
            f'<text x="{x + box_w/2}" y="{y + 86}" text-anchor="middle" '
            f'class="sub">{svg_escape(sub)}</text>',
        ]
        if is_gap:
            gap_label = (
                ("已检查" if zh else "CHECKED")
                if order_check_present
                else ("当前未检查" if zh else "NOT CHECKED")
            )
            label_class = "check" if order_check_present else "gap"
            parts.append(
                f'<text x="{x + box_w/2}" y="{y + 116}" text-anchor="middle" '
                f'class="{label_class}">{gap_label}</text>'
            )
    footer = (
        (
            "10C：前3项全部通过；订单摘要不匹配后终止，不安装且不生成收据"
            if order_check_present
            else "10C：前3项全部通过；缺少订单摘要检查导致错误Profile继续安装并生成收据"
        )
        if zh
        else (
            "10C: the first three checks pass; order mismatch stops installation and receipt"
            if order_check_present
            else "10C: the first three checks pass; the missing order check allows installation and a receipt"
        )
    )
    parts += [
        f'<text x="{width/2}" y="335" text-anchor="middle" class="sub">{svg_escape(footer)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--strict-security", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(__file__).resolve().parent
    config = load_json(Path(args.config))
    output = prepare_output(Path(args.output), experiment_root)
    profile_a, profile_a_path = load_profile(
        experiment_root,
        config["profile_a_path"],
        config["profile_a_fallback_path"],
    )
    profile_b, profile_b_path = load_profile(
        experiment_root,
        config["profile_b_path"],
    )
    audit = build_source_audit(experiment_root, config)
    sessions, scenarios = run_experiment(
        config,
        profile_a,
        profile_b,
        audit["current_client_checks_order_pid_h_after_decrypt"],
    )
    assertions = build_assertions(sessions, scenarios, audit)
    passed = sum(item["passed"] for item in assertions)
    security_properties = {
        "10a_ciphertext_integrity": all(
            not row["accepted"]
            and not row["installed"]
            and not row["receipt_generated"]
            for row in scenarios
            if row["category"] == "10A"
        ),
        "10b_cross_session_replay": all(
            not row["accepted"]
            and not row["installed"]
            and not row["receipt_generated"]
            for row in scenarios
            if row["category"] == "10B"
        ),
        "10c_wrong_plaintext_rejected": not by_name(scenarios)[
            "10c_current_client_wrong_profile"
        ]["accepted"],
    }
    security_passed = sum(security_properties.values())
    current = by_name(scenarios)["10c_current_client_wrong_profile"]
    status = (
        "PASS"
        if security_passed == len(security_properties)
        else "IMPLEMENTATION_GAP_DETECTED"
    )
    summary = {
        "experiment": config["experiment_name"],
        "status": status,
        "harness_status": "PASS",
        "seed": config["seed"],
        "profile_a_path": str(profile_a_path),
        "profile_b_path": str(profile_b_path),
        "profile_a_bytes": len(profile_a),
        "profile_b_bytes": len(profile_b),
        "session_evidence": sessions,
        "scenarios": scenarios,
        "security_properties": security_properties,
        "security_properties_passed": security_passed,
        "security_properties_total": len(security_properties),
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "metrics": {
            "10a_rejected": sum(
                not row["accepted"] for row in scenarios if row["category"] == "10A"
            ),
            "10a_total": sum(
                row["category"] == "10A" for row in scenarios
            ),
            "10b_rejected": sum(
                not row["accepted"] for row in scenarios if row["category"] == "10B"
            ),
            "10b_total": sum(
                row["category"] == "10B" for row in scenarios
            ),
            "10c_current_client_accepted_wrong_profile": current["accepted"],
            "10c_wrong_profile_installed": current["installed"],
            "10c_receipt_generated": current["receipt_generated"],
            "10c_aead_verified": current["aead_verified"],
            "10c_order_digest_match": current["order_digest_match"],
            "10c_order_digest_checked": current["order_digest_checked"],
            "10c_negative_control_accepted_wrong_profile": by_name(scenarios)[
                "10c_without_order_check_control"
            ]["accepted"],
        },
        "implementation_gap": audit["implementation_gap"],
        "fix_status": audit["fix_status"],
        "recommended_fix": audit["recommended_fix"],
        "trust_boundary": (
            "If MNO and SM-DP+ jointly authorize the wrong Profile hash in "
            "ticket.pid_h, protocol checks cannot identify the business decision."
        ),
        "results_dir": str(output),
    }
    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "source-audit.json", audit)
    write_jsonl(output / "raw" / "transcripts.jsonl", scenarios)
    write_csv(output / "scenarios.csv", scenarios)
    write_csv(output / "assertions.csv", assertions)
    write_csv(output / "paper" / "table-profile-integrity.csv", scenarios)
    render_report(output, summary, "zh")
    render_report(output, summary, "en")
    render_matrix_svg(
        output / "paper" / "profile-integrity-matrix-zh.svg",
        scenarios,
        "zh",
    )
    render_matrix_svg(
        output / "paper" / "profile-integrity-matrix-en.svg",
        scenarios,
        "en",
    )
    render_flow_svg(
        output / "paper" / "profile-verification-chain-zh.svg",
        "zh",
        audit["current_client_checks_order_pid_h_after_decrypt"],
    )
    render_flow_svg(
        output / "paper" / "profile-verification-chain-en.svg",
        "en",
        audit["current_client_checks_order_pid_h_after_decrypt"],
    )
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "matrix": "图：密文篡改、跨会话重放、错误明文替换及业务信任边界结果。",
                "flow": (
                    "图：修复后AURA Profile交付检查链，订单pid_h不匹配在安装前终止。"
                    if audit["current_client_checks_order_pid_h_after_decrypt"]
                    else "图：当前AURA Profile交付检查链及解密后订单pid_h检查缺口。"
                ),
            },
            "en": {
                "matrix": "Figure: Ciphertext tamper, cross-session replay, wrong-plaintext replacement, and trust-boundary results.",
                "flow": (
                    "Figure: Fixed AURA Profile delivery chain; an order pid_h mismatch stops before installation."
                    if audit["current_client_checks_order_pid_h_after_decrypt"]
                    else "Figure: Current AURA Profile delivery chain and the missing post-decryption order pid_h check."
                ),
            },
        },
    )
    render_terminal(summary, args.lang, args.machine_json)
    if not args.machine_json:
        print(f"\nRESULTS={output}")
        print(status)
    if args.strict_security and status != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
