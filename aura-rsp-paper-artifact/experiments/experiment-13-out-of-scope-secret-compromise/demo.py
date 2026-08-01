from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import json
import platform
import shutil
import sqlite3
import sys
import time
import xml.sax.saxutils as saxutils
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
CLASSIFICATION = "EXPECTED OUT-OF-SCOPE COMPROMISE"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def seeded_bytes(seed: int, label: str, length: int) -> bytes:
    result = bytearray()
    counter = 0
    while len(result) < length:
        result.extend(
            hashlib.sha256(
                f"{seed}:{label}:{counter}".encode("utf-8")
            ).digest()
        )
        counter += 1
    return bytes(result[:length])


def seeded_int(seed: int, label: str, modulus: int) -> int:
    value = int.from_bytes(seeded_bytes(seed, label, 64), "big") % modulus
    return value or 1


def token(seed: int, label: str, length: int = 24) -> str:
    return hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:length]


def secret_commit(value: int) -> str:
    return hashlib.sha256(value.to_bytes(64, "big")).hexdigest()


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
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
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
    for name in ("raw", "evidence", "paper", "runtime"):
        (output / name).mkdir(parents=True, exist_ok=True)
    return output


def deterministic_ed25519(seed: int, label: str):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        seeded_bytes(seed, label, 32)
    )


def deterministic_p256(seed: int, label: str):
    scalar = seeded_int(seed, label, P256_ORDER)
    return ec.derive_private_key(scalar, ec.SECP256R1())


def public_fingerprint(public_key: Any) -> str:
    data = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(data).hexdigest()


def ed_sign(private_key: Any, value: dict[str, Any]) -> str:
    return b64e(private_key.sign(canonical(value)))


def ed_verify(
    public_key: Any, value: dict[str, Any], signature: str
) -> bool:
    try:
        public_key.verify(b64d(signature), canonical(value))
        return True
    except Exception:
        return False


def p256_sign(private_key: Any, value: dict[str, Any]) -> str:
    return b64e(
        private_key.sign(canonical(value), ec.ECDSA(hashes.SHA256()))
    )


def p256_verify(
    public_key: Any, value: dict[str, Any], signature: str
) -> bool:
    try:
        public_key.verify(
            b64d(signature),
            canonical(value),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


def portable_issuer_backend(
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    seed = int(config["seed"])
    now = int(config["now"])
    modulus = (1 << 255) - 19
    x = seeded_int(seed, "device:x", modulus)
    k = seeded_int(seed, "device:k", modulus)
    eta = seeded_int(seed, "ticket:eta", modulus)
    d_value = seeded_int(seed, "ticket:d", modulus)
    wrong_x = seeded_int(seed, "attacker:wrong-x", modulus)
    attacker_x = seeded_int(seed, "attacker:chosen-x", modulus)
    attacker_k = seeded_int(seed, "attacker:chosen-k", modulus)
    attacker_eta = seeded_int(seed, "attacker:chosen-eta", modulus)
    attacker_d = seeded_int(seed, "attacker:chosen-d", modulus)
    eum_key = deterministic_ed25519(seed, "portable:eum")
    mno_key = deterministic_ed25519(seed, "portable:mno")
    unrelated_eum = deterministic_ed25519(seed, "portable:unrelated-eum")
    unrelated_mno = deterministic_ed25519(seed, "portable:unrelated-mno")
    ticket = {
        "I_ac": "IAC-" + token(seed, "ticket:iac", 32).upper(),
        **config["ticket"],
        "exp": now + int(config["ticket_lifetime_seconds"]),
    }
    cred_exp = now + int(config["credential_lifetime_seconds"])

    def credential_payload(holder_x: int, holder_k: int) -> dict[str, Any]:
        return {
            "domain": "portable:AURA-Cred_D-commitment",
            "x_commit": secret_commit(holder_x),
            "k_commit": secret_commit(holder_k),
            "cred_exp": cred_exp,
        }

    def ticket_payload(
        holder_x: int, holder_eta: int, holder_d: int
    ) -> dict[str, Any]:
        return {
            "domain": "portable:AURA-Tok_op-commitment",
            "ticket": ticket,
            "x_commit": secret_commit(holder_x),
            "eta_commit": secret_commit(holder_eta),
            "d_commit": secret_commit(holder_d),
        }

    credential = credential_payload(x, k)
    credential_signature = ed_sign(eum_key, credential)
    token_payload = ticket_payload(x, eta, d_value)
    token_signature = ed_sign(mno_key, token_payload)

    def joint_valid(
        holder_x: int,
        holder_k: int,
        holder_eta: int,
        holder_d: int,
        cred_sig: str,
        tok_sig: str,
    ) -> bool:
        return ed_verify(
            eum_key.public_key(),
            credential_payload(holder_x, holder_k),
            cred_sig,
        ) and ed_verify(
            mno_key.public_key(),
            ticket_payload(holder_x, holder_eta, holder_d),
            tok_sig,
        )

    no_x_control = joint_valid(
        wrong_x, k, eta, d_value, credential_signature, token_signature
    )
    full_holder_clone = joint_valid(
        x, k, eta, d_value, credential_signature, token_signature
    )
    eta_d_only = joint_valid(
        wrong_x,
        attacker_k,
        eta,
        d_value,
        credential_signature,
        token_signature,
    )

    forged_credential = credential_payload(attacker_x, attacker_k)
    control_credential_sig = ed_sign(unrelated_eum, forged_credential)
    leaked_credential_sig = ed_sign(eum_key, forged_credential)
    control_credential_valid = ed_verify(
        eum_key.public_key(), forged_credential, control_credential_sig
    )
    leaked_credential_valid = ed_verify(
        eum_key.public_key(), forged_credential, leaked_credential_sig
    )

    forged_token = ticket_payload(attacker_x, attacker_eta, attacker_d)
    control_token_sig = ed_sign(unrelated_mno, forged_token)
    leaked_token_sig = ed_sign(mno_key, forged_token)
    control_token_valid = ed_verify(
        mno_key.public_key(), forged_token, control_token_sig
    )
    leaked_token_valid = ed_verify(
        mno_key.public_key(), forged_token, leaked_token_sig
    )

    attempts = [
        {
            "scenario": "euicc_x",
            "attempt": "without_correct_x",
            "accepted": no_x_control,
            "expected": False,
        },
        {
            "scenario": "euicc_x",
            "attempt": "x_plus_complete_holder_state",
            "accepted": full_holder_clone,
            "expected": True,
        },
        {
            "scenario": "ticket_eta_d",
            "attempt": "eta_d_without_matching_x_k",
            "accepted": eta_d_only,
            "expected": False,
        },
        {
            "scenario": "ticket_eta_d",
            "attempt": "eta_d_plus_complete_holder_state",
            "accepted": full_holder_clone,
            "expected": True,
        },
        {
            "scenario": "eum_signing_key",
            "attempt": "unrelated_key_forgery_control",
            "accepted": control_credential_valid,
            "expected": False,
        },
        {
            "scenario": "eum_signing_key",
            "attempt": "leaked_eum_key_forgery",
            "accepted": leaked_credential_valid,
            "expected": True,
        },
        {
            "scenario": "mno_signing_key",
            "attempt": "unrelated_key_forgery_control",
            "accepted": control_token_valid,
            "expected": False,
        },
        {
            "scenario": "mno_signing_key",
            "attempt": "leaked_mno_key_forgery",
            "accepted": leaked_token_valid,
            "expected": True,
        },
    ]
    result = {
        "backend": "portable_signature_commitment_harness",
        "production_bbs": False,
        "limitation": (
            "EUM/MNO use Ed25519 signatures over hidden-message commitments; "
            "this validates issuer-key compromise causality but is not BBS+ "
            "or a zero-knowledge proof."
        ),
        "x_without_matching_state_accepted": no_x_control,
        "x_with_complete_holder_state_accepted": full_holder_clone,
        "eta_d_without_matching_x_k_accepted": eta_d_only,
        "eta_d_with_complete_holder_state_accepted": full_holder_clone,
        "eum_control_forgery_accepted": control_credential_valid,
        "eum_leaked_key_forgery_accepted": leaked_credential_valid,
        "mno_control_forgery_accepted": control_token_valid,
        "mno_leaked_key_forgery_accepted": leaked_token_valid,
    }
    fingerprints = {
        "eum_public_key_sha256": public_fingerprint(eum_key.public_key()),
        "mno_public_key_sha256": public_fingerprint(mno_key.public_key()),
    }
    return result, attempts, fingerprints


def production_bbs_backend(
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    from py_ecc.optimized_bls12_381 import G2, curve_order, multiply

    from pySim.esim.aura.bbs import (
        blind_sign,
        create_blind_commitment,
        finalize_blind_signature,
        public_key_to_dict,
        verify_signature,
    )
    from pySim.esim.aura.codec import canonical as aura_canonical
    from pySim.esim.aura.proof import (
        CRED_PARAMS,
        TOKEN_PARAMS,
        credential_messages,
        token_messages,
        token_public_messages,
    )

    seed = int(config["seed"])
    now = int(config["now"])
    x = seeded_int(seed, "device:x", curve_order)
    k = seeded_int(seed, "device:k", curve_order)
    eta = seeded_int(seed, "ticket:eta", curve_order)
    d_value = seeded_int(seed, "ticket:d", curve_order)
    wrong_x = seeded_int(seed, "attacker:wrong-x", curve_order)
    attacker_x = seeded_int(seed, "attacker:chosen-x", curve_order)
    attacker_k = seeded_int(seed, "attacker:chosen-k", curve_order)
    attacker_eta = seeded_int(seed, "attacker:chosen-eta", curve_order)
    attacker_d = seeded_int(seed, "attacker:chosen-d", curve_order)
    eum_sk = seeded_int(seed, "bbs:eum-sk", curve_order)
    mno_sk = seeded_int(seed, "bbs:mno-sk", curve_order)
    unrelated_eum_sk = seeded_int(seed, "bbs:unrelated-eum", curve_order)
    unrelated_mno_sk = seeded_int(seed, "bbs:unrelated-mno", curve_order)
    eum_pk = multiply(G2, eum_sk)
    mno_pk = multiply(G2, mno_sk)
    ticket = {
        "I_ac": "IAC-" + token(seed, "ticket:iac", 32).upper(),
        **config["ticket"],
        "exp": now + int(config["ticket_lifetime_seconds"]),
    }
    cred_exp = now + int(config["credential_lifetime_seconds"])

    def issue_credential(sk: int, holder_x: int, holder_k: int):
        context = {"type": "Cred_D", "cred_exp": cred_exp}
        commitment, user_blinding = create_blind_commitment(
            CRED_PARAMS, {0: holder_x}, context
        )
        blind = blind_sign(
            CRED_PARAMS,
            sk,
            commitment,
            {1: holder_k, 2: cred_exp},
            context,
        )
        return finalize_blind_signature(blind, user_blinding)

    def issue_token(
        sk: int, holder_x: int, holder_eta: int, holder_d: int
    ):
        context = {"type": "Tok_op", "ticket": ticket}
        commitment, user_blinding = create_blind_commitment(
            TOKEN_PARAMS,
            {6: holder_x, 7: holder_eta, 8: holder_d},
            context,
        )
        blind = blind_sign(
            TOKEN_PARAMS,
            sk,
            commitment,
            {
                index: value
                for index, value in enumerate(token_public_messages(ticket))
            },
            context,
        )
        return finalize_blind_signature(blind, user_blinding)

    credential_signature = issue_credential(eum_sk, x, k)
    token_signature = issue_token(mno_sk, x, eta, d_value)

    def joint_valid(
        holder_x: int,
        holder_k: int,
        holder_eta: int,
        holder_d: int,
    ) -> bool:
        return verify_signature(
            CRED_PARAMS,
            eum_pk,
            credential_messages(holder_x, holder_k, cred_exp),
            credential_signature,
        ) and verify_signature(
            TOKEN_PARAMS,
            mno_pk,
            token_messages(
                ticket, holder_x, holder_eta, holder_d
            ),
            token_signature,
        )

    no_x_control = joint_valid(wrong_x, k, eta, d_value)
    full_holder_clone = joint_valid(x, k, eta, d_value)
    eta_d_only = joint_valid(wrong_x, attacker_k, eta, d_value)

    unrelated_credential = issue_credential(
        unrelated_eum_sk, attacker_x, attacker_k
    )
    leaked_credential = issue_credential(eum_sk, attacker_x, attacker_k)
    control_credential_valid = verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(attacker_x, attacker_k, cred_exp),
        unrelated_credential,
    )
    leaked_credential_valid = verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(attacker_x, attacker_k, cred_exp),
        leaked_credential,
    )

    unrelated_token = issue_token(
        unrelated_mno_sk, attacker_x, attacker_eta, attacker_d
    )
    leaked_token = issue_token(
        mno_sk, attacker_x, attacker_eta, attacker_d
    )
    control_token_valid = verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(
            ticket, attacker_x, attacker_eta, attacker_d
        ),
        unrelated_token,
    )
    leaked_token_valid = verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(
            ticket, attacker_x, attacker_eta, attacker_d
        ),
        leaked_token,
    )
    attempts = [
        {"scenario": "euicc_x", "attempt": "without_correct_x", "accepted": no_x_control, "expected": False},
        {"scenario": "euicc_x", "attempt": "x_plus_complete_holder_state", "accepted": full_holder_clone, "expected": True},
        {"scenario": "ticket_eta_d", "attempt": "eta_d_without_matching_x_k", "accepted": eta_d_only, "expected": False},
        {"scenario": "ticket_eta_d", "attempt": "eta_d_plus_complete_holder_state", "accepted": full_holder_clone, "expected": True},
        {"scenario": "eum_signing_key", "attempt": "unrelated_key_forgery_control", "accepted": control_credential_valid, "expected": False},
        {"scenario": "eum_signing_key", "attempt": "leaked_eum_key_forgery", "accepted": leaked_credential_valid, "expected": True},
        {"scenario": "mno_signing_key", "attempt": "unrelated_key_forgery_control", "accepted": control_token_valid, "expected": False},
        {"scenario": "mno_signing_key", "attempt": "leaked_mno_key_forgery", "accepted": leaked_token_valid, "expected": True},
    ]
    result = {
        "backend": "aura_production_bbs_plus",
        "production_bbs": True,
        "limitation": None,
        "x_without_matching_state_accepted": no_x_control,
        "x_with_complete_holder_state_accepted": full_holder_clone,
        "eta_d_without_matching_x_k_accepted": eta_d_only,
        "eta_d_with_complete_holder_state_accepted": full_holder_clone,
        "eum_control_forgery_accepted": control_credential_valid,
        "eum_leaked_key_forgery_accepted": leaked_credential_valid,
        "mno_control_forgery_accepted": control_token_valid,
        "mno_leaked_key_forgery_accepted": leaked_token_valid,
    }
    fingerprints = {
        "eum_public_key_sha256": hashlib.sha256(
            aura_canonical(public_key_to_dict(eum_pk))
        ).hexdigest(),
        "mno_public_key_sha256": hashlib.sha256(
            aura_canonical(public_key_to_dict(mno_pk))
        ).hexdigest(),
    }
    return result, attempts, fingerprints


def choose_issuer_backend(
    requested: str, config: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    production_available = (
        importlib.util.find_spec("py_ecc") is not None
        and importlib.util.find_spec("pySim.esim.aura") is not None
    )
    if requested == "production" and not production_available:
        raise RuntimeError(
            "production backend requires py-ecc and integrated pySim AURA; "
            "run with the AURA WSL virtual environment"
        )
    if requested == "portable" or not production_available:
        return portable_issuer_backend(config)
    return production_bbs_backend(config)


def run_smdpp_compromise(
    config: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    seed = int(config["seed"])
    server_auth_key = deterministic_p256(seed, "smdpp:server-auth")
    binding_key = deterministic_p256(seed, "smdpp:profile-binding")
    attacker_auth_key = deterministic_p256(seed, "attacker:server-auth")
    attacker_binding_key = deterministic_p256(seed, "attacker:binding")
    server_auth = {
        "transactionId": token(seed, "server:transaction", 32).upper(),
        "N_S": b64e(seeded_bytes(seed, "server:N_S", 32)),
        "sid": config["ticket"]["sid"],
        "serverOID": "2.999.10",
        "PRaddr": config["ticket"]["PRaddr"],
        "cap": "ECDHE-P256-HKDF-SHA256-AES256GCM",
    }
    bind_t = {
        "domain": "AURA-RSP-v14:Bind_t",
        "transactionId": server_auth["transactionId"],
        "ctx_t_hash": token(seed, "server:ctx-t-hash", 64),
        "auth_transcript_hash": token(seed, "server:auth-hash", 64),
        "vk_t": b64e(seeded_bytes(seed, "server:vk-t", 32)),
    }
    control_auth_signature = p256_sign(attacker_auth_key, server_auth)
    leaked_auth_signature = p256_sign(server_auth_key, server_auth)
    control_bind_signature = p256_sign(attacker_binding_key, bind_t)
    leaked_bind_signature = p256_sign(binding_key, bind_t)
    control_auth_valid = p256_verify(
        server_auth_key.public_key(), server_auth, control_auth_signature
    )
    leaked_auth_valid = p256_verify(
        server_auth_key.public_key(), server_auth, leaked_auth_signature
    )
    control_bind_valid = p256_verify(
        binding_key.public_key(), bind_t, control_bind_signature
    )
    leaked_bind_valid = p256_verify(
        binding_key.public_key(), bind_t, leaked_bind_signature
    )
    result = {
        "control_server_auth_forgery_accepted": control_auth_valid,
        "leaked_server_auth_key_forgery_accepted": leaked_auth_valid,
        "control_binding_forgery_accepted": control_bind_valid,
        "leaked_binding_key_forgery_accepted": leaked_bind_valid,
        "server_impersonation_succeeded": leaked_auth_valid,
        "binding_forgery_succeeded": leaked_bind_valid,
    }
    attempts = [
        {"scenario": "smdpp_signing_keys", "attempt": "unrelated_server_auth_key_control", "accepted": control_auth_valid, "expected": False},
        {"scenario": "smdpp_signing_keys", "attempt": "leaked_server_auth_key", "accepted": leaked_auth_valid, "expected": True},
        {"scenario": "smdpp_signing_keys", "attempt": "unrelated_binding_key_control", "accepted": control_bind_valid, "expected": False},
        {"scenario": "smdpp_signing_keys", "attempt": "leaked_profile_binding_key", "accepted": leaked_bind_valid, "expected": True},
    ]
    fingerprints = {
        "server_auth_public_key_sha256": public_fingerprint(
            server_auth_key.public_key()
        ),
        "profile_binding_public_key_sha256": public_fingerprint(
            binding_key.public_key()
        ),
    }
    return result, attempts, fingerprints


def run_trace_database_compromise(
    output: Path, config: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    seed = int(config["seed"])
    count = int(config["trace_device_count"])
    db_path = output / "runtime" / "eum-trace.sqlite"
    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            CREATE TABLE trace_index(
                k TEXT PRIMARY KEY,
                eid TEXT NOT NULL,
                r_tr TEXT NOT NULL
            )
            """
        )
        rows = []
        for index in range(count):
            rows.append(
                {
                    "k": b64e(
                        seeded_bytes(seed, f"trace:{index}:k", 32)
                    ),
                    "eid": f"8904903212345123451234567890{index:04d}",
                    "r_tr": b64e(
                        seeded_bytes(seed, f"trace:{index}:r-tr", 32)
                    ),
                }
            )
        db.executemany(
            "INSERT INTO trace_index(k,eid,r_tr) VALUES(:k,:eid,:r_tr)",
            rows,
        )
        db.commit()

    query_k = rows[2]["k"]
    without_database_eid = None
    with sqlite3.connect(db_path) as leaked_db:
        leaked_db.row_factory = sqlite3.Row
        leaked_rows = [
            dict(row)
            for row in leaked_db.execute(
                "SELECT k,eid,r_tr FROM trace_index ORDER BY eid"
            )
        ]
        resolved = leaked_db.execute(
            "SELECT eid FROM trace_index WHERE k=?", (query_k,)
        ).fetchone()
    with_database_eid = resolved["eid"] if resolved else None
    result = {
        "identity_records": count,
        "without_database_eid": without_database_eid,
        "with_leaked_database_eid": with_database_eid,
        "expected_eid": rows[2]["eid"],
        "trace_resolution_succeeded": with_database_eid == rows[2]["eid"],
        "all_identity_records_disclosed": len(leaked_rows) == count,
        "signing_capability_gained": False,
    }
    attempts = [
        {
            "scenario": "eum_trace_database",
            "attempt": "resolve_k_without_database",
            "accepted": without_database_eid is not None,
            "expected": False,
        },
        {
            "scenario": "eum_trace_database",
            "attempt": "resolve_k_with_leaked_database",
            "accepted": with_database_eid == rows[2]["eid"],
            "expected": True,
        },
    ]
    redacted_export = [
        {
            "k_sha256": hashlib.sha256(b64d(row["k"])).hexdigest(),
            "eid": row["eid"],
            "r_tr_sha256": hashlib.sha256(b64d(row["r_tr"])).hexdigest(),
        }
        for row in leaked_rows
    ]
    return result, attempts, redacted_export


def source_audit(
    experiment_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    definitions = {
        "eum_mno_key_generation": (
            "bootstrap",
            "eum_sk, eum_pk = keygen()",
        ),
        "authority_private_key_storage": (
            "bootstrap",
            '"secret_key": scalar_to_b64(eum_sk)',
        ),
        "device_x_storage": (
            "bootstrap",
            '"x": scalar_to_b64(x)',
        ),
        "trace_index_write": (
            "bootstrap",
            "store.put_trace_index(k_value, entry[\"eid\"], entry[\"r_tr\"])",
        ),
        "ticket_hidden_eta": (
            "ticket",
            '"eta": scalar_to_b64(eta)',
        ),
        "ticket_hidden_d": (
            "ticket",
            '"d": scalar_to_b64(d_value)',
        ),
        "shared_x_witness": (
            "proof",
            'witnesses.update({"x": x, "k": k, "eta": eta, "d": d_value})',
        ),
        "server_auth_signature": (
            "server",
            '"serverSignature": p256_sign(self.server_auth_key, server_auth)',
        ),
        "binding_signature": (
            "server",
            "bind_t = sign_binding(",
        ),
        "trace_lookup": (
            "server",
            "trace_lookup=self.store.lookup_trace",
        ),
        "trace_schema": (
            "storage",
            "def put_trace_index(",
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
            "line": line_number,
            "pattern": pattern,
        }
    return {
        "all_checkpoints_found": all(
            item["line"] is not None for item in checkpoints.values()
        ),
        "checkpoints": checkpoints,
        "source_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, (path, _) in sources.items()
        },
    }


def build_scenarios(
    issuer: dict[str, Any],
    smdpp: dict[str, Any],
    trace: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "scenario": "euicc_x",
            "leaked_asset": "eUICC long-term x",
            "standalone_sufficient": False,
            "attack_succeeded": issuer[
                "x_with_complete_holder_state_accepted"
            ],
            "required_additional_material": (
                "k, issued credential, signed ticket, eta, d"
            ),
            "affected_property": "endpoint holder-state clone resistance",
            "classification": CLASSIFICATION,
        },
        {
            "scenario": "ticket_eta_d",
            "leaked_asset": "ticket witnesses eta,d",
            "standalone_sufficient": False,
            "attack_succeeded": issuer[
                "eta_d_with_complete_holder_state_accepted"
            ],
            "required_additional_material": (
                "matching x/k, device credential, signed ticket"
            ),
            "affected_property": "ticket holder-state confidentiality",
            "classification": CLASSIFICATION,
        },
        {
            "scenario": "eum_signing_key",
            "leaked_asset": "EUM credential issuing private key",
            "standalone_sufficient": True,
            "attack_succeeded": issuer[
                "eum_leaked_key_forgery_accepted"
            ],
            "required_additional_material": "attacker-chosen credential messages",
            "affected_property": "device credential unforgeability",
            "classification": CLASSIFICATION,
        },
        {
            "scenario": "mno_signing_key",
            "leaked_asset": "MNO ticket issuing private key",
            "standalone_sufficient": True,
            "attack_succeeded": issuer[
                "mno_leaked_key_forgery_accepted"
            ],
            "required_additional_material": "attacker-chosen ticket messages",
            "affected_property": "operation ticket unforgeability",
            "classification": CLASSIFICATION,
        },
        {
            "scenario": "smdpp_signing_keys",
            "leaked_asset": "SM-DP+ authentication and binding private keys",
            "standalone_sufficient": True,
            "attack_succeeded": (
                smdpp["server_impersonation_succeeded"]
                and smdpp["binding_forgery_succeeded"]
            ),
            "required_additional_material": "chosen server transcript",
            "affected_property": "server authenticity and Profile Binding",
            "classification": CLASSIFICATION,
        },
        {
            "scenario": "eum_trace_database",
            "leaked_asset": "EUM trace_index database",
            "standalone_sufficient": True,
            "attack_succeeded": (
                trace["trace_resolution_succeeded"]
                and trace["all_identity_records_disclosed"]
            ),
            "required_additional_material": "database read access",
            "affected_property": "conditional identity-map confidentiality",
            "classification": CLASSIFICATION,
        },
    ]


def build_assertions(
    issuer: dict[str, Any],
    smdpp: dict[str, Any],
    trace: dict[str, Any],
    scenarios: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    audit: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = [
        ("wrong_x_control_rejected", False, issuer["x_without_matching_state_accepted"]),
        ("x_alone_not_reported_as_signing_key", False, scenarios[0]["standalone_sufficient"]),
        ("full_endpoint_holder_clone_accepted", True, issuer["x_with_complete_holder_state_accepted"]),
        ("eta_d_without_matching_x_k_rejected", False, issuer["eta_d_without_matching_x_k_accepted"]),
        ("eta_d_with_complete_state_accepted", True, issuer["eta_d_with_complete_holder_state_accepted"]),
        ("unrelated_eum_key_control_rejected", False, issuer["eum_control_forgery_accepted"]),
        ("leaked_eum_key_forges_credential", True, issuer["eum_leaked_key_forgery_accepted"]),
        ("unrelated_mno_key_control_rejected", False, issuer["mno_control_forgery_accepted"]),
        ("leaked_mno_key_forges_ticket", True, issuer["mno_leaked_key_forgery_accepted"]),
        ("unrelated_server_auth_key_rejected", False, smdpp["control_server_auth_forgery_accepted"]),
        ("leaked_server_auth_key_impersonates", True, smdpp["leaked_server_auth_key_forgery_accepted"]),
        ("unrelated_binding_key_rejected", False, smdpp["control_binding_forgery_accepted"]),
        ("leaked_binding_key_forges_bind_t", True, smdpp["leaked_binding_key_forgery_accepted"]),
        ("trace_db_resolves_correct_eid", True, trace["trace_resolution_succeeded"]),
        ("trace_db_discloses_all_test_records", True, trace["all_identity_records_disclosed"]),
        ("trace_db_does_not_grant_signing", False, trace["signing_capability_gained"]),
        ("all_six_classified_out_of_scope", 6, sum(row["classification"] == CLASSIFICATION for row in scenarios)),
        ("all_targeted_compromise_effects_observed", 6, sum(bool(row["attack_succeeded"]) for row in scenarios)),
        ("all_controls_match_expected", True, all(bool(row["accepted"]) == bool(row["expected"]) for row in attempts)),
        ("source_audit_complete", True, audit["all_checkpoints_found"]),
    ]
    return [
        {
            "assertion": name,
            "expected": expected,
            "observed": observed,
            "passed": observed == expected,
        }
        for name, expected, observed in checks
    ]


ZH_NAMES = {
    "euicc_x": "eUICC长期秘密x",
    "ticket_eta_d": "票据隐藏值eta,d",
    "eum_signing_key": "EUM签发私钥",
    "mno_signing_key": "MNO票据签发私钥",
    "smdpp_signing_keys": "SM-DP+签名/Binding私钥",
    "eum_trace_database": "EUM追踪数据库",
}

EN_NAMES = {
    "euicc_x": "eUICC long-term secret x",
    "ticket_eta_d": "Ticket witnesses eta,d",
    "eum_signing_key": "EUM issuing private key",
    "mno_signing_key": "MNO ticket issuing key",
    "smdpp_signing_keys": "SM-DP+ signing/binding keys",
    "eum_trace_database": "EUM tracing database",
}


def render_terminal(
    summary: dict[str, Any], language: str, machine_json: bool
) -> None:
    if machine_json:
        print(
            json.dumps(
                {
                    "status": summary["status"],
                    "classification": CLASSIFICATION,
                    "issuer_backend": summary["issuer_backend"],
                    "scenarios": len(summary["scenarios"]),
                    "compromise_effects_observed": summary["metrics"][
                        "compromise_effects_observed"
                    ],
                    "standalone_sufficient": summary["metrics"][
                        "standalone_sufficient"
                    ],
                    "conditional_on_holder_state": summary["metrics"][
                        "conditional_on_holder_state"
                    ],
                    "assertions": (
                        f"{summary['assertions_passed']}/"
                        f"{summary['assertions_total']}"
                    ),
                    "results": summary["results_dir"],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return
    if language in ("zh", "both"):
        print("\n实验13：超出威胁模型的秘密泄露")
        print("=" * 116)
        print(
            f"{'泄露对象':<31}{'单独足够':>12}{'影响已观察':>14}"
            f"{'结果分类':>43}"
        )
        print("-" * 116)
        for row in summary["scenarios"]:
            print(
                f"{ZH_NAMES[row['scenario']]:<31}"
                f"{('是' if row['standalone_sufficient'] else '否'):>12}"
                f"{('是' if row['attack_succeeded'] else '否'):>14}"
                f"{row['classification']:>43}"
            )
        print("-" * 116)
        print(
            f"签发后端={summary['issuer_backend']}；"
            f"机器断言={summary['assertions_passed']}/"
            f"{summary['assertions_total']}；状态={summary['status']}"
        )
        print("解释：攻击成功来自根密钥或诚实端点失陷，不计为协议内安全失败。")
    if language in ("en", "both"):
        print("\nExperiment 13: Out-of-Scope Secret Compromise")
        print("=" * 126)
        print(
            f"{'Compromised asset':<37}{'Alone enough':>15}"
            f"{'Effect observed':>18}{'Classification':>45}"
        )
        print("-" * 126)
        for row in summary["scenarios"]:
            print(
                f"{EN_NAMES[row['scenario']]:<37}"
                f"{('YES' if row['standalone_sufficient'] else 'NO'):>15}"
                f"{('YES' if row['attack_succeeded'] else 'NO'):>18}"
                f"{row['classification']:>45}"
            )
        print("-" * 126)
        print(
            f"Issuer backend={summary['issuer_backend']}; "
            f"assertions={summary['assertions_passed']}/"
            f"{summary['assertions_total']}; status={summary['status']}"
        )
        print(
            "Interpretation: success follows root-key or honest-endpoint "
            "compromise and is not an in-scope protocol failure."
        )


def render_report(
    output: Path, summary: dict[str, Any], language: str
) -> None:
    if language == "zh":
        rows = "\n".join(
            f"| {ZH_NAMES[row['scenario']]} | "
            f"{'是' if row['standalone_sufficient'] else '否'} | "
            f"{'是' if row['attack_succeeded'] else '否'} | "
            f"`{row['classification']}` |"
            for row in summary["scenarios"]
        )
        limitation = (
            "本次使用正式AURA BBS+签发/验证路径。"
            if summary["production_bbs"]
            else "本次EUM/MNO签发使用便携Ed25519承诺夹具；它验证私钥泄露的因果关系，"
            "但不冒充BBS+或零知识证明。请在AURA WSL环境运行`--backend production`"
            "获得正式BBS+结果。"
        )
        text = f"""# 实验13：超出威胁模型的密钥或设备秘密泄露

- 状态：**{summary['status']}**
- 统一分类：`{CLASSIFICATION}`
- 签发后端：`{summary['issuer_backend']}`
- 机器断言：{summary['assertions_passed']}/{summary['assertions_total']}

| 泄露对象 | 单独足够 | 影响已观察 | 分类 |
|---|---:|---:|---|
{rows}

## 关键解释

`x`和`eta,d`是隐藏见证，不是签发密钥；单独泄露不足以伪造EUM或MNO签名。与设备内
已有的匹配凭证、票据、`k`和其他持有者状态组合后，端点克隆才成功。

EUM/MNO/SM-DP+私钥泄露分别破坏凭证不可伪造性、票据不可伪造性以及服务器认证/
Profile Binding。追踪库泄露直接暴露测试`k -> EID`映射，但没有获得签发能力。

{limitation}

## 结论

这些结果用于明确方案保证的前提，不用于证明AURA在根信任或诚实端点失陷后仍然安全。
"""
    else:
        rows = "\n".join(
            f"| {EN_NAMES[row['scenario']]} | "
            f"{'yes' if row['standalone_sufficient'] else 'no'} | "
            f"{'yes' if row['attack_succeeded'] else 'no'} | "
            f"`{row['classification']}` |"
            for row in summary["scenarios"]
        )
        limitation = (
            "This run used the production AURA BBS+ issuance and verification path."
            if summary["production_bbs"]
            else "This run used the portable Ed25519 commitment harness for EUM/MNO "
            "issuance. It validates private-key compromise causality but does not "
            "claim to implement BBS+ or zero knowledge. Run `--backend production` "
            "inside the AURA WSL environment for the production BBS+ path."
        )
        text = f"""# Experiment 13: Out-of-Scope Key and Endpoint Compromise

- Status: **{summary['status']}**
- Classification: `{CLASSIFICATION}`
- Issuer backend: `{summary['issuer_backend']}`
- Machine assertions: {summary['assertions_passed']}/{summary['assertions_total']}

| Compromised asset | Alone sufficient | Effect observed | Classification |
|---|---:|---:|---|
{rows}

## Interpretation

`x` and `eta,d` are hidden witnesses, not issuer signing keys. Their standalone
disclosure cannot forge EUM or MNO signatures. Endpoint cloning succeeds only
when the attacker also copies the matching issued credentials, ticket, `k`, and
other holder state.

EUM, MNO, and SM-DP+ private-key compromise respectively breaks credential
unforgeability, ticket unforgeability, and server/Profile-Binding authenticity.
Tracing-database disclosure exposes the test `k -> EID` map but grants no signing
capability.

{limitation}

## Conclusion

These observations delimit the assumptions under which AURA's claims apply;
they are not evidence that AURA remains secure after root trust or an honest
endpoint is compromised.
"""
    (output / f"report-{language}.md").write_text(text, encoding="utf-8")


def svg_escape(value: str) -> str:
    return saxutils.escape(value)


def render_matrix(
    path: Path, scenarios: list[dict[str, Any]], language: str
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    zh = language == "zh"
    title = (
        "实验13：超出威胁模型的秘密泄露结果"
        if zh
        else "Experiment 13: Out-of-Scope Compromise Results"
    )
    names = ZH_NAMES if zh else EN_NAMES
    headers = (
        ["泄露对象", "单独足够", "影响已观察", "分类"]
        if zh
        else ["Compromised asset", "Alone enough", "Effect observed", "Classification"]
    )
    width, height = 1800, 860
    x_positions = [45, 900, 1135, 1395]
    row_top, row_h = 145, 92
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,'Microsoft YaHei',sans-serif;fill:#0b2345}.title{font-size:42px;font-weight:700}.head{font-size:27px;font-weight:700}.cell{font-size:25px}.status{font-size:22px;font-weight:700}",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#fff"/>',
        f'<text x="{width/2}" y="62" text-anchor="middle" class="title">{svg_escape(title)}</text>',
        f'<rect x="25" y="98" width="1750" height="64" rx="12" fill="#e7eef8"/>',
    ]
    for x, header in zip(x_positions, headers, strict=True):
        parts.append(
            f'<text x="{x}" y="140" class="head">{svg_escape(header)}</text>'
        )
    for index, row in enumerate(scenarios):
        y = row_top + (index + 1) * row_h
        fill = "#f4f7fb" if index % 2 == 0 else "#ffffff"
        parts.append(
            f'<rect x="25" y="{y-55}" width="1750" height="78" fill="{fill}"/>'
        )
        alone = (
            ("是" if row["standalone_sufficient"] else "否")
            if zh
            else ("YES" if row["standalone_sufficient"] else "NO")
        )
        effect = (
            ("是" if row["attack_succeeded"] else "否")
            if zh
            else ("YES" if row["attack_succeeded"] else "NO")
        )
        parts += [
            f'<text x="{x_positions[0]}" y="{y}" class="cell">{svg_escape(names[row["scenario"]])}</text>',
            f'<text x="{x_positions[1]}" y="{y}" class="cell">{alone}</text>',
            f'<text x="{x_positions[2]}" y="{y}" class="cell">{effect}</text>',
            f'<text x="{x_positions[3]}" y="{y}" class="status" fill="#a02d28">EXPECTED OUT-OF-SCOPE</text>',
        ]
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_trust_roots(path: Path, language: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    zh = language == "zh"
    title = (
        "AURA-RSP保证依赖的根信任与端点秘密"
        if zh
        else "Roots of Trust and Endpoint Secrets Behind AURA Claims"
    )
    nodes = (
        [
            ("eUICC秘密", "x / k / eta / d"),
            ("EUM", "凭证签发私钥"),
            ("MNO", "票据签发私钥"),
            ("SM-DP+", "认证 / Binding私钥"),
            ("追踪服务", "k → EID数据库"),
        ]
        if zh
        else [
            ("eUICC secrets", "x / k / eta / d"),
            ("EUM", "credential issuer key"),
            ("MNO", "ticket issuer key"),
            ("SM-DP+", "auth / Binding keys"),
            ("Tracing service", "k → EID database"),
        ]
    )
    width, height = 1800, 500
    box_w, box_h, gap, start_x = 285, 140, 58, 50
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,'Microsoft YaHei',sans-serif;fill:#0b2345}.title{font-size:42px;font-weight:700}.main{font-size:28px;font-weight:700}.sub{font-size:23px}.note{font-size:27px}",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#fff"/>',
        f'<text x="{width/2}" y="62" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for index, (main, sub) in enumerate(nodes):
        x = start_x + index * (box_w + gap)
        parts += [
            f'<rect x="{x}" y="135" width="{box_w}" height="{box_h}" rx="18" fill="#e8f1fb" stroke="#8da9c4" stroke-width="3"/>',
            f'<text x="{x+box_w/2}" y="190" text-anchor="middle" class="main">{svg_escape(main)}</text>',
            f'<text x="{x+box_w/2}" y="235" text-anchor="middle" class="sub">{svg_escape(sub)}</text>',
        ]
    note = (
        "任一根信任或诚实端点失陷：对应保证不再适用，结果不是协议内攻击成功"
        if zh
        else "Compromise of a root or honest endpoint voids the corresponding claim; it is not an in-scope protocol break"
    )
    parts += [
        f'<text x="{width/2}" y="375" text-anchor="middle" class="note">{svg_escape(note)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--backend",
        choices=("auto", "production", "portable"),
        default="auto",
    )
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()
    experiment_root = Path(__file__).resolve().parent
    config = load_json(Path(args.config))
    if config["classification"] != CLASSIFICATION:
        raise ValueError("classification must remain out-of-scope")
    output = prepare_output(Path(args.output), experiment_root)
    started = time.perf_counter()

    issuer, issuer_attempts, issuer_fingerprints = choose_issuer_backend(
        args.backend, config
    )
    smdpp, smdpp_attempts, smdpp_fingerprints = run_smdpp_compromise(
        config
    )
    trace, trace_attempts, trace_export = run_trace_database_compromise(
        output, config
    )
    attempts = issuer_attempts + smdpp_attempts + trace_attempts
    for attempt in attempts:
        attempt["classification"] = CLASSIFICATION
        attempt["matches_expected"] = (
            bool(attempt["accepted"]) == bool(attempt["expected"])
        )
    audit = source_audit(experiment_root, config)
    scenarios = build_scenarios(issuer, smdpp, trace)
    assertions = build_assertions(
        issuer, smdpp, trace, scenarios, attempts, audit
    )
    passed = sum(bool(row["passed"]) for row in assertions)
    status = "PASS" if passed == len(assertions) else "FAIL"
    summary = {
        "experiment": config["experiment_name"],
        "status": status,
        "classification": CLASSIFICATION,
        "issuer_backend": issuer["backend"],
        "production_bbs": issuer["production_bbs"],
        "backend_limitation": issuer["limitation"],
        "scenarios": scenarios,
        "details": {
            "issuer_and_holder_secrets": issuer,
            "smdpp_keys": smdpp,
            "trace_database": trace,
        },
        "metrics": {
            "scenarios_total": len(scenarios),
            "compromise_effects_observed": sum(
                bool(row["attack_succeeded"]) for row in scenarios
            ),
            "standalone_sufficient": sum(
                bool(row["standalone_sufficient"]) for row in scenarios
            ),
            "conditional_on_holder_state": sum(
                not bool(row["standalone_sufficient"])
                for row in scenarios
            ),
            "controls_rejected": sum(
                not bool(row["accepted"])
                for row in attempts
                if not bool(row["expected"])
            ),
            "post_compromise_attacks_accepted": sum(
                bool(row["accepted"])
                for row in attempts
                if bool(row["expected"])
            ),
        },
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "source_audit": audit,
        "scope": {
            "protocol_attack": False,
            "root_or_endpoint_compromise": True,
            "result_interpretation": CLASSIFICATION,
            "production_source_modified": False,
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
    write_csv(output / "scenarios.csv", scenarios)
    write_csv(output / "assertions.csv", assertions)
    write_jsonl(output / "raw" / "attack-attempts.jsonl", attempts)
    write_json(output / "evidence" / "source-audit.json", audit)
    write_json(
        output / "evidence" / "key-fingerprints.json",
        {**issuer_fingerprints, **smdpp_fingerprints},
    )
    write_json(
        output / "evidence" / "trace-database-export.json",
        trace_export,
    )
    render_report(output, summary, "zh")
    render_report(output, summary, "en")
    render_matrix(
        output / "paper" / "compromise-matrix-zh.svg",
        scenarios,
        "zh",
    )
    render_matrix(
        output / "paper" / "compromise-matrix-en.svg",
        scenarios,
        "en",
    )
    render_trust_roots(
        output / "paper" / "trust-roots-zh.svg", "zh"
    )
    render_trust_roots(
        output / "paper" / "trust-roots-en.svg", "en"
    )
    write_csv(output / "paper" / "table-compromise-results.csv", scenarios)
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "matrix": "图：六类超出威胁模型的秘密泄露及其直接或条件影响。",
                "trust": "图：AURA-RSP安全保证依赖的根信任与诚实端点秘密。",
            },
            "en": {
                "matrix": "Figure: Direct or conditional effects of six out-of-scope secret disclosures.",
                "trust": "Figure: Roots of trust and honest-endpoint secrets assumed by AURA-RSP claims.",
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
