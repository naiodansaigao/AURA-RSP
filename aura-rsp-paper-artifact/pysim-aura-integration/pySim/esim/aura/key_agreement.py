"""Classical AURA-RSP key agreement with explicit transcript binding."""

from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .codec import b64d, canonical, sha256_hex
from .context import ctx_t_hash
from .primitives import p256_public_from_b64


CLASSICAL_MODE = "classical-p256"
HYBRID_MODE = "hybrid-p256-mlkem768"


def _mlkem():
    try:
        from kyber_py.ml_kem import ML_KEM_768
    except ImportError as exc:
        raise RuntimeError("ML_KEM_768_DEPENDENCY_MISSING") from exc
    return ML_KEM_768


def generate_mlkem_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    return _mlkem().key_derive(seed or secrets.token_bytes(64))


def mlkem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    return _mlkem().encaps(public_key)


def mlkem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    return _mlkem().decaps(private_key, ciphertext)


def ka_u_payload(
    *, i_t: str, q_u: str, bind_t: str, mode: str = CLASSICAL_MODE,
    mlkem_u: str | None = None,
) -> dict:
    payload = {
        "domain": "AURA-RSP-v14/ka-u",
        "I_t": i_t,
        "Q_U": q_u,
        "Bind_t_hash": sha256_hex(bind_t.encode("ascii")),
        "mode": mode,
    }
    if mode == HYBRID_MODE:
        if not mlkem_u:
            raise ValueError("MISSING_MLKEM_PUBLIC_KEY")
        payload["MLKEM_U_hash"] = sha256_hex(b64d(mlkem_u))
    elif mlkem_u is not None:
        raise ValueError("UNEXPECTED_MLKEM_PUBLIC_KEY")
    return payload


def build_ctx_k(
    *,
    ctx_t: dict,
    bind_t: str,
    q_u: str,
    q_s: str,
    mode: str = CLASSICAL_MODE,
    mlkem_u: str | None = None,
    mlkem_s: str | None = None,
) -> dict:
    context = {
        "domain": "AURA-RSP-v14/key",
        "ctx_t_hash": ctx_t_hash(ctx_t),
        "Bind_t_hash": sha256_hex(bind_t.encode("ascii")),
        "Q_U": q_u,
        "Q_S": q_s,
        "mode": mode,
    }
    if mode == HYBRID_MODE:
        if not mlkem_u or not mlkem_s:
            raise ValueError("MISSING_MLKEM_KEY_MATERIAL")
        context["MLKEM_U_hash"] = sha256_hex(b64d(mlkem_u))
        context["MLKEM_S_hash"] = sha256_hex(b64d(mlkem_s))
    elif mlkem_u is not None or mlkem_s is not None:
        raise ValueError("UNEXPECTED_MLKEM_KEY_MATERIAL")
    return context


def ka_s_payload(*, i_t: str, ctx_k: dict) -> dict:
    return {
        "domain": "AURA-RSP-v14/ka-s",
        "I_t": i_t,
        "ctx_K": ctx_k,
    }


def derive_profile_keys(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_b64: str,
    ctx_k: dict,
    pq_shared: bytes | None = None,
) -> tuple[bytes, bytes]:
    peer_public = p256_public_from_b64(peer_public_b64)
    shared = private_key.exchange(ec.ECDH(), peer_public)
    if ctx_k.get("mode") == HYBRID_MODE:
        if pq_shared is None:
            raise ValueError("MISSING_MLKEM_SHARED_SECRET")
        shared = b"AURA-HYBRID\x00" + shared + pq_shared
    elif pq_shared is not None:
        raise ValueError("UNEXPECTED_MLKEM_SHARED_SECRET")
    salt = hashlib.sha256(canonical(ctx_k)).digest()
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"AURA-RSP-v14/profile-download",
    ).derive(shared)
    return key_material[:32], key_material[32:]
