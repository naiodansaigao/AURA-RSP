"""Profile binding transcript construction."""

from __future__ import annotations

from .codec import canonical, sha256_hex
from .context import auth_message_hash, ctx_t_hash
from .primitives import p256_sign, p256_verify


def build_binding(ctx_t: dict, auth_message: dict) -> tuple[str, dict]:
    th_auth = sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/auth-transcript",
                "ctx_t_hash": ctx_t_hash(ctx_t),
                "auth_message_hash": auth_message_hash(auth_message),
            }
        )
    )
    ctx_bind = {
        "domain": "AURA-RSP-v14/bind",
        "ctx_t_hash": ctx_t_hash(ctx_t),
        "th_auth": th_auth,
    }
    return th_auth, ctx_bind


def sign_binding(private_key, ctx_bind: dict) -> str:
    return p256_sign(private_key, ctx_bind)


def verify_binding(public_key, ctx_bind: dict, bind_t: str) -> bool:
    return p256_verify(public_key, ctx_bind, bind_t)
