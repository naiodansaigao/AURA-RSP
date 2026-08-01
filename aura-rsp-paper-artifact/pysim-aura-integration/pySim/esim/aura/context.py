"""Canonical AURA-RSP transcript construction."""

from __future__ import annotations

from typing import Iterable

from .codec import canonical, hash_to_scalar, scalar_to_b64, sha256_hex
from .models import AuraOrderContext


def capability_transcript(offered: Iterable[str], selected: str) -> dict:
    normalized = sorted(set(str(item) for item in offered))
    if not normalized or selected not in normalized:
        raise ValueError("selected capability was not offered")
    return {
        "version": 1,
        "offered": normalized,
        "selected": selected,
    }


def build_ctx_t(
    *,
    transaction_id: str,
    i_t: str,
    n_s: str,
    n_u: str,
    server_oid: str,
    order: AuraOrderContext,
    salt_p: str,
    lph: str,
    nu: str,
    opid: str,
    vk_t_hash: str,
    cap: dict,
    cred_exp: int,
) -> dict:
    return {
        "domain": "AURA-RSP-v14/ctx",
        "transactionId": transaction_id,
        "I_t": i_t,
        "N_S": n_s,
        "N_U": n_u,
        "I_ac": order.I_ac,
        "sid": order.sid,
        "pid_h": order.pid_h,
        "op": order.op,
        "exp": order.exp,
        "PRaddr": order.PRaddr,
        "serverOID": server_oid,
        "salt_p": salt_p,
        "lph": lph,
        "nu": nu,
        "opid": opid,
        "vk_t_hash": vk_t_hash,
        "cap": cap,
        "cred_exp": int(cred_exp),
        # proof.py consumes the signed public ticket under this stable key.
        "ticket": order.ticket_public(),
    }


def ctx_t_hash(ctx_t: dict) -> str:
    return sha256_hex(canonical(ctx_t))


def gamma_for(ctx_t: dict) -> str:
    return scalar_to_b64(hash_to_scalar("AURA-RSP-v14:gamma", canonical(ctx_t)))


def ctx_auth(ctx_t: dict, gamma: str, c_value: str) -> dict:
    return {
        "domain": "AURA-RSP-v14/auth",
        "ctx_t_hash": ctx_t_hash(ctx_t),
        "gamma": gamma,
        "c": c_value,
    }


def auth_message_hash(message: dict) -> str:
    return sha256_hex(canonical(message))
