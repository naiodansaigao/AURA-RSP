"""Initial AURA-RSP install receipt and state-chain helpers."""

from __future__ import annotations

import hashlib
import hmac

from .codec import b64e, canonical, sha256_hex
from .models import AuraInstallReceipt


ZERO_HASH = "00" * 32


def install_receipt_fields(
    *,
    lph: str,
    ctx_t: dict,
    bind_t: str,
    ciphertext_hash: str,
) -> dict:
    rid_inst = sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/install",
                "ctx_t_hash": sha256_hex(canonical(ctx_t)),
                "Bind_t_hash": sha256_hex(bind_t.encode("ascii")),
                "ciphertext_hash": ciphertext_hash,
            }
        )
    )
    return {
        "lph": lph,
        "st_old": 0,
        "st_new": 1,
        "ctr_new": 1,
        "last_hash_old": ZERO_HASH,
        "rid_inst": rid_inst,
    }


def create_install_receipt(
    k_mac: bytes,
    *,
    lph: str,
    ctx_t: dict,
    bind_t: str,
    ciphertext_hash: str,
) -> AuraInstallReceipt:
    fields = install_receipt_fields(
        lph=lph,
        ctx_t=ctx_t,
        bind_t=bind_t,
        ciphertext_hash=ciphertext_hash,
    )
    tag = b64e(
        hmac.new(
            k_mac,
            canonical({"domain": "AURA-RSP-v14/install-mac", **fields}),
            hashlib.sha256,
        ).digest()
    )
    return AuraInstallReceipt(**fields, tag_inst=tag)


def verify_install_receipt(
    k_mac: bytes,
    receipt: dict,
    *,
    lph: str,
    ctx_t: dict,
    bind_t: str,
    ciphertext_hash: str,
) -> bool:
    expected = create_install_receipt(
        k_mac,
        lph=lph,
        ctx_t=ctx_t,
        bind_t=bind_t,
        ciphertext_hash=ciphertext_hash,
    ).to_dict()
    return hmac.compare_digest(
        canonical(expected),
        canonical(receipt),
    )


def initial_last_hash(receipt: dict) -> str:
    return sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/state",
                "last_hash_old": receipt["last_hash_old"],
                "rid": receipt["rid_inst"],
                "lph": receipt["lph"],
                "st_old": int(receipt["st_old"]),
                "st_new": int(receipt["st_new"]),
                "ctr_new": int(receipt["ctr_new"]),
                "tag": receipt["tag_inst"],
            }
        )
    )
