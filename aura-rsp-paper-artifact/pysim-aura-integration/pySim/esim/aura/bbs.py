from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, Iterable

from py_ecc.optimized_bls12_381 import (
    G2,
    Z1,
    add,
    curve_order,
    eq,
    multiply,
    neg,
    pairing,
)

from .codec import (
    canonical,
    g1_from_b64,
    g1_to_b64,
    g2_from_b64,
    g2_to_b64,
    hash_g1,
    hash_to_scalar,
    scalar_from_b64,
    scalar_to_b64,
)


def mod_inv(value: int) -> int:
    value %= curve_order
    if value == 0:
        raise ValueError("zero has no inverse")
    return pow(value, -1, curve_order)


def random_scalar(*, nonzero: bool = False) -> int:
    while True:
        value = secrets.randbelow(curve_order)
        if value or not nonzero:
            return value


def point_sum(points: Iterable):
    result = Z1
    for point in points:
        result = add(result, point)
    return result


@dataclass(frozen=True)
class BBSParams:
    label: str
    message_count: int
    g1: object
    h0: object
    hs: tuple

    @classmethod
    def create(cls, label: str, message_count: int) -> "BBSParams":
        return cls(
            label=label,
            message_count=message_count,
            g1=hash_g1(f"{label}:g1"),
            h0=hash_g1(f"{label}:h0"),
            hs=tuple(hash_g1(f"{label}:h:{i}") for i in range(message_count)),
        )


@dataclass(frozen=True)
class BBSSignature:
    A: object
    e: int
    s: int

    def to_dict(self) -> dict:
        return {
            "A": g1_to_b64(self.A),
            "e": scalar_to_b64(self.e),
            "s": scalar_to_b64(self.s),
        }

    @classmethod
    def from_dict(cls, value: dict) -> "BBSSignature":
        return cls(
            A=g1_from_b64(value["A"]),
            e=scalar_from_b64(value["e"]),
            s=scalar_from_b64(value["s"]),
        )


def keygen() -> tuple[int, object]:
    secret = random_scalar(nonzero=True)
    return secret, multiply(G2, secret)


def public_key_to_dict(public_key) -> dict:
    return {"w": g2_to_b64(public_key)}


def public_key_from_dict(value: dict):
    return g2_from_b64(value["w"])


def signature_base(params: BBSParams, messages: list[int], s: int):
    if len(messages) != params.message_count:
        raise ValueError("message count mismatch")
    return point_sum(
        [params.g1, multiply(params.h0, s)]
        + [multiply(base, msg % curve_order) for base, msg in zip(params.hs, messages)]
    )


def verify_signature(
    params: BBSParams,
    public_key,
    messages: list[int],
    signature: BBSSignature,
) -> bool:
    try:
        B = signature_base(params, messages, signature.s)
        left = pairing(add(public_key, multiply(G2, signature.e)), signature.A)
        right = pairing(G2, B)
        return left == right
    except Exception:
        return False


def create_blind_commitment(
    params: BBSParams,
    hidden_messages: Dict[int, int],
    context: dict,
) -> tuple[dict, int]:
    if not hidden_messages:
        raise ValueError("at least one hidden message is required")
    if any(i < 0 or i >= params.message_count for i in hidden_messages):
        raise ValueError("hidden message index out of range")

    s_user = random_scalar()
    commitment = point_sum(
        [multiply(params.h0, s_user)]
        + [multiply(params.hs[i], value) for i, value in sorted(hidden_messages.items())]
    )
    blind_s = random_scalar()
    blind_messages = {i: random_scalar() for i in hidden_messages}
    proof_commitment = point_sum(
        [multiply(params.h0, blind_s)]
        + [
            multiply(params.hs[i], blind_messages[i])
            for i in sorted(hidden_messages)
        ]
    )
    challenge_payload = {
        "domain": "AURA-RSP-BBSPLUS-BLIND-ISSUE-v1",
        "params": params.label,
        "context": context,
        "hidden_indices": sorted(hidden_messages),
        "C": g1_to_b64(commitment),
        "T": g1_to_b64(proof_commitment),
    }
    challenge = hash_to_scalar("blind-issue-proof", canonical(challenge_payload))
    proof = {
        "C": g1_to_b64(commitment),
        "T": g1_to_b64(proof_commitment),
        "hidden_indices": sorted(hidden_messages),
        "z_s": scalar_to_b64(blind_s + challenge * s_user),
        "z_messages": {
            str(i): scalar_to_b64(blind_messages[i] + challenge * hidden_messages[i])
            for i in sorted(hidden_messages)
        },
    }
    return proof, s_user


def verify_blind_commitment(
    params: BBSParams,
    proof: dict,
    context: dict,
) -> bool:
    try:
        hidden_indices = [int(i) for i in proof["hidden_indices"]]
        if len(set(hidden_indices)) != len(hidden_indices):
            return False
        commitment = g1_from_b64(proof["C"])
        proof_commitment = g1_from_b64(proof["T"])
        challenge_payload = {
            "domain": "AURA-RSP-BBSPLUS-BLIND-ISSUE-v1",
            "params": params.label,
            "context": context,
            "hidden_indices": hidden_indices,
            "C": proof["C"],
            "T": proof["T"],
        }
        challenge = hash_to_scalar("blind-issue-proof", canonical(challenge_payload))
        lhs = point_sum(
            [multiply(params.h0, scalar_from_b64(proof["z_s"]))]
            + [
                multiply(
                    params.hs[i],
                    scalar_from_b64(proof["z_messages"][str(i)]),
                )
                for i in hidden_indices
            ]
        )
        rhs = add(proof_commitment, multiply(commitment, challenge))
        return eq(lhs, rhs)
    except Exception:
        return False


def blind_sign(
    params: BBSParams,
    secret_key: int,
    blind_proof: dict,
    known_messages: Dict[int, int],
    context: dict,
) -> dict:
    if not verify_blind_commitment(params, blind_proof, context):
        raise ValueError("invalid blind commitment proof")
    hidden_indices = {int(i) for i in blind_proof["hidden_indices"]}
    if hidden_indices & set(known_messages):
        raise ValueError("message cannot be both hidden and known")
    if hidden_indices | set(known_messages) != set(range(params.message_count)):
        raise ValueError("issuer did not receive a complete message layout")

    commitment = g1_from_b64(blind_proof["C"])
    e = random_scalar()
    while (secret_key + e) % curve_order == 0:
        e = random_scalar()
    s_issuer = random_scalar()
    B = point_sum(
        [params.g1, commitment, multiply(params.h0, s_issuer)]
        + [
            multiply(params.hs[i], value)
            for i, value in sorted(known_messages.items())
        ]
    )
    A = multiply(B, mod_inv(secret_key + e))
    return {
        "A": g1_to_b64(A),
        "e": scalar_to_b64(e),
        "s_issuer": scalar_to_b64(s_issuer),
    }


def finalize_blind_signature(blind_signature: dict, s_user: int) -> BBSSignature:
    return BBSSignature(
        A=g1_from_b64(blind_signature["A"]),
        e=scalar_from_b64(blind_signature["e"]),
        s=(s_user + scalar_from_b64(blind_signature["s_issuer"])) % curve_order,
    )
