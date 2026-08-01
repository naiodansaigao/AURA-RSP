from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from py_ecc.optimized_bls12_381 import (
    G2,
    add,
    curve_order,
    eq,
    multiply,
    neg,
    pairing,
)

from .bbs import BBSParams, BBSSignature, mod_inv, point_sum, random_scalar, signature_base
from .codec import (
    canonical,
    g1_from_b64,
    g1_to_b64,
    hash_g1,
    hash_to_scalar,
    scalar_from_b64,
    scalar_to_b64,
)


CRED_PARAMS = BBSParams.create("AURA-RSP-v14:EUM-CredD", 3)
TOKEN_PARAMS = BBSParams.create("AURA-RSP-v14:MNO-TokOp", 9)
G_V = hash_g1("AURA-RSP-v14:nullifier-base")
G_C = hash_g1("AURA-RSP-v14:trace-response-base")


def text_scalar(label: str, value: str) -> int:
    return hash_to_scalar(label, value.encode("utf-8"))


def credential_messages(x: int, k: int, cred_exp: int) -> list[int]:
    return [x % curve_order, k % curve_order, cred_exp % curve_order]


def token_public_messages(ticket: dict) -> list[int]:
    return [
        text_scalar("ticket:I_ac", ticket["I_ac"]),
        text_scalar("ticket:sid", ticket["sid"]),
        text_scalar("ticket:pid_h", ticket["pid_h"]),
        text_scalar("ticket:op", ticket["op"]),
        int(ticket["exp"]) % curve_order,
        text_scalar("ticket:PRaddr", ticket["PRaddr"]),
    ]


def token_messages(ticket: dict, x: int, eta: int, d: int) -> list[int]:
    return token_public_messages(ticket) + [
        x % curve_order,
        eta % curve_order,
        d % curve_order,
    ]


def lph_base(pid_h: str, salt_p: bytes):
    return hash_g1("AURA-RSP-v14:lph", pid_h.encode("utf-8") + b"\x00" + salt_p)


@dataclass
class Relation:
    target: object
    terms: Dict[str, object]


@dataclass
class StatementState:
    proof_public: dict
    relations: list[Relation]
    witnesses: Dict[str, int]


def _randomized_signature_statement(
    prefix: str,
    params: BBSParams,
    public_key,
    signature: BBSSignature,
    messages: list[int],
    disclosed: Dict[int, int],
    hidden_names: Dict[int, str],
) -> StatementState:
    if set(disclosed) | set(hidden_names) != set(range(params.message_count)):
        raise ValueError("incomplete disclosed/hidden message layout")
    if set(disclosed) & set(hidden_names):
        raise ValueError("message cannot be both disclosed and hidden")

    r1 = random_scalar(nonzero=True)
    r2 = random_scalar()
    r3 = mod_inv(r1)
    s_prime = (signature.s - r2 * r3) % curve_order
    B = signature_base(params, messages, signature.s)
    A_prime = multiply(signature.A, r1)
    A_bar = add(multiply(B, r1), neg(multiply(A_prime, signature.e)))
    d_point = add(multiply(B, r1), neg(multiply(params.h0, r2)))

    if pairing(G2, A_bar) != pairing(public_key, A_prime):
        raise ValueError("randomized BBS+ pairing check failed")

    disclosed_target = point_sum(
        [params.g1]
        + [multiply(params.hs[i], disclosed[i]) for i in sorted(disclosed)]
    )
    witnesses = {
        f"{prefix}:e": signature.e,
        f"{prefix}:r2": r2,
        f"{prefix}:r3": r3,
        f"{prefix}:s_prime": s_prime,
    }
    witnesses.update({name: messages[i] for i, name in hidden_names.items()})
    relations = [
        Relation(
            target=add(A_bar, neg(d_point)),
            terms={
                f"{prefix}:e": neg(A_prime),
                f"{prefix}:r2": params.h0,
            },
        ),
        Relation(
            target=disclosed_target,
            terms={
                f"{prefix}:r3": d_point,
                f"{prefix}:s_prime": neg(params.h0),
                **{name: neg(params.hs[i]) for i, name in hidden_names.items()},
            },
        ),
    ]
    return StatementState(
        proof_public={
            "A_prime": g1_to_b64(A_prime),
            "A_bar": g1_to_b64(A_bar),
            "d": g1_to_b64(d_point),
        },
        relations=relations,
        witnesses=witnesses,
    )


def _commit_relation(relation: Relation, blinders: Dict[str, int]):
    return point_sum(
        multiply(base, blinders[name]) for name, base in relation.terms.items()
    )


def _transcript(
    ctx_t: dict,
    gamma: int,
    c_value: int,
    v_b64: str,
    lph_b64: str,
    cred_public: dict,
    token_public: dict,
    commitments: list[str],
) -> dict:
    return {
        "domain": "AURA-RSP-v14:Pi_auth",
        "ctx_t": ctx_t,
        "gamma": scalar_to_b64(gamma),
        "c": scalar_to_b64(c_value),
        "v": v_b64,
        "lph": lph_b64,
        "credential_statement": cred_public,
        "token_statement": token_public,
        "commitments": commitments,
    }


def create_auth_proof(
    *,
    ctx_t: dict,
    eum_public_key,
    mno_public_key,
    cred_signature: BBSSignature,
    token_signature: BBSSignature,
    x: int,
    k: int,
    eta: int,
    d_value: int,
    cred_exp: int,
    salt_p: bytes,
) -> dict:
    cred_messages = credential_messages(x, k, cred_exp)
    tok_messages = token_messages(ctx_t["ticket"], x, eta, d_value)
    cred_state = _randomized_signature_statement(
        "cred",
        CRED_PARAMS,
        eum_public_key,
        cred_signature,
        cred_messages,
        disclosed={2: cred_exp},
        hidden_names={0: "x", 1: "k"},
    )
    token_state = _randomized_signature_statement(
        "token",
        TOKEN_PARAMS,
        mno_public_key,
        token_signature,
        tok_messages,
        disclosed={i: tok_messages[i] for i in range(6)},
        hidden_names={6: "x", 7: "eta", 8: "d"},
    )

    h_lph = lph_base(ctx_t["ticket"]["pid_h"], salt_p)
    v = multiply(G_V, eta)
    lph = multiply(h_lph, x)
    gamma = hash_to_scalar("AURA-RSP-v14:gamma", canonical(ctx_t))
    c_value = (d_value + gamma * k) % curve_order

    extra_relations = [
        Relation(target=v, terms={"eta": G_V}),
        Relation(target=lph, terms={"x": h_lph}),
        Relation(
            target=multiply(G_C, c_value),
            terms={"d": G_C, "k": multiply(G_C, gamma)},
        ),
    ]
    witnesses: Dict[str, int] = {}
    for state in (cred_state, token_state):
        for name, value in state.witnesses.items():
            if name in witnesses and witnesses[name] != value:
                raise ValueError(f"shared witness mismatch: {name}")
            witnesses[name] = value
    witnesses.update({"x": x, "k": k, "eta": eta, "d": d_value})

    relations = cred_state.relations + token_state.relations + extra_relations
    blinders = {name: random_scalar() for name in witnesses}
    commitments = [g1_to_b64(_commit_relation(rel, blinders)) for rel in relations]
    transcript = _transcript(
        ctx_t,
        gamma,
        c_value,
        g1_to_b64(v),
        g1_to_b64(lph),
        cred_state.proof_public,
        token_state.proof_public,
        commitments,
    )
    challenge = hash_to_scalar("AURA-RSP-v14:Fiat-Shamir", canonical(transcript))
    responses = {
        name: scalar_to_b64(blinders[name] + challenge * value)
        for name, value in sorted(witnesses.items())
    }
    return {
        "version": "AURA-Pi-auth-1",
        "v": g1_to_b64(v),
        "lph": g1_to_b64(lph),
        "gamma": scalar_to_b64(gamma),
        "c": scalar_to_b64(c_value),
        "cred": cred_state.proof_public,
        "token": token_state.proof_public,
        "commitments": commitments,
        "responses": responses,
        "challenge": scalar_to_b64(challenge),
    }


def _verification_statement(
    prefix: str,
    params: BBSParams,
    public_key,
    proof_public: dict,
    disclosed: Dict[int, int],
    hidden_names: Dict[int, str],
) -> tuple[list[Relation], bool]:
    A_prime = g1_from_b64(proof_public["A_prime"])
    A_bar = g1_from_b64(proof_public["A_bar"])
    d_point = g1_from_b64(proof_public["d"])
    pairing_ok = pairing(G2, A_bar) == pairing(public_key, A_prime)
    disclosed_target = point_sum(
        [params.g1]
        + [multiply(params.hs[i], disclosed[i]) for i in sorted(disclosed)]
    )
    return (
        [
            Relation(
                target=add(A_bar, neg(d_point)),
                terms={
                    f"{prefix}:e": neg(A_prime),
                    f"{prefix}:r2": params.h0,
                },
            ),
            Relation(
                target=disclosed_target,
                terms={
                    f"{prefix}:r3": d_point,
                    f"{prefix}:s_prime": neg(params.h0),
                    **{
                        name: neg(params.hs[i])
                        for i, name in hidden_names.items()
                    },
                },
            ),
        ],
        pairing_ok,
    )


def verify_auth_proof(
    *,
    ctx_t: dict,
    proof: dict,
    eum_public_key,
    mno_public_key,
    salt_p: bytes,
) -> tuple[bool, str]:
    try:
        if proof.get("version") != "AURA-Pi-auth-1":
            return False, "unsupported proof version"
        cred_exp = int(ctx_t["cred_exp"])
        token_public_values = token_public_messages(ctx_t["ticket"])
        cred_relations, cred_pairing = _verification_statement(
            "cred",
            CRED_PARAMS,
            eum_public_key,
            proof["cred"],
            disclosed={2: cred_exp},
            hidden_names={0: "x", 1: "k"},
        )
        token_relations, token_pairing = _verification_statement(
            "token",
            TOKEN_PARAMS,
            mno_public_key,
            proof["token"],
            disclosed={i: token_public_values[i] for i in range(6)},
            hidden_names={6: "x", 7: "eta", 8: "d"},
        )
        if not cred_pairing or not token_pairing:
            return False, "BBS+ randomized signature pairing failed"

        v = g1_from_b64(proof["v"])
        lph = g1_from_b64(proof["lph"])
        gamma = scalar_from_b64(proof["gamma"])
        expected_gamma = hash_to_scalar("AURA-RSP-v14:gamma", canonical(ctx_t))
        if gamma != expected_gamma:
            return False, "gamma/context mismatch"
        c_value = scalar_from_b64(proof["c"])
        h_lph = lph_base(ctx_t["ticket"]["pid_h"], salt_p)
        extra_relations = [
            Relation(target=v, terms={"eta": G_V}),
            Relation(target=lph, terms={"x": h_lph}),
            Relation(
                target=multiply(G_C, c_value),
                terms={"d": G_C, "k": multiply(G_C, gamma)},
            ),
        ]
        relations = cred_relations + token_relations + extra_relations
        if len(proof["commitments"]) != len(relations):
            return False, "commitment count mismatch"
        transcript = _transcript(
            ctx_t,
            gamma,
            c_value,
            proof["v"],
            proof["lph"],
            proof["cred"],
            proof["token"],
            proof["commitments"],
        )
        challenge = hash_to_scalar(
            "AURA-RSP-v14:Fiat-Shamir", canonical(transcript)
        )
        if scalar_from_b64(proof["challenge"]) != challenge:
            return False, "Fiat-Shamir challenge mismatch"
        responses = {
            name: scalar_from_b64(value)
            for name, value in proof["responses"].items()
        }
        for relation, commitment_b64 in zip(relations, proof["commitments"]):
            if any(name not in responses for name in relation.terms):
                return False, "missing witness response"
            lhs = point_sum(
                multiply(base, responses[name])
                for name, base in relation.terms.items()
            )
            rhs = add(
                g1_from_b64(commitment_b64),
                multiply(relation.target, challenge),
            )
            if not eq(lhs, rhs):
                return False, "Sigma relation failed"
        return True, "ok"
    except Exception as exc:
        return False, f"proof parse/verification error: {type(exc).__name__}: {exc}"
