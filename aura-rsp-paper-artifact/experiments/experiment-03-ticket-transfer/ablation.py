"""Experiment-only AURA-RSP ablation without credential-ticket x equality.

This module deliberately gives the credential statement and ticket statement
different witness names (``x_cred`` and ``x_ticket``).  It is never imported by
the production pySim/osmo-smdpp service.  Its sole purpose is to quantify the
security contribution of the shared-secret equality relation.
"""

from __future__ import annotations

from typing import Dict

from py_ecc.optimized_bls12_381 import add, curve_order, eq, multiply

from pySim.esim.aura.bbs import BBSSignature, point_sum, random_scalar
from pySim.esim.aura.codec import (
    canonical,
    g1_from_b64,
    g1_to_b64,
    hash_to_scalar,
    scalar_from_b64,
    scalar_to_b64,
)
from pySim.esim.aura.proof import (
    CRED_PARAMS,
    G_C,
    G_V,
    TOKEN_PARAMS,
    Relation,
    _commit_relation,
    _randomized_signature_statement,
    _transcript,
    _verification_statement,
    credential_messages,
    lph_base,
    token_messages,
    token_public_messages,
)


def create_auth_proof_without_secret_binding(
    *,
    ctx_t: dict,
    eum_public_key,
    mno_public_key,
    cred_signature: BBSSignature,
    token_signature: BBSSignature,
    credential_x: int,
    ticket_x: int,
    k: int,
    eta: int,
    d_value: int,
    cred_exp: int,
    salt_p: bytes,
) -> dict:
    """Construct the intentionally weakened joint proof.

    Both BBS+ signatures remain valid, but the two hidden x witnesses are no
    longer constrained to be equal.
    """

    cred_messages = credential_messages(credential_x, k, cred_exp)
    tok_messages = token_messages(ctx_t["ticket"], ticket_x, eta, d_value)
    cred_state = _randomized_signature_statement(
        "cred",
        CRED_PARAMS,
        eum_public_key,
        cred_signature,
        cred_messages,
        disclosed={2: cred_exp},
        hidden_names={0: "x_cred", 1: "k"},
    )
    token_state = _randomized_signature_statement(
        "token",
        TOKEN_PARAMS,
        mno_public_key,
        token_signature,
        tok_messages,
        disclosed={i: tok_messages[i] for i in range(6)},
        hidden_names={6: "x_ticket", 7: "eta", 8: "d"},
    )

    h_lph = lph_base(ctx_t["ticket"]["pid_h"], salt_p)
    v = multiply(G_V, eta)
    lph = multiply(h_lph, credential_x)
    gamma = hash_to_scalar("AURA-RSP-v14:gamma", canonical(ctx_t))
    c_value = (d_value + gamma * k) % curve_order

    extra_relations = [
        Relation(target=v, terms={"eta": G_V}),
        Relation(target=lph, terms={"x_cred": h_lph}),
        Relation(
            target=multiply(G_C, c_value),
            terms={"d": G_C, "k": multiply(G_C, gamma)},
        ),
    ]
    witnesses: Dict[str, int] = {}
    for state in (cred_state, token_state):
        for name, value in state.witnesses.items():
            if name in witnesses and witnesses[name] != value:
                raise ValueError(f"unexpected shared witness mismatch: {name}")
            witnesses[name] = value
    witnesses.update(
        {
            "x_cred": credential_x,
            "x_ticket": ticket_x,
            "k": k,
            "eta": eta,
            "d": d_value,
        }
    )

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
        "version": "AURA-Pi-auth-1-ABLATION-NO-SECRET-BINDING",
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


def verify_auth_proof_without_secret_binding(
    *,
    ctx_t: dict,
    proof: dict,
    eum_public_key,
    mno_public_key,
    salt_p: bytes,
) -> tuple[bool, str]:
    """Verify only the deliberately weakened experiment relation."""

    try:
        if proof.get("version") != "AURA-Pi-auth-1-ABLATION-NO-SECRET-BINDING":
            return False, "unsupported ablation proof version"
        cred_exp = int(ctx_t["cred_exp"])
        token_public_values = token_public_messages(ctx_t["ticket"])
        cred_relations, cred_pairing = _verification_statement(
            "cred",
            CRED_PARAMS,
            eum_public_key,
            proof["cred"],
            disclosed={2: cred_exp},
            hidden_names={0: "x_cred", 1: "k"},
        )
        token_relations, token_pairing = _verification_statement(
            "token",
            TOKEN_PARAMS,
            mno_public_key,
            proof["token"],
            disclosed={i: token_public_values[i] for i in range(6)},
            hidden_names={6: "x_ticket", 7: "eta", 8: "d"},
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
            Relation(target=lph, terms={"x_cred": h_lph}),
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
        challenge = hash_to_scalar("AURA-RSP-v14:Fiat-Shamir", canonical(transcript))
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
            rhs = add(g1_from_b64(commitment_b64), multiply(relation.target, challenge))
            if not eq(lhs, rhs):
                return False, "Sigma relation failed"
        return True, "ok"
    except Exception as exc:
        return False, f"proof parse/verification error: {type(exc).__name__}: {exc}"
