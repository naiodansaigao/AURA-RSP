from __future__ import annotations

import argparse
import copy
import json
import secrets
import time

from py_ecc.optimized_bls12_381 import curve_order

from .bbs import (
    blind_sign,
    create_blind_commitment,
    finalize_blind_signature,
    keygen,
    random_scalar,
    verify_signature,
)
from .codec import b64e, canonical, scalar_to_b64
from .local_ticket_log import (
    LocalTicketContextConflict,
    LocalTicketLogCorrupt,
    lookup_cached_auth_request,
    store_auth_request,
)
from .proof import (
    CRED_PARAMS,
    TOKEN_PARAMS,
    create_auth_proof,
    credential_messages,
    token_messages,
    token_public_messages,
    verify_auth_proof,
)


def run_selftest(verbose: bool = True) -> dict:
    started = time.perf_counter()
    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    x = random_scalar(nonzero=True)
    k = random_scalar(nonzero=True)
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    cred_exp = 2_000_000_000
    ticket = {
        "I_ac": "AURA-ORDER-SELFTEST",
        "sid": "aura-smdpp.test",
        "pid_h": "profile:TS48V2-SAIP2-1-NOBERTLV-UNIQUE",
        "op": "download",
        "exp": 2_000_000_000,
        "PRaddr": "aura-pr.test",
    }

    issue_start = time.perf_counter()
    cred_context = {"type": "Cred_D", "cred_exp": cred_exp}
    cred_commit, cred_s_user = create_blind_commitment(
        CRED_PARAMS, {0: x}, cred_context
    )
    cred_blind_sig = blind_sign(
        CRED_PARAMS,
        eum_sk,
        cred_commit,
        {1: k, 2: cred_exp},
        cred_context,
    )
    cred_sig = finalize_blind_signature(cred_blind_sig, cred_s_user)
    assert verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x, k, cred_exp),
        cred_sig,
    )

    token_context = {"type": "Tok_op", "ticket": ticket}
    token_commit, token_s_user = create_blind_commitment(
        TOKEN_PARAMS,
        {6: x, 7: eta, 8: d_value},
        token_context,
    )
    token_blind_sig = blind_sign(
        TOKEN_PARAMS,
        mno_sk,
        token_commit,
        {i: value for i, value in enumerate(token_public_messages(ticket))},
        token_context,
    )
    token_sig = finalize_blind_signature(token_blind_sig, token_s_user)
    assert verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(ticket, x, eta, d_value),
        token_sig,
    )
    issue_ms = (time.perf_counter() - issue_start) * 1000

    salt_p = secrets.token_bytes(32)
    ctx_t = {
        "transactionId": "00" * 16,
        "I_t": b64e(secrets.token_bytes(16)),
        "N_U": b64e(secrets.token_bytes(32)),
        "N_S": b64e(secrets.token_bytes(32)),
        "sid": ticket["sid"],
        "serverOID": "2.999.10",
        "PRaddr": ticket["PRaddr"],
        "cap": "ECDHE-P256-HKDF-SHA256-AES256GCM",
        "ticket": ticket,
        "cred_exp": cred_exp,
        "opid": b64e(secrets.token_bytes(16)),
        "vk_t_hash": "selftest",
    }
    prove_start = time.perf_counter()
    proof = create_auth_proof(
        ctx_t=ctx_t,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        cred_signature=cred_sig,
        token_signature=token_sig,
        x=x,
        k=k,
        eta=eta,
        d_value=d_value,
        cred_exp=cred_exp,
        salt_p=salt_p,
    )
    prove_ms = (time.perf_counter() - prove_start) * 1000

    verify_start = time.perf_counter()
    ok, reason = verify_auth_proof(
        ctx_t=ctx_t,
        proof=proof,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=salt_p,
    )
    verify_ms = (time.perf_counter() - verify_start) * 1000
    assert ok, reason

    tampered_ctx = copy.deepcopy(ctx_t)
    tampered_ctx["cap"] = "DOWNGRADED"
    tamper_ok, _ = verify_auth_proof(
        ctx_t=tampered_ctx,
        proof=proof,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=salt_p,
    )
    assert not tamper_ok

    tampered_proof = copy.deepcopy(proof)
    tampered_proof["responses"]["x"] = scalar_to_b64(
        (int.from_bytes(secrets.token_bytes(32), "big") % curve_order)
    )
    response_ok, _ = verify_auth_proof(
        ctx_t=ctx_t,
        proof=tampered_proof,
        eum_public_key=eum_pk,
        mno_public_key=mno_pk,
        salt_p=salt_p,
    )
    assert not response_ok

    local_device: dict = {}
    local_v = proof["v"]
    local_opid = ctx_t["opid"]
    assert (
        lookup_cached_auth_request(
            local_device, v=local_v, opid=local_opid, ctx_t=ctx_t
        )
        is None
    )
    auth_request = {"ctx_t": ctx_t, "Pi_auth": proof, "marker": "selftest"}
    store_auth_request(
        local_device,
        v=local_v,
        opid=local_opid,
        ctx_t=ctx_t,
        auth_request=auth_request,
    )
    cached = lookup_cached_auth_request(
        local_device, v=local_v, opid=local_opid, ctx_t=ctx_t
    )
    assert canonical(cached) == canonical(auth_request)
    cached["marker"] = "mutated-copy"
    assert (
        lookup_cached_auth_request(
            local_device, v=local_v, opid=local_opid, ctx_t=ctx_t
        )["marker"]
        == "selftest"
    )
    conflict_rejected = False
    conflicting_ctx = copy.deepcopy(ctx_t)
    conflicting_ctx["N_S"] = b64e(secrets.token_bytes(32))
    try:
        lookup_cached_auth_request(
            local_device,
            v=local_v,
            opid=local_opid,
            ctx_t=conflicting_ctx,
        )
    except LocalTicketContextConflict:
        conflict_rejected = True
    assert conflict_rejected

    legacy_rejected = False
    legacy_device = {"local_ticket_log": {f"{local_v}:{local_opid}": "old-hash"}}
    try:
        lookup_cached_auth_request(
            legacy_device, v=local_v, opid=local_opid, ctx_t=ctx_t
        )
    except LocalTicketLogCorrupt:
        legacy_rejected = True
    assert legacy_rejected

    result = {
        "status": "AURA_CRYPTO_SELFTEST_PASS",
        "blind_issue_ms": round(issue_ms, 3),
        "proof_generate_ms": round(prove_ms, 3),
        "proof_verify_ms": round(verify_ms, 3),
        "proof_bytes": len(canonical(proof)),
        "tampered_context_rejected": True,
        "tampered_shared_x_response_rejected": True,
        "local_ticket_exact_replay_cached": True,
        "local_ticket_context_conflict_rejected": conflict_rejected,
        "local_ticket_legacy_entry_fails_closed": legacy_rejected,
        "total_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    if verbose:
        print(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    run_selftest(verbose=not args.quiet)


if __name__ == "__main__":
    main()
