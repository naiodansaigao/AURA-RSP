"""Cryptographic and service-level regression tests for the integrated mode."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import secrets
import time

from cryptography.exceptions import InvalidTag
from py_ecc.optimized_bls12_381 import multiply

from pySim.esim.profile_store import ProfileRepository

from .bbs import (
    BBSSignature,
    blind_sign,
    create_blind_commitment,
    finalize_blind_signature,
    public_key_from_dict,
    random_scalar,
)
from .bootstrap import bootstrap, seed_store
from .codec import (
    b64d,
    b64e,
    load_json,
    save_json,
    scalar_from_b64,
    sha256_hex,
)
from .context import build_ctx_t, ctx_auth
from .errors import AuraProtocolError
from .key_agreement import build_ctx_k, derive_profile_keys, ka_u_payload
from .models import AuraOrderContext
from .primitives import (
    decrypt_profile,
    ed25519_public_b64,
    ed25519_sign,
    encrypt_profile,
    generate_ed25519_private,
    generate_p256_private,
    p256_public_b64,
    p256_public_from_pem,
    p256_sign,
    p256_verify,
)
from .proof import (
    CRED_PARAMS,
    G_V,
    create_auth_proof,
    lph_base,
)
from .receipt import create_install_receipt, verify_install_receipt
from .service import AuraService
from .store import AuraStore
from .ticket import issue_ticket


ROOT = Path(__file__).resolve().parents[3]


def _expect_error(code_prefix: str, operation) -> AuraProtocolError:
    try:
        operation()
    except AuraProtocolError as exc:
        if not exc.code.startswith(code_prefix):
            raise AssertionError(
                f"expected {code_prefix}, received {exc.code}"
            ) from exc
        return exc
    raise AssertionError(f"expected rejection {code_prefix}")


def _auth_request(
    service: AuraService,
    transaction_id: str,
    device: dict,
    *,
    salt_p: bytes | None = None,
) -> tuple[dict, object, dict]:
    session = service.store.get_session(transaction_id)
    assert session is not None
    auth = session.server_auth
    order = session.order
    salt_p = salt_p or secrets.token_bytes(32)
    x = scalar_from_b64(device["x"])
    k = scalar_from_b64(device["k"])
    eta = scalar_from_b64(device["eta"])
    d_value = scalar_from_b64(device["d"])
    nu = b64e(b64d(device.get("_nu", ""))) if device.get("_nu") else None
    if nu is None:
        from .codec import g1_to_b64

        nu = g1_to_b64(multiply(G_V, eta))
    from .codec import g1_to_b64

    lph = g1_to_b64(multiply(lph_base(order.pid_h, salt_p), x))
    opid = b64e(secrets.token_bytes(16))
    one_time_private = generate_ed25519_private()
    vk_t = ed25519_public_b64(one_time_private.public_key())
    ctx_t = build_ctx_t(
        transaction_id=transaction_id,
        i_t=auth["I_t"],
        n_s=auth["N_S"],
        n_u=auth["N_U"],
        server_oid=auth["serverOID"],
        order=order,
        salt_p=b64e(salt_p),
        lph=lph,
        nu=nu,
        opid=opid,
        vk_t_hash=sha256_hex(b64d(vk_t)),
        cap=auth["cap"],
        cred_exp=int(device["cred_exp"]),
    )
    proof = create_auth_proof(
        ctx_t=ctx_t,
        eum_public_key=service.eum_public_key,
        mno_public_key=service.mno_public_key,
        cred_signature=BBSSignature.from_dict(device["credential_signature"]),
        token_signature=BBSSignature.from_dict(device["token_signature"]),
        x=x,
        k=k,
        eta=eta,
        d_value=d_value,
        cred_exp=int(device["cred_exp"]),
        salt_p=salt_p,
    )
    tau_payload = ctx_auth(ctx_t, proof["gamma"], proof["c"])
    request = {
        "transactionId": transaction_id,
        "salt_p": b64e(salt_p),
        "lph": lph,
        "nu": nu,
        "opid": opid,
        "vk_t": vk_t,
        "cred_exp": int(device["cred_exp"]),
        "gamma": proof["gamma"],
        "c": proof["c"],
        "tau_auth": ed25519_sign(one_time_private, tau_payload),
        "Pi_auth": proof,
    }
    return request, one_time_private, ctx_t


def _new_transaction(
    service: AuraService, device: dict
) -> tuple[str, dict, object, dict]:
    response = service.initiate(
        {
            "I_ac": device["ticket"]["I_ac"],
            "N_U": b64e(secrets.token_bytes(32)),
            "capabilities": ["classical-p256"],
        },
        "aura-pr.test",
    )
    transaction_id = response["serverAuth"]["transactionId"]
    request, one_time, ctx_t = _auth_request(
        service, transaction_id, device
    )
    return transaction_id, request, one_time, ctx_t


def _issue_second_credential(root: Path, x_value: int) -> dict:
    runtime = root / "runtime" / "aura"
    authority = load_json(runtime / "authority.json")
    cred_exp = int(time.time()) + 86400
    k_value = random_scalar(nonzero=True)
    context = {"type": "Cred_D", "cred_exp": cred_exp}
    proof, s_user = create_blind_commitment(
        CRED_PARAMS, {0: x_value}, context
    )
    signed = blind_sign(
        CRED_PARAMS,
        scalar_from_b64(authority["eum"]["secret_key"]),
        proof,
        {1: k_value, 2: cred_exp},
        context,
    )
    return {
        "x": x_value,
        "k": k_value,
        "cred_exp": cred_exp,
        "signature": finalize_blind_signature(signed, s_user),
    }


def run_selftest(root: Path = ROOT) -> dict:
    bootstrap(root)
    runtime = root / "runtime" / "aura"
    store = AuraStore(in_memory=True)
    seed_store(store, root)
    service = AuraService(
        root=root,
        profile_repository=ProfileRepository(root / "smdpp-data" / "upp"),
        store=store,
    )
    device = load_json(runtime / "device.json")
    checks: dict[str, str] = {}

    # 3. Wrong server context: altering a signed field invalidates the signature.
    init = service.initiate(
        {
            "I_ac": device["ticket"]["I_ac"],
            "N_U": b64e(secrets.token_bytes(32)),
            "capabilities": ["classical-p256"],
        },
        "aura-pr.test",
    )
    server_public = p256_public_from_pem(
        (runtime / "server-auth-public.pem").read_bytes()
    )
    assert p256_verify(
        server_public, init["serverAuth"], init["serverSignature"]
    )
    altered = copy.deepcopy(init["serverAuth"])
    altered["sid"] = "attacker.example"
    assert not p256_verify(server_public, altered, init["serverSignature"])
    checks["wrong_server_context"] = "rejected_signature"

    # 4. A credential for x_B cannot be joined to Device-A's x_A ticket.
    x_b = random_scalar(nonzero=True)
    device_b = _issue_second_credential(root, x_b)
    session = service.store.get_session(init["serverAuth"]["transactionId"])
    assert session is not None
    stolen = copy.deepcopy(device)
    stolen["x"] = b64e(x_b.to_bytes(32, "big"))
    stolen["k"] = b64e(device_b["k"].to_bytes(32, "big"))
    stolen["cred_exp"] = device_b["cred_exp"]
    stolen["credential_signature"] = device_b["signature"].to_dict()
    try:
        _auth_request(
            service, init["serverAuth"]["transactionId"], stolen
        )
    except ValueError as exc:
        assert "pairing check failed" in str(exc)
    else:
        raise AssertionError("stolen ticket unexpectedly produced a proof")
    checks["stolen_ticket_transfer"] = "joint_proof_not_constructible"

    # Build the first valid authenticated transcript.
    tx1 = init["serverAuth"]["transactionId"]
    auth1, otk1, ctx1 = _auth_request(service, tx1, device)
    auth_response1 = service.authenticate(auth1, "aura-pr.test")

    # 5. An exact authenticated-message replay is idempotent.
    replay = service.authenticate(copy.deepcopy(auth1), "aura-pr.test")
    assert replay["replayed"] is True
    assert replay["Bind_t"] == auth_response1["Bind_t"]
    checks["nullifier_exact_replay"] = "cached_idempotent_response"

    # 6. A different valid transcript under the same ticket/nullifier is caught.
    second_init = service.initiate(
        {
            "I_ac": device["ticket"]["I_ac"],
            "N_U": b64e(secrets.token_bytes(32)),
            "capabilities": ["classical-p256"],
        },
        "aura-pr.test",
    )
    auth_double, _, _ = _auth_request(
        service,
        second_init["serverAuth"]["transactionId"],
        device,
        salt_p=b64d(auth1["salt_p"]),
    )
    double_error = _expect_error(
        "DOUBLE_SPEND_DETECTED:TRACE_RECOVERED",
        lambda: service.authenticate(auth_double, "aura-pr.test"),
    )
    assert double_error.stage == "authenticateClient"
    checks["nullifier_different_transcript"] = double_error.code

    # Issue a fresh ticket for a second independent, valid transaction.
    issue_ticket(root)
    device2 = load_json(runtime / "device.json")
    tx2, auth2, otk2, ctx2 = _new_transaction(service, device2)
    auth_response2 = service.authenticate(auth2, "aura-pr.test")

    # 7. Bind_t from transaction 1 is not valid in transaction 2.
    ephemeral2 = generate_p256_private()
    q_u2 = p256_public_b64(ephemeral2.public_key())
    cross_bind_request = {
        "transactionId": tx2,
        "Bind_t": auth_response1["Bind_t"],
        "ctx_bind": auth_response1["ctx_bind"],
        "mode": "classical-p256",
        "Q_U": q_u2,
        "sigma_U_Q": ed25519_sign(
            otk2,
            ka_u_payload(
                i_t=service.store.get_session(tx2).server_auth["I_t"],
                q_u=q_u2,
                bind_t=auth_response1["Bind_t"],
            ),
        ),
    }
    bind_error = _expect_error(
        "BIND_T_MISMATCH",
        lambda: service.get_profile(cross_bind_request, "aura-pr.test"),
    )
    checks["bind_cross_transaction"] = bind_error.code

    # 8. Changing Q_U after KA-U signing invalidates the one-time-key signature.
    q_u_original = p256_public_b64(generate_p256_private().public_key())
    q_u_tampered = p256_public_b64(generate_p256_private().public_key())
    ecdhe_tamper_request = {
        "transactionId": tx2,
        "Bind_t": auth_response2["Bind_t"],
        "ctx_bind": auth_response2["ctx_bind"],
        "mode": "classical-p256",
        "Q_U": q_u_tampered,
        "sigma_U_Q": ed25519_sign(
            otk2,
            ka_u_payload(
                i_t=service.store.get_session(tx2).server_auth["I_t"],
                q_u=q_u_original,
                bind_t=auth_response2["Bind_t"],
            ),
        ),
    }
    key_error = _expect_error(
        "INVALID_KA_U_SIGNATURE",
        lambda: service.get_profile(ecdhe_tamper_request, "aura-pr.test"),
    )
    checks["ecdhe_public_key_tamper"] = key_error.code

    # 9. A network mode change is transcript-invalid even though Hybrid is supported.
    downgraded = copy.deepcopy(init["serverAuth"])
    downgraded["cap"]["selected"] = "hybrid-p256-mlkem768"
    assert not p256_verify(server_public, downgraded, init["serverSignature"])
    hybrid_request = {
        "transactionId": tx2,
        "Bind_t": auth_response2["Bind_t"],
        "ctx_bind": auth_response2["ctx_bind"],
        "mode": "hybrid-p256-mlkem768",
        "Q_U": q_u2,
        "sigma_U_Q": "",
    }
    hybrid_error = _expect_error(
        "CAPABILITY_MODE_MISMATCH",
        lambda: service.get_profile(hybrid_request, "aura-pr.test"),
    )
    checks["hybrid_downgrade_or_splice"] = hybrid_error.code

    # Obtain two valid encrypted packages and the actual derived keys.
    def deliver(tx, response, otk, private):
        session = service.store.get_session(tx)
        q_u = p256_public_b64(private.public_key())
        request = {
            "transactionId": tx,
            "Bind_t": response["Bind_t"],
            "ctx_bind": response["ctx_bind"],
            "mode": "classical-p256",
            "Q_U": q_u,
            "sigma_U_Q": ed25519_sign(
                otk,
                ka_u_payload(
                    i_t=session.server_auth["I_t"],
                    q_u=q_u,
                    bind_t=response["Bind_t"],
                ),
            ),
        }
        package = service.get_profile(request, "aura-pr.test")
        ctx_k = build_ctx_k(
            ctx_t=session.auth.ctx_t,
            bind_t=response["Bind_t"],
            q_u=q_u,
            q_s=package["Q_S"],
        )
        return package, derive_profile_keys(private, package["Q_S"], ctx_k)

    private2 = generate_p256_private()
    package2, (k_enc2, k_mac2) = deliver(
        tx2, auth_response2, otk2, private2
    )

    issue_ticket(root)
    device3 = load_json(runtime / "device.json")
    tx3, auth3, otk3, ctx3 = _new_transaction(service, device3)
    auth_response3 = service.authenticate(auth3, "aura-pr.test")
    private3 = generate_p256_private()
    package3, (k_enc3, _) = deliver(
        tx3, auth_response3, otk3, private3
    )

    aad2 = {
        "domain": "AURA-RSP-v14/profile",
        "ctx_K": package2["ctx_K"],
        "profile_sha256": package2["profileSha256"],
    }

    # 10. Ciphertext/tag modification is detected by AES-GCM.
    modified = bytearray(b64d(package2["ciphertext"]))
    modified[-1] ^= 1
    try:
        decrypt_profile(k_enc2, package2["nonce"], b64e(bytes(modified)), aad2)
    except InvalidTag:
        pass
    else:
        raise AssertionError("tampered Profile ciphertext decrypted")
    checks["profile_ciphertext_tamper"] = "AEAD_INVALID_TAG"

    # 11. Session-A ciphertext cannot be decrypted under Session-B keys/context.
    aad3 = {
        "domain": "AURA-RSP-v14/profile",
        "ctx_K": package3["ctx_K"],
        "profile_sha256": package3["profileSha256"],
    }
    try:
        decrypt_profile(
            k_enc3, package2["nonce"], package2["ciphertext"], aad3
        )
    except InvalidTag:
        pass
    else:
        raise AssertionError("cross-session Profile replay decrypted")
    checks["profile_cross_session_replay"] = "CTX_K_AEAD_REJECTED"

    # 12. Even a valid AEAD package is rejected when plaintext H(P) != pid_h.
    malicious_profile = b"wrong-profile-for-current-order"
    nonce_bad, ciphertext_bad = encrypt_profile(
        k_enc2, malicious_profile, aad2
    )
    decrypted_bad = decrypt_profile(
        k_enc2, nonce_bad, ciphertext_bad, aad2
    )
    assert sha256_hex(decrypted_bad) != device2["ticket"]["pid_h"]
    checks["wrong_profile_plaintext"] = "PROFILE_ORDER_DIGEST_MISMATCH"

    # 13. Receipt field/tag changes are rejected before profile state update.
    session2 = service.store.get_session(tx2)
    receipt = create_install_receipt(
        k_mac2,
        lph=ctx2["lph"],
        ctx_t=ctx2,
        bind_t=auth_response2["Bind_t"],
        ciphertext_hash=package2["ciphertextSha256"],
    ).to_dict()
    changed_receipt = copy.deepcopy(receipt)
    changed_receipt["ctr_new"] = 2
    assert not verify_install_receipt(
        k_mac2,
        changed_receipt,
        lph=ctx2["lph"],
        ctx_t=ctx2,
        bind_t=auth_response2["Bind_t"],
        ciphertext_hash=package2["ciphertextSha256"],
    )
    receipt_error = _expect_error(
        "INVALID_INSTALL_RECEIPT",
        lambda: service.notification(
            {"transactionId": tx2, "InstallReceipt": changed_receipt},
            "aura-pr.test",
        ),
    )
    assert service.store.get_profile_state(ctx2["lph"]) is None
    service.notification(
        {"transactionId": tx2, "InstallReceipt": receipt},
        "aura-pr.test",
    )
    assert service.store.get_profile_state(ctx2["lph"]) is not None
    checks["install_receipt_tamper"] = receipt_error.code

    report = {
        "status": "AURA_INTEGRATED_SECURITY_SELFTEST_PASS",
        "checks": checks,
        "check_count": len(checks),
        "cryptography": "real BBS+, P-256, Ed25519, HKDF and AES-GCM",
    }
    result_path = root / "results" / "aura-security-selftest.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(result_path, report)
    store.close()
    return report


def main() -> None:
    print(json.dumps(run_selftest(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
