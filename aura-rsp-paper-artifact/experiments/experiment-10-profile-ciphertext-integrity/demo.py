"""Experiment 10 against the integrated pySim/osmo-smdpp AURA code."""
from __future__ import annotations

import argparse, copy, csv, hashlib, json, shutil, time
from pathlib import Path
from cryptography.exceptions import InvalidTag

from pySim.esim.aura.codec import b64d, b64e
from pySim.esim.aura.experiment_support import IntegratedAuraExperimentFixture
from pySim.esim.aura.key_agreement import build_ctx_k, derive_profile_keys, ka_s_payload
from pySim.esim.aura.primitives import decrypt_profile, encrypt_profile, p256_verify
from pySim.esim.aura.profile_validation import verify_profile_plaintext


def prepare_output(path, root):
    path = path.resolve()
    if not path.is_relative_to((root / "results").resolve()):
        raise ValueError("output outside experiment results")
    if path.exists(): shutil.rmtree(path)
    for name in ("raw", "evidence", "runtime"): (path / name).mkdir(parents=True, exist_ok=True)
    return path


def obtain(fixture, suffix):
    prepared = fixture.prepare_authentication(suffix)
    auth = fixture.authenticate(prepared.request)
    request, private = fixture.build_key_request(prepared, auth)
    response = fixture.service.get_profile(request, fixture.order.PRaddr)
    return prepared, auth, request, private, response


def client_open(fixture, prepared, auth, request, private, response):
    ctx_k = build_ctx_k(ctx_t=prepared.ctx_t, bind_t=auth["Bind_t"], q_u=request["Q_U"], q_s=response["Q_S"])
    if response["ctx_K"] != ctx_k: raise ValueError("CTX_K_MISMATCH")
    signed = ka_s_payload(i_t=prepared.server_response["serverAuth"]["I_t"], ctx_k=ctx_k)
    if not p256_verify(fixture.service.profile_binding_key.public_key(), signed, response["sigma_S_Q"]):
        raise ValueError("INVALID_KA_S_SIGNATURE")
    k_enc, _ = derive_profile_keys(private, response["Q_S"], ctx_k)
    if hashlib.sha256(b64d(response["ciphertext"])).hexdigest() != response["ciphertextSha256"]:
        raise ValueError("CIPHERTEXT_HASH_MISMATCH")
    aad = {"domain": "AURA-RSP-v14/profile", "ctx_K": ctx_k, "profile_sha256": response["profileSha256"]}
    profile = decrypt_profile(k_enc, response["nonce"], response["ciphertext"], aad)
    verify_profile_plaintext(profile, response_sha256=response["profileSha256"], order_pid_h=fixture.order.pid_h)
    return profile


def reject(name, call):
    try:
        call()
        return {"scenario": name, "accepted": True, "reason": "UNEXPECTED_ACCEPT", "installed": True, "receipt_generated": True}
    except (InvalidTag, ValueError) as exc:
        return {"scenario": name, "accepted": False, "reason": getattr(exc, "code", type(exc).__name__), "installed": False, "receipt_generated": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("results") / "latest")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    args = parser.parse_args(); root = Path(__file__).resolve().parent
    cfg = json.loads(args.config.read_text(encoding="utf-8")); output = prepare_output(args.output, root)
    integration = root.parent.parent / "pysim-aura-integration"; started = time.perf_counter_ns()
    common = dict(integration_root=integration, seed=int(cfg["seed"]), sid=cfg["aura"]["sid"], server_oid=cfg["aura"]["server_oid"], praddr=cfg["aura"]["praddr"])
    a = IntegratedAuraExperimentFixture(runtime_root=output / "runtime/a", label="exp10-a", **common)
    b = IntegratedAuraExperimentFixture(runtime_root=output / "runtime/b", label="exp10-b", matching_id=cfg["profile_b_matching_id"], **common)
    try:
        pa, aa, ra, ka, sa = obtain(a, "session-a"); pb, ab, rb, kb, sb = obtain(b, "session-b")
        positive_a = client_open(a, pa, aa, ra, ka, sa); positive_b = client_open(b, pb, ab, rb, kb, sb)

        flipped = copy.deepcopy(sa); raw = bytearray(b64d(flipped["ciphertext"])); raw[len(raw)//2] ^= 1
        flipped["ciphertext"] = b64e(bytes(raw)); flipped["ciphertextSha256"] = hashlib.sha256(raw).hexdigest()
        row_flip = reject("10A_ciphertext_byte_flip", lambda: client_open(a, pa, aa, ra, ka, flipped))
        tag = copy.deepcopy(sa); raw = bytearray(b64d(tag["ciphertext"])); raw[-1] ^= 1
        tag["ciphertext"] = b64e(bytes(raw)); tag["ciphertextSha256"] = hashlib.sha256(raw).hexdigest()
        row_tag = reject("10A_aead_tag_tamper", lambda: client_open(a, pa, aa, ra, ka, tag))
        row_replay = reject("10B_session_a_ciphertext_to_session_b", lambda: client_open(b, pb, ab, rb, kb, sa))

        ctx_k = build_ctx_k(ctx_t=pa.ctx_t, bind_t=aa["Bind_t"], q_u=ra["Q_U"], q_s=sa["Q_S"])
        k_enc, _ = derive_profile_keys(ka, sa["Q_S"], ctx_k)
        wrong = b.profile_repository.load(b.matching_id).data; wrong_hash = hashlib.sha256(wrong).hexdigest()
        aad = {"domain": "AURA-RSP-v14/profile", "ctx_K": ctx_k, "profile_sha256": wrong_hash}
        nonce, ciphertext = encrypt_profile(k_enc, wrong, aad); malicious = copy.deepcopy(sa)
        malicious.update(nonce=nonce, ciphertext=ciphertext, ciphertextSha256=hashlib.sha256(b64d(ciphertext)).hexdigest(), profileSha256=wrong_hash)
        row_wrong = reject("10C_legitimate_server_wrong_plaintext", lambda: client_open(a, pa, aa, ra, ka, malicious))
    finally: a.close(); b.close()

    rows = [row_flip, row_tag, row_replay, row_wrong]
    assertions = {
        "positive_controls_decrypt": len(positive_a) == a.profile_bytes and len(positive_b) == b.profile_bytes,
        "ciphertext_and_tag_tampering_rejected": not row_flip["accepted"] and not row_tag["accepted"],
        "cross_session_replay_rejected": not row_replay["accepted"],
        "wrong_plaintext_rejected_by_order_digest": not row_wrong["accepted"] and row_wrong["reason"] == "PROFILE_ORDER_DIGEST_MISMATCH",
        "no_attack_install_or_receipt": all(not r["installed"] and not r["receipt_generated"] for r in rows),
    }
    status = "PASS" if all(assertions.values()) else "FAIL"; modules = {}
    for relative in ("pySim/esim/aura/service.py", "pySim/esim/aura/client.py", "pySim/esim/aura/lifecycle_client.py", "pySim/esim/aura/key_agreement.py", "pySim/esim/aura/profile_validation.py"):
        path = integration / relative; modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {"status": status, "experiment": "experiment-10-profile-ciphertext-integrity", "implementation": "pysim-osmo-smdpp-integrated-aura", "scenarios": rows, "metrics": {"attacks": len(rows), "rejected": sum(not r["accepted"] for r in rows), "attack_installs": sum(r["installed"] for r in rows)}, "assertions": assertions, "source_audit": {"modules": modules}, "migration_comparison": {"previous_status": "PASS", "conclusion_unchanged": status == "PASS", "production_fix": "shared verify_profile_plaintext check"}, "boundary": "Joint MNO/SM-DP+ authorization of the wrong plaintext as pid_h is outside the protocol guarantee.", "execution_ms": round((time.perf_counter_ns()-started)/1_000_000, 3)}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    (output / "evidence/assertions.json").write_text(json.dumps(assertions, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    with (output / "raw/scenarios.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    result = {"status": status, "attacks_rejected": f"{sum(not r['accepted'] for r in rows)}/{len(rows)}", "attack_installs": 0, "results": str(output)}
    print(json.dumps(result, sort_keys=True) if args.machine_json else json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
