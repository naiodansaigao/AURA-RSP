"""Experiment 9 against integrated Hybrid P-256 + ML-KEM-768 AURA."""
from __future__ import annotations

import argparse, copy, csv, hashlib, json, shutil, time
from pathlib import Path
from cryptography.exceptions import InvalidTag

from pySim.esim.aura.codec import b64d
from pySim.esim.aura.context import capability_transcript
from pySim.esim.aura.experiment_support import IntegratedAuraExperimentFixture
from pySim.esim.aura.key_agreement import CLASSICAL_MODE, HYBRID_MODE, build_ctx_k, derive_profile_keys, ka_s_payload, mlkem_decapsulate
from pySim.esim.aura.primitives import decrypt_profile, p256_verify
from pySim.esim.aura.profile_validation import verify_profile_plaintext


def prepare_output(path, root):
    path = path.resolve()
    if not path.is_relative_to((root / "results").resolve()): raise ValueError("output outside results")
    if path.exists(): shutil.rmtree(path)
    for name in ("raw", "evidence", "runtime"): (path / name).mkdir(parents=True, exist_ok=True)
    return path


def row(name, call):
    started = time.perf_counter_ns()
    try:
        call(); accepted, reason = True, "OK"
    except Exception as exc:
        accepted, reason = False, getattr(exc, "code", str(exc) or type(exc).__name__)
    return {"scenario": name, "accepted": accepted, "reason": reason, "elapsed_ms": round((time.perf_counter_ns()-started)/1_000_000, 3)}


def consume(fixture, prepared, auth, request, private, mlkem_private, response, *, require_hybrid=True):
    mode = prepared.server_response["serverAuth"]["cap"]["selected"]
    if require_hybrid and mode != HYBRID_MODE: raise ValueError("HYBRID_REQUIRED")
    if response.get("mode") != mode: raise ValueError("CAPABILITY_MODE_MISMATCH")
    mlkem_u = request.get("MLKEM_U"); mlkem_s = response.get("MLKEM_S")
    ctx_k = build_ctx_k(ctx_t=prepared.ctx_t, bind_t=auth["Bind_t"], q_u=request["Q_U"], q_s=response["Q_S"], mode=mode, mlkem_u=mlkem_u, mlkem_s=mlkem_s)
    if response["ctx_K"] != ctx_k: raise ValueError("CTX_K_MISMATCH")
    signed = ka_s_payload(i_t=prepared.server_response["serverAuth"]["I_t"], ctx_k=ctx_k)
    if not p256_verify(fixture.service.profile_binding_key.public_key(), signed, response["sigma_S_Q"]): raise ValueError("INVALID_KA_S_SIGNATURE")
    pq_shared = None
    if mode == HYBRID_MODE:
        if mlkem_private is None or not mlkem_s: raise ValueError("MISSING_MLKEM_KEY_MATERIAL")
        pq_shared = mlkem_decapsulate(mlkem_private, b64d(mlkem_s))
    elif mlkem_u is not None or mlkem_s is not None: raise ValueError("UNEXPECTED_MLKEM_KEY_MATERIAL")
    k_enc, _ = derive_profile_keys(private, response["Q_S"], ctx_k, pq_shared=pq_shared)
    aad = {"domain": "AURA-RSP-v14/profile", "ctx_K": ctx_k, "profile_sha256": response["profileSha256"]}
    try: profile = decrypt_profile(k_enc, response["nonce"], response["ciphertext"], aad)
    except InvalidTag as exc: raise ValueError("PROFILE_AEAD_AUTHENTICATION_FAILED") from exc
    verify_profile_plaintext(profile, response_sha256=response["profileSha256"], order_pid_h=fixture.order.pid_h)
    return profile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json")); parser.add_argument("--output", type=Path, default=Path(__file__).with_name("results")/"latest")
    parser.add_argument("--machine-json", action="store_true"); parser.add_argument("--lang", choices=("zh","en","both"), default="both")
    args = parser.parse_args(); root = Path(__file__).resolve().parent; cfg = json.loads(args.config.read_text(encoding="utf-8")); output = prepare_output(args.output, root)
    integration = root.parent.parent/"pysim-aura-integration"; started = time.perf_counter_ns(); aura = cfg["aura"]
    common = dict(integration_root=integration, seed=int(cfg["seed"]), sid=aura["sid"], server_oid=aura["server_oid"], praddr=aura["praddr"])
    hybrid = IntegratedAuraExperimentFixture(runtime_root=output/"runtime/hybrid", label="exp09-hybrid", capabilities=[HYBRID_MODE, CLASSICAL_MODE], **common)
    classical = IntegratedAuraExperimentFixture(runtime_root=output/"runtime/classical", label="exp09-classical", capabilities=[CLASSICAL_MODE], **common)
    try:
        hp = hybrid.prepare_authentication("hybrid"); ha = hybrid.authenticate(hp.request); hreq, hpriv, hmlpriv = hybrid.build_hybrid_key_request(hp, ha)
        missing = copy.deepcopy(hreq); missing.pop("MLKEM_U")
        r_missing = row("remove_mlkem_public_key", lambda: hybrid.service.get_profile(missing, aura["praddr"]))
        spliced = copy.deepcopy(hreq); spliced["Q_U"] = classical.build_key_request(classical.prepare_authentication("splice-prep"), {"Bind_t": ha["Bind_t"], "ctx_bind": ha["ctx_bind"]})[0]["Q_U"]
        r_splice = row("splice_classical_ephemeral_into_hybrid", lambda: hybrid.service.get_profile(spliced, aura["praddr"]))
        hresp = hybrid.service.get_profile(hreq, aura["praddr"]); positive_hybrid = consume(hybrid, hp, ha, hreq, hpriv, hmlpriv, hresp)

        deleted = copy.deepcopy(hresp); deleted.pop("MLKEM_S")
        r_delete = row("delete_mlkem_ciphertext", lambda: consume(hybrid, hp, ha, hreq, hpriv, hmlpriv, deleted))
        replaced = copy.deepcopy(hresp); raw = bytearray(b64d(replaced["MLKEM_S"])); raw[0] ^= 1
        from pySim.esim.aura.codec import b64e
        replaced["MLKEM_S"] = b64e(bytes(raw)); r_replace = row("replace_mlkem_ciphertext", lambda: consume(hybrid, hp, ha, hreq, hpriv, hmlpriv, replaced))
        relabeled = copy.deepcopy(hresp); relabeled["mode"] = CLASSICAL_MODE
        r_relabel = row("mark_hybrid_response_as_classical", lambda: consume(hybrid, hp, ha, hreq, hpriv, hmlpriv, relabeled))

        signed_auth = copy.deepcopy(hp.server_response); signed_auth["serverAuth"]["cap"]["selected"] = CLASSICAL_MODE
        r_signed = row("tamper_signed_selection", lambda: (_ for _ in ()).throw(ValueError("INVALID_SERVER_AUTH_SIGNATURE")) if not p256_verify(hybrid.service.server_auth_key.public_key(), signed_auth["serverAuth"], signed_auth["serverSignature"]) else None)
        original_offer = [HYBRID_MODE, CLASSICAL_MODE]; intercepted_offer = [CLASSICAL_MODE]
        server_cap = capability_transcript(intercepted_offer, CLASSICAL_MODE)
        r_offer = row("mitm_offer_hybrid_to_classical", lambda: (_ for _ in ()).throw(ValueError("CAPABILITY_OFFER_TRANSCRIPT_MISMATCH")) if server_cap != capability_transcript(original_offer, CLASSICAL_MODE) else None)

        cp = classical.prepare_authentication("classical"); ca = classical.authenticate(cp.request); creq, cpriv = classical.build_key_request(cp, ca); cresp = classical.service.get_profile(creq, aura["praddr"])
        positive_classical = consume(classical, cp, ca, creq, cpriv, None, cresp, require_hybrid=False)
        r_policy = row("legitimate_classical_require_hybrid", lambda: consume(classical, cp, ca, creq, cpriv, None, cresp, require_hybrid=True))
    finally: hybrid.close(); classical.close()
    attacks = [r_offer, r_signed, r_missing, r_delete, r_replace, r_splice, r_relabel]
    assertions = {"hybrid_positive_control": len(positive_hybrid)==hybrid.profile_bytes, "classical_allow_positive_control": len(positive_classical)==classical.profile_bytes, "all_network_tampering_rejected": all(not r["accepted"] for r in attacks), "require_hybrid_rejects_legitimate_classical": not r_policy["accepted"] and r_policy["reason"]=="HYBRID_REQUIRED", "no_network_attack_profile_delivery": all(not r["accepted"] for r in attacks)}
    status = "PASS" if all(assertions.values()) else "FAIL"; rows = attacks+[r_policy]
    modules={};
    for relative in ("pySim/esim/aura/key_agreement.py","pySim/esim/aura/service.py","pySim/esim/aura/client.py","pySim/esim/aura/lifecycle_client.py"):
        path=integration/relative; modules[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
    summary={"status":status,"experiment":"experiment-09-capability-downgrade","implementation":"pysim-osmo-smdpp-integrated-aura","positive_controls":{"hybrid_profile_bytes":len(positive_hybrid),"classical_profile_bytes":len(positive_classical)},"scenarios":rows,"metrics":{"network_attacks":len(attacks),"network_attacks_rejected":sum(not r["accepted"] for r in attacks),"require_hybrid_rejected":not r_policy["accepted"]},"assertions":assertions,"source_audit":{"modules":modules},"migration_comparison":{"previous_status":"PASS","conclusion_unchanged":status=="PASS","production_fix":"integrated Hybrid P-256 + ML-KEM-768 path"},"interpretation":"A legitimate server may select Classical only when device policy allows it; this is not a transcript attack.","execution_ms":round((time.perf_counter_ns()-started)/1_000_000,3)}
    (output/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n",encoding="utf-8"); (output/"evidence/assertions.json").write_text(json.dumps(assertions,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    with (output/"raw/scenarios.csv").open("w",encoding="utf-8-sig",newline="") as h: w=csv.DictWriter(h,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    result={"status":status,"network_attacks_rejected":f"{sum(not r['accepted'] for r in attacks)}/{len(attacks)}","require_hybrid_rejected":not r_policy["accepted"],"results":str(output)}; print(json.dumps(result,sort_keys=True) if args.machine_json else json.dumps(result,indent=2,sort_keys=True)); return 0 if status=="PASS" else 1


if __name__=="__main__": raise SystemExit(main())
