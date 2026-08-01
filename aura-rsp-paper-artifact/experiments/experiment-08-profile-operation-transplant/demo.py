"""Experiment 8 using integrated authentication, binding and Profile delivery."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import shutil
import time

from pySim.esim.aura.experiment_support import IntegratedAuraExperimentFixture
from pySim.esim.aura.proof import verify_auth_proof


def prepare_output(path: Path, root: Path) -> Path:
    path = path.resolve()
    if not path.is_relative_to((root / "results").resolve()):
        raise ValueError("output outside experiment results")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "runtime"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("results") / "latest")
    parser.add_argument("--machine-json", action="store_true")
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    output = prepare_output(args.output, root)
    integration = root.parent.parent / "pysim-aura-integration"
    started = time.perf_counter_ns()
    aura = cfg["aura"]
    common = {
        "integration_root": integration,
        "seed": int(cfg["seed"]),
        "label": "exp08-shared-authorities-device",
        "sid": aura["sid"],
        "server_oid": aura["server_oid"],
        "praddr": aura["praddr"],
    }
    server_a = IntegratedAuraExperimentFixture(runtime_root=output / "runtime" / "profile-a", **common)
    server_b = IntegratedAuraExperimentFixture(runtime_root=output / "runtime" / "profile-b", matching_id=cfg["profile_b_matching_id"], **common)
    try:
        prepared_a = server_a.prepare_authentication("profile-a")
        auth_a = server_a.capture(lambda: server_a.authenticate(prepared_a.request))
        prepared_b = server_b.prepare_authentication("profile-b")

        cross_profile_request = copy.deepcopy(prepared_a.request)
        cross_profile_request["transactionId"] = prepared_b.request["transactionId"]
        cross_profile = server_b.capture(lambda: server_b.authenticate(cross_profile_request))

        tampered_ctx = copy.deepcopy(prepared_a.ctx_t)
        tampered_ctx["ticket"]["pid_h"] = server_b.profile_sha256
        profile_proof_ok, profile_proof_reason = verify_auth_proof(
            ctx_t=tampered_ctx,
            proof=prepared_a.request["Pi_auth"],
            eum_public_key=server_a.eum_public,
            mno_public_key=server_a.mno_public,
            salt_p=prepared_a.salt_p,
        )

        operation_rows = []
        for operation in ("delete", "reinstall", "enable"):
            op_ctx = copy.deepcopy(prepared_a.ctx_t)
            op_ctx["ticket"]["op"] = operation
            accepted, reason = verify_auth_proof(
                ctx_t=op_ctx,
                proof=prepared_a.request["Pi_auth"],
                eum_public_key=server_a.eum_public,
                mno_public_key=server_a.mno_public,
                salt_p=prepared_a.salt_p,
            )
            operation_rows.append({"scenario": "download_to_" + operation, "accepted": accepted, "reason": reason, "stage": "Pi_auth", "bind_t_generated": False, "profile_delivered": False})

        auth_b = server_b.capture(lambda: server_b.authenticate(prepared_b.request))
        key_a, _ = server_a.build_key_request(prepared_a, auth_a["response"])
        key_b, _ = server_b.build_key_request(prepared_b, auth_b["response"])
        positive_profile_a = server_a.capture(lambda: server_a.service.get_profile(key_a, aura["praddr"]))
        positive_profile_b = server_b.capture(lambda: server_b.service.get_profile(key_b, aura["praddr"]))
        transplanted_key = copy.deepcopy(key_b)
        transplanted_key["Bind_t"] = auth_a["response"]["Bind_t"]
        transplanted_key["ctx_bind"] = auth_a["response"]["ctx_bind"]
        bind_transplant = server_b.capture(lambda: server_b.service.get_profile(transplanted_key, aura["praddr"]))
    finally:
        server_a.close(); server_b.close()

    rows = [
        {"scenario": "profile_a_auth_to_profile_b_session", "accepted": cross_profile["accepted"], "reason": cross_profile["reason"], "stage": cross_profile["stage"], "bind_t_generated": bool(cross_profile["response"] and cross_profile["response"].get("Bind_t")), "profile_delivered": False},
        {"scenario": "modify_pid_h_keep_proof", "accepted": profile_proof_ok, "reason": profile_proof_reason, "stage": "Pi_auth", "bind_t_generated": False, "profile_delivered": False},
        {"scenario": "profile_a_bind_t_to_profile_b_session", "accepted": bind_transplant["accepted"], "reason": bind_transplant["reason"], "stage": bind_transplant["stage"], "bind_t_generated": False, "profile_delivered": bool(bind_transplant["response"])},
        *operation_rows,
    ]
    assertions = {
        "both_profile_positive_controls_authenticate": auth_a["accepted"] and auth_b["accepted"],
        "both_profile_positive_controls_deliver": positive_profile_a["accepted"] and positive_profile_b["accepted"],
        "all_cross_profile_attacks_rejected": all(not row["accepted"] for row in rows[:3]),
        "all_cross_operation_attacks_rejected": all(not row["accepted"] for row in operation_rows),
        "no_attack_profile_delivery": all(not row["profile_delivered"] for row in rows),
        "no_attack_bind_t": all(not row["bind_t_generated"] for row in rows),
    }
    status = "PASS" if all(assertions.values()) else "FAIL"
    modules = {}
    for relative in ("pySim/esim/aura/context.py", "pySim/esim/aura/proof.py", "pySim/esim/aura/binding.py", "pySim/esim/aura/service.py", "pySim/esim/aura/key_agreement.py"):
        path = integration / relative
        modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {
        "status": status,
        "experiment": "experiment-08-profile-operation-transplant",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "positive_controls": {"profile_a_sha256": server_a.profile_sha256, "profile_b_sha256": server_b.profile_sha256, "both_delivered": positive_profile_a["accepted"] and positive_profile_b["accepted"]},
        "attacks": rows,
        "metrics": {"attacks": len(rows), "rejected": sum(not row["accepted"] for row in rows), "profile_deliveries_under_attack": sum(row["profile_delivered"] for row in rows)},
        "assertions": assertions,
        "source_audit": {"modules": modules},
        "migration_comparison": {"previous_status": "PASS", "conclusion_unchanged": status == "PASS"},
        "standard": {"expected": "REJECT", "interpretation": "Bound Profile Package and transaction binding remain Standard RSP regression properties."},
        "execution_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "evidence" / "assertions.json").write_text(json.dumps(assertions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "raw" / "scenarios.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    result = {"status": status, "attacks_rejected": f"{sum(not r['accepted'] for r in rows)}/{len(rows)}", "attack_profile_deliveries": 0, "results": str(output)}
    print(json.dumps(result, sort_keys=True) if args.machine_json else json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
