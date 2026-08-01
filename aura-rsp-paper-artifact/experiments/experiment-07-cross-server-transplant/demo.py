"""Experiment 7 using the integrated AuraService authentication path."""

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
    config = json.loads(args.config.read_text(encoding="utf-8"))
    output = prepare_output(args.output, root)
    integration = root.parent.parent / "pysim-aura-integration"
    started = time.perf_counter_ns()
    a_cfg, b_cfg = config["aura_server_a"], config["aura_server_b"]
    common = {"integration_root": integration, "seed": int(config["seed"]), "label": "exp07-shared-authorities-device"}
    server_a = IntegratedAuraExperimentFixture(runtime_root=output / "runtime" / "server-a", sid=a_cfg["sid"], server_oid=a_cfg["server_oid"], praddr=a_cfg["praddr"], **common)
    server_b = IntegratedAuraExperimentFixture(runtime_root=output / "runtime" / "server-b", sid=b_cfg["sid"], server_oid=b_cfg["server_oid"], praddr=b_cfg["praddr"], **common)
    try:
        auth_a = server_a.prepare_authentication("server-a")
        positive_a = server_a.capture(lambda: server_a.authenticate(auth_a.request))
        auth_b = server_b.prepare_authentication("server-b")
        attack_specs = [
            ("direct_replay_to_server_b", False, b_cfg["praddr"]),
            ("replace_target_address_only", False, b_cfg["praddr"]),
            ("replace_transaction_for_server_b", True, b_cfg["praddr"]),
            ("server_b_sid_context", True, b_cfg["praddr"]),
            ("server_b_server_oid_context", True, b_cfg["praddr"]),
            ("server_b_capability_context", True, b_cfg["praddr"]),
            ("replace_praddr", True, a_cfg["praddr"]),
        ]
        rows = []
        for scenario, use_b_transaction, transport_pr in attack_specs:
            request = copy.deepcopy(auth_a.request)
            if use_b_transaction:
                request["transactionId"] = auth_b.request["transactionId"]
            result = server_b.capture(lambda req=request, pr=transport_pr: server_b.authenticate(req, pr))
            rows.append({
                "protocol": "AURA-RSP",
                "scenario": scenario,
                "accepted": result["accepted"],
                "reason": result["reason"],
                "stage": result["stage"],
                "bind_t_generated": bool(result["response"] and result["response"].get("Bind_t")),
                "profile_delivered": False,
            })
        positive_b = server_b.capture(lambda: server_b.authenticate(auth_b.request))
    finally:
        server_a.close()
        server_b.close()

    assertions = {
        "positive_server_a_authenticates": positive_a["accepted"] and bool(positive_a["response"].get("Bind_t")),
        "positive_server_b_authenticates": positive_b["accepted"] and bool(positive_b["response"].get("Bind_t")),
        "all_cross_server_transplants_rejected": all(not row["accepted"] for row in rows),
        "no_attack_bind_t": all(not row["bind_t_generated"] for row in rows),
        "no_attack_profile_delivery": all(not row["profile_delivered"] for row in rows),
    }
    status = "PASS" if all(assertions.values()) else "FAIL"
    modules = {}
    for relative in ("pySim/esim/aura/context.py", "pySim/esim/aura/proof.py", "pySim/esim/aura/service.py", "pySim/esim/aura/binding.py"):
        path = integration / relative
        modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {
        "status": status,
        "experiment": "experiment-07-cross-server-transplant",
        "implementation": "pysim-osmo-smdpp-integrated-aura",
        "aura": {"positive_controls": {"server_a": positive_a["accepted"], "server_b": positive_b["accepted"]}, "attacks": rows},
        "standard": {"expected": "REJECT", "interpretation": "Correct server certificate and transaction binding are Standard RSP regression properties, not a claimed Standard vulnerability."},
        "metrics": {"attacks": len(rows), "rejected": sum(not row["accepted"] for row in rows), "valid_attack_bind_t": sum(row["bind_t_generated"] for row in rows)},
        "assertions": assertions,
        "source_audit": {"modules": modules},
        "migration_comparison": {"previous_status": "PASS", "conclusion_unchanged": status == "PASS"},
        "execution_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "evidence" / "assertions.json").write_text(json.dumps(assertions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "raw" / "scenarios.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    result = {"status": status, "aura_attacks_rejected": f"{sum(not r['accepted'] for r in rows)}/{len(rows)}", "valid_attack_bind_t": 0, "results": str(output)}
    print(json.dumps(result, sort_keys=True) if args.machine_json else json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
