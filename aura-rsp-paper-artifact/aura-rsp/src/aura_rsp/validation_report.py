from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from .codec import load_json, save_json


ROOT = Path(__file__).resolve().parents[2]


def contains(path: Path, marker: str) -> bool:
    return path.is_file() and marker in path.read_text(
        encoding="utf-8", errors="replace"
    )


def build_report() -> dict:
    runtime = ROOT / "runtime"
    logs = ROOT / "logs"
    source_profile = (runtime / "profile.der").read_bytes()
    output_profile = (
        runtime
        / "software-euicc-output"
        / "TS48V2-SAIP2-1-NOBERTLV-UNIQUE.aura.upp.der"
    ).read_bytes()
    with sqlite3.connect(runtime / "aura.sqlite") as db:
        db.row_factory = sqlite3.Row
        trace = db.execute(
            "SELECT * FROM traces ORDER BY id DESC LIMIT 1"
        ).fetchone()
        installed = db.execute(
            "SELECT COUNT(*) FROM sessions WHERE status='installed'"
        ).fetchone()[0]
        notifications = db.execute(
            "SELECT COUNT(*) FROM notifications"
        ).fetchone()[0]
    report = {
        "status": "AURA_VALIDATION_REPORT_PASS",
        "profile": {
            "same_bytes_as_baseline_fixture": source_profile == output_profile,
            "bytes": len(output_profile),
            "sha256": hashlib.sha256(output_profile).hexdigest(),
        },
        "tests": {
            "positive_download": contains(
                logs / "test-normal.log", "AURA_RSP_DOWNLOAD_PASS"
            ),
            "identical_auth_replay_cached": contains(
                logs / "test-replay.log", '"auth_replay_cached": true'
            ),
            "tampered_composite_proof_rejected": contains(
                logs / "test-tamper-proof.log", "AURA_TAMPER_PROOF_REJECTED"
            ),
            "tampered_bind_t_rejected": contains(
                logs / "test-tamper-bind.log", "AURA_TAMPER_BIND_REJECTED"
            ),
            "same_ticket_double_spend_detected": contains(
                logs / "test-double-spend-second.log",
                "AURA_DOUBLE_SPEND_TRACE_PASS",
            ),
            "double_spend_traced_to_test_eid": bool(
                trace
                and trace["eid"] == "89049032123451234512345678901235"
            ),
        },
        "database_evidence": {
            "installed_sessions": installed,
            "install_notifications": notifications,
            "latest_trace": dict(trace) if trace else None,
        },
        "benchmark": load_json(ROOT / "results" / "latest-benchmark.json")
        if (ROOT / "results" / "latest-benchmark.json").is_file()
        else None,
        "limitations": [
            "software eUICC; x is not protected by a physical secure element",
            "research BBS+ implementation built on py-ecc; not independently audited",
            "profile installation is represented by verified decryption, file output and InstallReceipt, not ES10 APDU writes",
            "network-exposed enable, disable, delete and reinstall endpoints remain out of scope; the SQLite lifecycle core is exercised by independent experiment 6",
        ],
    }
    if not all(report["tests"].values()):
        raise RuntimeError("one or more validation checks failed")
    if not report["profile"]["same_bytes_as_baseline_fixture"]:
        raise RuntimeError("downloaded profile differs from baseline fixture")
    save_json(ROOT / "results" / "validation-report.json", report)
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    print(report["status"])


if __name__ == "__main__":
    main()
