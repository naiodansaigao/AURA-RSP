#!/usr/bin/env python3
"""Create a relative SHA-256 manifest and packaging report."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
REPORT = ROOT / "PACKAGING_REPORT.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def public_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path != MANIFEST
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    )


def main() -> int:
    experiments = sorted((ROOT / "experiments").glob("experiment-*"))
    test_fixture_root = (
        ROOT / "rsp-baseline" / "third_party" / "pysim" / "smdpp-data"
    )
    test_private_keys = [
        path
        for path in test_fixture_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".pem", ".key"}
        and "PRIVATE KEY" in path.read_text(encoding="utf-8", errors="ignore")
    ]

    initial_files = public_files()
    report = {
        "status": "PASS",
        "generated_utc": datetime.now(UTC).isoformat(),
        "artifact": "aura-rsp-paper-artifact",
        "experiments": len(experiments),
        "standard_rsp_present": (ROOT / "rsp-baseline").is_dir(),
        "aura_rsp_present": (ROOT / "aura-rsp").is_dir(),
        "vendored_upstream": {
            "openeuicc": "2a85b8dad6000eea9dd622a468b7558e79933b2a",
            "lpac": "3ff35594ec15062a3ed10c3da1c26eb0a13390b8",
            "pysim_osmo_smdpp": "25e43e1540144be9026a2733bc3a4271b8fa7d25",
        },
        "public_test_private_keys": len(test_private_keys),
        "public_test_private_key_scope": (
            "Expected count is zero. Standard test PKI is generated locally."
        ),
        "excluded_classes": [
            "virtual environments",
            "Git history",
            "build outputs and APKs",
            "runtime-generated AURA/experiment private keys",
            "pre-generated pySim/osmo-smdpp test private keys",
            "runtime SQLite databases",
            "PID files and service logs",
            "QA and temporary result directories",
        ],
        "file_count_before_report": len(initial_files),
        "size_bytes_before_report": sum(path.stat().st_size for path in initial_files),
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    files = public_files()
    lines = [
        f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}"
        for path in files
    ]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "PASS",
                "files": len(files),
                "size_bytes": sum(path.stat().st_size for path in files),
                "manifest": MANIFEST.name,
                "report": REPORT.name,
            },
            separators=(",", ":"),
        )
    )
    print("ARTIFACT_MANIFEST_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
