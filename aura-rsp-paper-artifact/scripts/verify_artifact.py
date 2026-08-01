#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_RE = re.compile(r"^experiment-(0[1-9]|1[0-3])-")
FORBIDDEN_DIRS = {"__pycache__", ".pytest_cache", ".venv", "runtime", "logs"}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db", ".log", ".pid", ".p12", ".pfx"}


def fail(message: str) -> None:
    raise SystemExit(f"ARTIFACT_VERIFICATION_FAIL: {message}")


def main() -> None:
    experiments = sorted(
        path for path in (ROOT / "experiments").iterdir()
        if path.is_dir() and EXPERIMENT_RE.match(path.name)
    )
    if len(experiments) != 13:
        fail(f"expected 13 experiments, found {len(experiments)}")

    for experiment in experiments:
        for required in ("README.md", "config.json", "demo.py", "run_demo.sh"):
            if not (experiment / required).is_file():
                fail(f"missing {experiment.name}/{required}")

    json_count = 0
    python_count = 0
    shell_count = 0
    file_count = 0
    total_bytes = 0
    manifest_lines: list[str] = []

    for path in sorted(ROOT.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.as_posix() == "MANIFEST.sha256":
            continue
        if any(part in FORBIDDEN_DIRS for part in relative.parts):
            fail(f"forbidden runtime directory included: {relative}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            fail(f"forbidden generated file included: {relative}")
        if path.suffix.lower() == ".pem":
            fail(f"PEM key/certificate must be generated locally: {relative}")
        data = path.read_bytes()
        file_count += 1
        total_bytes += len(data)
        manifest_lines.append(f"{hashlib.sha256(data).hexdigest()}  {relative.as_posix()}")
        if path.suffix == ".json":
            json.loads(data.decode("utf-8"))
            json_count += 1
        elif path.suffix == ".py":
            compile(data, str(relative), "exec")
            python_count += 1
        elif path.suffix == ".sh":
            shell_count += 1
            if b"\r\n" in data:
                fail(f"CRLF shell script: {relative}")

    manifest_path = ROOT / "MANIFEST.sha256"
    if manifest_path.exists():
        recorded = [line for line in manifest_path.read_text(encoding="utf-8").splitlines() if line]
        if recorded != manifest_lines:
            fail("MANIFEST.sha256 does not match current files")

    print(json.dumps({
        "status": "AURA_RSP_GITHUB_ARTIFACT_PASS",
        "experiment_directories": len(experiments),
        "files": file_count,
        "bytes": total_bytes,
        "python_files_compiled": python_count,
        "json_files_parsed": json_count,
        "shell_scripts_checked": shell_count,
        "manifest_checked": manifest_path.exists(),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SyntaxError) as exc:
        fail(str(exc))
