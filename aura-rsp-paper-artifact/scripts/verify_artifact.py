#!/usr/bin/env python3
"""Static verifier for the public AURA-RSP paper artifact."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


required = [
    ROOT / "rsp-baseline" / "README.md",
    ROOT / "rsp-baseline" / "requirements-rsp.lock",
    ROOT / "rsp-baseline" / "third_party" / "pysim" / "COPYING",
    ROOT / "rsp-baseline" / "third_party" / "openeuicc" / "LICENSE",
    ROOT / "aura-rsp" / "requirements-aura.lock",
    ROOT / "aura-rsp" / "src" / "aura_rsp" / "client.py",
    ROOT / "aura-rsp" / "src" / "aura_rsp" / "server.py",
    ROOT / "aura-rsp" / "src" / "aura_rsp" / "lifecycle.py",
    ROOT / "THIRD_PARTY_NOTICES.md",
]

for index in range(1, 14):
    matches = sorted((ROOT / "experiments").glob(f"experiment-{index:02d}-*"))
    if len(matches) != 1:
        fail(f"expected one experiment {index:02d}, found {len(matches)}")
    required.extend(
        [
            matches[0] / "demo.py",
            matches[0] / "config.json",
            matches[0] / "run_demo.sh",
            matches[0] / "README.md",
        ]
    )

missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
if missing:
    fail("missing required files: " + ", ".join(missing))

python_files = sorted(ROOT.rglob("*.py"))
for path in python_files:
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        fail(f"Python parse error in {path.relative_to(ROOT)}: {exc}")

json_files = sorted(ROOT.rglob("*.json"))
for path in json_files:
    try:
        json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        fail(f"JSON parse error in {path.relative_to(ROOT)}: {exc}")

forbidden_dirs = {"__pycache__", ".git", ".gradle", ".venv"}
found_forbidden = [
    str(path.relative_to(ROOT))
    for path in ROOT.rglob("*")
    if path.is_dir() and path.name in forbidden_dirs
]
if found_forbidden:
    fail("forbidden generated directories: " + ", ".join(found_forbidden[:10]))

allowed_test_fixture = (
    ROOT / "rsp-baseline" / "third_party" / "pysim" / "smdpp-data"
)
secret_suffixes = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db"}
unexpected_secrets: list[str] = []
for path in ROOT.rglob("*"):
    if not path.is_file() or path.suffix.lower() not in secret_suffixes:
        continue
    try:
        path.relative_to(allowed_test_fixture)
    except ValueError:
        unexpected_secrets.append(str(path.relative_to(ROOT)))
if unexpected_secrets:
    fail("unexpected runtime secret/database files: " + ", ".join(unexpected_secrets[:10]))

shell_files = sorted(ROOT.rglob("*.sh"))
for path in shell_files:
    data = path.read_bytes()
    is_project_script = "third_party" not in path.parts
    if is_project_script and not data.startswith(b"#!"):
        fail(f"missing shell shebang in {path.relative_to(ROOT)}")
    if b"\r\n" in data:
        fail(f"CRLF line endings in {path.relative_to(ROOT)}")

manifest_path = ROOT / "MANIFEST.sha256"
if manifest_path.is_file():
    for line_number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line:
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError:
            fail(f"malformed manifest line {line_number}")
        path = ROOT / Path(relative)
        if not path.is_file():
            fail(f"manifest file missing: {relative}")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != expected:
            fail(f"manifest hash mismatch: {relative}")

print(
    json.dumps(
        {
            "status": "PASS",
            "experiments": 13,
            "python_files": len(python_files),
            "json_files": len(json_files),
            "shell_files": len(shell_files),
            "runtime_secrets_outside_test_fixtures": 0,
            "manifest_verified": manifest_path.is_file(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
)
print("ARTIFACT_VERIFY_PASS")
