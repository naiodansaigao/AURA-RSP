"""Generate a reproducible source-only diff summary against the pySim baseline."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path


IGNORED_PARTS = {
    ".git",
    "__pycache__",
    "runtime",
    "logs",
    "results",
    "generated",
}
IGNORED_SUFFIXES = {".pyc", ".pyo"}
IGNORED_PREFIXES = {
    "pySim.egg-info/",
    "tests/unittests/smdpp_data/",
}


def source_files(root: Path) -> dict[str, Path]:
    result = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        relative_name = relative.as_posix()
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if any(relative_name.startswith(prefix) for prefix in IGNORED_PREFIXES):
            continue
        if path.name.startswith("sm-dp-sessions"):
            continue
        if path.suffix in IGNORED_SUFFIXES:
            continue
        result[relative_name] = path
    return result


def text_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--integration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    baseline = source_files(args.baseline.resolve())
    integration = source_files(args.integration.resolve())
    added = sorted(set(integration) - set(baseline))
    deleted = sorted(set(baseline) - set(integration))
    modified = []
    additions = 0
    deletions = 0

    for name in sorted(set(baseline) & set(integration)):
        before = baseline[name].read_bytes()
        after = integration[name].read_bytes()
        if hashlib.sha256(before).digest() == hashlib.sha256(after).digest():
            continue
        modified.append(name)
        before_lines = text_lines(baseline[name])
        after_lines = text_lines(integration[name])
        if before_lines is None or after_lines is None:
            continue
        for line in difflib.ndiff(before_lines, after_lines):
            if line.startswith("+ "):
                additions += 1
            elif line.startswith("- "):
                deletions += 1

    for name in added:
        lines = text_lines(integration[name])
        if lines is not None:
            additions += len(lines)
    for name in deleted:
        lines = text_lines(baseline[name])
        if lines is not None:
            deletions += len(lines)

    report = {
        "status": "SOURCE_DIFF_AUDIT_PASS",
        "baseline_commit": "25e43e1540144be9026a2733bc3a4271b8fa7d25",
        "added_files": len(added),
        "modified_files": len(modified),
        "deleted_files": len(deleted),
        "text_line_additions": additions,
        "text_line_deletions": deletions,
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "ignored_runtime_categories": sorted(IGNORED_PARTS),
        "ignored_fixture_prefixes": sorted(IGNORED_PREFIXES),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        key: report[key]
        for key in (
            "status", "added_files", "modified_files", "deleted_files",
            "text_line_additions", "text_line_deletions",
        )
    }, sort_keys=True))


if __name__ == "__main__":
    main()
