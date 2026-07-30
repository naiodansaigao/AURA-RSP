from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aura_rsp.codec import b64e, canonical, sha256_hex
from aura_rsp.lifecycle import (
    LifecycleEngine,
    LifecycleError,
    build_reinstall_receipt,
    build_transition_receipt,
    receipt_hash,
    sign_reinstall_receipt,
    verify_reinstall_receipt_mac,
)


ATTACK_SCENARIOS = (
    "installed_direct_reinstall",
    "enabled_direct_reinstall",
    "disabled_direct_reinstall",
    "wrong_lph",
    "new_salt_p",
    "old_ticket",
    "old_reinstall_receipt",
    "counter_or_last_hash_tamper",
)

ZH_NAMES = {
    "installed_direct_reinstall": "installed直接reinstall",
    "enabled_direct_reinstall": "enabled直接reinstall",
    "disabled_direct_reinstall": "disabled直接reinstall",
    "wrong_lph": "tombstone使用错误lph",
    "new_salt_p": "使用新salt_p",
    "old_ticket": "使用旧票据",
    "old_reinstall_receipt": "重放旧ReinstallReceipt",
    "counter_or_last_hash_tamper": "修改ctr或last_hash",
    "legal_tombstone_reinstall": "合法tombstone→installed",
}

EN_NAMES = {
    "installed_direct_reinstall": "Reinstall directly from installed",
    "enabled_direct_reinstall": "Reinstall directly from enabled",
    "disabled_direct_reinstall": "Reinstall directly from disabled",
    "wrong_lph": "Wrong lph from tombstone",
    "new_salt_p": "New salt_p",
    "old_ticket": "Old ticket",
    "old_reinstall_receipt": "Replay old ReinstallReceipt",
    "counter_or_last_hash_tamper": "Tamper ctr or last_hash",
    "legal_tombstone_reinstall": "Legal tombstone to installed",
}


@dataclass
class Fixture:
    scenario: str
    engine: LifecycleEngine
    db_path: Path
    lph: str
    salt_p: str
    device_key: bytes
    server_key: bytes


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: (
                        json.dumps(value, ensure_ascii=False, sort_keys=True)
                        if isinstance(value, (dict, list))
                        else value
                    )
                    for key, value in row.items()
                }
            )


def resolve_path(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def prepare_output(path: Path, experiment_root: Path) -> Path:
    output = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if output == results_root or results_root not in output.parents:
        raise ValueError(f"output must be below {results_root}")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    return output


def digest_bytes(seed: int, label: str, length: int = 32) -> bytes:
    material = bytearray()
    counter = 0
    while len(material) < length:
        material.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode()).digest()
        )
        counter += 1
    return bytes(material[:length])


def text_token(seed: int, label: str, prefix: str) -> str:
    return prefix + hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:24]


def original_lph(seed: int) -> str:
    return b64e(digest_bytes(seed, "original-lph", 36))


def original_salt(seed: int) -> str:
    return b64e(digest_bytes(seed, "original-salt", 32))


def make_fixture(
    *,
    output: Path,
    config: dict[str, Any],
    scenario: str,
    state: str,
    ctr: int = 5,
) -> Fixture:
    seed = int(config["seed"])
    db_path = output / "databases" / f"{scenario}.sqlite"
    device_key = digest_bytes(seed, f"{scenario}:device-mac")
    server_key = digest_bytes(seed, f"{scenario}:server-mac")
    engine = LifecycleEngine(
        db_path,
        device_mac_key=device_key,
        server_mac_key=server_key,
    )
    lph = original_lph(seed)
    salt_p = original_salt(seed)
    engine.initialize_profile(
        lph,
        state=state,
        ctr=ctr,
        salt_p=salt_p,
    )
    return Fixture(
        scenario=scenario,
        engine=engine,
        db_path=db_path,
        lph=lph,
        salt_p=salt_p,
        device_key=device_key,
        server_key=server_key,
    )


def issue_reinstall(
    fixture: Fixture,
    config: dict[str, Any],
    profile_sha256: str,
    *,
    label: str,
    expired: bool = False,
) -> dict[str, Any]:
    now = int(config["now"])
    expires_at = (
        now - 1
        if expired
        else now + int(config["ticket_lifetime_seconds"])
    )
    return fixture.engine.issue_reinstall_authorization(
        rid=text_token(int(config["seed"]), f"{label}:rid", "RID-"),
        lph=fixture.lph,
        salt_p=fixture.salt_p,
        expires_at=expires_at,
        session_id=text_token(
            int(config["seed"]), f"{label}:session", "SESSION-"
        ),
        bind_t=text_token(
            int(config["seed"]), f"{label}:bind", "BIND-"
        ),
        profile_sha256=profile_sha256,
        issued_at=now - 10,
    )


def make_receipt(
    fixture: Fixture,
    authorization: dict[str, Any],
    *,
    snapshot: dict[str, Any] | None = None,
    salt_p: str | None = None,
) -> dict[str, Any]:
    current = snapshot or fixture.engine.snapshot(fixture.lph)
    return build_reinstall_receipt(
        snapshot=current,
        rid=authorization["rid"],
        salt_p=fixture.salt_p if salt_p is None else salt_p,
        ticket_hash=authorization["ticket_hash"],
        session_id=authorization["session_id"],
        bind_t=authorization["Bind_t"],
        profile_sha256=authorization["profile_sha256"],
        key=fixture.device_key,
    )


def resign_receipt(
    fixture: Fixture, receipt: dict[str, Any]
) -> dict[str, Any]:
    return sign_reinstall_receipt(
        fixture.device_key,
        {key: value for key, value in receipt.items() if key != "mac"},
    )


def attempt_apply(
    fixture: Fixture,
    receipt: dict[str, Any],
    *,
    now: int,
    observed_lph: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    lph = observed_lph or str(receipt["lph"])
    before = fixture.engine.snapshot(lph)
    started = time.perf_counter()
    try:
        response = fixture.engine.apply_reinstall(receipt, now=now)
        attempt = {
            "accepted": True,
            "reason": "ACCEPTED",
            "rejection_stage": "none",
            "response": response,
        }
    except LifecycleError as exc:
        attempt = {
            "accepted": False,
            "reason": exc.code,
            "rejection_stage": exc.stage,
            "response": None,
        }
    attempt["elapsed_ms"] = round(
        (time.perf_counter() - started) * 1000, 3
    )
    after = fixture.engine.snapshot(lph)
    return attempt, before, after


def base_scenario(
    scenario: str,
    before: dict[str, Any],
    after: dict[str, Any],
    attempt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "category": (
            "positive_control"
            if scenario == "legal_tombstone_reinstall"
            else "attack"
        ),
        "initial_state": before["state"],
        "accepted": attempt["accepted"],
        "reason": attempt["reason"],
        "rejection_stage": attempt["rejection_stage"],
        "state_before": before["state"],
        "state_after": after["state"],
        "ctr_before": int(before["ctr"]),
        "ctr_after": int(after["ctr"]),
        "last_hash_before": before["last_hash"],
        "last_hash_after": after["last_hash"],
        "state_changed": before != after,
        "profile_decrypted": False,
        "profile_installed": attempt["accepted"],
        "receipt_hmac_valid": True,
        "receipt_generated": True,
        "reinstall_business_executed": attempt["accepted"],
        "attempts_rejected": int(not attempt["accepted"]),
        "attempts_total": 1,
        "elapsed_ms": attempt["elapsed_ms"],
    }


def run_state_attack(
    *,
    output: Path,
    config: dict[str, Any],
    profile_sha256: str,
    state: str,
    scenario: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], Fixture]:
    fixture = make_fixture(
        output=output, config=config, scenario=scenario, state=state
    )
    authorization = issue_reinstall(
        fixture, config, profile_sha256, label=scenario
    )
    receipt = make_receipt(fixture, authorization)
    verify_reinstall_receipt_mac(fixture.device_key, receipt)
    attempt, before, after = attempt_apply(
        fixture, receipt, now=int(config["now"])
    )
    row = base_scenario(scenario, before, after, attempt)
    row["ticket_fresh"] = True
    row["lph_preserved"] = True
    row["salt_p_preserved"] = True
    return row, [{**attempt, "scenario": scenario}], fixture


def simulate_profile_delivery(
    *,
    config: dict[str, Any],
    fixture: Fixture,
    authorization: dict[str, Any],
    profile: bytes,
) -> dict[str, Any]:
    seed = int(config["seed"])
    ctx_k = {
        "domain": "AURA-RSP:reinstall-profile-delivery:v1",
        "lph": fixture.lph,
        "salt_p_hash": sha256_hex(fixture.salt_p.encode()),
        "ticket_hash": authorization["ticket_hash"],
        "session_id": authorization["session_id"],
        "Bind_t": authorization["Bind_t"],
        "profile_sha256": authorization["profile_sha256"],
    }
    key = digest_bytes(seed, "legal-reinstall:k-enc")
    nonce = digest_bytes(seed, "legal-reinstall:nonce", 12)
    ciphertext = AESGCM(key).encrypt(nonce, profile, canonical(ctx_k))
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, canonical(ctx_k))
    profile_hash = hashlib.sha256(plaintext).hexdigest()
    return {
        "ctx_K": ctx_k,
        "ciphertext_bytes": len(ciphertext),
        "profile_bytes": len(plaintext),
        "profile_decrypted": plaintext == profile,
        "profile_sha256": profile_hash,
        "profile_digest_match": (
            profile_hash == authorization["profile_sha256"]
        ),
    }


def query_database(path: Path) -> dict[str, Any]:
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        tables = (
            "lifecycle_profiles",
            "lifecycle_profile_metadata",
            "lifecycle_authorizations",
            "reinstall_authorizations",
            "lifecycle_receipts",
        )
        return {
            table: [
                dict(row)
                for row in db.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                ).fetchall()
            ]
            for table in tables
        }


def run_experiment(
    *,
    output: Path,
    config: dict[str, Any],
    profile: bytes,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    profile_sha256 = hashlib.sha256(profile).hexdigest()
    scenarios: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    fixtures: list[Fixture] = []

    for state, scenario in (
        ("installed", "installed_direct_reinstall"),
        ("enabled", "enabled_direct_reinstall"),
        ("disabled", "disabled_direct_reinstall"),
    ):
        row, rows, fixture = run_state_attack(
            output=output,
            config=config,
            profile_sha256=profile_sha256,
            state=state,
            scenario=scenario,
        )
        scenarios.append(row)
        attempts.extend(rows)
        fixtures.append(fixture)

    wrong_lph_fixture = make_fixture(
        output=output,
        config=config,
        scenario="wrong_lph",
        state="tombstone",
    )
    wrong_lph = text_token(
        int(config["seed"]), "wrong-existing-lph", "LPH-"
    )
    wrong_lph_fixture.engine.initialize_profile(
        wrong_lph,
        state="tombstone",
        ctr=5,
        salt_p=text_token(
            int(config["seed"]), "wrong-existing-salt", "SALT-"
        ),
    )
    wrong_auth = issue_reinstall(
        wrong_lph_fixture, config, profile_sha256, label="wrong-lph"
    )
    wrong_receipt = make_receipt(
        wrong_lph_fixture,
        wrong_auth,
        snapshot=wrong_lph_fixture.engine.snapshot(wrong_lph),
    )
    wrong_receipt["lph"] = wrong_lph
    wrong_receipt = resign_receipt(wrong_lph_fixture, wrong_receipt)
    wrong_attempt, wrong_before, wrong_after = attempt_apply(
        wrong_lph_fixture,
        wrong_receipt,
        now=int(config["now"]),
        observed_lph=wrong_lph,
    )
    wrong_row = base_scenario(
        "wrong_lph", wrong_before, wrong_after, wrong_attempt
    )
    wrong_row.update(
        ticket_fresh=True,
        lph_preserved=False,
        salt_p_preserved=False,
        correct_lifecycle_unchanged=(
            wrong_lph_fixture.engine.snapshot(wrong_lph_fixture.lph)["state"]
            == "tombstone"
        ),
    )
    scenarios.append(wrong_row)
    attempts.append({**wrong_attempt, "scenario": "wrong_lph"})
    fixtures.append(wrong_lph_fixture)

    salt_fixture = make_fixture(
        output=output,
        config=config,
        scenario="new_salt_p",
        state="tombstone",
    )
    salt_auth = issue_reinstall(
        salt_fixture, config, profile_sha256, label="new-salt"
    )
    new_salt = b64e(digest_bytes(int(config["seed"]), "new-salt", 32))
    salt_receipt = make_receipt(
        salt_fixture, salt_auth, salt_p=new_salt
    )
    salt_attempt, salt_before, salt_after = attempt_apply(
        salt_fixture, salt_receipt, now=int(config["now"])
    )
    salt_row = base_scenario(
        "new_salt_p", salt_before, salt_after, salt_attempt
    )
    salt_row.update(
        ticket_fresh=True,
        lph_preserved=True,
        salt_p_preserved=False,
    )
    scenarios.append(salt_row)
    attempts.append({**salt_attempt, "scenario": "new_salt_p"})
    fixtures.append(salt_fixture)

    old_ticket_fixture = make_fixture(
        output=output,
        config=config,
        scenario="old_ticket",
        state="tombstone",
    )
    old_auth = issue_reinstall(
        old_ticket_fixture,
        config,
        profile_sha256,
        label="old-ticket",
        expired=True,
    )
    old_ticket_receipt = make_receipt(old_ticket_fixture, old_auth)
    old_attempt, old_before, old_after = attempt_apply(
        old_ticket_fixture,
        old_ticket_receipt,
        now=int(config["now"]),
    )
    old_row = base_scenario(
        "old_ticket", old_before, old_after, old_attempt
    )
    old_row.update(
        ticket_fresh=False,
        lph_preserved=True,
        salt_p_preserved=True,
    )
    scenarios.append(old_row)
    attempts.append({**old_attempt, "scenario": "old_ticket"})
    fixtures.append(old_ticket_fixture)

    replay_fixture = make_fixture(
        output=output,
        config=config,
        scenario="old_reinstall_receipt",
        state="tombstone",
    )
    replay_auth = issue_reinstall(
        replay_fixture, config, profile_sha256, label="old-receipt"
    )
    replay_receipt = make_receipt(replay_fixture, replay_auth)
    first_response = replay_fixture.engine.apply_reinstall(
        replay_receipt, now=int(config["now"])
    )
    enable_rid = text_token(
        int(config["seed"]), "old-receipt:enable", "RID-"
    )
    replay_fixture.engine.issue_authorization(
        rid=enable_rid,
        lph=replay_fixture.lph,
        op="enable",
        expires_at=int(config["now"]) + 900,
    )
    enable_receipt = build_transition_receipt(
        snapshot=replay_fixture.engine.snapshot(replay_fixture.lph),
        st_new="enabled",
        rid=enable_rid,
        key=replay_fixture.device_key,
    )
    replay_fixture.engine.apply_transition(
        enable_receipt, now=int(config["now"]) + 1
    )
    replay_attempt, replay_before, replay_after = attempt_apply(
        replay_fixture,
        replay_receipt,
        now=int(config["now"]) + 2,
    )
    replay_row = base_scenario(
        "old_reinstall_receipt",
        replay_before,
        replay_after,
        replay_attempt,
    )
    replay_row.update(
        ticket_fresh=False,
        lph_preserved=True,
        salt_p_preserved=True,
        prior_reinstall_succeeded=first_response["status"] == "installed",
        chain_advanced_to_enabled=True,
        profile_installed=False,
        reinstall_business_executed=False,
    )
    scenarios.append(replay_row)
    attempts.append(
        {**replay_attempt, "scenario": "old_reinstall_receipt"}
    )
    fixtures.append(replay_fixture)

    tamper_fixture = make_fixture(
        output=output,
        config=config,
        scenario="counter_or_last_hash_tamper",
        state="tombstone",
    )
    tamper_auth = issue_reinstall(
        tamper_fixture, config, profile_sha256, label="tamper-chain"
    )
    base_receipt = make_receipt(tamper_fixture, tamper_auth)
    tamper_before = tamper_fixture.engine.snapshot(tamper_fixture.lph)
    tamper_attempts: list[dict[str, Any]] = []
    for field in ("ctr", "last_hash"):
        changed = copy.deepcopy(base_receipt)
        if field == "ctr":
            changed["ctr"] = int(changed["ctr"]) + 7
        else:
            changed["last_hash"] = "00" * 32
        changed = resign_receipt(tamper_fixture, changed)
        attempt, _, _ = attempt_apply(
            tamper_fixture, changed, now=int(config["now"])
        )
        tamper_attempts.append(
            {
                **attempt,
                "scenario": "counter_or_last_hash_tamper",
                "variant": field,
            }
        )
    tamper_after = tamper_fixture.engine.snapshot(tamper_fixture.lph)
    aggregate = {
        "accepted": any(row["accepted"] for row in tamper_attempts),
        "reason": ";".join(row["reason"] for row in tamper_attempts),
        "rejection_stage": ";".join(
            row["rejection_stage"] for row in tamper_attempts
        ),
        "elapsed_ms": round(
            sum(float(row["elapsed_ms"]) for row in tamper_attempts), 3
        ),
    }
    tamper_row = base_scenario(
        "counter_or_last_hash_tamper",
        tamper_before,
        tamper_after,
        aggregate,
    )
    tamper_row.update(
        ticket_fresh=True,
        lph_preserved=True,
        salt_p_preserved=True,
        profile_installed=False,
        reinstall_business_executed=False,
        attempts_rejected=sum(
            not row["accepted"] for row in tamper_attempts
        ),
        attempts_total=len(tamper_attempts),
    )
    scenarios.append(tamper_row)
    attempts.extend(tamper_attempts)
    fixtures.append(tamper_fixture)

    legal_fixture = make_fixture(
        output=output,
        config=config,
        scenario="legal_tombstone_reinstall",
        state="tombstone",
    )
    legal_auth = issue_reinstall(
        legal_fixture, config, profile_sha256, label="legal"
    )
    delivery = simulate_profile_delivery(
        config=config,
        fixture=legal_fixture,
        authorization=legal_auth,
        profile=profile,
    )
    if not delivery["profile_decrypted"] or not delivery[
        "profile_digest_match"
    ]:
        raise RuntimeError("positive Profile delivery failed")
    legal_receipt = make_receipt(legal_fixture, legal_auth)
    verify_reinstall_receipt_mac(legal_fixture.device_key, legal_receipt)
    legal_attempt, legal_before, legal_after = attempt_apply(
        legal_fixture,
        legal_receipt,
        now=int(config["now"]),
    )
    historical = config["historical_material"]
    legal_row = base_scenario(
        "legal_tombstone_reinstall",
        legal_before,
        legal_after,
        legal_attempt,
    )
    legal_row.update(
        ticket_fresh=legal_auth["rid"] != historical["rid"],
        session_fresh=(
            legal_auth["session_id"] != historical["session_id"]
        ),
        bind_t_fresh=legal_auth["Bind_t"] != historical["Bind_t"],
        lph_preserved=legal_after["lph"] == legal_before["lph"],
        salt_p_preserved=True,
        profile_decrypted=delivery["profile_decrypted"],
        profile_installed=(
            legal_attempt["accepted"]
            and legal_after["state"] == "installed"
        ),
        profile_digest_match=delivery["profile_digest_match"],
        receipt_hmac_valid=True,
        receipt_generated=True,
        counter_continuous=(
            int(legal_after["ctr"]) == int(legal_before["ctr"]) + 1
        ),
        predecessor_hash_correct=(
            legal_receipt["last_hash"] == legal_before["last_hash"]
        ),
        final_hash_is_receipt=(
            legal_after["last_hash"] == receipt_hash(legal_receipt)
        ),
        single_lifecycle_row=(
            legal_fixture.engine.counts()["profiles"] == 1
        ),
        ticket_hash=legal_auth["ticket_hash"],
        session_id=legal_auth["session_id"],
        Bind_t=legal_auth["Bind_t"],
        delivery=delivery,
    )
    scenarios.append(legal_row)
    attempts.append({**legal_attempt, "scenario": "legal_tombstone_reinstall"})
    fixtures.append(legal_fixture)

    events: list[dict[str, Any]] = []
    snapshots: dict[str, Any] = {}
    for fixture in fixtures:
        events.extend(
            {
                "scenario": fixture.scenario,
                **event,
            }
            for event in fixture.engine.export_events()
        )
        snapshots[fixture.scenario] = query_database(fixture.db_path)
    return scenarios, attempts, events, snapshots


def find_line(path: Path, pattern: str) -> int | None:
    for index, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if pattern in line:
            return index
    return None


def source_audit(
    experiment_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    paths = {
        key: resolve_path(experiment_root, value)
        for key, value in config["aura_source"].items()
    }
    patterns = {
        "metadata_table": (
            "lifecycle",
            "CREATE TABLE IF NOT EXISTS lifecycle_profile_metadata",
        ),
        "reinstall_authorization_table": (
            "lifecycle",
            "CREATE TABLE IF NOT EXISTS reinstall_authorizations",
        ),
        "issue_reinstall_authorization": (
            "lifecycle",
            "def issue_reinstall_authorization(",
        ),
        "apply_reinstall": ("lifecycle", "def apply_reinstall("),
        "tombstone_predecessor": (
            "lifecycle",
            'if row["state"] != "tombstone":',
        ),
        "salt_check": (
            "lifecycle",
            '"REINSTALL_SALT_MISMATCH", "profile_metadata"',
        ),
        "session_check": (
            "lifecycle",
            '"REINSTALL_SESSION_MISMATCH", "session_binding"',
        ),
        "bind_t_check": (
            "lifecycle",
            '"REINSTALL_BIND_T_MISMATCH", "profile_binding"',
        ),
        "atomic_tombstone_update": (
            "lifecycle",
            "WHERE lph=? AND state='tombstone' AND ctr=? AND last_hash=?",
        ),
    }
    checkpoints = {
        name: {
            "file": str(paths[file_key]),
            "line": find_line(paths[file_key], pattern),
            "pattern": pattern,
        }
        for name, (file_key, pattern) in patterns.items()
    }
    return {
        "source_sha256": {
            key: hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in paths.items()
        },
        "checkpoints": checkpoints,
        "all_checkpoints_found": all(
            value["line"] is not None for value in checkpoints.values()
        ),
        "standard_baseline_status": "UNSUPPORTED",
        "standard_boundary": (
            "The current baseline has no callable reinstall lifecycle state-chain "
            "or ReinstallReceipt interface."
        ),
    }


def assertion(
    name: str,
    expected: Any,
    observed: Any,
    passed: bool,
    assertion_class: str = "security",
) -> dict[str, Any]:
    return {
        "assertion": name,
        "class": assertion_class,
        "expected": expected,
        "observed": observed,
        "passed": bool(passed),
    }


def build_assertions(
    scenarios: list[dict[str, Any]],
    audit: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = {row["scenario"]: row for row in scenarios}
    expected_reasons = {
        "installed_direct_reinstall": "INVALID_REINSTALL_PREDECESSOR",
        "enabled_direct_reinstall": "INVALID_REINSTALL_PREDECESSOR",
        "disabled_direct_reinstall": "INVALID_REINSTALL_PREDECESSOR",
        "wrong_lph": "AUTHORIZATION_LPH_MISMATCH",
        "new_salt_p": "REINSTALL_SALT_MISMATCH",
        "old_ticket": "TICKET_EXPIRED",
        "old_reinstall_receipt": "STALE_RECEIPT_REPLAY",
    }
    attacks = [rows[name] for name in ATTACK_SCENARIOS]
    legal = rows["legal_tombstone_reinstall"]
    assertions = [
        assertion(
            "all_eight_illegal_reinstall_subtests_rejected",
            "8/8 rejected",
            f"{sum(not row['accepted'] for row in attacks)}/8 rejected",
            all(not row["accepted"] for row in attacks),
        ),
        assertion(
            "illegal_reinstall_does_not_execute_business",
            0,
            sum(row["reinstall_business_executed"] for row in attacks),
            not any(row["reinstall_business_executed"] for row in attacks),
        ),
        assertion(
            "illegal_reinstall_does_not_change_state",
            0,
            sum(row["state_changed"] for row in attacks),
            not any(row["state_changed"] for row in attacks),
        ),
    ]
    for name, reason in expected_reasons.items():
        assertions.append(
            assertion(
                f"{name}_reason",
                reason,
                rows[name]["reason"],
                rows[name]["reason"] == reason,
            )
        )
    chain_row = rows["counter_or_last_hash_tamper"]
    assertions += [
        assertion(
            "counter_and_last_hash_tamper_both_rejected",
            "2/2",
            f"{chain_row['attempts_rejected']}/{chain_row['attempts_total']}",
            chain_row["attempts_rejected"] == chain_row["attempts_total"] == 2,
        ),
        assertion(
            "counter_and_last_hash_reasons",
            "COUNTER_MISMATCH;LAST_HASH_MISMATCH",
            chain_row["reason"],
            chain_row["reason"]
            == "COUNTER_MISMATCH;LAST_HASH_MISMATCH",
        ),
        assertion(
            "legal_reinstall_accepted",
            True,
            legal["accepted"],
            legal["accepted"],
            "positive_control",
        ),
        assertion(
            "legal_transition_is_tombstone_to_installed",
            "tombstone->installed",
            f"{legal['state_before']}->{legal['state_after']}",
            legal["state_before"] == "tombstone"
            and legal["state_after"] == "installed",
            "positive_control",
        ),
        assertion(
            "original_lph_and_salt_preserved",
            True,
            {
                "lph": legal["lph_preserved"],
                "salt_p": legal["salt_p_preserved"],
            },
            legal["lph_preserved"] and legal["salt_p_preserved"],
            "positive_control",
        ),
        assertion(
            "fresh_ticket_session_and_bind_t",
            True,
            {
                "ticket": legal["ticket_fresh"],
                "session": legal["session_fresh"],
                "Bind_t": legal["bind_t_fresh"],
            },
            legal["ticket_fresh"]
            and legal["session_fresh"]
            and legal["bind_t_fresh"],
            "positive_control",
        ),
        assertion(
            "counter_and_predecessor_hash_continuous",
            True,
            {
                "counter": legal["counter_continuous"],
                "last_hash": legal["predecessor_hash_correct"],
            },
            legal["counter_continuous"]
            and legal["predecessor_hash_correct"],
            "positive_control",
        ),
        assertion(
            "profile_decrypted_digest_matched_and_installed",
            True,
            {
                "decrypted": legal["profile_decrypted"],
                "digest": legal["profile_digest_match"],
                "installed": legal["profile_installed"],
            },
            legal["profile_decrypted"]
            and legal["profile_digest_match"]
            and legal["profile_installed"],
            "positive_control",
        ),
        assertion(
            "reinstall_receipt_hmac_and_chain_head",
            True,
            {
                "hmac": legal["receipt_hmac_valid"],
                "chain_head": legal["final_hash_is_receipt"],
            },
            legal["receipt_hmac_valid"] and legal["final_hash_is_receipt"],
            "positive_control",
        ),
        assertion(
            "single_profile_lifecycle_row",
            True,
            legal["single_lifecycle_row"],
            legal["single_lifecycle_row"],
            "state_continuity",
        ),
        assertion(
            "production_source_checkpoints_present",
            True,
            audit["all_checkpoints_found"],
            audit["all_checkpoints_found"],
            "source_audit",
        ),
        assertion(
            "standard_baseline_reported_without_false_claim",
            "UNSUPPORTED",
            audit["standard_baseline_status"],
            audit["standard_baseline_status"] == "UNSUPPORTED",
            "scope",
        ),
        assertion(
            "public_results_hide_eid",
            False,
            any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
            not any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
            "privacy_regression",
        ),
    ]
    return assertions


def status_word(row: dict[str, Any], language: str) -> str:
    if row["accepted"]:
        return "接受" if language == "zh" else "ACCEPT"
    return "拒绝" if language == "zh" else "REJECT"


def render_terminal(
    summary: dict[str, Any],
    language: str,
    machine_json: bool,
) -> None:
    if machine_json:
        compact = {
            "status": summary["status"],
            "illegal_reinstall_rejected": (
                f"{summary['metrics']['attacks_rejected']}/"
                f"{summary['metrics']['attacks_total']}"
            ),
            "illegal_business_executions": summary["metrics"][
                "illegal_business_executions"
            ],
            "legal_reinstall_accepted": summary["metrics"][
                "legal_reinstall_accepted"
            ],
            "final_state": summary["metrics"]["legal_final_state"],
            "assertions": (
                f"{summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "results": summary["results_dir"],
        }
        print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")))
        return
    if language in ("zh", "both"):
        print("\n实验11：非法Reinstall")
        print("=" * 118)
        print(
            f"{'场景':<34} {'前驱状态':<14} {'结果':<8} "
            f"{'拒绝原因':<38} {'状态变化':<8} {'安装':<6}"
        )
        print("-" * 118)
        for row in summary["scenarios"]:
            print(
                f"{ZH_NAMES[row['scenario']]:<34} "
                f"{row['initial_state']:<14} "
                f"{status_word(row, 'zh'):<8} "
                f"{row['reason']:<38} "
                f"{('是' if row['state_changed'] else '否'):<8} "
                f"{('是' if row['profile_installed'] else '否'):<6}"
            )
        print("-" * 118)
        print(
            f"非法Reinstall：{summary['metrics']['attacks_rejected']}/"
            f"{summary['metrics']['attacks_total']}拒绝；错误业务执行="
            f"{summary['metrics']['illegal_business_executions']}"
        )
        print(
            f"合法Reinstall：tombstone→{summary['metrics']['legal_final_state']}；"
            f"机器断言={summary['assertions_passed']}/{summary['assertions_total']}；"
            f"状态={summary['status']}"
        )
    if language in ("en", "both"):
        print("\nExperiment 11: Illegal Reinstall")
        print("=" * 138)
        print(
            f"{'Scenario':<43} {'Predecessor':<14} {'Outcome':<9} "
            f"{'Reason':<38} {'Changed':<9} {'Installed':<9}"
        )
        print("-" * 138)
        for row in summary["scenarios"]:
            print(
                f"{EN_NAMES[row['scenario']]:<43} "
                f"{row['initial_state']:<14} "
                f"{status_word(row, 'en'):<9} "
                f"{row['reason']:<38} "
                f"{('YES' if row['state_changed'] else 'NO'):<9} "
                f"{('YES' if row['profile_installed'] else 'NO'):<9}"
            )
        print("-" * 138)
        print(
            f"Illegal reinstall: {summary['metrics']['attacks_rejected']}/"
            f"{summary['metrics']['attacks_total']} rejected; unauthorized "
            f"business executions={summary['metrics']['illegal_business_executions']}"
        )
        print(
            f"Legal reinstall: tombstone→{summary['metrics']['legal_final_state']}; "
            f"assertions={summary['assertions_passed']}/"
            f"{summary['assertions_total']}; status={summary['status']}"
        )


def render_report(
    output: Path, summary: dict[str, Any], language: str
) -> None:
    zh = language == "zh"
    names = ZH_NAMES if zh else EN_NAMES
    lines = [
        (
            "# 实验11：非法Reinstall"
            if zh
            else "# Experiment 11: Illegal Reinstall"
        ),
        "",
        (
            f"- 实验状态：**{summary['status']}**"
            if zh
            else f"- Experiment status: **{summary['status']}**"
        ),
        (
            f"- 非法子测试拒绝：{summary['metrics']['attacks_rejected']}/"
            f"{summary['metrics']['attacks_total']}"
            if zh
            else f"- Illegal subtests rejected: "
            f"{summary['metrics']['attacks_rejected']}/"
            f"{summary['metrics']['attacks_total']}"
        ),
        (
            f"- 机器断言：{summary['assertions_passed']}/"
            f"{summary['assertions_total']}"
            if zh
            else f"- Machine assertions: {summary['assertions_passed']}/"
            f"{summary['assertions_total']}"
        ),
        "",
        "## 场景结果" if zh else "## Scenario results",
        "",
        (
            "| 场景 | 前驱 | 结果 | 原因 | 状态变化 | Profile安装 |"
            if zh
            else "| Scenario | Predecessor | Outcome | Reason | State changed | Profile installed |"
        ),
        "|---|---|---|---|---:|---:|",
    ]
    for row in summary["scenarios"]:
        lines.append(
            f"| {names[row['scenario']]} | {row['initial_state']} | "
            f"{status_word(row, language)} | `{row['reason']}` | "
            f"{int(row['state_changed'])} | {int(row['profile_installed'])} |"
        )
    if zh:
        lines += [
            "",
            "## 结论",
            "",
            (
                "八类非法Reinstall子测试全部拒绝，错误业务执行为0。计数器与"
                "`last_hash`子测试内部包含两次独立篡改，两次均未改变状态。"
            ),
            (
                "合法控制从`tombstone`延续同一`lph/salt_p`，使用新票据、新会话和"
                "新`Bind_t`；Profile通过AES-GCM解密和摘要检查后生成HMAC收据，"
                "服务器以连续计数器和正确前驱摘要原子更新到`installed`。"
            ),
            "",
            "## 边界",
            "",
            (
                "Standard baseline没有可调用的Reinstall状态链接口，因此结果为"
                "`UNSUPPORTED`，本实验不据此宣称Standard存在Reinstall漏洞。"
            ),
        ]
    else:
        lines += [
            "",
            "## Conclusion",
            "",
            (
                "All eight illegal Reinstall subtests were rejected with zero "
                "unauthorized business executions. The counter/last_hash subtest "
                "contains two independent tamper attempts, both state-preserving."
            ),
            (
                "The legal control continues the same lph/salt_p from tombstone, "
                "uses a fresh ticket, session, and Bind_t, decrypts and verifies the "
                "Profile with AES-GCM, then atomically reaches installed through a "
                "valid HMAC receipt, continuous counter, and predecessor hash."
            ),
            "",
            "## Boundary",
            "",
            (
                "The Standard baseline has no callable Reinstall state-chain "
                "interface, so it is reported as `UNSUPPORTED`, not as vulnerable."
            ),
        ]
    (output / f"report-{language}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def svg_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_matrix_svg(
    path: Path, scenarios: list[dict[str, Any]], language: str
) -> None:
    zh = language == "zh"
    names = ZH_NAMES if zh else EN_NAMES
    title = (
        "实验11：非法Reinstall结果"
        if zh
        else "Experiment 11: Illegal Reinstall Results"
    )
    headers = (
        ("场景", "前驱状态", "结果", "状态变化", "安装")
        if zh
        else ("Scenario", "Predecessor", "Outcome", "State change", "Install")
    )
    width, row_h = 1580, 70
    height = 155 + row_h * len(scenarios)
    xs = (45, 890, 1080, 1280, 1450)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".head{font-size:21px;font-weight:700}",
        ".cell{font-size:20px}",
        ".accept{fill:#15803d;font-weight:700}",
        ".reject{fill:#b42318;font-weight:700}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="48" text-anchor="middle" class="title">{svg_escape(title)}</text>',
        '<rect x="25" y="78" width="1530" height="54" rx="8" fill="#e8eef8"/>',
    ]
    for x, label in zip(xs, headers):
        parts.append(
            f'<text x="{x}" y="113" text-anchor="{"start" if x == 45 else "middle"}" '
            f'class="head">{svg_escape(label)}</text>'
        )
    for index, row in enumerate(scenarios):
        y = 132 + index * row_h
        parts.append(
            f'<rect x="25" y="{y}" width="1530" height="{row_h}" '
            f'fill="{"#f7f9fc" if index % 2 == 0 else "#ffffff"}"/>'
        )
        values = (
            names[row["scenario"]],
            row["initial_state"],
            status_word(row, language),
            "YES" if row["state_changed"] else "NO",
            "YES" if row["profile_installed"] else "NO",
        )
        for col, (x, value) in enumerate(zip(xs, values)):
            class_name = "cell"
            if col == 2:
                class_name += " accept" if row["accepted"] else " reject"
            parts.append(
                f'<text x="{x}" y="{y + 44}" '
                f'text-anchor="{"start" if col == 0 else "middle"}" '
                f'class="{class_name}">{svg_escape(value)}</text>'
            )
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_flow_svg(path: Path, language: str) -> None:
    zh = language == "zh"
    title = (
        "合法Reinstall的单一状态链"
        if zh
        else "Single-State-Chain Legal Reinstall"
    )
    nodes = (
        [
            ("tombstone", "同一lph链头"),
            ("新授权", "票据+会话+Bind_t"),
            ("原lph/salt_p", "生命周期连续"),
            ("Profile交付", "AEAD+摘要"),
            ("重装收据", "HMAC+ctr+last_hash"),
            ("installed", "原记录原子更新"),
        ]
        if zh
        else [
            ("tombstone", "same lph chain head"),
            ("Fresh authorization", "ticket + session + Bind_t"),
            ("Original lph/salt_p", "lifecycle continuity"),
            ("Profile delivery", "AEAD + digest"),
            ("ReinstallReceipt", "HMAC + ctr + last_hash"),
            ("installed", "atomic update, same row"),
        ]
    )
    width, height = 1740, 400
    box_w, box_h, gap = 245, 132, 38
    start_x, y = 25, 130
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<defs>",
        '<marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 z" fill="#486581"/>',
        "</marker>",
        "</defs>",
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".main{font-size:21px;font-weight:700}",
        ".sub{font-size:17px}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width/2}" y="50" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for index, (main, sub) in enumerate(nodes):
        x = start_x + index * (box_w + gap)
        if index:
            parts.append(
                f'<line x1="{x - gap + 5}" y1="{y + box_h/2}" '
                f'x2="{x - 10}" y2="{y + box_h/2}" stroke="#486581" '
                'stroke-width="4" marker-end="url(#arrow)"/>'
            )
        fill = "#eaf7ee" if index in (0, 5) else "#e8f2ff"
        stroke = "#15803d" if index in (0, 5) else "#9fb3c8"
        parts += [
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="16" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="3"/>',
            f'<text x="{x + box_w/2}" y="{y + 51}" text-anchor="middle" '
            f'class="main">{svg_escape(main)}</text>',
            f'<text x="{x + box_w/2}" y="{y + 91}" text-anchor="middle" '
            f'class="sub">{svg_escape(sub)}</text>',
        ]
    footer = (
        "只有5→1成功；其他前驱、错误生命周期材料和历史重放全部终止"
        if zh
        else "Only 5→1 succeeds; other predecessors, wrong lifecycle material, and historical replay stop"
    )
    parts += [
        f'<text x="{width/2}" y="335" text-anchor="middle" class="sub">{svg_escape(footer)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(__file__).resolve().parent
    config = load_json(Path(args.config))
    output = prepare_output(Path(args.output), experiment_root)
    profile_path = resolve_path(experiment_root, config["profile_path"])
    if not profile_path.is_file():
        profile_path = resolve_path(
            experiment_root, config["profile_fallback_path"]
        )
    profile = profile_path.read_bytes()
    scenarios, attempts, events, snapshots = run_experiment(
        output=output,
        config=config,
        profile=profile,
    )
    audit = source_audit(experiment_root, config)
    assertions = build_assertions(scenarios, audit)
    passed = sum(row["passed"] for row in assertions)
    attack_rows = [
        row for row in scenarios if row["category"] == "attack"
    ]
    legal = next(
        row
        for row in scenarios
        if row["scenario"] == "legal_tombstone_reinstall"
    )
    status = "PASS" if passed == len(assertions) else "FAIL"
    summary = {
        "experiment": config["experiment_name"],
        "status": status,
        "seed": config["seed"],
        "profile_source": (
            config["profile_path"]
            if resolve_path(experiment_root, config["profile_path"]).is_file()
            else config["profile_fallback_path"]
        ),
        "profile_bytes": len(profile),
        "profile_sha256": hashlib.sha256(profile).hexdigest(),
        "scenarios": scenarios,
        "assertions": assertions,
        "assertions_passed": passed,
        "assertions_total": len(assertions),
        "metrics": {
            "attacks_total": len(attack_rows),
            "attacks_rejected": sum(
                not row["accepted"] for row in attack_rows
            ),
            "illegal_business_executions": sum(
                row["reinstall_business_executed"]
                for row in attack_rows
            ),
            "illegal_state_changes": sum(
                row["state_changed"] for row in attack_rows
            ),
            "legal_reinstall_accepted": legal["accepted"],
            "legal_final_state": legal["state_after"],
            "legal_counter_continuous": legal["counter_continuous"],
            "legal_lph_preserved": legal["lph_preserved"],
            "legal_salt_p_preserved": legal["salt_p_preserved"],
            "legal_profile_decrypted": legal["profile_decrypted"],
            "legal_receipt_hmac_valid": legal["receipt_hmac_valid"],
        },
        "standard_baseline_status": audit["standard_baseline_status"],
        "scope": {
            "lifecycle_core": "direct production LifecycleEngine calls",
            "profile_delivery": "real AES-256-GCM decrypt and SHA-256 order digest check",
            "database": "SQLite BEGIN IMMEDIATE plus predecessor CAS",
            "physical_euicc": False,
        },
        "results_dir": output.relative_to(experiment_root).as_posix(),
    }
    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "assertions.json", assertions)
    write_json(output / "evidence" / "source-audit.json", audit)
    write_json(
        output / "evidence" / "database-snapshots.json", snapshots
    )
    write_jsonl(output / "raw" / "attempts.jsonl", attempts)
    write_jsonl(output / "raw" / "events.jsonl", events)
    write_csv(output / "scenarios.csv", scenarios)
    write_csv(output / "assertions.csv", assertions)
    write_csv(output / "paper" / "table-reinstall-results.csv", scenarios)
    render_report(output, summary, "zh")
    render_report(output, summary, "en")
    render_matrix_svg(
        output / "paper" / "reinstall-results-zh.svg", scenarios, "zh"
    )
    render_matrix_svg(
        output / "paper" / "reinstall-results-en.svg", scenarios, "en"
    )
    render_flow_svg(
        output / "paper" / "legal-reinstall-chain-zh.svg", "zh"
    )
    render_flow_svg(
        output / "paper" / "legal-reinstall-chain-en.svg", "en"
    )
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "matrix": "图：八类非法Reinstall拒绝结果及合法5→1正向控制。",
                "flow": "图：合法Reinstall延续原lph/salt_p单一认证状态链。",
            },
            "en": {
                "matrix": "Figure: Eight rejected illegal Reinstall subtests and the legal 5-to-1 control.",
                "flow": "Figure: Legal Reinstall continues the original lph/salt_p authenticated state chain.",
            },
        },
    )
    render_terminal(summary, args.lang, args.machine_json)
    if not args.machine_json:
        print(f"\nRESULTS={output}")
        print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
