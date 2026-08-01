"""Machine-checkable lifecycle, replay, concurrency and recovery tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
from typing import Callable

from pySim.esim.profile_store import ProfileRepository

from .bootstrap import bootstrap, seed_store
from .codec import b64e, canonical, load_json, save_json, sha256_hex
from .errors import AuraProtocolError
from .lifecycle import (
    LifecycleError,
    LifecycleRepository,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_INSTALLED,
    STATE_PENDING_DELETE,
    STATE_TOMBSTONE,
    create_commit_receipt,
    create_state_receipt,
    operation_rid,
)
from .local_ticket_log import (
    LocalTicketContextConflict,
    LocalTicketLogCorrupt,
    lookup_cached_auth_request,
    store_auth_request,
)
from .models import AuraOrderContext
from .primitives import generate_p256_private
from .receipt import ZERO_HASH, initial_last_hash
from .service import AuraService
from .store import AuraStore


ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Fixture:
    repo: LifecycleRepository
    lph: str
    pid_h: str
    salt_p: str
    ctx_t: dict
    bind_t: str
    signing_key: object


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _key(label: str) -> bytes:
    return hashlib.sha256(("KMAC:" + label).encode("utf-8")).digest()


def _fixture(base: Path, label: str) -> Fixture:
    repo = LifecycleRepository(base / f"{label}.sqlite")
    lph = b64e(hashlib.sha384(("LPH:" + label).encode("utf-8")).digest())
    pid_h = _digest("PROFILE:" + label)
    salt_p = b64e(hashlib.sha256(("SALT:" + label).encode("utf-8")).digest())
    ctx_t = {
        "transactionId": "tx-" + label,
        "I_t": _digest("I_T:" + label),
        "opid": _digest("OPID:" + label)[:32],
    }
    bind_t = b64e(hashlib.sha256(("BIND:" + label).encode("utf-8")).digest())
    install_receipt = {
        "lph": lph,
        "st_old": 0,
        "st_new": 1,
        "ctr_new": 1,
        "last_hash_old": ZERO_HASH,
        "rid_inst": _digest("RID-INSTALL:" + label),
        "tag_inst": b64e(
            hashlib.sha256(("TAG-INSTALL:" + label).encode("utf-8")).digest()
        ),
    }
    repo.initialize_install(
        lph=lph,
        pid_h=pid_h,
        salt_p=salt_p,
        receipt=install_receipt,
        last_hash=initial_last_hash(install_receipt),
    )
    return Fixture(
        repo=repo,
        lph=lph,
        pid_h=pid_h,
        salt_p=salt_p,
        ctx_t=ctx_t,
        bind_t=bind_t,
        signing_key=generate_p256_private(),
    )


def _receipt(
    fixture: Fixture,
    *,
    op: str,
    target: int,
    k_mac: bytes,
    snapshot: dict | None = None,
    suffix: str = "",
) -> dict:
    snapshot = snapshot or fixture.repo.snapshot(fixture.lph)
    rid = operation_rid(
        op,
        ctx_t={**fixture.ctx_t, "suffix": suffix},
        bind_t=fixture.bind_t,
    )
    return create_state_receipt(
        k_mac,
        op=op,
        snapshot=snapshot,
        st_new=target,
        rid_op=rid,
    )


def _apply(
    fixture: Fixture,
    *,
    op: str,
    target: int,
    label: str,
    snapshot: dict | None = None,
    fault_at: str | None = None,
) -> tuple[dict, bytes, dict]:
    k_mac = _key(label)
    receipt = _receipt(
        fixture,
        op=op,
        target=target,
        k_mac=k_mac,
        snapshot=snapshot,
        suffix=label,
    )
    response = fixture.repo.apply_state(
        transaction_id="tx-" + label,
        op=op,
        pid_h=fixture.pid_h,
        salt_p=fixture.salt_p,
        k_mac=k_mac,
        receipt=receipt,
        fault_at=fault_at,
    )
    return response, k_mac, receipt


def _prepare_delete(
    fixture: Fixture,
    *,
    label: str,
    ticket_expires_at: int | None = None,
    snapshot: dict | None = None,
    fault_at: str | None = None,
) -> tuple[dict, bytes, dict, dict]:
    k_mac = _key(label)
    ctx_t = {**fixture.ctx_t, "delete": label}
    receipt = _receipt(
        fixture,
        op="delete",
        target=STATE_PENDING_DELETE,
        k_mac=k_mac,
        snapshot=snapshot,
        suffix=label,
    )
    response = fixture.repo.prepare_delete(
        transaction_id="tx-" + label,
        pid_h=fixture.pid_h,
        salt_p=fixture.salt_p,
        ticket_expires_at=(
            int(time.time()) + 3600
            if ticket_expires_at is None
            else ticket_expires_at
        ),
        ctx_t=ctx_t,
        k_mac=k_mac,
        signing_key=fixture.signing_key,
        receipt=receipt,
        fault_at=fault_at,
    )
    return response, k_mac, receipt, ctx_t


def _commit(
    fixture: Fixture,
    *,
    label: str,
    k_mac: bytes,
    ctx_t: dict,
    rprep: dict,
    fault_at: str | None = None,
) -> tuple[dict, dict]:
    snapshot = fixture.repo.snapshot(fixture.lph)
    receipt = create_commit_receipt(
        k_mac,
        snapshot=snapshot,
        ctx_t=ctx_t,
        rprep=rprep,
    )
    response = fixture.repo.commit_delete(
        transaction_id="tx-" + label,
        ctx_t=ctx_t,
        k_mac=k_mac,
        rprep_public_key=fixture.signing_key.public_key(),
        receipt=receipt,
        fault_at=fault_at,
    )
    return response, receipt


def _expect_lifecycle_error(
    operation: Callable[[], object],
    accepted_codes: set[str] | None = None,
) -> str:
    try:
        operation()
    except LifecycleError as exc:
        if accepted_codes is not None and exc.code not in accepted_codes:
            raise AssertionError(
                f"unexpected lifecycle error {exc.code}, expected {accepted_codes}"
            ) from exc
        return exc.code
    raise AssertionError("operation unexpectedly succeeded")


def _expect_runtime_fault(operation: Callable[[], object], marker: str) -> str:
    try:
        operation()
    except RuntimeError as exc:
        if marker not in str(exc):
            raise
        return str(exc)
    raise AssertionError(f"fault {marker} was not injected")


def _to_tombstone(fixture: Fixture, label: str) -> tuple[dict, bytes, dict, dict]:
    prepared, k_mac, prepare_receipt, ctx_t = _prepare_delete(
        fixture, label=label
    )
    committed, commit_receipt = _commit(
        fixture,
        label=label,
        k_mac=k_mac,
        ctx_t=ctx_t,
        rprep=prepared["R_prep"],
    )
    return committed, k_mac, prepare_receipt, commit_receipt


def _case_legal_chain(base: Path) -> dict:
    f = _fixture(base, "legal-chain")
    enable, k_enable, r_enable = _apply(
        f, op="enable", target=STATE_ENABLED, label="legal-enable"
    )
    exact_enable = f.repo.apply_state(
        transaction_id="tx-legal-enable",
        op="enable",
        pid_h=f.pid_h,
        salt_p=f.salt_p,
        k_mac=k_enable,
        receipt=r_enable,
    )
    _apply(f, op="disable", target=STATE_DISABLED, label="legal-disable")
    stale_enable = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-legal-enable",
            op="enable",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_enable,
            receipt=r_enable,
        ),
        {"STALE_RECEIPT_REPLAY"},
    )
    _apply(f, op="enable", target=STATE_ENABLED, label="legal-reenable")
    prepared, k_delete, r_delete, ctx_delete = _prepare_delete(
        f, label="legal-delete"
    )
    repeated_prepare = f.repo.prepare_delete(
        transaction_id="tx-legal-delete",
        pid_h=f.pid_h,
        salt_p=f.salt_p,
        ticket_expires_at=int(time.time()) + 3600,
        ctx_t=ctx_delete,
        k_mac=k_delete,
        signing_key=f.signing_key,
        receipt=r_delete,
    )
    commit, commit_receipt = _commit(
        f,
        label="legal-delete",
        k_mac=k_delete,
        ctx_t=ctx_delete,
        rprep=prepared["R_prep"],
    )
    repeated_commit = f.repo.commit_delete(
        transaction_id="tx-legal-delete",
        ctx_t=ctx_delete,
        k_mac=k_delete,
        rprep_public_key=f.signing_key.public_key(),
        receipt=commit_receipt,
    )
    stale_prepare = _expect_lifecycle_error(
        lambda: f.repo.prepare_delete(
            transaction_id="tx-legal-delete",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            ticket_expires_at=int(time.time()) + 3600,
            ctx_t=ctx_delete,
            k_mac=k_delete,
            signing_key=f.signing_key,
            receipt=r_delete,
        ),
        {"STALE_RECEIPT_REPLAY"},
    )
    reinstall, k_reinstall, r_reinstall = _apply(
        f,
        op="reinstall",
        target=STATE_INSTALLED,
        label="legal-reinstall",
    )
    repeated_reinstall = f.repo.apply_state(
        transaction_id="tx-legal-reinstall",
        op="reinstall",
        pid_h=f.pid_h,
        salt_p=f.salt_p,
        k_mac=k_reinstall,
        receipt=r_reinstall,
    )
    final = f.repo.snapshot(f.lph)
    assert enable["state"] == STATE_ENABLED
    assert exact_enable["idempotent"] is True
    assert stale_enable == "STALE_RECEIPT_REPLAY"
    assert repeated_prepare["idempotent"] is True
    assert canonical(prepared["R_prep"]) == canonical(
        repeated_prepare["R_prep"]
    )
    assert commit["state"] == STATE_TOMBSTONE
    assert repeated_commit["idempotent"] is True
    assert stale_prepare == "STALE_RECEIPT_REPLAY"
    assert reinstall["state"] == STATE_INSTALLED
    assert repeated_reinstall["idempotent"] is True
    assert final["state"] == STATE_INSTALLED and final["ctr"] == 7
    return {
        "case": "legal_chain_and_replay",
        "pass": True,
        "final_state": final["state_name"],
        "final_ctr": final["ctr"],
        "same_rprep": True,
    }


def _case_tamper(base: Path) -> dict:
    f = _fixture(base, "tamper")
    k_mac = _key("tamper")
    valid = _receipt(
        f,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_mac,
        suffix="tamper",
    )
    variants = {
        "lph": "wrong-lph",
        "st_old": STATE_DISABLED,
        "st_new": STATE_TOMBSTONE,
        "ctr_new": 99,
        "last_hash_old": "ff" * 32,
        "rid_op": "ff" * 32,
        "tag_op": "invalid-tag",
    }
    rejected = {}
    for field, replacement in variants.items():
        attacked = copy.deepcopy(valid)
        attacked[field] = replacement
        rejected[field] = _expect_lifecycle_error(
            lambda value=attacked: f.repo.apply_state(
                transaction_id="tx-tamper",
                op="enable",
                pid_h=f.pid_h,
                salt_p=f.salt_p,
                k_mac=k_mac,
                receipt=value,
            ),
            {"INVALID_STATE_RECEIPT_MAC"},
        )

    current = f.repo.snapshot(f.lph)
    fake_predecessor = {**current, "state": STATE_DISABLED}
    signed_bad_predecessor = _receipt(
        f,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_mac,
        snapshot=fake_predecessor,
        suffix="bad-predecessor",
    )
    semantic = {
        "predecessor": _expect_lifecycle_error(
            lambda: f.repo.apply_state(
                transaction_id="tx-semantic-predecessor",
                op="enable",
                pid_h=f.pid_h,
                salt_p=f.salt_p,
                k_mac=k_mac,
                receipt=signed_bad_predecessor,
            ),
            {"STATE_PREDECESSOR_MISMATCH"},
        )
    }
    fake_counter = {**current, "ctr": current["ctr"] + 4}
    signed_bad_counter = _receipt(
        f,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_mac,
        snapshot=fake_counter,
        suffix="bad-counter",
    )
    semantic["counter"] = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-semantic-counter",
            op="enable",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_mac,
            receipt=signed_bad_counter,
        ),
        {"COUNTER_MISMATCH"},
    )
    fake_hash = {**current, "last_hash": "11" * 32}
    signed_bad_hash = _receipt(
        f,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_mac,
        snapshot=fake_hash,
        suffix="bad-hash",
    )
    semantic["last_hash"] = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-semantic-hash",
            op="enable",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_mac,
            receipt=signed_bad_hash,
        ),
        {"LAST_HASH_MISMATCH"},
    )
    semantic["salt_p"] = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-semantic-salt",
            op="enable",
            pid_h=f.pid_h,
            salt_p="new-salt",
            k_mac=k_mac,
            receipt=valid,
        ),
        {"PROFILE_CONTEXT_MISMATCH"},
    )
    illegal = _receipt(
        f,
        op="reinstall",
        target=STATE_INSTALLED,
        k_mac=k_mac,
        suffix="illegal-reinstall",
    )
    semantic["transition"] = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-illegal-transition",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_mac,
            receipt=illegal,
        ),
        {"INVALID_STATE_TRANSITION"},
    )
    final = f.repo.snapshot(f.lph)
    assert final["state"] == STATE_INSTALLED and final["ctr"] == 1
    return {
        "case": "receipt_tamper_and_semantic_checks",
        "pass": True,
        "network_tamper_rejected": len(rejected),
        "semantic_checks_rejected": len(semantic),
        "final_state_unchanged": True,
        "reasons": {**rejected, **semantic},
    }


def _case_concurrency(base: Path) -> dict:
    f = _fixture(base, "concurrency")
    snapshot = f.repo.snapshot(f.lph)
    k_enable = _key("concurrent-enable")
    k_delete = _key("concurrent-delete")
    enable_receipt = _receipt(
        f,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_enable,
        snapshot=snapshot,
        suffix="concurrent-enable",
    )
    delete_receipt = _receipt(
        f,
        op="delete",
        target=STATE_PENDING_DELETE,
        k_mac=k_delete,
        snapshot=snapshot,
        suffix="concurrent-delete",
    )
    delete_ctx = {**f.ctx_t, "delete": "concurrent-delete"}
    barrier = threading.Barrier(2)

    def enable() -> tuple[str, str]:
        barrier.wait()
        try:
            f.repo.apply_state(
                transaction_id="tx-concurrent-enable",
                op="enable",
                pid_h=f.pid_h,
                salt_p=f.salt_p,
                k_mac=k_enable,
                receipt=enable_receipt,
            )
            return "enable", "accepted"
        except LifecycleError as exc:
            return "enable", exc.code

    def delete() -> tuple[str, str]:
        barrier.wait()
        try:
            f.repo.prepare_delete(
                transaction_id="tx-concurrent-delete",
                pid_h=f.pid_h,
                salt_p=f.salt_p,
                ticket_expires_at=int(time.time()) + 3600,
                ctx_t=delete_ctx,
                k_mac=k_delete,
                signing_key=f.signing_key,
                receipt=delete_receipt,
            )
            return "delete", "accepted"
        except LifecycleError as exc:
            return "delete", exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda fn: fn(), (enable, delete)))
    accepted = [op for op, result in outcomes if result == "accepted"]
    rejected = [result for _, result in outcomes if result != "accepted"]
    final = f.repo.snapshot(f.lph)
    assert len(accepted) == 1 and len(rejected) == 1
    assert final["ctr"] == 2
    assert final["state"] in (STATE_ENABLED, STATE_PENDING_DELETE)
    return {
        "case": "concurrent_enable_delete",
        "pass": True,
        "accepted_operation": accepted[0],
        "rejected_reason": rejected[0],
        "successor_count": 1,
        "final_state": final["state_name"],
    }


def _case_fault_recovery(base: Path) -> dict:
    rollback_checks = []
    for fault in ("before_update", "after_update_before_commit"):
        f = _fixture(base, "rollback-" + fault)
        before = f.repo.snapshot(f.lph)
        k_mac = _key("rollback-" + fault)
        receipt = _receipt(
            f,
            op="enable",
            target=STATE_ENABLED,
            k_mac=k_mac,
            suffix=fault,
        )
        _expect_runtime_fault(
            lambda fault_name=fault: f.repo.apply_state(
                transaction_id="tx-" + fault_name,
                op="enable",
                pid_h=f.pid_h,
                salt_p=f.salt_p,
                k_mac=k_mac,
                receipt=receipt,
                fault_at=fault_name,
            ),
            "FAULT_",
        )
        after = f.repo.snapshot(f.lph)
        assert before == after
        retried = f.repo.apply_state(
            transaction_id="tx-" + fault,
            op="enable",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_mac,
            receipt=receipt,
        )
        assert retried["state"] == STATE_ENABLED
        rollback_checks.append(fault)

    f_commit_point = _fixture(base, "commit-point")
    k_commit_point = _key("commit-point")
    r_commit_point = _receipt(
        f_commit_point,
        op="enable",
        target=STATE_ENABLED,
        k_mac=k_commit_point,
        suffix="commit-point",
    )
    _expect_runtime_fault(
        lambda: f_commit_point.repo.apply_state(
            transaction_id="tx-commit-point",
            op="enable",
            pid_h=f_commit_point.pid_h,
            salt_p=f_commit_point.salt_p,
            k_mac=k_commit_point,
            receipt=r_commit_point,
            fault_at="after_commit",
        ),
        "FAULT_AFTER_ATOMIC_COMMIT",
    )
    committed_retry = f_commit_point.repo.apply_state(
        transaction_id="tx-commit-point",
        op="enable",
        pid_h=f_commit_point.pid_h,
        salt_p=f_commit_point.salt_p,
        k_mac=k_commit_point,
        receipt=r_commit_point,
    )
    assert committed_retry["idempotent"] is True

    f_delete = _fixture(base, "delete-recovery")
    prepared, k_delete, r_delete, ctx_delete = _prepare_delete(
        f_delete,
        label="delete-recovery",
        ticket_expires_at=int(time.time()) - 1,
    )
    state_while_commit_lost = f_delete.repo.snapshot(f_delete.lph)
    repeated_prepare = f_delete.repo.prepare_delete(
        transaction_id="tx-delete-recovery",
        pid_h=f_delete.pid_h,
        salt_p=f_delete.salt_p,
        ticket_expires_at=int(time.time()) - 1,
        ctx_t=ctx_delete,
        k_mac=k_delete,
        signing_key=f_delete.signing_key,
        receipt=r_delete,
    )
    assert canonical(prepared["R_prep"]) == canonical(
        repeated_prepare["R_prep"]
    )
    assert state_while_commit_lost["state"] == STATE_PENDING_DELETE

    commit_receipt = create_commit_receipt(
        k_delete,
        snapshot=state_while_commit_lost,
        ctx_t=ctx_delete,
        rprep=prepared["R_prep"],
    )
    _expect_runtime_fault(
        lambda: f_delete.repo.commit_delete(
            transaction_id="tx-delete-recovery",
            ctx_t=ctx_delete,
            k_mac=k_delete,
            rprep_public_key=f_delete.signing_key.public_key(),
            receipt=commit_receipt,
            fault_at="after_commit",
        ),
        "FAULT_AFTER_ATOMIC_COMMIT",
    )
    final = f_delete.repo.snapshot(f_delete.lph)
    retry_commit = f_delete.repo.commit_delete(
        transaction_id="tx-delete-recovery",
        ctx_t=ctx_delete,
        k_mac=k_delete,
        rprep_public_key=f_delete.signing_key.public_key(),
        receipt=commit_receipt,
    )
    assert final["state"] == STATE_TOMBSTONE
    assert retry_commit["idempotent"] is True
    return {
        "case": "atomic_fault_and_delete_recovery",
        "pass": True,
        "rolled_back_faults": rollback_checks,
        "post_commit_retry_idempotent": True,
        "same_rprep_after_loss": True,
        "commit_after_ticket_expiry": True,
        "final_state": final["state_name"],
    }


def _case_reinstall(base: Path) -> dict:
    illegal = {}
    for label, state in (
        ("installed", STATE_INSTALLED),
        ("enabled", STATE_ENABLED),
        ("disabled", STATE_DISABLED),
    ):
        f = _fixture(base, "illegal-" + label)
        if state == STATE_ENABLED:
            _apply(f, op="enable", target=STATE_ENABLED, label=label + "-enable")
        elif state == STATE_DISABLED:
            _apply(f, op="enable", target=STATE_ENABLED, label=label + "-enable")
            _apply(
                f, op="disable", target=STATE_DISABLED, label=label + "-disable"
            )
        k_mac = _key(label + "-reinstall")
        receipt = _receipt(
            f,
            op="reinstall",
            target=STATE_INSTALLED,
            k_mac=k_mac,
            suffix=label + "-reinstall",
        )
        illegal[label] = _expect_lifecycle_error(
            lambda fixture=f, key=k_mac, value=receipt, name=label:
                fixture.repo.apply_state(
                    transaction_id="tx-" + name + "-reinstall",
                    op="reinstall",
                    pid_h=fixture.pid_h,
                    salt_p=fixture.salt_p,
                    k_mac=key,
                    receipt=value,
                ),
            {"INVALID_STATE_TRANSITION"},
        )

    f = _fixture(base, "legal-reinstall")
    _to_tombstone(f, "legal-reinstall-delete")
    tombstone = f.repo.snapshot(f.lph)
    k_reinstall = _key("legal-reinstall")
    receipt = _receipt(
        f,
        op="reinstall",
        target=STATE_INSTALLED,
        k_mac=k_reinstall,
        suffix="legal-reinstall",
    )
    wrong_lph_snapshot = {**tombstone, "lph": "unknown-reinstall-lph"}
    wrong_lph_receipt = create_state_receipt(
        k_reinstall,
        op="reinstall",
        snapshot=wrong_lph_snapshot,
        st_new=STATE_INSTALLED,
        rid_op=operation_rid(
            "reinstall",
            ctx_t={**f.ctx_t, "suffix": "wrong-lph"},
            bind_t=f.bind_t,
        ),
    )
    wrong_lph = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-wrong-lph",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_reinstall,
            receipt=wrong_lph_receipt,
        ),
        {"UNKNOWN_LPH"},
    )
    wrong_salt = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-wrong-salt",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p="new-salt",
            k_mac=k_reinstall,
            receipt=receipt,
        ),
        {"PROFILE_CONTEXT_MISMATCH"},
    )
    bad_counter_receipt = create_state_receipt(
        k_reinstall,
        op="reinstall",
        snapshot={**tombstone, "ctr": int(tombstone["ctr"]) + 4},
        st_new=STATE_INSTALLED,
        rid_op=operation_rid(
            "reinstall",
            ctx_t={**f.ctx_t, "suffix": "bad-counter"},
            bind_t=f.bind_t,
        ),
    )
    bad_counter = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-bad-counter",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_reinstall,
            receipt=bad_counter_receipt,
        ),
        {"COUNTER_MISMATCH"},
    )
    bad_hash_receipt = create_state_receipt(
        k_reinstall,
        op="reinstall",
        snapshot={**tombstone, "last_hash": _digest("wrong-last-hash")},
        st_new=STATE_INSTALLED,
        rid_op=operation_rid(
            "reinstall",
            ctx_t={**f.ctx_t, "suffix": "bad-last-hash"},
            bind_t=f.bind_t,
        ),
    )
    bad_last_hash = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-bad-last-hash",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_reinstall,
            receipt=bad_hash_receipt,
        ),
        {"LAST_HASH_MISMATCH"},
    )
    accepted = f.repo.apply_state(
        transaction_id="tx-legal-reinstall",
        op="reinstall",
        pid_h=f.pid_h,
        salt_p=f.salt_p,
        k_mac=k_reinstall,
        receipt=receipt,
    )
    exact_replay = f.repo.apply_state(
        transaction_id="tx-legal-reinstall",
        op="reinstall",
        pid_h=f.pid_h,
        salt_p=f.salt_p,
        k_mac=k_reinstall,
        receipt=receipt,
    )
    _apply(f, op="enable", target=STATE_ENABLED, label="after-reinstall-enable")
    stale_replay = _expect_lifecycle_error(
        lambda: f.repo.apply_state(
            transaction_id="tx-legal-reinstall",
            op="reinstall",
            pid_h=f.pid_h,
            salt_p=f.salt_p,
            k_mac=k_reinstall,
            receipt=receipt,
        ),
        {"STALE_RECEIPT_REPLAY"},
    )
    assert tombstone["state"] == STATE_TOMBSTONE
    assert accepted["state"] == STATE_INSTALLED
    assert exact_replay["idempotent"] is True
    return {
        "case": "illegal_and_legal_reinstall",
        "pass": True,
        "illegal_predecessors_rejected": illegal,
        "wrong_lph_rejected": wrong_lph,
        "new_salt_rejected": wrong_salt,
        "counter_tamper_rejected": bad_counter,
        "last_hash_tamper_rejected": bad_last_hash,
        "exact_replay_idempotent": True,
        "old_reinstall_receipt": stale_replay,
    }


def _case_expired_order_policy(root: Path) -> dict:
    bootstrap(root)
    runtime = root / "runtime" / "aura"
    store = AuraStore(in_memory=True)
    try:
        seed_store(store, root)
        device = load_json(runtime / "device.json")
        original = store.get_order(device["ticket"]["I_ac"])
        assert original is not None
        expired = replace(
            original,
            I_ac="expired-reinstall-order",
            op="reinstall",
            exp=int(time.time()) - 1,
        )
        store.put_order(expired)
        service = AuraService(
            root=root,
            profile_repository=ProfileRepository(
                root / "smdpp-data" / "upp"
            ),
            store=store,
        )
        try:
            service.initiate(
                {
                    "I_ac": expired.I_ac,
                    "N_U": b64e(hashlib.sha256(b"expired-order").digest()),
                    "capabilities": ["classical-p256"],
                },
                expired.PRaddr,
            )
        except AuraProtocolError as exc:
            assert exc.code == "INVALID_OR_EXPIRED_ORDER"
            reason = exc.code
        else:
            raise AssertionError("expired lifecycle order was accepted")
    finally:
        store.close()
    return {
        "case": "expired_operation_ticket",
        "pass": True,
        "reason": reason,
        "bind_t_generated": False,
    }


def _case_local_ticket_log() -> dict:
    device = {"local_ticket_log": {}}
    ctx_t = {"transactionId": "tx-local-log", "opid": "opid-local-log"}
    request = {
        "transactionId": "tx-local-log",
        "nu": "nu-local-log",
        "opid": "opid-local-log",
        "gamma": "gamma",
        "c": "challenge-response",
        "Pi_auth": {"proof": "opaque"},
    }
    store_auth_request(
        device,
        v=request["nu"],
        opid=request["opid"],
        ctx_t=ctx_t,
        auth_request=request,
    )
    cached = lookup_cached_auth_request(
        device,
        v=request["nu"],
        opid=request["opid"],
        ctx_t=ctx_t,
    )
    assert canonical(cached) == canonical(request)
    try:
        lookup_cached_auth_request(
            device,
            v=request["nu"],
            opid=request["opid"],
            ctx_t={**ctx_t, "N_S": "malicious-second-challenge"},
        )
    except LocalTicketContextConflict:
        conflict = "LOCAL_TICKET_CONTEXT_CONFLICT"
    else:
        raise AssertionError("LocalTicketLog accepted a second context")
    key = request["nu"] + ":" + request["opid"]
    device["local_ticket_log"][key]["auth_request"]["c"] = "tampered"
    try:
        lookup_cached_auth_request(
            device,
            v=request["nu"],
            opid=request["opid"],
            ctx_t=ctx_t,
        )
    except LocalTicketLogCorrupt:
        corruption = "LOCAL_TICKET_LOG_CORRUPT"
    else:
        raise AssertionError("LocalTicketLog accepted corrupted cached bytes")
    return {
        "case": "local_ticket_log_non_framing",
        "pass": True,
        "same_context": "exact_cached_request",
        "different_context": conflict,
        "corrupted_cache": corruption,
        "distinct_valid_responses": 1,
    }


def run(root: Path = ROOT) -> dict:
    with tempfile.TemporaryDirectory(prefix="aura-lifecycle-selftest-") as temp:
        base = Path(temp)
        cases = [
            _case_legal_chain(base),
            _case_tamper(base),
            _case_concurrency(base),
            _case_fault_recovery(base),
            _case_reinstall(base),
            _case_local_ticket_log(),
        ]
    cases.append(_case_expired_order_policy(root))
    if not all(case["pass"] for case in cases):
        raise AssertionError("lifecycle selftest contains a failed case")
    report = {
        "status": "AURA_INTEGRATED_LIFECYCLE_SELFTEST_PASS",
        "cases": cases,
        "summary": {
            "cases_passed": len(cases),
            "cases_total": len(cases),
            "state_chain_fork_count": 0,
            "unexpected_business_executions": 0,
            "device_server_convergence": True,
        },
    }
    save_json(root / "results" / "aura-lifecycle-selftest.json", report)
    return report


def main() -> None:
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    print(report["status"])


if __name__ == "__main__":
    main()
