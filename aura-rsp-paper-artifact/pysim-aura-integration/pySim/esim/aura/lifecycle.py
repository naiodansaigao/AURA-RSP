"""AURA-RSP v14 authenticated Profile lifecycle state chain.

The module is HTTP independent.  It implements the paper state machine,
operation-specific receipts, two-phase deletion, reinstall, atomic SQLite CAS,
and exact-replay idempotency.  Every operation receipt is authenticated with
the fresh ``K_mac`` derived by that operation's AURA session.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from .codec import b64e, canonical, sha256_hex
from .primitives import p256_sign, p256_verify


STATE_NOT_INSTALLED = 0
STATE_INSTALLED = 1
STATE_ENABLED = 2
STATE_DISABLED = 3
STATE_PENDING_DELETE = 4
STATE_TOMBSTONE = 5

STATE_NAMES = {
    STATE_NOT_INSTALLED: "not-installed",
    STATE_INSTALLED: "installed",
    STATE_ENABLED: "enabled",
    STATE_DISABLED: "disabled",
    STATE_PENDING_DELETE: "pending-delete",
    STATE_TOMBSTONE: "tombstone",
}

LEGAL_TRANSITIONS = {
    "enable": {
        (STATE_INSTALLED, STATE_ENABLED),
        (STATE_DISABLED, STATE_ENABLED),
    },
    "disable": {(STATE_ENABLED, STATE_DISABLED)},
    "delete": {
        (STATE_INSTALLED, STATE_PENDING_DELETE),
        (STATE_ENABLED, STATE_PENDING_DELETE),
        (STATE_DISABLED, STATE_PENDING_DELETE),
    },
    "commit-delete": {(STATE_PENDING_DELETE, STATE_TOMBSTONE)},
    "reinstall": {(STATE_TOMBSTONE, STATE_INSTALLED)},
}

STATE_RECEIPT_FIELDS = (
    "lph",
    "st_old",
    "st_new",
    "ctr_new",
    "last_hash_old",
    "rid_op",
)
COMMIT_RECEIPT_FIELDS = (
    "lph",
    "st_old",
    "st_new",
    "ctr_new",
    "last_hash_old",
    "rid_tomb",
    "R_prep",
)


class LifecycleError(RuntimeError):
    def __init__(self, code: str, stage: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.stage = stage
        self.detail = detail or code


def _required(value: dict[str, Any], names: tuple[str, ...], code: str) -> dict:
    missing = [name for name in names if name not in value]
    if missing:
        raise LifecycleError(code, "receipt_format", f"missing fields: {missing}")
    return {name: value[name] for name in names}


def _mac(key: bytes, domain: str, fields: dict[str, Any]) -> str:
    return b64e(
        hmac.new(
            key,
            canonical({"domain": domain, **fields}),
            hashlib.sha256,
        ).digest()
    )


def state_receipt_fields(receipt: dict[str, Any]) -> dict[str, Any]:
    return _required(receipt, STATE_RECEIPT_FIELDS, "MALFORMED_STATE_RECEIPT")


def create_state_receipt(
    k_mac: bytes,
    *,
    op: str,
    snapshot: dict[str, Any],
    st_new: int,
    rid_op: str,
) -> dict[str, Any]:
    fields = {
        "lph": snapshot["lph"],
        "st_old": int(snapshot["state"]),
        "st_new": int(st_new),
        "ctr_new": int(snapshot["ctr"]) + 1,
        "last_hash_old": snapshot["last_hash"],
        "rid_op": rid_op,
    }
    return {
        **fields,
        "tag_op": _mac(k_mac, f"AURA-RSP-v14/{op}", fields),
    }


def verify_state_receipt(
    k_mac: bytes,
    *,
    op: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    fields = state_receipt_fields(receipt)
    expected = _mac(k_mac, f"AURA-RSP-v14/{op}", fields)
    if not hmac.compare_digest(expected, str(receipt.get("tag_op", ""))):
        raise LifecycleError("INVALID_STATE_RECEIPT_MAC", "receipt_authentication")
    try:
        fields["st_old"] = int(fields["st_old"])
        fields["st_new"] = int(fields["st_new"])
        fields["ctr_new"] = int(fields["ctr_new"])
    except (TypeError, ValueError) as exc:
        raise LifecycleError("INVALID_STATE_RECEIPT_TYPE", "receipt_format") from exc
    return fields


def state_last_hash(receipt: dict[str, Any]) -> str:
    fields = state_receipt_fields(receipt)
    return sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/state",
                "last_hash_old": fields["last_hash_old"],
                "rid": fields["rid_op"],
                "lph": fields["lph"],
                "st_old": int(fields["st_old"]),
                "st_new": int(fields["st_new"]),
                "ctr_new": int(fields["ctr_new"]),
                "tag": receipt["tag_op"],
            }
        )
    )


def operation_rid(
    op: str,
    *,
    ctx_t: dict[str, Any],
    bind_t: str,
    ciphertext_hash: str | None = None,
) -> str:
    value = {
        "domain": f"AURA-RSP-v14/rid/{op}",
        "ctx_t_hash": sha256_hex(canonical(ctx_t)),
        "Bind_t_hash": sha256_hex(bind_t.encode("ascii")),
    }
    if ciphertext_hash is not None:
        value["ciphertext_hash"] = ciphertext_hash
    return sha256_hex(canonical(value))


def rprep_payload(
    *,
    transaction_id: str,
    ctx_t: dict[str, Any],
    rid_del: str,
    ctr_pending: int,
    last_hash_pending: str,
) -> dict[str, Any]:
    return {
        "domain": "AURA-RSP-v14/prep-delete",
        "transactionId": transaction_id,
        "ctx_t_hash": sha256_hex(canonical(ctx_t)),
        "rid_del": rid_del,
        "ctr_pending": int(ctr_pending),
        "last_hash_pending": last_hash_pending,
    }


def create_rprep(
    signing_key,
    *,
    transaction_id: str,
    ctx_t: dict[str, Any],
    rid_del: str,
    ctr_pending: int,
    last_hash_pending: str,
) -> dict[str, Any]:
    payload = rprep_payload(
        transaction_id=transaction_id,
        ctx_t=ctx_t,
        rid_del=rid_del,
        ctr_pending=ctr_pending,
        last_hash_pending=last_hash_pending,
    )
    return {
        "payload": payload,
        "signature": p256_sign(signing_key, payload),
    }


def verify_rprep(public_key, rprep: dict[str, Any]) -> dict[str, Any]:
    if set(rprep) != {"payload", "signature"}:
        raise LifecycleError("MALFORMED_RPREP", "rprep_format")
    payload = rprep["payload"]
    if not isinstance(payload, dict) or not p256_verify(
        public_key, payload, str(rprep["signature"])
    ):
        raise LifecycleError("INVALID_RPREP_SIGNATURE", "rprep_authentication")
    return payload


def commit_rid(*, ctx_t: dict[str, Any], rprep: dict[str, Any]) -> str:
    return sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/rid/commit-delete",
                "ctx_t_hash": sha256_hex(canonical(ctx_t)),
                "R_prep_hash": sha256_hex(canonical(rprep)),
            }
        )
    )


def commit_receipt_fields(receipt: dict[str, Any]) -> dict[str, Any]:
    return _required(receipt, COMMIT_RECEIPT_FIELDS, "MALFORMED_COMMIT_RECEIPT")


def create_commit_receipt(
    k_mac: bytes,
    *,
    snapshot: dict[str, Any],
    ctx_t: dict[str, Any],
    rprep: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "lph": snapshot["lph"],
        "st_old": STATE_PENDING_DELETE,
        "st_new": STATE_TOMBSTONE,
        "ctr_new": int(snapshot["ctr"]) + 1,
        "last_hash_old": snapshot["last_hash"],
        "rid_tomb": commit_rid(ctx_t=ctx_t, rprep=rprep),
        "R_prep": rprep,
    }
    mac_fields = {
        **{key: fields[key] for key in COMMIT_RECEIPT_FIELDS if key != "R_prep"},
        "R_prep_hash": sha256_hex(canonical(rprep)),
    }
    return {
        **fields,
        "tag_tomb": _mac(k_mac, "AURA-RSP-v14/commit-delete", mac_fields),
    }


def verify_commit_receipt(
    k_mac: bytes,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    fields = commit_receipt_fields(receipt)
    try:
        fields["st_old"] = int(fields["st_old"])
        fields["st_new"] = int(fields["st_new"])
        fields["ctr_new"] = int(fields["ctr_new"])
    except (TypeError, ValueError) as exc:
        raise LifecycleError("INVALID_COMMIT_RECEIPT_TYPE", "receipt_format") from exc
    mac_fields = {
        **{key: fields[key] for key in COMMIT_RECEIPT_FIELDS if key != "R_prep"},
        "R_prep_hash": sha256_hex(canonical(fields["R_prep"])),
    }
    expected = _mac(k_mac, "AURA-RSP-v14/commit-delete", mac_fields)
    if not hmac.compare_digest(expected, str(receipt.get("tag_tomb", ""))):
        raise LifecycleError("INVALID_COMMIT_RECEIPT_MAC", "receipt_authentication")
    return fields


def commit_last_hash(receipt: dict[str, Any]) -> str:
    fields = commit_receipt_fields(receipt)
    return sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14/state",
                "last_hash_old": fields["last_hash_old"],
                "rid": fields["rid_tomb"],
                "lph": fields["lph"],
                "st_old": int(fields["st_old"]),
                "st_new": int(fields["st_new"]),
                "ctr_new": int(fields["ctr_new"]),
                "tag": receipt["tag_tomb"],
            }
        )
    )


class LifecycleRepository:
    """Persistent, transactionally updated AURA lifecycle records."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def _initialize(self) -> None:
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifecycle_profiles (
                    lph TEXT PRIMARY KEY,
                    pid_h TEXT NOT NULL,
                    salt_p TEXT NOT NULL,
                    state INTEGER NOT NULL,
                    ctr INTEGER NOT NULL,
                    last_hash TEXT NOT NULL,
                    install_receipt_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_receipts (
                    receipt_hash TEXT PRIMARY KEY,
                    lph TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    rid TEXT NOT NULL,
                    op TEXT NOT NULL,
                    new_last_hash TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_deletes (
                    lph TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL,
                    rid_del TEXT NOT NULL,
                    prepare_receipt_hash TEXT NOT NULL,
                    rprep_json TEXT NOT NULL,
                    ticket_expires_at INTEGER NOT NULL,
                    committed INTEGER NOT NULL DEFAULT 0,
                    commit_receipt_hash TEXT,
                    final_response_json TEXT
                );
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    lph TEXT,
                    transaction_id TEXT,
                    outcome TEXT NOT NULL,
                    reason TEXT,
                    detail_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
            )

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "lph": row["lph"],
            "pid_h": row["pid_h"],
            "salt_p": row["salt_p"],
            "state": int(row["state"]),
            "state_name": STATE_NAMES[int(row["state"])],
            "ctr": int(row["ctr"]),
            "last_hash": row["last_hash"],
        }

    def snapshot(self, lph: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
            ).fetchone()
        if row is None:
            raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
        return self._snapshot(row)

    def initialize_install(
        self,
        *,
        lph: str,
        pid_h: str,
        salt_p: str,
        receipt: dict[str, Any],
        last_hash: str,
    ) -> dict[str, Any]:
        receipt_json = canonical(receipt).decode("ascii")
        now = int(time.time())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["pid_h"] == pid_h
                    and existing["salt_p"] == salt_p
                    and existing["install_receipt_json"] == receipt_json
                ):
                    db.commit()
                    result = self._snapshot(existing)
                    result["idempotent"] = True
                    return result
                raise LifecycleError("INSTALL_STATE_CONFLICT", "install_state")
            db.execute(
                """
                INSERT INTO lifecycle_profiles(
                    lph,pid_h,salt_p,state,ctr,last_hash,
                    install_receipt_json,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    lph,
                    pid_h,
                    salt_p,
                    STATE_INSTALLED,
                    1,
                    last_hash,
                    receipt_json,
                    now,
                ),
            )
            db.commit()
        result = self.snapshot(lph)
        result["idempotent"] = False
        return result

    @staticmethod
    def _validate_predecessor(row: sqlite3.Row, fields: dict[str, Any]) -> None:
        if int(fields["st_old"]) != int(row["state"]):
            raise LifecycleError("STATE_PREDECESSOR_MISMATCH", "state_predecessor")
        if int(fields["ctr_new"]) != int(row["ctr"]) + 1:
            raise LifecycleError("COUNTER_MISMATCH", "counter")
        if fields["last_hash_old"] != row["last_hash"]:
            raise LifecycleError("LAST_HASH_MISMATCH", "last_hash")

    @staticmethod
    def _check_transition(op: str, st_old: int, st_new: int) -> None:
        if (st_old, st_new) not in LEGAL_TRANSITIONS.get(op, set()):
            raise LifecycleError("INVALID_STATE_TRANSITION", "state_transition")

    @staticmethod
    def _cached(
        db: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        receipt_hash: str,
    ) -> dict[str, Any] | None:
        prior = db.execute(
            """
            SELECT new_last_hash,response_json
            FROM lifecycle_receipts WHERE receipt_hash=?
            """,
            (receipt_hash,),
        ).fetchone()
        if prior is None:
            return None
        if row["last_hash"] != prior["new_last_hash"]:
            raise LifecycleError("STALE_RECEIPT_REPLAY", "replay_detection")
        response = json.loads(prior["response_json"])
        response["idempotent"] = True
        return response

    def _insert_receipt(
        self,
        db: sqlite3.Connection,
        *,
        receipt_hash: str,
        lph: str,
        transaction_id: str,
        rid: str,
        op: str,
        new_last_hash: str,
        receipt: dict[str, Any],
        response: dict[str, Any],
        now: int,
    ) -> None:
        db.execute(
            """
            INSERT INTO lifecycle_receipts(
                receipt_hash,lph,transaction_id,rid,op,new_last_hash,
                receipt_json,response_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_hash,
                lph,
                transaction_id,
                rid,
                op,
                new_last_hash,
                canonical(receipt).decode("ascii"),
                json.dumps(response, sort_keys=True),
                now,
            ),
        )

    def apply_state(
        self,
        *,
        transaction_id: str,
        op: str,
        pid_h: str,
        salt_p: str,
        k_mac: bytes,
        receipt: dict[str, Any],
        fault_at: str | None = None,
    ) -> dict[str, Any]:
        fields = verify_state_receipt(k_mac, op=op, receipt=receipt)
        lph = str(fields["lph"])
        receipt_hash = sha256_hex(canonical(receipt))
        new_last_hash = state_last_hash(receipt)
        now = int(time.time())
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                cached = self._cached(db, row=row, receipt_hash=receipt_hash)
                if cached is not None:
                    db.commit()
                    return cached
                if row["pid_h"] != pid_h or row["salt_p"] != salt_p:
                    raise LifecycleError("PROFILE_CONTEXT_MISMATCH", "profile_context")
                self._check_transition(op, fields["st_old"], fields["st_new"])
                self._validate_predecessor(row, fields)
                if fault_at == "before_update":
                    raise RuntimeError("FAULT_BEFORE_ATOMIC_UPDATE")
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state=?,ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state=? AND ctr=? AND last_hash=?
                    """,
                    (
                        fields["st_new"],
                        fields["ctr_new"],
                        new_last_hash,
                        now,
                        lph,
                        int(row["state"]),
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError("ATOMIC_CAS_CONFLICT", "atomic_update")
                response = {
                    "status": "accepted",
                    "idempotent": False,
                    "transactionId": transaction_id,
                    "lph": lph,
                    "state": fields["st_new"],
                    "stateName": STATE_NAMES[fields["st_new"]],
                    "ctr": fields["ctr_new"],
                    "last_hash": new_last_hash,
                }
                self._insert_receipt(
                    db,
                    receipt_hash=receipt_hash,
                    lph=lph,
                    transaction_id=transaction_id,
                    rid=str(fields["rid_op"]),
                    op=op,
                    new_last_hash=new_last_hash,
                    receipt=receipt,
                    response=response,
                    now=now,
                )
                if fault_at == "after_update_before_commit":
                    raise RuntimeError("FAULT_AFTER_UPDATE_BEFORE_COMMIT")
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        if fault_at == "after_commit":
            raise RuntimeError("FAULT_AFTER_ATOMIC_COMMIT")
        return response

    def prepare_delete(
        self,
        *,
        transaction_id: str,
        pid_h: str,
        salt_p: str,
        ticket_expires_at: int,
        ctx_t: dict[str, Any],
        k_mac: bytes,
        signing_key,
        receipt: dict[str, Any],
        fault_at: str | None = None,
    ) -> dict[str, Any]:
        fields = verify_state_receipt(k_mac, op="delete", receipt=receipt)
        lph = str(fields["lph"])
        receipt_hash = sha256_hex(canonical(receipt))
        new_last_hash = state_last_hash(receipt)
        now = int(time.time())
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                pending = db.execute(
                    "SELECT * FROM pending_deletes WHERE lph=?", (lph,)
                ).fetchone()
                if pending is not None:
                    if (
                        int(pending["committed"]) == 0
                        and pending["transaction_id"] == transaction_id
                        and pending["prepare_receipt_hash"] == receipt_hash
                        and int(row["state"]) == STATE_PENDING_DELETE
                        and row["last_hash"] == new_last_hash
                    ):
                        db.commit()
                        return {
                            "status": "pending-delete",
                            "idempotent": True,
                            "R_prep": json.loads(pending["rprep_json"]),
                        }
                    if (
                        pending["prepare_receipt_hash"] == receipt_hash
                        and (
                            int(pending["committed"]) == 1
                            or int(row["state"]) != STATE_PENDING_DELETE
                            or row["last_hash"] != new_last_hash
                        )
                    ):
                        raise LifecycleError(
                            "STALE_RECEIPT_REPLAY", "replay_detection"
                        )
                    raise LifecycleError("PENDING_DELETE_CONFLICT", "pending_delete")
                if row["pid_h"] != pid_h or row["salt_p"] != salt_p:
                    raise LifecycleError("PROFILE_CONTEXT_MISMATCH", "profile_context")
                self._check_transition("delete", fields["st_old"], fields["st_new"])
                self._validate_predecessor(row, fields)
                rprep = create_rprep(
                    signing_key,
                    transaction_id=transaction_id,
                    ctx_t=ctx_t,
                    rid_del=str(fields["rid_op"]),
                    ctr_pending=fields["ctr_new"],
                    last_hash_pending=new_last_hash,
                )
                if fault_at == "before_update":
                    raise RuntimeError("FAULT_BEFORE_ATOMIC_UPDATE")
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state=?,ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state=? AND ctr=? AND last_hash=?
                    """,
                    (
                        STATE_PENDING_DELETE,
                        fields["ctr_new"],
                        new_last_hash,
                        now,
                        lph,
                        int(row["state"]),
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError("ATOMIC_CAS_CONFLICT", "atomic_update")
                response = {
                    "status": "pending-delete",
                    "idempotent": False,
                    "R_prep": rprep,
                }
                self._insert_receipt(
                    db,
                    receipt_hash=receipt_hash,
                    lph=lph,
                    transaction_id=transaction_id,
                    rid=str(fields["rid_op"]),
                    op="delete",
                    new_last_hash=new_last_hash,
                    receipt=receipt,
                    response=response,
                    now=now,
                )
                db.execute(
                    """
                    INSERT INTO pending_deletes(
                        lph,transaction_id,rid_del,prepare_receipt_hash,
                        rprep_json,ticket_expires_at,committed
                    ) VALUES(?,?,?,?,?,?,0)
                    """,
                    (
                        lph,
                        transaction_id,
                        str(fields["rid_op"]),
                        receipt_hash,
                        json.dumps(rprep, sort_keys=True),
                        int(ticket_expires_at),
                    ),
                )
                if fault_at == "after_update_before_commit":
                    raise RuntimeError("FAULT_AFTER_UPDATE_BEFORE_COMMIT")
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        if fault_at == "after_commit":
            raise RuntimeError("FAULT_AFTER_ATOMIC_COMMIT")
        return response

    def commit_delete(
        self,
        *,
        transaction_id: str,
        ctx_t: dict[str, Any],
        k_mac: bytes,
        rprep_public_key,
        receipt: dict[str, Any],
        fault_at: str | None = None,
    ) -> dict[str, Any]:
        fields = verify_commit_receipt(k_mac, receipt)
        lph = str(fields["lph"])
        rprep_payload_value = verify_rprep(rprep_public_key, fields["R_prep"])
        expected_rid = commit_rid(ctx_t=ctx_t, rprep=fields["R_prep"])
        if fields["rid_tomb"] != expected_rid:
            raise LifecycleError("COMMIT_RID_MISMATCH", "commit_context")
        receipt_hash = sha256_hex(canonical(receipt))
        new_last_hash = commit_last_hash(receipt)
        now = int(time.time())
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                pending = db.execute(
                    "SELECT * FROM pending_deletes WHERE lph=?", (lph,)
                ).fetchone()
                if pending is None:
                    raise LifecycleError("PENDING_DELETE_NOT_FOUND", "pending_delete")
                if (
                    int(pending["committed"]) == 1
                    and pending["commit_receipt_hash"] == receipt_hash
                    and int(row["state"]) == STATE_TOMBSTONE
                    and row["last_hash"] == new_last_hash
                ):
                    response = json.loads(pending["final_response_json"])
                    response["idempotent"] = True
                    db.commit()
                    return response
                stored_rprep = json.loads(pending["rprep_json"])
                if pending["transaction_id"] != transaction_id:
                    raise LifecycleError(
                        "PENDING_DELETE_TRANSACTION_MISMATCH", "pending_delete"
                    )
                if canonical(stored_rprep) != canonical(fields["R_prep"]):
                    raise LifecycleError("RPREP_MISMATCH", "pending_delete")
                if (
                    rprep_payload_value["transactionId"] != transaction_id
                    or rprep_payload_value["ctx_t_hash"]
                    != sha256_hex(canonical(ctx_t))
                    or rprep_payload_value["rid_del"] != pending["rid_del"]
                ):
                    raise LifecycleError("RPREP_CONTEXT_MISMATCH", "pending_delete")
                self._check_transition(
                    "commit-delete", fields["st_old"], fields["st_new"]
                )
                self._validate_predecessor(row, fields)
                if fault_at == "before_update":
                    raise RuntimeError("FAULT_BEFORE_ATOMIC_UPDATE")
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state=?,ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state=? AND ctr=? AND last_hash=?
                    """,
                    (
                        STATE_TOMBSTONE,
                        fields["ctr_new"],
                        new_last_hash,
                        now,
                        lph,
                        STATE_PENDING_DELETE,
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError("ATOMIC_CAS_CONFLICT", "atomic_update")
                response = {
                    "status": "tombstone",
                    "idempotent": False,
                    "transactionId": transaction_id,
                    "lph": lph,
                    "state": STATE_TOMBSTONE,
                    "stateName": STATE_NAMES[STATE_TOMBSTONE],
                    "ctr": fields["ctr_new"],
                    "last_hash": new_last_hash,
                }
                self._insert_receipt(
                    db,
                    receipt_hash=receipt_hash,
                    lph=lph,
                    transaction_id=transaction_id,
                    rid=str(fields["rid_tomb"]),
                    op="commit-delete",
                    new_last_hash=new_last_hash,
                    receipt=receipt,
                    response=response,
                    now=now,
                )
                db.execute(
                    """
                    UPDATE pending_deletes
                    SET committed=1,commit_receipt_hash=?,final_response_json=?
                    WHERE lph=?
                    """,
                    (receipt_hash, json.dumps(response, sort_keys=True), lph),
                )
                if fault_at == "after_update_before_commit":
                    raise RuntimeError("FAULT_AFTER_UPDATE_BEFORE_COMMIT")
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        if fault_at == "after_commit":
            raise RuntimeError("FAULT_AFTER_ATOMIC_COMMIT")
        return response

    def events(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM lifecycle_events ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with closing(self._connect()) as db:
            return {
                "profiles": int(
                    db.execute("SELECT COUNT(*) FROM lifecycle_profiles").fetchone()[0]
                ),
                "receipts": int(
                    db.execute("SELECT COUNT(*) FROM lifecycle_receipts").fetchone()[0]
                ),
                "pending_deletes": int(
                    db.execute("SELECT COUNT(*) FROM pending_deletes").fetchone()[0]
                ),
            }
