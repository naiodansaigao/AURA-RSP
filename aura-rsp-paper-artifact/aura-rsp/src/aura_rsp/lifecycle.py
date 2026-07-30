from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from .codec import b64d, b64e, canonical, sha256_hex
from .primitives import receipt_mac


STATE_OPS = {
    ("installed", "enabled"): "enable",
    ("enabled", "disabled"): "disable",
    ("disabled", "enabled"): "enable",
}


class LifecycleError(RuntimeError):
    def __init__(self, code: str, stage: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.stage = stage
        self.detail = detail or code


def receipt_fields(receipt: dict[str, Any]) -> dict[str, Any]:
    required = ("rid", "lph", "st_old", "st_new", "ctr", "last_hash")
    missing = [name for name in required if name not in receipt]
    if missing:
        raise LifecycleError(
            "MALFORMED_RECEIPT", "receipt_format", f"missing fields: {missing}"
        )
    return {name: receipt[name] for name in required}


def sign_receipt(key: bytes, fields: dict[str, Any]) -> dict[str, Any]:
    return {**fields, "mac": receipt_mac(key, fields)}


def receipt_hash(receipt: dict[str, Any]) -> str:
    return sha256_hex(canonical(receipt))


def reinstall_receipt_fields(receipt: dict[str, Any]) -> dict[str, Any]:
    required = (
        "rid",
        "lph",
        "salt_p",
        "st_old",
        "st_new",
        "ctr",
        "last_hash",
        "ticket_hash",
        "session_id",
        "Bind_t",
        "profile_sha256",
        "status",
    )
    missing = [name for name in required if name not in receipt]
    if missing:
        raise LifecycleError(
            "MALFORMED_REINSTALL_RECEIPT",
            "reinstall_receipt_format",
            f"missing fields: {missing}",
        )
    return {name: receipt[name] for name in required}


def sign_reinstall_receipt(
    key: bytes, fields: dict[str, Any]
) -> dict[str, Any]:
    normalized = reinstall_receipt_fields(fields)
    return {**normalized, "mac": receipt_mac(key, normalized)}


def verify_reinstall_receipt_mac(
    key: bytes, receipt: dict[str, Any]
) -> None:
    fields = reinstall_receipt_fields(receipt)
    expected = receipt_mac(key, fields)
    if not hmac.compare_digest(expected, str(receipt.get("mac", ""))):
        raise LifecycleError(
            "INVALID_REINSTALL_RECEIPT_MAC",
            "reinstall_receipt_authentication",
        )


def build_reinstall_receipt(
    *,
    snapshot: dict[str, Any],
    rid: str,
    salt_p: str,
    ticket_hash: str,
    session_id: str,
    bind_t: str,
    profile_sha256: str,
    key: bytes,
) -> dict[str, Any]:
    return sign_reinstall_receipt(
        key,
        {
            "rid": rid,
            "lph": snapshot["lph"],
            "salt_p": salt_p,
            "st_old": snapshot["state"],
            "st_new": "installed",
            "ctr": int(snapshot["ctr"]) + 1,
            "last_hash": snapshot["last_hash"],
            "ticket_hash": ticket_hash,
            "session_id": session_id,
            "Bind_t": bind_t,
            "profile_sha256": profile_sha256,
            "status": "installed",
        },
    )


def verify_receipt_mac(key: bytes, receipt: dict[str, Any]) -> None:
    fields = receipt_fields(receipt)
    expected = receipt_mac(key, fields)
    if not hmac.compare_digest(expected, str(receipt.get("mac", ""))):
        raise LifecycleError(
            "INVALID_RECEIPT_MAC", "receipt_authentication"
        )


def rprep_fields(rprep: dict[str, Any]) -> dict[str, Any]:
    required = (
        "type",
        "rid",
        "lph",
        "state",
        "ctr",
        "last_hash",
        "prepare_hash",
    )
    missing = [name for name in required if name not in rprep]
    if missing:
        raise LifecycleError(
            "MALFORMED_RPREP", "rprep_format", f"missing fields: {missing}"
        )
    return {name: rprep[name] for name in required}


def verify_rprep_mac(key: bytes, rprep: dict[str, Any]) -> None:
    fields = rprep_fields(rprep)
    expected = receipt_mac(key, fields)
    if not hmac.compare_digest(expected, str(rprep.get("mac", ""))):
        raise LifecycleError("INVALID_RPREP_MAC", "rprep_authentication")


def build_transition_receipt(
    *,
    snapshot: dict[str, Any],
    st_new: str,
    rid: str,
    key: bytes,
) -> dict[str, Any]:
    return sign_receipt(
        key,
        {
            "rid": rid,
            "lph": snapshot["lph"],
            "st_old": snapshot["state"],
            "st_new": st_new,
            "ctr": int(snapshot["ctr"]) + 1,
            "last_hash": snapshot["last_hash"],
        },
    )


class LifecycleEngine:
    """SQLite-backed AURA lifecycle state chain used by the research prototype."""

    def __init__(
        self,
        db_path: Path,
        *,
        device_mac_key: bytes,
        server_mac_key: bytes,
    ):
        self.db_path = Path(db_path)
        self.device_mac_key = bytes(device_mac_key)
        self.server_mac_key = bytes(server_mac_key)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def _initialize_schema(self) -> None:
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifecycle_profiles (
                    lph TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    ctr INTEGER NOT NULL,
                    last_hash TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_profile_metadata (
                    lph TEXT PRIMARY KEY,
                    salt_p TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(lph) REFERENCES lifecycle_profiles(lph)
                );
                CREATE TABLE IF NOT EXISTS lifecycle_authorizations (
                    rid TEXT PRIMARY KEY,
                    lph TEXT NOT NULL,
                    op TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS reinstall_authorizations (
                    rid TEXT PRIMARY KEY,
                    lph TEXT NOT NULL,
                    salt_p TEXT NOT NULL,
                    ticket_hash TEXT NOT NULL,
                    ticket_json TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    bind_t TEXT NOT NULL,
                    profile_sha256 TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    FOREIGN KEY(rid) REFERENCES lifecycle_authorizations(rid)
                );
                CREATE TABLE IF NOT EXISTS lifecycle_receipts (
                    receipt_hash TEXT PRIMARY KEY,
                    lph TEXT NOT NULL,
                    rid TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_deletes (
                    lph TEXT PRIMARY KEY,
                    rid TEXT NOT NULL,
                    prepare_hash TEXT NOT NULL,
                    rprep_json TEXT NOT NULL,
                    ticket_expires_at INTEGER NOT NULL,
                    committed INTEGER NOT NULL DEFAULT 0,
                    commit_hash TEXT,
                    final_response_json TEXT
                );
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    lph TEXT,
                    rid TEXT,
                    outcome TEXT NOT NULL,
                    reason TEXT,
                    detail_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
            )

    def _event(
        self,
        event: str,
        *,
        lph: str | None,
        rid: str | None,
        outcome: str,
        reason: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        with closing(self._connect()) as db:
            db.execute(
                """
                INSERT INTO lifecycle_events(
                    event,lph,rid,outcome,reason,detail_json,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    event,
                    lph,
                    rid,
                    outcome,
                    reason,
                    json.dumps(detail or {}, sort_keys=True),
                    int(time.time()),
                ),
            )

    def initialize_profile(
        self,
        lph: str,
        *,
        state: str = "installed",
        ctr: int = 1,
        last_hash: str | None = None,
        salt_p: str | None = None,
    ) -> dict[str, Any]:
        if last_hash is None:
            last_hash = sha256_hex(
                canonical(
                    {
                        "domain": "AURA-RSP:lifecycle-genesis",
                        "lph": lph,
                        "state": state,
                        "ctr": ctr,
                    }
                )
            )
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO lifecycle_profiles(lph,state,ctr,last_hash,updated_at)
                VALUES(?,?,?,?,?)
                """,
                (lph, state, ctr, last_hash, int(time.time())),
            )
            if salt_p is not None:
                db.execute(
                    """
                    INSERT INTO lifecycle_profile_metadata(lph,salt_p,created_at)
                    VALUES(?,?,?)
                    """,
                    (lph, salt_p, int(time.time())),
                )
            db.commit()
        self._event(
            "initialize",
            lph=lph,
            rid=None,
            outcome="accepted",
            detail={
                "state": state,
                "ctr": ctr,
                "last_hash": last_hash,
                "salt_p_stored": salt_p is not None,
            },
        )
        return self.snapshot(lph)

    def snapshot(self, lph: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT lph,state,ctr,last_hash FROM lifecycle_profiles WHERE lph=?",
                (lph,),
            ).fetchone()
        if row is None:
            raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
        return dict(row)

    def issue_authorization(
        self,
        *,
        rid: str,
        lph: str,
        op: str,
        expires_at: int,
    ) -> dict[str, Any]:
        self.snapshot(lph)
        with closing(self._connect()) as db:
            db.execute(
                """
                INSERT INTO lifecycle_authorizations(rid,lph,op,expires_at,used)
                VALUES(?,?,?,?,0)
                """,
                (rid, lph, op, int(expires_at)),
            )
        return {
            "rid": rid,
            "lph": lph,
            "op": op,
            "expires_at": int(expires_at),
        }

    def issue_reinstall_authorization(
        self,
        *,
        rid: str,
        lph: str,
        salt_p: str,
        expires_at: int,
        session_id: str,
        bind_t: str,
        profile_sha256: str,
        issued_at: int | None = None,
    ) -> dict[str, Any]:
        issued_at = int(time.time()) if issued_at is None else int(issued_at)
        with closing(self._connect()) as db:
            metadata = db.execute(
                "SELECT salt_p FROM lifecycle_profile_metadata WHERE lph=?",
                (lph,),
            ).fetchone()
            if metadata is None:
                raise LifecycleError(
                    "REINSTALL_METADATA_NOT_FOUND", "profile_metadata"
                )
            if metadata["salt_p"] != salt_p:
                raise LifecycleError(
                    "REINSTALL_SALT_MISMATCH", "profile_metadata"
                )
            ticket_fields = {
                "rid": rid,
                "lph": lph,
                "salt_p": salt_p,
                "op": "reinstall",
                "issued_at": issued_at,
                "expires_at": int(expires_at),
                "session_id": session_id,
                "Bind_t": bind_t,
                "profile_sha256": profile_sha256,
            }
            ticket_hash = sha256_hex(canonical(ticket_fields))
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO lifecycle_authorizations(rid,lph,op,expires_at,used)
                VALUES(?,?,?,?,0)
                """,
                (rid, lph, "reinstall", int(expires_at)),
            )
            db.execute(
                """
                INSERT INTO reinstall_authorizations(
                    rid,lph,salt_p,ticket_hash,ticket_json,session_id,bind_t,
                    profile_sha256,issued_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    rid,
                    lph,
                    salt_p,
                    ticket_hash,
                    json.dumps(ticket_fields, sort_keys=True),
                    session_id,
                    bind_t,
                    profile_sha256,
                    issued_at,
                ),
            )
            db.commit()
        authorization = {**ticket_fields, "ticket_hash": ticket_hash}
        self._event(
            "issue-reinstall-authorization",
            lph=lph,
            rid=rid,
            outcome="accepted",
            detail={
                "ticket_hash": ticket_hash,
                "session_id": session_id,
                "profile_sha256": profile_sha256,
            },
        )
        return authorization

    @staticmethod
    def _row_snapshot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "lph": row["lph"],
            "state": row["state"],
            "ctr": int(row["ctr"]),
            "last_hash": row["last_hash"],
        }

    def _authorization(
        self,
        db: sqlite3.Connection,
        *,
        rid: str,
        lph: str,
        op: str,
        now: int,
        allow_expired: bool = False,
    ) -> sqlite3.Row:
        auth = db.execute(
            "SELECT * FROM lifecycle_authorizations WHERE rid=?", (rid,)
        ).fetchone()
        if auth is None:
            raise LifecycleError(
                "AUTHORIZATION_NOT_FOUND", "authorization"
            )
        if auth["lph"] != lph:
            raise LifecycleError(
                "AUTHORIZATION_LPH_MISMATCH", "authorization"
            )
        if auth["op"] != op:
            raise LifecycleError(
                "AUTHORIZATION_OP_MISMATCH", "authorization"
            )
        if not allow_expired and int(auth["expires_at"]) < now:
            raise LifecycleError("TICKET_EXPIRED", "authorization")
        return auth

    @staticmethod
    def _validate_predecessor(
        row: sqlite3.Row,
        fields: dict[str, Any],
    ) -> None:
        if fields["st_old"] != row["state"]:
            raise LifecycleError(
                "STATE_PREDECESSOR_MISMATCH", "state_predecessor"
            )
        if int(fields["ctr"]) != int(row["ctr"]) + 1:
            raise LifecycleError("COUNTER_MISMATCH", "counter")
        if fields["last_hash"] != row["last_hash"]:
            raise LifecycleError("LAST_HASH_MISMATCH", "last_hash")

    def _cached_latest(
        self,
        db: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        digest: str,
    ) -> dict[str, Any] | None:
        prior = db.execute(
            "SELECT response_json FROM lifecycle_receipts WHERE receipt_hash=?",
            (digest,),
        ).fetchone()
        if prior is None:
            return None
        if row["last_hash"] != digest:
            raise LifecycleError(
                "STALE_RECEIPT_REPLAY", "replay_detection"
            )
        response = json.loads(prior["response_json"])
        response["idempotent"] = True
        return response

    def apply_transition(
        self, receipt: dict[str, Any], *, now: int | None = None
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        fields = receipt_fields(receipt)
        lph, rid = str(fields["lph"]), str(fields["rid"])
        try:
            verify_receipt_mac(self.device_mac_key, receipt)
            digest = receipt_hash(receipt)
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                cached = self._cached_latest(db, row=row, digest=digest)
                if cached is not None:
                    db.commit()
                    self._event(
                        "transition",
                        lph=lph,
                        rid=rid,
                        outcome="idempotent",
                        detail=cached,
                    )
                    return cached
                op = STATE_OPS.get((fields["st_old"], fields["st_new"]))
                if op is None:
                    raise LifecycleError(
                        "INVALID_STATE_TRANSITION", "state_transition"
                    )
                self._authorization(
                    db, rid=rid, lph=lph, op=op, now=now
                )
                self._validate_predecessor(row, fields)
                response = {
                    "status": "accepted",
                    "idempotent": False,
                    "rid": rid,
                    "lph": lph,
                    "state": fields["st_new"],
                    "ctr": int(fields["ctr"]),
                    "last_hash": digest,
                }
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state=?,ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state=? AND ctr=? AND last_hash=?
                    """,
                    (
                        fields["st_new"],
                        int(fields["ctr"]),
                        digest,
                        now,
                        lph,
                        row["state"],
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError(
                        "ATOMIC_CAS_CONFLICT", "atomic_update"
                    )
                db.execute(
                    """
                    INSERT INTO lifecycle_receipts(
                        receipt_hash,lph,rid,kind,receipt_json,response_json,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        digest,
                        lph,
                        rid,
                        "state",
                        canonical(receipt).decode("ascii"),
                        json.dumps(response, sort_keys=True),
                        now,
                    ),
                )
                db.execute(
                    "UPDATE lifecycle_authorizations SET used=1 WHERE rid=?",
                    (rid,),
                )
                db.commit()
            self._event(
                "transition",
                lph=lph,
                rid=rid,
                outcome="accepted",
                detail=response,
            )
            return response
        except LifecycleError as exc:
            self._event(
                "transition",
                lph=lph,
                rid=rid,
                outcome="rejected",
                reason=exc.code,
                detail={"stage": exc.stage},
            )
            raise

    def prepare_delete(
        self, receipt: dict[str, Any], *, now: int | None = None
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        fields = receipt_fields(receipt)
        lph, rid = str(fields["lph"]), str(fields["rid"])
        try:
            verify_receipt_mac(self.device_mac_key, receipt)
            digest = receipt_hash(receipt)
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                pending = db.execute(
                    "SELECT * FROM pending_deletes WHERE lph=?", (lph,)
                ).fetchone()
                if pending is not None and pending["prepare_hash"] == digest:
                    response = {
                        "status": "pending-delete",
                        "idempotent": True,
                        "Rprep": json.loads(pending["rprep_json"]),
                    }
                    db.commit()
                    self._event(
                        "prepare-delete",
                        lph=lph,
                        rid=rid,
                        outcome="idempotent",
                        detail=response,
                    )
                    return response
                if pending is not None:
                    raise LifecycleError(
                        "PENDING_DELETE_CONFLICT", "pending_delete"
                    )
                auth = self._authorization(
                    db, rid=rid, lph=lph, op="delete", now=now
                )
                if fields["st_new"] != "pending-delete":
                    raise LifecycleError(
                        "INVALID_DELETE_TARGET", "state_transition"
                    )
                if fields["st_old"] not in ("installed", "disabled"):
                    raise LifecycleError(
                        "INVALID_DELETE_PREDECESSOR", "state_transition"
                    )
                self._validate_predecessor(row, fields)
                rprep_unsigned = {
                    "type": "Rprep",
                    "rid": rid,
                    "lph": lph,
                    "state": "pending-delete",
                    "ctr": int(fields["ctr"]),
                    "last_hash": digest,
                    "prepare_hash": digest,
                }
                rprep = sign_receipt(self.server_mac_key, rprep_unsigned)
                response = {
                    "status": "pending-delete",
                    "idempotent": False,
                    "Rprep": rprep,
                }
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state='pending-delete',ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state=? AND ctr=? AND last_hash=?
                    """,
                    (
                        int(fields["ctr"]),
                        digest,
                        now,
                        lph,
                        row["state"],
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError(
                        "ATOMIC_CAS_CONFLICT", "atomic_update"
                    )
                db.execute(
                    """
                    INSERT INTO lifecycle_receipts(
                        receipt_hash,lph,rid,kind,receipt_json,response_json,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        digest,
                        lph,
                        rid,
                        "prepare-delete",
                        canonical(receipt).decode("ascii"),
                        json.dumps(response, sort_keys=True),
                        now,
                    ),
                )
                db.execute(
                    """
                    INSERT INTO pending_deletes(
                        lph,rid,prepare_hash,rprep_json,ticket_expires_at,committed
                    ) VALUES(?,?,?,?,?,0)
                    """,
                    (
                        lph,
                        rid,
                        digest,
                        json.dumps(rprep, sort_keys=True),
                        int(auth["expires_at"]),
                    ),
                )
                db.execute(
                    "UPDATE lifecycle_authorizations SET used=1 WHERE rid=?",
                    (rid,),
                )
                db.commit()
            self._event(
                "prepare-delete",
                lph=lph,
                rid=rid,
                outcome="accepted",
                detail=response,
            )
            return response
        except LifecycleError as exc:
            self._event(
                "prepare-delete",
                lph=lph,
                rid=rid,
                outcome="rejected",
                reason=exc.code,
                detail={"stage": exc.stage},
            )
            raise

    def commit_delete(
        self,
        receipt: dict[str, Any],
        rprep: dict[str, Any],
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        fields = receipt_fields(receipt)
        lph, rid = str(fields["lph"]), str(fields["rid"])
        try:
            verify_receipt_mac(self.device_mac_key, receipt)
            verify_rprep_mac(self.server_mac_key, rprep)
            digest = receipt_hash(receipt)
            with closing(self._connect()) as db:
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
                    raise LifecycleError(
                        "PENDING_DELETE_NOT_FOUND", "pending_delete"
                    )
                if (
                    int(pending["committed"]) == 1
                    and pending["commit_hash"] == digest
                    and row["state"] == "tombstone"
                    and row["last_hash"] == digest
                ):
                    response = json.loads(pending["final_response_json"])
                    response["idempotent"] = True
                    db.commit()
                    self._event(
                        "commit-delete",
                        lph=lph,
                        rid=rid,
                        outcome="idempotent",
                        detail=response,
                    )
                    return response
                if pending["rid"] != rid:
                    raise LifecycleError(
                        "PENDING_DELETE_RID_MISMATCH", "pending_delete"
                    )
                stored_rprep = json.loads(pending["rprep_json"])
                if canonical(stored_rprep) != canonical(rprep):
                    raise LifecycleError(
                        "RPREP_MISMATCH", "pending_delete"
                    )
                if rprep["prepare_hash"] != pending["prepare_hash"]:
                    raise LifecycleError(
                        "RPREP_PREPARE_HASH_MISMATCH", "pending_delete"
                    )
                if fields["st_old"] != "pending-delete" or fields["st_new"] != "tombstone":
                    raise LifecycleError(
                        "INVALID_COMMIT_TRANSITION", "state_transition"
                    )
                self._validate_predecessor(row, fields)
                response = {
                    "status": "tombstone",
                    "idempotent": False,
                    "rid": rid,
                    "lph": lph,
                    "state": "tombstone",
                    "ctr": int(fields["ctr"]),
                    "last_hash": digest,
                }
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state='tombstone',ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state='pending-delete' AND ctr=? AND last_hash=?
                    """,
                    (
                        int(fields["ctr"]),
                        digest,
                        now,
                        lph,
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError(
                        "ATOMIC_CAS_CONFLICT", "atomic_update"
                    )
                db.execute(
                    """
                    INSERT INTO lifecycle_receipts(
                        receipt_hash,lph,rid,kind,receipt_json,response_json,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        digest,
                        lph,
                        rid,
                        "commit-delete",
                        canonical(receipt).decode("ascii"),
                        json.dumps(response, sort_keys=True),
                        now,
                    ),
                )
                db.execute(
                    """
                    UPDATE pending_deletes
                    SET committed=1,commit_hash=?,final_response_json=?
                    WHERE lph=?
                    """,
                    (digest, json.dumps(response, sort_keys=True), lph),
                )
                db.commit()
            self._event(
                "commit-delete",
                lph=lph,
                rid=rid,
                outcome="accepted",
                detail=response,
            )
            return response
        except LifecycleError as exc:
            self._event(
                "commit-delete",
                lph=lph,
                rid=rid,
                outcome="rejected",
                reason=exc.code,
                detail={"stage": exc.stage},
            )
            raise

    def apply_reinstall(
        self,
        receipt: dict[str, Any],
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        fields = reinstall_receipt_fields(receipt)
        lph, rid = str(fields["lph"]), str(fields["rid"])
        try:
            verify_reinstall_receipt_mac(self.device_mac_key, receipt)
            digest = receipt_hash(receipt)
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM lifecycle_profiles WHERE lph=?", (lph,)
                ).fetchone()
                if row is None:
                    raise LifecycleError("UNKNOWN_LPH", "profile_lookup")
                cached = self._cached_latest(db, row=row, digest=digest)
                if cached is not None:
                    db.commit()
                    self._event(
                        "reinstall",
                        lph=lph,
                        rid=rid,
                        outcome="idempotent",
                        detail=cached,
                    )
                    return cached
                auth = self._authorization(
                    db, rid=rid, lph=lph, op="reinstall", now=now
                )
                if int(auth["used"]) != 0:
                    raise LifecycleError(
                        "AUTHORIZATION_ALREADY_USED", "authorization"
                    )
                reinstall_auth = db.execute(
                    "SELECT * FROM reinstall_authorizations WHERE rid=?",
                    (rid,),
                ).fetchone()
                if reinstall_auth is None:
                    raise LifecycleError(
                        "REINSTALL_AUTHORIZATION_NOT_FOUND",
                        "authorization",
                    )
                metadata = db.execute(
                    "SELECT salt_p FROM lifecycle_profile_metadata WHERE lph=?",
                    (lph,),
                ).fetchone()
                if metadata is None:
                    raise LifecycleError(
                        "REINSTALL_METADATA_NOT_FOUND", "profile_metadata"
                    )
                if (
                    fields["salt_p"] != metadata["salt_p"]
                    or fields["salt_p"] != reinstall_auth["salt_p"]
                ):
                    raise LifecycleError(
                        "REINSTALL_SALT_MISMATCH", "profile_metadata"
                    )
                if fields["ticket_hash"] != reinstall_auth["ticket_hash"]:
                    raise LifecycleError(
                        "REINSTALL_TICKET_MISMATCH", "authorization"
                    )
                if fields["session_id"] != reinstall_auth["session_id"]:
                    raise LifecycleError(
                        "REINSTALL_SESSION_MISMATCH", "session_binding"
                    )
                if fields["Bind_t"] != reinstall_auth["bind_t"]:
                    raise LifecycleError(
                        "REINSTALL_BIND_T_MISMATCH", "profile_binding"
                    )
                if fields["profile_sha256"] != reinstall_auth["profile_sha256"]:
                    raise LifecycleError(
                        "REINSTALL_PROFILE_MISMATCH", "profile_binding"
                    )
                if fields["status"] != "installed":
                    raise LifecycleError(
                        "REINSTALL_INSTALLATION_NOT_CONFIRMED",
                        "installation_receipt",
                    )
                if row["state"] != "tombstone":
                    raise LifecycleError(
                        "INVALID_REINSTALL_PREDECESSOR",
                        "state_transition",
                    )
                if (
                    fields["st_old"] != "tombstone"
                    or fields["st_new"] != "installed"
                ):
                    raise LifecycleError(
                        "INVALID_REINSTALL_TRANSITION", "state_transition"
                    )
                self._validate_predecessor(row, fields)
                response = {
                    "status": "installed",
                    "idempotent": False,
                    "rid": rid,
                    "lph": lph,
                    "state": "installed",
                    "ctr": int(fields["ctr"]),
                    "last_hash": digest,
                    "ticket_hash": fields["ticket_hash"],
                    "session_id": fields["session_id"],
                    "Bind_t": fields["Bind_t"],
                    "profile_sha256": fields["profile_sha256"],
                }
                updated = db.execute(
                    """
                    UPDATE lifecycle_profiles
                    SET state='installed',ctr=?,last_hash=?,updated_at=?
                    WHERE lph=? AND state='tombstone' AND ctr=? AND last_hash=?
                    """,
                    (
                        int(fields["ctr"]),
                        digest,
                        now,
                        lph,
                        int(row["ctr"]),
                        row["last_hash"],
                    ),
                )
                if updated.rowcount != 1:
                    raise LifecycleError(
                        "ATOMIC_CAS_CONFLICT", "atomic_update"
                    )
                db.execute(
                    """
                    INSERT INTO lifecycle_receipts(
                        receipt_hash,lph,rid,kind,receipt_json,response_json,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        digest,
                        lph,
                        rid,
                        "reinstall",
                        canonical(receipt).decode("ascii"),
                        json.dumps(response, sort_keys=True),
                        now,
                    ),
                )
                db.execute(
                    "UPDATE lifecycle_authorizations SET used=1 WHERE rid=?",
                    (rid,),
                )
                db.commit()
            self._event(
                "reinstall",
                lph=lph,
                rid=rid,
                outcome="accepted",
                detail=response,
            )
            return response
        except LifecycleError as exc:
            self._event(
                "reinstall",
                lph=lph,
                rid=rid,
                outcome="rejected",
                reason=exc.code,
                detail={"stage": exc.stage},
            )
            raise

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
                "events": int(
                    db.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0]
                ),
            }

    def export_events(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM lifecycle_events ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]
