"""SQLite UsedNullifier backend for Experiment 4.

Every classification calls the production ``classify_nullifier`` function from
the integrated pySim/osmo-smdpp tree.  SQLite only supplies durable indexed
state, atomic first-use insertion, trace de-duplication and retry accounting.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class SQLiteUsedNullifier:
    def __init__(self, path: Path, classify_nullifier):
        self.path = path
        self.classify_nullifier = classify_nullifier
        self._local = threading.local()
        self._retry_lock = threading.Lock()
        self._retry_count = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(
                self.path, timeout=30.0, isolation_level=None, check_same_thread=False
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA busy_timeout=30000")
            self._local.connection = connection
        return connection

    def _initialize(self) -> None:
        db = self._connect()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS used_nullifiers (
                nu TEXT PRIMARY KEY,
                auth_hash TEXT NOT NULL,
                gamma TEXT NOT NULL,
                c_value TEXT NOT NULL,
                opid TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_ns INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS trace_index (
                k TEXT PRIMARY KEY,
                eid TEXT NOT NULL,
                r_tr TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS business_executions (
                nu TEXT PRIMARY KEY,
                executed_ns INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS trace_events (
                nu TEXT PRIMARY KEY,
                recovered_k TEXT NOT NULL,
                eid TEXT,
                traced_ns INTEGER NOT NULL
            ) WITHOUT ROWID;
            """
        )

    def reset(self) -> None:
        db = self._connect()
        db.executescript(
            """
            DELETE FROM trace_events;
            DELETE FROM business_executions;
            DELETE FROM used_nullifiers;
            DELETE FROM trace_index;
            """
        )
        with self._retry_lock:
            self._retry_count = 0

    def close_thread(self) -> None:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            self._local.connection = None

    @property
    def retry_count(self) -> int:
        with self._retry_lock:
            return self._retry_count

    def _add_retry(self) -> None:
        with self._retry_lock:
            self._retry_count += 1

    def put_trace(self, k: str, eid: str, r_tr: str) -> None:
        self._connect().execute(
            "INSERT OR REPLACE INTO trace_index(k,eid,r_tr) VALUES(?,?,?)",
            (k, eid, r_tr),
        )

    def lookup_trace(self, k: str) -> dict | None:
        row = self._connect().execute(
            "SELECT eid,r_tr FROM trace_index WHERE k=?", (k,)
        ).fetchone()
        return None if row is None else {"eid": row["eid"], "r_tr": row["r_tr"]}

    def prefill(self, count: int, *, batch_size: int = 10_000) -> float:
        """Insert inert indexed rows in one transaction and return elapsed ms."""

        db = self._connect()
        started = time.perf_counter_ns()
        db.execute("BEGIN IMMEDIATE")
        try:
            for start in range(0, count, batch_size):
                stop = min(count, start + batch_size)
                rows = [
                    (
                        f"prefill-{index:09d}",
                        f"hash-{index:09d}",
                        "AA==",
                        "AA==",
                        f"op-{index:09d}",
                        f"tx-{index:09d}",
                        "{}",
                        index,
                    )
                    for index in range(start, stop)
                ]
                db.executemany(
                    """
                    INSERT INTO used_nullifiers
                    (nu,auth_hash,gamma,c_value,opid,transaction_id,response_json,created_ns)
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    rows,
                )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return (time.perf_counter_ns() - started) / 1_000_000

    def count(self, table: str = "used_nullifiers") -> int:
        if table not in {
            "used_nullifiers",
            "business_executions",
            "trace_events",
            "trace_index",
        }:
            raise ValueError("unsupported table")
        return int(self._connect().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def classify(
        self,
        *,
        nu: str,
        auth_hash: str,
        gamma: str,
        c_value: str,
        opid: str,
        transaction_id: str,
        response: dict[str, Any] | None = None,
        max_retries: int = 12,
    ) -> dict[str, Any]:
        submitted_ns = time.perf_counter_ns()
        retries = 0
        while True:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                query_started = time.perf_counter_ns()
                row = db.execute(
                    """
                    SELECT auth_hash,gamma,c_value,opid,transaction_id,response_json
                    FROM used_nullifiers WHERE nu=?
                    """,
                    (nu,),
                ).fetchone()
                query_ms = (time.perf_counter_ns() - query_started) / 1_000_000
                existing = None
                if row is not None:
                    existing = {
                        "auth_hash": row["auth_hash"],
                        "gamma": row["gamma"],
                        "c": row["c_value"],
                        "opid": row["opid"],
                        "transaction_id": row["transaction_id"],
                        "response": json.loads(row["response_json"]),
                    }

                trace_lookup_ms = 0.0

                def lookup(k_value: str) -> dict | None:
                    nonlocal trace_lookup_ms
                    trace_started = time.perf_counter_ns()
                    trace_row = db.execute(
                        "SELECT eid,r_tr FROM trace_index WHERE k=?", (k_value,)
                    ).fetchone()
                    trace_lookup_ms += (
                        time.perf_counter_ns() - trace_started
                    ) / 1_000_000
                    if trace_row is None:
                        return None
                    return {"eid": trace_row["eid"], "r_tr": trace_row["r_tr"]}

                decision_started = time.perf_counter_ns()
                decision = self.classify_nullifier(
                    existing=existing,
                    auth_hash=auth_hash,
                    opid=opid,
                    gamma=gamma,
                    c_value=c_value,
                    trace_lookup=lookup,
                )
                decision_ms = (time.perf_counter_ns() - decision_started) / 1_000_000
                trace_event_new = False
                if decision.outcome == "new":
                    now = time.time_ns()
                    db.execute(
                        """
                        INSERT INTO used_nullifiers
                        (nu,auth_hash,gamma,c_value,opid,transaction_id,response_json,created_ns)
                        VALUES(?,?,?,?,?,?,?,?)
                        """,
                        (
                            nu,
                            auth_hash,
                            gamma,
                            c_value,
                            opid,
                            transaction_id,
                            json.dumps(response or {}, sort_keys=True, separators=(",", ":")),
                            now,
                        ),
                    )
                    db.execute(
                        "INSERT INTO business_executions(nu,executed_ns) VALUES(?,?)",
                        (nu, now),
                    )
                elif decision.outcome == "double_spend" and decision.trace is not None:
                    before = db.total_changes
                    db.execute(
                        """
                        INSERT OR IGNORE INTO trace_events(nu,recovered_k,eid,traced_ns)
                        VALUES(?,?,?,?)
                        """,
                        (nu, decision.recovered_k, decision.trace["eid"], time.time_ns()),
                    )
                    trace_event_new = db.total_changes > before
                db.commit()
                total_ms = (time.perf_counter_ns() - submitted_ns) / 1_000_000
                return {
                    "outcome": decision.outcome,
                    "error_code": decision.error_code,
                    "recovered_k": decision.recovered_k,
                    "trace": decision.trace,
                    "trace_event_new": trace_event_new,
                    "query_ms": query_ms,
                    "decision_ms": decision_ms,
                    "trace_lookup_ms": trace_lookup_ms,
                    "total_ms": total_ms,
                    "retries": retries,
                    "business_executed": decision.outcome == "new",
                }
            except sqlite3.OperationalError as exc:
                try:
                    db.rollback()
                except sqlite3.Error:
                    pass
                if "locked" not in str(exc).lower() or retries >= max_retries:
                    raise
                retries += 1
                self._add_retry()
                time.sleep(min(0.001 * (2**retries), 0.05))
            except Exception:
                try:
                    db.rollback()
                except sqlite3.Error:
                    pass
                raise
