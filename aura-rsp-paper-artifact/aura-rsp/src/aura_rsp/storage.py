from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            transaction_id TEXT PRIMARY KEY,
            init_json TEXT NOT NULL,
            ctx_json TEXT,
            auth_hash TEXT,
            auth_request_json TEXT,
            auth_response_json TEXT,
            vk_t TEXT,
            bind_t TEXT,
            k_mac TEXT,
            profile_sha256 TEXT,
            status TEXT NOT NULL DEFAULT 'initiated',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS used_nullifiers (
            v TEXT PRIMARY KEY,
            auth_hash TEXT NOT NULL,
            gamma TEXT NOT NULL,
            c_value TEXT NOT NULL,
            transaction_id TEXT NOT NULL,
            response_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            v TEXT NOT NULL,
            recovered_k TEXT NOT NULL,
            eid TEXT,
            first_transaction_id TEXT NOT NULL,
            second_transaction_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notifications (
            transaction_id TEXT PRIMARY KEY,
            receipt_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    return db


def connect_trace(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS trace_index (
            k TEXT PRIMARY KEY,
            eid TEXT NOT NULL,
            r_tr TEXT NOT NULL
        )
        """
    )
    return db
