"""AURA-RSP research state store with the same memory/file choice as RSP."""

from __future__ import annotations

from contextlib import contextmanager
import shelve
import threading
from typing import Iterator

from .models import AuraOrderContext, AuraSessionState


class AuraStore:
    """Namespaced store for sessions, orders, nullifiers and install state.

    The in-memory mode is used for the fair benchmark.  File mode uses a
    dedicated shelf and never shares keys with ``RspSessionStore``.
    """

    def __init__(self, filename: str | None = None, *, in_memory: bool = False):
        if not in_memory and filename is None:
            raise ValueError("filename is required for persistent AURA storage")
        self._in_memory = in_memory
        self._db = shelve.Shelf({}) if in_memory else shelve.open(filename)
        self._lock = threading.RLock()

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self._lock:
            yield

    @staticmethod
    def _key(namespace: str, identifier: str) -> str:
        return f"{namespace}:{identifier}"

    def put_order(self, order: AuraOrderContext) -> None:
        with self._lock:
            self._db[self._key("order", order.I_ac)] = order
            self._db.sync()

    def get_order(self, i_ac: str) -> AuraOrderContext | None:
        with self._lock:
            return self._db.get(self._key("order", i_ac))

    def put_session(self, session: AuraSessionState) -> None:
        with self._lock:
            self._db[self._key("session", session.transaction_id)] = session
            self._db.sync()

    def get_session(self, transaction_id: str) -> AuraSessionState | None:
        with self._lock:
            return self._db.get(self._key("session", transaction_id))

    def get_nullifier(self, nu: str) -> dict | None:
        with self._lock:
            return self._db.get(self._key("nullifier", nu))

    def put_nullifier(self, nu: str, value: dict) -> None:
        with self._lock:
            key = self._key("nullifier", nu)
            if key in self._db:
                raise ValueError("nullifier already exists")
            self._db[key] = value
            self._db.sync()

    def put_trace_index(self, k: str, eid: str, r_tr: str) -> None:
        with self._lock:
            self._db[self._key("trace-index", k)] = {
                "eid": eid,
                "r_tr": r_tr,
            }
            self._db.sync()

    def lookup_trace(self, k: str) -> dict | None:
        with self._lock:
            return self._db.get(self._key("trace-index", k))

    def put_profile_state(self, lph: str, state: dict) -> None:
        with self._lock:
            self._db[self._key("profile-state", lph)] = state
            self._db.sync()

    def get_profile_state(self, lph: str) -> dict | None:
        with self._lock:
            return self._db.get(self._key("profile-state", lph))

    def close(self) -> None:
        with self._lock:
            self._db.close()
