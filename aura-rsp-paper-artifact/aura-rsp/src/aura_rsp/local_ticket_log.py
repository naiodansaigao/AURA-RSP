from __future__ import annotations

import copy
from typing import Any

from .codec import canonical, sha256_hex


LOG_VERSION = 2


class LocalTicketLogError(RuntimeError):
    """Base class for local ticket-log failures."""


class LocalTicketContextConflict(LocalTicketLogError):
    """The same (v, opid) was presented with a different transcript context."""


class LocalTicketLogCorrupt(LocalTicketLogError):
    """The persisted entry is incomplete, legacy, or internally inconsistent."""


def ticket_log_key(v: str, opid: str) -> str:
    if not v or not opid:
        raise ValueError("v and opid must be non-empty")
    return f"{v}:{opid}"


def _ctx_hash(ctx_t: dict[str, Any]) -> str:
    return sha256_hex(canonical(ctx_t))


def lookup_cached_auth_request(
    device: dict[str, Any],
    *,
    v: str,
    opid: str,
    ctx_t: dict[str, Any],
) -> dict[str, Any] | None:
    """Return an exact cached request, or fail closed on a context conflict."""

    entry = device.setdefault("local_ticket_log", {}).get(ticket_log_key(v, opid))
    if entry is None:
        return None
    if not isinstance(entry, dict) or entry.get("version") != LOG_VERSION:
        raise LocalTicketLogCorrupt(
            "legacy or malformed LocalTicketLog entry cannot be replayed safely"
        )

    expected_ctx_hash = _ctx_hash(ctx_t)
    if entry.get("ctx_hash") != expected_ctx_hash:
        raise LocalTicketContextConflict(
            "same (v, opid) was used with a different authentication context"
        )

    request = entry.get("auth_request")
    if not isinstance(request, dict):
        raise LocalTicketLogCorrupt("cached authentication request is missing")
    if entry.get("auth_hash") != sha256_hex(canonical(request)):
        raise LocalTicketLogCorrupt("cached authentication request hash mismatch")
    cached_ctx = request.get("ctx_t")
    if not isinstance(cached_ctx, dict) or _ctx_hash(cached_ctx) != expected_ctx_hash:
        raise LocalTicketLogCorrupt("cached request/context binding mismatch")
    return copy.deepcopy(request)


def store_auth_request(
    device: dict[str, Any],
    *,
    v: str,
    opid: str,
    ctx_t: dict[str, Any],
    auth_request: dict[str, Any],
) -> None:
    """Persist a complete request so exact retries never create a new response."""

    key = ticket_log_key(v, opid)
    log = device.setdefault("local_ticket_log", {})
    existing = log.get(key)
    if existing is not None:
        cached = lookup_cached_auth_request(
            device, v=v, opid=opid, ctx_t=ctx_t
        )
        if canonical(cached) != canonical(auth_request):
            raise LocalTicketLogCorrupt(
                "attempted to overwrite a cached request with different bytes"
            )
        return

    request_copy = copy.deepcopy(auth_request)
    log[key] = {
        "version": LOG_VERSION,
        "ctx_hash": _ctx_hash(ctx_t),
        "auth_hash": sha256_hex(canonical(request_copy)),
        "auth_request": request_copy,
    }
