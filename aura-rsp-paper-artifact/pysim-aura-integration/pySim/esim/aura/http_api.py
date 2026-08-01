"""Strict AURA JSON request decoding for Klein/Twisted handlers."""

from __future__ import annotations

import json
from typing import Iterable

from twisted.web.iweb import IRequest

from .codec import canonical
from .errors import AuraProtocolError


MAX_BODY_BYTES = 1_000_000


def decode_json_request(
    request: IRequest,
    *,
    mandatory: Iterable[str],
    allowed: Iterable[str],
) -> dict:
    raw = request.content.read()
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise AuraProtocolError("INVALID_BODY_LENGTH", "http", 413)
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise AuraProtocolError("INVALID_JSON", "http", 400) from exc
    if not isinstance(value, dict):
        raise AuraProtocolError("JSON_OBJECT_REQUIRED", "http", 400)
    mandatory_set = set(mandatory)
    allowed_set = set(allowed)
    missing = sorted(mandatory_set - value.keys())
    unknown = sorted(value.keys() - allowed_set)
    if missing:
        raise AuraProtocolError(
            "MISSING_FIELDS:" + ",".join(missing), "http", 400
        )
    if unknown:
        raise AuraProtocolError(
            "UNKNOWN_FIELDS:" + ",".join(unknown), "http", 400
        )
    return value


def encode_json_response(request: IRequest, status: int, value: dict | None):
    request.setResponseCode(status)
    request.setHeader("X-Admin-Protocol", "aura/rsp/v14")
    if value is None:
        return b""
    request.setHeader("Content-Type", "application/json;charset=UTF-8")
    return canonical(value)
