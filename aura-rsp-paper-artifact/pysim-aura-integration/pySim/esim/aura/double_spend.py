"""Reusable AURA-RSP nullifier replay and double-spend classification.

The service and scalability experiments share this module so that the database
benchmark cannot silently drift from the production protocol decision order.
Proof verification happens before this classifier in :mod:`service`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from py_ecc.optimized_bls12_381 import curve_order

from .codec import scalar_from_b64, scalar_to_b64
from .proof import mod_inv


@dataclass(frozen=True)
class NullifierDecision:
    outcome: str
    error_code: str | None = None
    recovered_k: str | None = None
    trace: dict | None = None


def recover_trace_key(
    old_gamma_b64: str,
    old_c_b64: str,
    new_gamma_b64: str,
    new_c_b64: str,
) -> str:
    """Recover the tracing key from two distinct responses under one ticket."""

    old_gamma = scalar_from_b64(old_gamma_b64)
    old_c = scalar_from_b64(old_c_b64)
    new_gamma = scalar_from_b64(new_gamma_b64)
    new_c = scalar_from_b64(new_c_b64)
    denominator = (old_gamma - new_gamma) % curve_order
    if denominator == 0:
        raise ZeroDivisionError("double-spend responses use the same gamma")
    recovered_k = ((old_c - new_c) * mod_inv(denominator)) % curve_order
    return scalar_to_b64(recovered_k)


def classify_nullifier(
    *,
    existing: dict | None,
    auth_hash: str,
    opid: str,
    gamma: str,
    c_value: str,
    trace_lookup: Callable[[str], dict | None],
) -> NullifierDecision:
    """Apply the production replay/double-spend decision order."""

    if existing is None:
        return NullifierDecision("new")
    if existing["auth_hash"] == auth_hash:
        return NullifierDecision("exact_replay")
    if existing["opid"] == opid:
        return NullifierDecision(
            "opid_context_conflict", error_code="OPID_CONTEXT_CONFLICT"
        )
    try:
        recovered_k = recover_trace_key(
            existing["gamma"], existing["c"], gamma, c_value
        )
    except ZeroDivisionError:
        return NullifierDecision(
            "zero_denominator", error_code="DOUBLE_SPEND_ZERO_DENOMINATOR"
        )
    trace = trace_lookup(recovered_k)
    suffix = ":TRACE_RECOVERED" if trace else ":TRACE_NOT_FOUND"
    return NullifierDecision(
        "double_spend",
        error_code="DOUBLE_SPEND_DETECTED" + suffix,
        recovered_k=recovered_k,
        trace=trace,
    )
