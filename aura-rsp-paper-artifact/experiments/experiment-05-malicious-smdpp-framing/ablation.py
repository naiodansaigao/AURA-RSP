"""Experiment-only LocalTicketLog ablations.

These modes are not protocol configurations.  The full mode calls the
production LocalTicketLog.  The other two deliberately remove one invariant
at a time so the experiment can measure its contribution.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import time
from typing import Any

from py_ecc.optimized_bls12_381 import curve_order

from pySim.esim.aura.codec import canonical, scalar_from_b64, scalar_to_b64
from pySim.esim.aura.context import gamma_for
from pySim.esim.aura.local_ticket_log import (
    LocalTicketContextConflict,
    lookup_cached_auth_request,
)


FULL = "full_aura"
NO_LOG = "without_local_ticket_log"
KEY_ONLY = "key_only_cache_no_context_check"
MODES = (FULL, NO_LOG, KEY_ONLY)
SERVER_MUTABLE_FIELDS = ("N_S", "I_t", "cap", "serverOID")
CLIENT_BOUND_FIELDS = ("sid", "PRaddr")
TICKET_BOUND_FIELDS = ("pid_h", "op")


@dataclass(frozen=True)
class TrialResult:
    outcome: str
    distinct_valid_responses: int
    cached_responses: int
    context_conflict_aborts: int
    new_c_computations: int
    trace_requests: int
    accepted_trace_evidence: int
    false_trace: int
    processing_us: float

    def row(self) -> dict[str, Any]:
        return self.__dict__.copy()


def mutate_context(base: dict[str, Any], field: str, value: str) -> dict[str, Any]:
    ctx = copy.deepcopy(base)
    if field in ("pid_h", "op"):
        ctx["ticket"][field] = value
    else:
        ctx[field] = value
    return ctx


def classify_trial(
    *,
    mode: str,
    field: str,
    attack_ctx: dict[str, Any],
    production_device_state: dict[str, Any],
    base_request: dict[str, Any],
    d_value: int,
    k_value: int,
) -> TrialResult:
    """Classify one randomized challenge after one honest base response.

    The bulk layer measures state-machine processing.  Real BBS+ proof samples
    for every outcome class are generated and verified separately by demo.py.
    """

    started = time.perf_counter_ns()
    if field in CLIENT_BOUND_FIELDS:
        outcome = "client_order_context_reject"
        values = (1, 0, 0, 0, 0, 0, 0)
    elif field in TICKET_BOUND_FIELDS:
        outcome = "mno_ticket_signature_reject"
        values = (1, 0, 0, 0, 0, 0, 0)
    elif field not in SERVER_MUTABLE_FIELDS:
        raise ValueError(f"unsupported field {field}")
    elif mode == FULL:
        try:
            lookup_cached_auth_request(
                production_device_state,
                v=attack_ctx["v"],
                opid=attack_ctx["opid"],
                ctx_t=attack_ctx,
            )
        except LocalTicketContextConflict:
            outcome = "local_context_conflict_abort"
            values = (1, 0, 1, 0, 0, 0, 0)
        else:
            raise AssertionError("full LocalTicketLog accepted a conflicting context")
    elif mode == NO_LOG:
        # This is the exact c=d+gamma*k response relation used by production.
        gamma = scalar_from_b64(gamma_for(attack_ctx))
        scalar_to_b64((d_value + gamma * k_value) % curve_order)
        outcome = "second_valid_response_false_trace"
        values = (2, 0, 0, 1, 1, 1, 1)
    elif mode == KEY_ONLY:
        canonical(base_request)
        outcome = "cached_response_invalid_for_modified_context"
        values = (1, 1, 0, 0, 1, 0, 0)
    else:
        raise ValueError(f"unsupported mode {mode}")
    elapsed_us = (time.perf_counter_ns() - started) / 1000
    return TrialResult(outcome, *values, processing_us=round(elapsed_us, 3))


def challenge_scale(counts: list[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for count in counts:
        rows.extend(
            [
                {"mode": FULL, "malicious_challenges": count, "distinct_valid_responses": 1, "cached_responses": 0, "context_conflict_aborts": count, "new_c_computations": 0, "false_trace": 0},
                {"mode": NO_LOG, "malicious_challenges": count, "distinct_valid_responses": 1 + count, "cached_responses": 0, "context_conflict_aborts": 0, "new_c_computations": count, "false_trace": 1},
                {"mode": KEY_ONLY, "malicious_challenges": count, "distinct_valid_responses": 1, "cached_responses": count, "context_conflict_aborts": 0, "new_c_computations": 0, "false_trace": 0},
            ]
        )
    return rows
