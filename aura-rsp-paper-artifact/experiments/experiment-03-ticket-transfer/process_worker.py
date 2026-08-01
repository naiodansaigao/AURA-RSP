"""Multi-process worker for Experiment 3 production proof verification."""

from __future__ import annotations

import os
import sys
import time
from typing import Any


_STATE: dict[str, Any] = {}


def initialize_worker(integration_root: str, fixture: dict[str, Any]) -> None:
    """Import pySim once and retain immutable verification material per worker."""

    if integration_root not in sys.path:
        sys.path.insert(0, integration_root)
    from pySim.esim.aura.bbs import public_key_from_dict
    from pySim.esim.aura.codec import b64d
    from pySim.esim.aura.proof import verify_auth_proof

    _STATE.update(
        {
            "verify": verify_auth_proof,
            "ctx_t": fixture["ctx_t"],
            "valid_proof": fixture["valid_proof"],
            "invalid_proof": fixture["invalid_proof"],
            "eum_public_key": public_key_from_dict(fixture["eum_public_key"]),
            "mno_public_key": public_key_from_dict(fixture["mno_public_key"]),
            "salt_p": b64d(fixture["salt_p"]),
        }
    )


def worker_ready() -> int:
    """Return the worker PID after the initializer has completed."""

    time.sleep(0.02)
    return os.getpid()


def verify_task(workload: str, submitted_ns: int) -> dict[str, Any]:
    """Run the exact production verifier and expose queue/service timing."""

    started_ns = time.perf_counter_ns()
    proof_key = "valid_proof" if workload == "normal_authentication" else "invalid_proof"
    accepted, reason = _STATE["verify"](
        ctx_t=_STATE["ctx_t"],
        proof=_STATE[proof_key],
        eum_public_key=_STATE["eum_public_key"],
        mno_public_key=_STATE["mno_public_key"],
        salt_p=_STATE["salt_p"],
    )
    finished_ns = time.perf_counter_ns()
    return {
        "accepted": accepted,
        "reason": reason,
        "pid": os.getpid(),
        "queue_wait_ms": (started_ns - submitted_ns) / 1_000_000,
        "service_ms": (finished_ns - started_ns) / 1_000_000,
        "end_to_end_ms": (finished_ns - submitted_ns) / 1_000_000,
    }
