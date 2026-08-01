"""Shared measurement primitives for Standard RSP and AURA-RSP."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import time
from typing import Iterator


@dataclass
class RspMeasurements:
    protocol_mode: str
    stages_ms: dict[str, float | None] = field(default_factory=dict)
    wire_request_bytes: int = 0
    wire_response_bytes: int = 0
    started_ns: int = field(default_factory=time.perf_counter_ns)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter_ns()
        try:
            yield
        finally:
            self.stages_ms[name] = round(
                (time.perf_counter_ns() - started) / 1_000_000, 3
            )

    def add_wire(self, *, request_bytes: int = 0, response_bytes: int = 0) -> None:
        self.wire_request_bytes += request_bytes
        self.wire_response_bytes += response_bytes

    def finish(self) -> dict:
        return {
            "protocol_mode": self.protocol_mode,
            "end_to_end_ms": round(
                (time.perf_counter_ns() - self.started_ns) / 1_000_000, 3
            ),
            "wire_request_bytes": self.wire_request_bytes,
            "wire_response_bytes": self.wire_response_bytes,
            **self.stages_ms,
        }
