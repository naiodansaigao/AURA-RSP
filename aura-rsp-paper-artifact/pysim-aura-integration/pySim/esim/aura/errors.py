"""Typed fail-closed errors used at the HTTP/service boundary."""

from __future__ import annotations


class AuraProtocolError(RuntimeError):
    def __init__(self, code: str, stage: str, http_status: int = 400):
        super().__init__(code)
        self.code = code
        self.stage = stage
        self.http_status = http_status


class AuraAuthenticationError(AuraProtocolError):
    def __init__(self, code: str):
        super().__init__(code, "authenticateClient", 401)


class AuraStateError(AuraProtocolError):
    def __init__(self, code: str, stage: str):
        super().__init__(code, stage, 409)


class AuraPolicyError(AuraProtocolError):
    def __init__(self, code: str, stage: str):
        super().__init__(code, stage, 403)
