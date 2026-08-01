"""Typed AURA-RSP protocol and session state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AuraOrderContext:
    I_ac: str
    matching_id: str
    sid: str
    pid_h: str
    op: str
    exp: int
    PRaddr: str

    def ticket_public(self) -> dict[str, Any]:
        return {
            "I_ac": self.I_ac,
            "sid": self.sid,
            "pid_h": self.pid_h,
            "op": self.op,
            "exp": self.exp,
            "PRaddr": self.PRaddr,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuraOrderContext":
        return cls(
            I_ac=str(value["I_ac"]),
            matching_id=str(value["matching_id"]),
            sid=str(value["sid"]),
            pid_h=str(value["pid_h"]),
            op=str(value["op"]),
            exp=int(value["exp"]),
            PRaddr=str(value["PRaddr"]),
        )


@dataclass
class AuraCredentialState:
    x: str = field(repr=False)
    k: str = field(repr=False)
    cred_exp: int
    credential_signature: dict[str, Any] = field(repr=False)


@dataclass
class AuraTicketState:
    order: AuraOrderContext
    eta: str = field(repr=False)
    d: str = field(repr=False)
    token_signature: dict[str, Any] = field(repr=False)
    nu: str | None = None


@dataclass
class AuraAuthTranscript:
    ctx_t: dict[str, Any]
    auth_request: dict[str, Any]
    auth_hash: str
    nu: str
    gamma: str
    c_value: str
    opid: str
    vk_t: str


@dataclass
class AuraBindingState:
    th_auth: str
    ctx_bind: dict[str, Any]
    bind_t: str


@dataclass
class AuraKeyState:
    mode: str
    q_u: str
    q_s: str
    ctx_k: dict[str, Any]
    k_mac: bytes = field(repr=False)
    k_enc: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuraInstallReceipt:
    lph: str
    st_old: int
    st_new: int
    ctr_new: int
    last_hash_old: str
    rid_inst: str
    tag_inst: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuraSessionState:
    transaction_id: str
    order: AuraOrderContext
    server_auth: dict[str, Any]
    status: str = "initiated"
    auth: AuraAuthTranscript | None = None
    binding: AuraBindingState | None = None
    key_state: AuraKeyState | None = None
    cached_auth_response: dict[str, Any] | None = None
    profile_ciphertext_hash: str | None = None
    created_at: int = 0
