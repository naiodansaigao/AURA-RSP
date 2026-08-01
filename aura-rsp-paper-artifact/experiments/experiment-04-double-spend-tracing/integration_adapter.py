"""Experiment 4 adapter for the integrated pySim/osmo-smdpp AURA code."""

from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TraceTranscript:
    index: int
    ctx_t: dict
    proof: dict
    auth_hash: str
    opid: str


class IntegratedDoubleSpendAdapter:
    def __init__(self, integration_root: Path, seed: int):
        self.root = integration_root.resolve()
        if not (self.root / "pySim" / "esim" / "aura" / "service.py").is_file():
            raise FileNotFoundError(f"integrated AURA source missing: {self.root}")
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))

        from py_ecc.optimized_bls12_381 import G2, curve_order, multiply
        from pySim.esim.aura.bbs import (
            blind_sign,
            create_blind_commitment,
            finalize_blind_signature,
            verify_signature,
        )
        from pySim.esim.aura.codec import b64e, canonical, g1_to_b64, scalar_to_b64, sha256_hex
        from pySim.esim.aura.context import auth_message_hash, build_ctx_t, capability_transcript
        from pySim.esim.aura.double_spend import classify_nullifier, recover_trace_key
        from pySim.esim.aura.models import AuraOrderContext
        from pySim.esim.aura.proof import (
            CRED_PARAMS,
            G_V,
            TOKEN_PARAMS,
            create_auth_proof,
            credential_messages,
            lph_base,
            token_messages,
            token_public_messages,
            verify_auth_proof,
        )
        from pySim.esim.profile_store import ProfileRepository

        import json

        self.seed = int(seed)
        self.G2 = G2
        self.curve_order = curve_order
        self.multiply = multiply
        self.blind_sign = blind_sign
        self.create_blind_commitment = create_blind_commitment
        self.finalize_blind_signature = finalize_blind_signature
        self.verify_signature = verify_signature
        self.b64e = b64e
        self.canonical = canonical
        self.g1_to_b64 = g1_to_b64
        self.scalar_to_b64 = scalar_to_b64
        self.sha256_hex = sha256_hex
        self.auth_message_hash = auth_message_hash
        self.build_ctx_t = build_ctx_t
        self.capability_transcript = capability_transcript
        self.classify_nullifier = classify_nullifier
        self.recover_trace_key = recover_trace_key
        self.AuraOrderContext = AuraOrderContext
        self.CRED_PARAMS = CRED_PARAMS
        self.G_V = G_V
        self.TOKEN_PARAMS = TOKEN_PARAMS
        self.create_auth_proof = create_auth_proof
        self.credential_messages = credential_messages
        self.lph_base = lph_base
        self.token_messages = token_messages
        self.token_public_messages = token_public_messages
        self.verify_auth_proof = verify_auth_proof

        self.config = json.loads((self.root / "config" / "aura.json").read_text(encoding="utf-8"))
        profile = ProfileRepository(self.root / "smdpp-data" / "upp").load(
            self.config["matching_id"]
        )
        self.profile_sha256 = profile.sha256
        self.profile_bytes = len(profile.data)

        self.eum_secret = self.scalar("authority:eum")
        self.mno_secret = self.scalar("authority:mno")
        self.eum_public = self.multiply(self.G2, self.eum_secret)
        self.mno_public = self.multiply(self.G2, self.mno_secret)
        self.x = self.scalar("device:x")
        self.k = self.scalar("device:k")
        self.eta = self.scalar("ticket:eta")
        self.d_value = self.scalar("ticket:d")
        self.cred_exp = 2_100_000_000
        self.eid = "89" + f"{int.from_bytes(self.raw('device:eid', 14), 'big'):030d}"[-30:]
        self.r_tr = self.b64e(self.raw("trace:r-tr"))
        self.salt_p = self.raw("ticket:salt")
        self._issue_material()

    def raw(self, label: str, length: int = 32) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hashlib.sha256(
                    f"EXP04|{self.seed}|{label}|{counter}".encode("utf-8")
                ).digest()
            )
            counter += 1
        return bytes(output[:length])

    def scalar(self, label: str) -> int:
        return int.from_bytes(self.raw(label), "big") % self.curve_order or 1

    def _issue_material(self) -> None:
        cred_context = {"type": "Cred_D", "cred_exp": self.cred_exp}
        commitment, s_user = self.create_blind_commitment(
            self.CRED_PARAMS, {0: self.x}, cred_context
        )
        blind = self.blind_sign(
            self.CRED_PARAMS,
            self.eum_secret,
            commitment,
            {1: self.k, 2: self.cred_exp},
            cred_context,
        )
        self.credential_signature = self.finalize_blind_signature(blind, s_user)
        if not self.verify_signature(
            self.CRED_PARAMS,
            self.eum_public,
            self.credential_messages(self.x, self.k, self.cred_exp),
            self.credential_signature,
        ):
            raise RuntimeError("integrated credential verification failed")

        self.order = self.AuraOrderContext(
            I_ac="EXP04-" + self.raw("ticket:iac", 8).hex().upper(),
            matching_id=self.config["matching_id"],
            sid=self.config["sid"],
            pid_h=self.profile_sha256,
            op="download",
            exp=2_100_000_000,
            PRaddr=self.config["praddr"],
        )
        public_ticket = self.order.ticket_public()
        ticket_context = {"type": "Tok_op", "ticket": public_ticket}
        commitment, s_user = self.create_blind_commitment(
            self.TOKEN_PARAMS,
            {6: self.x, 7: self.eta, 8: self.d_value},
            ticket_context,
        )
        blind = self.blind_sign(
            self.TOKEN_PARAMS,
            self.mno_secret,
            commitment,
            {i: value for i, value in enumerate(self.token_public_messages(public_ticket))},
            ticket_context,
        )
        self.token_signature = self.finalize_blind_signature(blind, s_user)
        if not self.verify_signature(
            self.TOKEN_PARAMS,
            self.mno_public,
            self.token_messages(public_ticket, self.x, self.eta, self.d_value),
            self.token_signature,
        ):
            raise RuntimeError("integrated ticket verification failed")

        self.nu = self.g1_to_b64(self.multiply(self.G_V, self.eta))
        self.lph = self.g1_to_b64(
            self.multiply(self.lph_base(self.order.pid_h, self.salt_p), self.x)
        )

    def build_transcript(self, index: int) -> tuple[TraceTranscript, float]:
        opid = self.b64e(self.raw(f"transcript:{index}:opid", 16))
        ctx_t = self.build_ctx_t(
            transaction_id=self.raw(f"transcript:{index}:tx", 16).hex().upper(),
            i_t=self.b64e(self.raw(f"transcript:{index}:it")),
            n_s=self.b64e(self.raw(f"transcript:{index}:ns")),
            n_u=self.b64e(self.raw(f"transcript:{index}:nu")),
            server_oid=self.config["server_oid"],
            order=self.order,
            salt_p=self.b64e(self.salt_p),
            lph=self.lph,
            nu=self.nu,
            opid=opid,
            vk_t_hash=self.sha256_hex(self.raw(f"transcript:{index}:vkt")),
            cap=self.capability_transcript(
                self.config["capabilities"], self.config["capabilities"][0]
            ),
            cred_exp=self.cred_exp,
        )
        started = time.perf_counter_ns()
        proof = self.create_auth_proof(
            ctx_t=ctx_t,
            eum_public_key=self.eum_public,
            mno_public_key=self.mno_public,
            cred_signature=self.credential_signature,
            token_signature=self.token_signature,
            x=self.x,
            k=self.k,
            eta=self.eta,
            d_value=self.d_value,
            cred_exp=self.cred_exp,
            salt_p=self.salt_p,
        )
        generation_ms = (time.perf_counter_ns() - started) / 1_000_000
        message = {
            "transactionId": ctx_t["transactionId"],
            "nu": self.nu,
            "opid": opid,
            "gamma": proof["gamma"],
            "c": proof["c"],
            "Pi_auth": proof,
        }
        return (
            TraceTranscript(
                index=index,
                ctx_t=ctx_t,
                proof=proof,
                auth_hash=self.auth_message_hash(message),
                opid=opid,
            ),
            generation_ms,
        )

    def verify_transcript(self, transcript: TraceTranscript) -> tuple[bool, str, float]:
        started = time.perf_counter_ns()
        accepted, reason = self.verify_auth_proof(
            ctx_t=transcript.ctx_t,
            proof=transcript.proof,
            eum_public_key=self.eum_public,
            mno_public_key=self.mno_public,
            salt_p=self.salt_p,
        )
        return accepted, reason, (time.perf_counter_ns() - started) / 1_000_000

    def trace_key_b64(self) -> str:
        return self.scalar_to_b64(self.k)

    def source_audit(self) -> dict[str, Any]:
        paths = [
            self.root / "pySim" / "esim" / "aura" / "proof.py",
            self.root / "pySim" / "esim" / "aura" / "double_spend.py",
            self.root / "pySim" / "esim" / "aura" / "service.py",
            self.root / "pySim" / "esim" / "aura" / "store.py",
        ]
        return {
            "implementation": "pysim-osmo-smdpp-integrated-aura",
            "integration_root": "../../pysim-aura-integration",
            "modules": {
                str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in paths
            },
            "profile_sha256": self.profile_sha256,
            "profile_bytes": self.profile_bytes,
        }
