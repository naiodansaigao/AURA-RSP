"""Adapter from Experiment 3 to the integrated pySim/osmo-smdpp AURA code."""

from __future__ import annotations

import copy
import hashlib
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DeviceMaterial:
    index: int
    eid: str
    x: int
    k: int
    cred_exp: int
    credential_signature: Any


@dataclass(frozen=True)
class TicketMaterial:
    round_index: int
    owner_index: int
    order: Any
    x: int
    eta: int
    d_value: int
    token_signature: Any
    salt_p: bytes
    ctx_t: dict


class IntegratedTicketTransferAdapter:
    """Issue and test credentials/tickets using the integrated implementation."""

    def __init__(self, integration_root: Path, seed: int):
        self.root = integration_root.resolve()
        if not (self.root / "pySim" / "esim" / "aura" / "proof.py").is_file():
            raise FileNotFoundError(f"integrated pySim AURA source missing: {self.root}")
        root_text = str(self.root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)

        from py_ecc.optimized_bls12_381 import G2, curve_order, multiply
        from pySim.esim.aura.bbs import (
            blind_sign,
            create_blind_commitment,
            finalize_blind_signature,
            public_key_to_dict,
            verify_signature,
        )
        from pySim.esim.aura.codec import b64e, g1_to_b64, sha256_hex
        from pySim.esim.aura.context import build_ctx_t, capability_transcript
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

        from ablation import (
            create_auth_proof_without_secret_binding,
            verify_auth_proof_without_secret_binding,
        )

        self.seed = int(seed)
        self.G2 = G2
        self.curve_order = curve_order
        self.multiply = multiply
        self.blind_sign = blind_sign
        self.create_blind_commitment = create_blind_commitment
        self.finalize_blind_signature = finalize_blind_signature
        self.public_key_to_dict = public_key_to_dict
        self.verify_signature = verify_signature
        self.b64e = b64e
        self.g1_to_b64 = g1_to_b64
        self.sha256_hex = sha256_hex
        self.build_ctx_t = build_ctx_t
        self.capability_transcript = capability_transcript
        self.AuraOrderContext = AuraOrderContext
        self.CRED_PARAMS = CRED_PARAMS
        self.TOKEN_PARAMS = TOKEN_PARAMS
        self.G_V = G_V
        self.create_auth_proof = create_auth_proof
        self.credential_messages = credential_messages
        self.lph_base = lph_base
        self.token_messages = token_messages
        self.token_public_messages = token_public_messages
        self.verify_auth_proof = verify_auth_proof
        self.create_ablation_proof = create_auth_proof_without_secret_binding
        self.verify_ablation_proof = verify_auth_proof_without_secret_binding

        config_path = self.root / "config" / "aura.json"
        import json

        self.config = json.loads(config_path.read_text(encoding="utf-8"))
        profile = ProfileRepository(self.root / "smdpp-data" / "upp").load(
            self.config["matching_id"]
        )
        self.profile_sha256 = profile.sha256
        self.profile_bytes = len(profile.data)

        self.eum_secret = self.scalar("authority:eum", "0")
        self.mno_secret = self.scalar("authority:mno", "0")
        self.eum_public = self.multiply(self.G2, self.eum_secret)
        self.mno_public = self.multiply(self.G2, self.mno_secret)

    def raw(self, domain: str, index: str, length: int = 32) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hashlib.sha256(
                    f"EXP03|{self.seed}|{domain}|{index}|{counter}".encode("utf-8")
                ).digest()
            )
            counter += 1
        return bytes(output[:length])

    def scalar(self, domain: str, index: str) -> int:
        return int.from_bytes(self.raw(domain, index), "big") % self.curve_order or 1

    def issue_device(self, index: int) -> DeviceMaterial:
        x = self.scalar("device:x", str(index))
        k = self.scalar("device:k", str(index))
        cred_exp = 2_100_000_000
        context = {"type": "Cred_D", "cred_exp": cred_exp}
        blind_proof, s_user = self.create_blind_commitment(
            self.CRED_PARAMS, {0: x}, context
        )
        blind_signature = self.blind_sign(
            self.CRED_PARAMS,
            self.eum_secret,
            blind_proof,
            {1: k, 2: cred_exp},
            context,
        )
        signature = self.finalize_blind_signature(blind_signature, s_user)
        if not self.verify_signature(
            self.CRED_PARAMS,
            self.eum_public,
            self.credential_messages(x, k, cred_exp),
            signature,
        ):
            raise RuntimeError(f"credential verification failed for device {index}")
        eid_suffix = int.from_bytes(self.raw("device:eid", str(index), 14), "big")
        eid = "89" + f"{eid_suffix:030d}"[-30:]
        return DeviceMaterial(index, eid, x, k, cred_exp, signature)

    def issue_ticket(
        self, round_index: int, owner: DeviceMaterial
    ) -> TicketMaterial:
        order = self.AuraOrderContext(
            I_ac=(
                f"IAC-R{round_index:02d}-D{owner.index:03d}-"
                + self.raw("ticket:iac", f"{round_index}:{owner.index}", 8).hex().upper()
            ),
            matching_id=self.config["matching_id"],
            sid=self.config["sid"],
            pid_h=self.profile_sha256,
            op="download",
            exp=2_000_000_000 + round_index,
            PRaddr=self.config["praddr"],
        )
        eta = self.scalar("ticket:eta", f"{round_index}:{owner.index}")
        d_value = self.scalar("ticket:d", f"{round_index}:{owner.index}")
        public_ticket = order.ticket_public()
        context = {"type": "Tok_op", "ticket": public_ticket}
        blind_proof, s_user = self.create_blind_commitment(
            self.TOKEN_PARAMS,
            {6: owner.x, 7: eta, 8: d_value},
            context,
        )
        blind_signature = self.blind_sign(
            self.TOKEN_PARAMS,
            self.mno_secret,
            blind_proof,
            {
                i: value
                for i, value in enumerate(self.token_public_messages(public_ticket))
            },
            context,
        )
        signature = self.finalize_blind_signature(blind_signature, s_user)
        if not self.verify_signature(
            self.TOKEN_PARAMS,
            self.mno_public,
            self.token_messages(public_ticket, owner.x, eta, d_value),
            signature,
        ):
            raise RuntimeError(
                f"ticket verification failed for round {round_index}, device {owner.index}"
            )
        salt_p = self.raw("ticket:salt", f"{round_index}:{owner.index}")
        nu = self.g1_to_b64(self.multiply(self.G_V, eta))
        lph = self.g1_to_b64(
            self.multiply(self.lph_base(order.pid_h, salt_p), owner.x)
        )
        ctx_t = self.build_ctx_t(
            transaction_id=self.raw(
                "ctx:transaction", f"{round_index}:{owner.index}", 16
            ).hex().upper(),
            i_t=self.b64e(self.raw("ctx:it", f"{round_index}:{owner.index}")),
            n_s=self.b64e(self.raw("ctx:ns", f"{round_index}:{owner.index}")),
            n_u=self.b64e(self.raw("ctx:nu", f"{round_index}:{owner.index}")),
            server_oid=self.config["server_oid"],
            order=order,
            salt_p=self.b64e(salt_p),
            lph=lph,
            nu=nu,
            opid=self.b64e(self.raw("ctx:opid", f"{round_index}:{owner.index}", 16)),
            vk_t_hash=self.sha256_hex(
                self.raw("ctx:vkt", f"{round_index}:{owner.index}")
            ),
            cap=self.capability_transcript(
                self.config["capabilities"], self.config["capabilities"][0]
            ),
            cred_exp=owner.cred_exp,
        )
        return TicketMaterial(
            round_index,
            owner.index,
            order,
            owner.x,
            eta,
            d_value,
            signature,
            salt_p,
            ctx_t,
        )

    def build_full_proof(
        self, ticket: TicketMaterial, device: DeviceMaterial
    ) -> tuple[dict | None, float, str]:
        ctx_t = self.context_for_device(ticket, device)
        started = time.perf_counter_ns()
        try:
            proof = self.create_auth_proof(
                ctx_t=ctx_t,
                eum_public_key=self.eum_public,
                mno_public_key=self.mno_public,
                cred_signature=device.credential_signature,
                token_signature=ticket.token_signature,
                x=device.x,
                k=device.k,
                eta=ticket.eta,
                d_value=ticket.d_value,
                cred_exp=device.cred_exp,
                salt_p=ticket.salt_p,
            )
            return proof, (time.perf_counter_ns() - started) / 1_000_000, "ok"
        except Exception as exc:
            return (
                None,
                (time.perf_counter_ns() - started) / 1_000_000,
                f"{type(exc).__name__}: {exc}",
            )

    def build_ablation_proof(
        self,
        ticket: TicketMaterial,
        ticket_owner: DeviceMaterial,
        target: DeviceMaterial,
    ) -> tuple[dict | None, float, str]:
        ctx_t = self.context_for_device(ticket, target)
        started = time.perf_counter_ns()
        try:
            proof = self.create_ablation_proof(
                ctx_t=ctx_t,
                eum_public_key=self.eum_public,
                mno_public_key=self.mno_public,
                cred_signature=target.credential_signature,
                token_signature=ticket.token_signature,
                credential_x=target.x,
                ticket_x=ticket_owner.x,
                k=target.k,
                eta=ticket.eta,
                d_value=ticket.d_value,
                cred_exp=target.cred_exp,
                salt_p=ticket.salt_p,
            )
            return proof, (time.perf_counter_ns() - started) / 1_000_000, "ok"
        except Exception as exc:
            return (
                None,
                (time.perf_counter_ns() - started) / 1_000_000,
                f"{type(exc).__name__}: {exc}",
            )

    def verify_full(
        self, ticket: TicketMaterial, proof: dict, ctx_t: dict | None = None
    ) -> tuple[bool, str, float]:
        started = time.perf_counter_ns()
        accepted, reason = self.verify_auth_proof(
            ctx_t=ctx_t or ticket.ctx_t,
            proof=proof,
            eum_public_key=self.eum_public,
            mno_public_key=self.mno_public,
            salt_p=ticket.salt_p,
        )
        return accepted, reason, (time.perf_counter_ns() - started) / 1_000_000

    def verify_ablation(
        self, ticket: TicketMaterial, proof: dict, ctx_t: dict | None = None
    ) -> tuple[bool, str, float]:
        started = time.perf_counter_ns()
        accepted, reason = self.verify_ablation_proof(
            ctx_t=ctx_t or ticket.ctx_t,
            proof=proof,
            eum_public_key=self.eum_public,
            mno_public_key=self.mno_public,
            salt_p=ticket.salt_p,
        )
        return accepted, reason, (time.perf_counter_ns() - started) / 1_000_000

    @staticmethod
    def splice_forced_transfer(owner_proof: dict, target_proof: dict) -> dict:
        """Create a forced invalid submission from two independently valid proofs."""

        invalid = copy.deepcopy(owner_proof)
        invalid["cred"] = copy.deepcopy(target_proof["cred"])
        return invalid

    def context_for_device(
        self, ticket: TicketMaterial, device: DeviceMaterial
    ) -> dict:
        """Return the request context that the target device would actually send."""

        context = copy.deepcopy(ticket.ctx_t)
        context["lph"] = self.g1_to_b64(
            self.multiply(self.lph_base(ticket.order.pid_h, ticket.salt_p), device.x)
        )
        context["cred_exp"] = int(device.cred_exp)
        return context

    def source_audit(self) -> dict:
        paths = [
            self.root / "pySim" / "esim" / "aura" / "bbs.py",
            self.root / "pySim" / "esim" / "aura" / "proof.py",
            self.root / "pySim" / "esim" / "aura" / "service.py",
        ]
        return {
            "integration_root": "../../pysim-aura-integration",
            "modules": {
                str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in paths
            },
            "profile_sha256": self.profile_sha256,
            "profile_bytes": self.profile_bytes,
        }

    def process_verifier_fixture(
        self,
        *,
        ticket: TicketMaterial,
        valid_proof: dict,
        valid_context: dict,
        invalid_proof: dict,
    ) -> dict:
        """Return a JSON/pickle-safe fixture for production verifier workers."""

        return {
            "ctx_t": valid_context,
            "valid_proof": valid_proof,
            "invalid_proof": invalid_proof,
            "eum_public_key": self.public_key_to_dict(self.eum_public),
            "mno_public_key": self.public_key_to_dict(self.mno_public),
            "salt_p": self.b64e(ticket.salt_p),
        }
