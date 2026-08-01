"""Implementation-backed transcript factory for Experiment 1.

The experiment is a bulk linkability analysis, not an 80-download throughput
test.  It therefore constructs the public transcript with the production
pySim/AURA models and cryptographic field formulas, while omitting the costly
pairing proof body and network transport already covered by integration tests.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


class IntegratedTranscriptFactory:
    def __init__(self, integration_root: Path, tokens: Any):
        self.root = integration_root.resolve()
        if not (self.root / "pySim" / "esim" / "aura").is_dir():
            raise FileNotFoundError(
                f"pySim AURA integration source not found: {self.root}"
            )
        root_text = str(self.root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)

        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from py_ecc.optimized_bls12_381 import curve_order, multiply
        from pySim.esim.aura.binding import build_binding
        from pySim.esim.aura.codec import (
            b64d,
            b64e,
            canonical,
            g1_to_b64,
            scalar_from_b64,
            scalar_to_b64,
            sha256_hex,
        )
        from pySim.esim.aura.context import (
            auth_message_hash,
            build_ctx_t,
            capability_transcript,
            ctx_auth,
            gamma_for,
        )
        from pySim.esim.aura.models import AuraOrderContext
        from pySim.esim.aura.primitives import (
            ed25519_public_b64,
            ed25519_sign,
            p256_public_b64,
        )
        from pySim.esim.aura.proof import G_V, lph_base

        self.tokens = tokens
        self.ec = ec
        self.ed25519 = ed25519
        self.curve_order = curve_order
        self.multiply = multiply
        self.build_binding = build_binding
        self.b64d = b64d
        self.b64e = b64e
        self.canonical = canonical
        self.g1_to_b64 = g1_to_b64
        self.scalar_from_b64 = scalar_from_b64
        self.scalar_to_b64 = scalar_to_b64
        self.sha256_hex = sha256_hex
        self.auth_message_hash = auth_message_hash
        self.build_ctx_t = build_ctx_t
        self.capability_transcript = capability_transcript
        self.ctx_auth = ctx_auth
        self.gamma_for = gamma_for
        self.AuraOrderContext = AuraOrderContext
        self.ed25519_public_b64 = ed25519_public_b64
        self.ed25519_sign = ed25519_sign
        self.p256_public_b64 = p256_public_b64
        self.G_V = G_V
        self.lph_base = lph_base

        self.config = json.loads(
            (self.root / "config" / "aura.json").read_text(encoding="utf-8")
        )
        self.capabilities = list(self.config["capabilities"])
        self.selected_mode = self.capabilities[0]

    def _scalar(self, domain: str, index: str) -> int:
        value = int.from_bytes(self.tokens.raw(domain, index, 32), "big")
        return value % self.curve_order or 1

    def _p256_private(self, domain: str, index: str):
        value = int.from_bytes(self.tokens.raw(domain, index, 32), "big")
        value = value % P256_ORDER or 1
        return self.ec.derive_private_key(value, self.ec.SECP256R1())

    def standard_device_identity(self, device_id: str, eid: str) -> dict[str, str]:
        private_key = self._p256_private("standard-euicc-key", device_id)
        public_key = self.p256_public_b64(private_key.public_key())
        certificate_record = {
            "domain": "SGP.22/test-euicc-certificate-record",
            "eid": eid,
            "public_key": public_key,
        }
        return {
            "eid": eid,
            "euicc_certificate_fingerprint": self.sha256_hex(
                self.canonical(certificate_record)
            ),
            "euicc_public_key_fingerprint": self.sha256_hex(
                self.b64d(public_key)
            ),
        }

    def standard_auth_hash(
        self,
        *,
        transaction_id: str,
        identity: dict[str, str],
        logical_id: str,
    ) -> str:
        public_auth_record = {
            "domain": "SGP.22/test-euicc-authentication",
            "transactionId": transaction_id,
            "eid": identity["eid"],
            "certificate_fingerprint": identity[
                "euicc_certificate_fingerprint"
            ],
            "challenge": self.b64e(
                self.tokens.raw("standard-auth-challenge", logical_id, 32)
            ),
        }
        return self.sha256_hex(self.canonical(public_auth_record))

    def aura_public_fields(
        self,
        *,
        device_id: str,
        logical_id: str,
        transaction_id: str,
        pid_h: str,
        timestamp: int,
    ) -> dict[str, Any]:
        x = self._scalar("aura-hidden-x", device_id)
        k = self._scalar("aura-trace-k", device_id)
        eta = self._scalar("aura-ticket-eta", logical_id)
        d_value = self._scalar("aura-ticket-d", logical_id)
        salt_p = self.tokens.raw("aura-profile-salt", logical_id, 32)
        salt_p_b64 = self.b64e(salt_p)

        nu = self.g1_to_b64(self.multiply(self.G_V, eta))
        lph = self.g1_to_b64(
            self.multiply(self.lph_base(pid_h, salt_p), x)
        )
        opid = self.b64e(self.tokens.raw("aura-opid", logical_id, 16))

        one_time_private = self.ed25519.Ed25519PrivateKey.from_private_bytes(
            self.tokens.raw("aura-vk-t", logical_id, 32)
        )
        vk_t = self.ed25519_public_b64(one_time_private.public_key())
        session_private = self._p256_private("aura-session-p256", logical_id)
        session_public = self.p256_public_b64(session_private.public_key())

        order = self.AuraOrderContext(
            I_ac="IAC-" + self.tokens.hex(
                "aura-iac", logical_id, 16
            ).upper(),
            matching_id="MID-" + self.tokens.hex(
                "matching-id", logical_id, 12
            ),
            sid=str(self.config["sid"]),
            pid_h=pid_h,
            op="download",
            exp=timestamp + int(self.config["ticket_valid_minutes"]) * 60,
            PRaddr=str(self.config["praddr"]),
        )
        i_t = self.b64e(self.tokens.raw("aura-I-t", logical_id, 16))
        n_u = self.b64e(self.tokens.raw("aura-N-U", logical_id, 16))
        n_s = self.b64e(self.tokens.raw("aura-N-S", logical_id, 32))
        cap = self.capability_transcript(
            self.capabilities, self.selected_mode
        )
        cred_exp = timestamp + int(self.config["credential_valid_days"]) * 86400
        ctx_t = self.build_ctx_t(
            transaction_id=transaction_id,
            i_t=i_t,
            n_s=n_s,
            n_u=n_u,
            server_oid=str(self.config["server_oid"]),
            order=order,
            salt_p=salt_p_b64,
            lph=lph,
            nu=nu,
            opid=opid,
            vk_t_hash=self.sha256_hex(self.b64d(vk_t)),
            cap=cap,
            cred_exp=cred_exp,
        )
        gamma = self.gamma_for(ctx_t)
        c_value = self.scalar_to_b64(
            (
                d_value
                + self.scalar_from_b64(gamma) * k
            )
            % self.curve_order
        )
        tau_payload = self.ctx_auth(ctx_t, gamma, c_value)
        tau_auth = self.ed25519_sign(one_time_private, tau_payload)

        # The full randomized BBS+ proof is deliberately not generated 80 times.
        # These are exactly the production proof's public relation fields and
        # canonical context, which are the only inputs needed for linkability.
        proof_public_handle = {
            "domain": "AURA-RSP-v14/Pi_auth-public-handle",
            "ctx_auth": tau_payload,
            "v": nu,
            "lph": lph,
            "gamma": gamma,
            "c": c_value,
        }
        auth_message = {
            "transactionId": transaction_id,
            "salt_p": salt_p_b64,
            "lph": lph,
            "nu": nu,
            "opid": opid,
            "vk_t": vk_t,
            "cred_exp": cred_exp,
            "gamma": gamma,
            "c": c_value,
            "tau_auth": tau_auth,
            "Pi_auth": proof_public_handle,
        }
        _, ctx_bind = self.build_binding(ctx_t, auth_message)

        return {
            "I_ac": order.I_ac,
            "I_t": i_t,
            "sid": order.sid,
            "pid_h": order.pid_h,
            "op": order.op,
            "nu": nu,
            "lph": lph,
            "opid": opid,
            "vk_t": vk_t,
            "proof_hash": self.auth_message_hash(proof_public_handle),
            # ECDSA signatures are randomized. For deterministic controlled
            # datasets, hash the exact production ctx_bind signed by Bind_t.
            "Bind_t_hash": self.sha256_hex(self.canonical(ctx_bind)),
            "session_public_key": session_public,
            "N_U": n_u,
            "N_S": n_s,
            "serverOID": str(self.config["server_oid"]),
            "PRaddr": order.PRaddr,
            "cap": cap,
        }

    def audit(self) -> dict[str, Any]:
        relative_files = (
            "pySim/esim/aura/models.py",
            "pySim/esim/aura/context.py",
            "pySim/esim/aura/proof.py",
            "pySim/esim/aura/primitives.py",
            "pySim/esim/aura/binding.py",
        )
        source_hashes = {}
        for relative in relative_files:
            path = self.root / relative
            source_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "implementation": "pysim-aura-integration",
            "protocol": self.config["protocol"],
            "source_directory": self.root.name,
            "production_modules": list(relative_files),
            "production_source_sha256": source_hashes,
            "capabilities": self.capabilities,
            "bulk_method": "production_public_transcript_construction",
            "full_https_download_per_transaction": False,
            "full_randomized_pairing_proof_per_transaction": False,
            "proof_scope": (
                "production ctx_t, nu, lph, gamma, c, tau_auth and binding "
                "context; randomized BBS+ proof body omitted"
            ),
        }
