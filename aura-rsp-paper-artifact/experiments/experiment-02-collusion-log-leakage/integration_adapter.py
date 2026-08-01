"""pySim/AURA implementation-backed log factory for Experiment 2.

Experiment 2 is a bulk privacy-impact analysis rather than a throughput test.
It derives protocol-visible download fields and lifecycle receipts from the
integrated production modules, while full HTTPS closed-loop execution remains
covered by the integration regression suite.
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


class IntegratedLogFactory:
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
        from pySim.esim.aura.lifecycle import (
            STATE_ENABLED,
            STATE_INSTALLED,
            create_state_receipt,
            operation_rid,
            state_last_hash,
        )
        from pySim.esim.aura.models import AuraOrderContext
        from pySim.esim.aura.primitives import (
            ed25519_public_b64,
            ed25519_sign,
            p256_public_b64,
        )
        from pySim.esim.aura.proof import G_V, lph_base
        from pySim.esim.aura.receipt import (
            ZERO_HASH,
            create_install_receipt,
            initial_last_hash,
        )

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
        self.STATE_ENABLED = STATE_ENABLED
        self.STATE_INSTALLED = STATE_INSTALLED
        self.create_state_receipt = create_state_receipt
        self.operation_rid = operation_rid
        self.state_last_hash = state_last_hash
        self.AuraOrderContext = AuraOrderContext
        self.ed25519_public_b64 = ed25519_public_b64
        self.ed25519_sign = ed25519_sign
        self.p256_public_b64 = p256_public_b64
        self.G_V = G_V
        self.lph_base = lph_base
        self.ZERO_HASH = ZERO_HASH
        self.create_install_receipt = create_install_receipt
        self.initial_last_hash = initial_last_hash

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

    def _operation_context(
        self,
        *,
        device_id: str,
        logical_id: str,
        transaction_id: str,
        pid_h: str,
        timestamp: int,
        op: str,
        salt_p: bytes,
        lph: str,
        suffix: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        k = self._scalar("aura-trace-k", device_id)
        eta = self._scalar(f"aura-ticket-eta-{op}", logical_id)
        d_value = self._scalar(f"aura-ticket-d-{op}", logical_id)
        nu = self.g1_to_b64(self.multiply(self.G_V, eta))
        opid = self.b64e(self.tokens.raw(f"aura-opid-{op}", logical_id, 16))

        one_time_private = self.ed25519.Ed25519PrivateKey.from_private_bytes(
            self.tokens.raw(f"aura-vk-t-{op}", logical_id, 32)
        )
        vk_t = self.ed25519_public_b64(one_time_private.public_key())
        order = self.AuraOrderContext(
            I_ac="IAC-"
            + self.tokens.hex(f"aura-iac-{op}", logical_id, 16).upper(),
            matching_id="MID-"
            + self.tokens.hex(f"matching-id-{op}", logical_id, 12),
            sid=str(self.config["sid"]),
            pid_h=pid_h,
            op=op,
            exp=timestamp + int(self.config["ticket_valid_minutes"]) * 60,
            PRaddr=str(self.config["praddr"]),
        )
        i_t = self.b64e(self.tokens.raw(f"aura-I-t-{op}", logical_id, 16))
        n_u = self.b64e(self.tokens.raw(f"aura-N-U-{op}", logical_id, 16))
        n_s = self.b64e(self.tokens.raw(f"aura-N-S-{op}", logical_id, 32))
        cap = self.capability_transcript(self.capabilities, self.selected_mode)
        cred_exp = timestamp + int(self.config["credential_valid_days"]) * 86400
        ctx_t = self.build_ctx_t(
            transaction_id=transaction_id,
            i_t=i_t,
            n_s=n_s,
            n_u=n_u,
            server_oid=str(self.config["server_oid"]),
            order=order,
            salt_p=self.b64e(salt_p),
            lph=lph,
            nu=nu,
            opid=opid,
            vk_t_hash=self.sha256_hex(self.b64d(vk_t)),
            cap=cap,
            cred_exp=cred_exp,
        )
        gamma = self.gamma_for(ctx_t)
        c_value = self.scalar_to_b64(
            (d_value + self.scalar_from_b64(gamma) * k) % self.curve_order
        )
        tau_payload = self.ctx_auth(ctx_t, gamma, c_value)
        tau_auth = self.ed25519_sign(one_time_private, tau_payload)
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
            "salt_p": self.b64e(salt_p),
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
        bind_handle = self.b64e(hashlib.sha256(self.canonical(ctx_bind)).digest())
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
            "Bind_t_hash": self.sha256_hex(self.canonical(ctx_bind)),
            "session_public_key": self.p256_public_b64(
                self._p256_private(
                    f"aura-session-p256-{op}", logical_id
                ).public_key()
            ),
            "N_U": n_u,
            "N_S": n_s,
            "serverOID": str(self.config["server_oid"]),
            "PRaddr": order.PRaddr,
            "cap": cap,
        }, {
            "ctx_t": ctx_t,
            "bind_handle": bind_handle,
            "suffix": suffix,
        }

    def aura_download_bundle(
        self,
        *,
        device_id: str,
        logical_id: str,
        transaction_id: str,
        pid_h: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        x = self._scalar("aura-hidden-x", device_id)
        salt_p = self.tokens.raw("aura-profile-salt", logical_id, 32)
        lph = self.g1_to_b64(self.multiply(self.lph_base(pid_h, salt_p), x))
        public, internal = self._operation_context(
            device_id=device_id,
            logical_id=logical_id,
            transaction_id=transaction_id,
            pid_h=pid_h,
            timestamp=timestamp,
            op="download",
            salt_p=salt_p,
            lph=lph,
            suffix="download",
        )

        ciphertext_hash = self.sha256_hex(
            self.canonical(
                {
                    "domain": "AURA-RSP-v14/bulk-profile-ciphertext-evidence",
                    "transactionId": transaction_id,
                    "pid_h": pid_h,
                }
            )
        )
        install_receipt = self.create_install_receipt(
            self.tokens.raw("aura-k-mac-install", logical_id, 32),
            lph=lph,
            ctx_t=internal["ctx_t"],
            bind_t=internal["bind_handle"],
            ciphertext_hash=ciphertext_hash,
        ).to_dict()
        installed_hash = self.initial_last_hash(install_receipt)

        enable_tx = self.tokens.hex("aura-enable-transaction", logical_id, 16).upper()
        _, enable_internal = self._operation_context(
            device_id=device_id,
            logical_id=logical_id,
            transaction_id=enable_tx,
            pid_h=pid_h,
            timestamp=timestamp + 20,
            op="enable",
            salt_p=salt_p,
            lph=lph,
            suffix="enable",
        )
        snapshot = {
            "lph": lph,
            "state": self.STATE_INSTALLED,
            "ctr": 1,
            "last_hash": installed_hash,
        }
        enable_rid = self.operation_rid(
            "enable",
            ctx_t=enable_internal["ctx_t"],
            bind_t=enable_internal["bind_handle"],
        )
        enable_receipt = self.create_state_receipt(
            self.tokens.raw("aura-k-mac-enable", logical_id, 32),
            op="enable",
            snapshot=snapshot,
            st_new=self.STATE_ENABLED,
            rid_op=enable_rid,
        )
        enabled_hash = self.state_last_hash(enable_receipt)

        lifecycle = [
            {
                "event": "downloaded",
                "counter": 0,
                "state": 0,
                "last_hash": self.ZERO_HASH,
                "receipt_hash": ciphertext_hash,
                "semantic_scope": "integrated_profile_delivery_audit",
            },
            {
                "event": "installed",
                "counter": 1,
                "state": self.STATE_INSTALLED,
                "last_hash": installed_hash,
                "receipt_hash": self.sha256_hex(self.canonical(install_receipt)),
                "semantic_scope": "integrated_authenticated_state_chain",
            },
            {
                "event": "enabled",
                "counter": 2,
                "state": self.STATE_ENABLED,
                "last_hash": enabled_hash,
                "receipt_hash": self.sha256_hex(self.canonical(enable_receipt)),
                "semantic_scope": "integrated_authenticated_state_chain",
            },
        ]
        return public, lifecycle

    def audit(self) -> dict[str, Any]:
        relative_files = (
            "pySim/esim/aura/models.py",
            "pySim/esim/aura/context.py",
            "pySim/esim/aura/proof.py",
            "pySim/esim/aura/binding.py",
            "pySim/esim/aura/receipt.py",
            "pySim/esim/aura/lifecycle.py",
        )
        source_hashes = {
            relative: hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
            for relative in relative_files
        }
        return {
            "implementation": "pysim-aura-integration",
            "protocol": self.config["protocol"],
            "source_directory": self.root.name,
            "production_modules": list(relative_files),
            "production_source_sha256": source_hashes,
            "capabilities": self.capabilities,
            "bulk_method": "production_public_log_and_state_receipt_construction",
            "full_https_download_per_transaction": False,
            "full_randomized_pairing_proof_per_transaction": False,
            "proof_scope": (
                "production ctx_t, BLS12-381 nu/lph, gamma/c, tau_auth, "
                "binding context, install receipt and enable state receipt; "
                "randomized BBS+ proof body omitted"
            ),
        }
