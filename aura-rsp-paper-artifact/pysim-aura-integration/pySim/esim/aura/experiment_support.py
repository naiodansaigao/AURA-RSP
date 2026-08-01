"""Test-only fixture that drives the integrated AuraService without HTTP.

Security decisions remain in the production service, proof, binding and key
agreement modules.  This helper only issues deterministic research material
and assembles well-formed requests for attack experiments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import time
from typing import Any

from py_ecc.optimized_bls12_381 import G2, curve_order, multiply
from pySim.esim.profile_store import ProfileRepository

from .bbs import (
    blind_sign,
    create_blind_commitment,
    finalize_blind_signature,
    public_key_to_dict,
)
from .codec import b64d, b64e, g1_to_b64, scalar_to_b64, save_json, sha256_hex
from .context import build_ctx_t, ctx_auth
from .errors import AuraProtocolError
from .models import AuraOrderContext
from .primitives import (
    ed25519_public_b64,
    ed25519_sign,
    generate_ed25519_private,
    generate_p256_private,
    p256_private_to_pem,
    p256_public_to_pem,
    p256_public_b64,
)
from .key_agreement import (
    CLASSICAL_MODE,
    HYBRID_MODE,
    generate_mlkem_keypair,
    ka_u_payload,
)
from .proof import (
    CRED_PARAMS,
    G_V,
    TOKEN_PARAMS,
    create_auth_proof,
    credential_messages,
    lph_base,
    token_messages,
    token_public_messages,
)
from .service import AuraService
from .store import AuraStore


@dataclass
class PreparedAuthentication:
    request: dict[str, Any]
    ctx_t: dict[str, Any]
    salt_p: bytes
    server_response: dict[str, Any]
    one_time_private: Any


class IntegratedAuraExperimentFixture:
    def __init__(
        self,
        *,
        integration_root: Path,
        runtime_root: Path,
        label: str,
        seed: int,
        sid: str,
        server_oid: str,
        praddr: str,
        op: str = "download",
        matching_id: str | None = None,
        capabilities: list[str] | None = None,
    ):
        self.integration_root = integration_root.resolve()
        self.root = runtime_root.resolve()
        self.label = label
        self.seed = int(seed)
        base_config = __import__("json").loads(
            (self.integration_root / "config" / "aura.json").read_text(encoding="utf-8")
        )
        self.matching_id = matching_id or base_config["matching_id"]
        self.profile_repository = ProfileRepository(
            self.integration_root / "smdpp-data" / "upp"
        )
        profile = self.profile_repository.load(self.matching_id)
        self.profile_sha256 = profile.sha256
        self.profile_bytes = len(profile.data)
        self.config = {
            "protocol": "AURA-RSP-v14-pysim-integration-experiment",
            "matching_id": self.matching_id,
            "sid": sid,
            "server_oid": server_oid,
            "praddr": praddr,
            "capabilities": capabilities or [CLASSICAL_MODE],
        }
        (self.root / "config").mkdir(parents=True, exist_ok=True)
        runtime = self.root / "runtime" / "aura"
        runtime.mkdir(parents=True, exist_ok=True)
        save_json(self.root / "config" / "aura.json", self.config)

        self.eum_secret = self.scalar("authority:eum")
        self.mno_secret = self.scalar("authority:mno")
        self.eum_public = multiply(G2, self.eum_secret)
        self.mno_public = multiply(G2, self.mno_secret)
        server_auth_key = generate_p256_private()
        binding_key = generate_p256_private()
        (runtime / "server-auth-key.pem").write_bytes(
            p256_private_to_pem(server_auth_key)
        )
        (runtime / "profile-binding-key.pem").write_bytes(
            p256_private_to_pem(binding_key)
        )
        save_json(
            runtime / "server-public.json",
            {
                "eum_public_key": public_key_to_dict(self.eum_public),
                "mno_public_key": public_key_to_dict(self.mno_public),
                "server_auth_public_pem": p256_public_to_pem(
                    server_auth_key.public_key()
                ).decode("ascii"),
                "profile_binding_public_pem": p256_public_to_pem(
                    binding_key.public_key()
                ).decode("ascii"),
            },
        )

        self.x = self.scalar("device:x")
        self.k = self.scalar("device:k")
        self.eta = self.scalar("ticket:eta")
        self.d_value = self.scalar("ticket:d")
        self.cred_exp = int(time.time()) + 86400
        self.eid = "89" + f"{int.from_bytes(self.raw('device:eid', 14), 'big'):030d}"[-30:]
        self.credential_signature = self._issue_credential()
        self.order = AuraOrderContext(
            I_ac="IAC-" + self.raw("order:iac", 16).hex().upper(),
            matching_id=self.matching_id,
            sid=sid,
            pid_h=self.profile_sha256,
            op=op,
            exp=int(time.time()) + 3600,
            PRaddr=praddr,
        )
        self.token_signature = self._issue_ticket()
        self.store = AuraStore(in_memory=True)
        self.store.put_order(self.order)
        self.store.put_trace_index(
            scalar_to_b64(self.k), self.eid, b64e(self.raw("trace:rtr"))
        )
        self.service = AuraService(
            root=self.root,
            profile_repository=self.profile_repository,
            store=self.store,
        )

    def raw(self, purpose: str, length: int = 32) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hashlib.sha256(
                    f"AURA-EXP|{self.seed}|{self.label}|{purpose}|{counter}".encode()
                ).digest()
            )
            counter += 1
        return bytes(output[:length])

    def scalar(self, purpose: str) -> int:
        return int.from_bytes(self.raw(purpose), "big") % curve_order or 1

    def _issue_credential(self):
        context = {"type": "Cred_D", "cred_exp": self.cred_exp}
        commitment, blinding = create_blind_commitment(
            CRED_PARAMS, {0: self.x}, context
        )
        return finalize_blind_signature(
            blind_sign(
                CRED_PARAMS,
                self.eum_secret,
                commitment,
                {1: self.k, 2: self.cred_exp},
                context,
            ),
            blinding,
        )

    def _issue_ticket(self):
        public = self.order.ticket_public()
        context = {"type": "Tok_op", "ticket": public}
        commitment, blinding = create_blind_commitment(
            TOKEN_PARAMS,
            {6: self.x, 7: self.eta, 8: self.d_value},
            context,
        )
        return finalize_blind_signature(
            blind_sign(
                TOKEN_PARAMS,
                self.mno_secret,
                commitment,
                {i: value for i, value in enumerate(token_public_messages(public))},
                context,
            ),
            blinding,
        )

    def prepare_authentication(self, suffix: str = "auth") -> PreparedAuthentication:
        init = self.service.initiate(
            {
                "I_ac": self.order.I_ac,
                "N_U": b64e(self.raw(suffix + ":N_U")),
                "capabilities": list(self.config["capabilities"]),
            },
            self.order.PRaddr,
        )
        auth = init["serverAuth"]
        salt_p = self.raw(suffix + ":salt")
        salt_p_b64 = b64e(salt_p)
        nu = g1_to_b64(multiply(G_V, self.eta))
        lph = g1_to_b64(multiply(lph_base(self.order.pid_h, salt_p), self.x))
        one_time = generate_ed25519_private()
        vk_t = ed25519_public_b64(one_time.public_key())
        opid = b64e(self.raw(suffix + ":opid", 16))
        ctx_t = build_ctx_t(
            transaction_id=auth["transactionId"],
            i_t=auth["I_t"],
            n_s=auth["N_S"],
            n_u=auth["N_U"],
            server_oid=auth["serverOID"],
            order=self.order,
            salt_p=salt_p_b64,
            lph=lph,
            nu=nu,
            opid=opid,
            vk_t_hash=sha256_hex(b64d(vk_t)),
            cap=auth["cap"],
            cred_exp=self.cred_exp,
        )
        proof = create_auth_proof(
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
            salt_p=salt_p,
        )
        request = {
            "transactionId": auth["transactionId"],
            "salt_p": salt_p_b64,
            "lph": lph,
            "nu": nu,
            "opid": opid,
            "vk_t": vk_t,
            "cred_exp": self.cred_exp,
            "gamma": proof["gamma"],
            "c": proof["c"],
            "tau_auth": ed25519_sign(
                one_time, ctx_auth(ctx_t, proof["gamma"], proof["c"])
            ),
            "Pi_auth": proof,
        }
        return PreparedAuthentication(request, ctx_t, salt_p, init, one_time)

    def build_key_request(
        self,
        prepared: PreparedAuthentication,
        auth_response: dict[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        ephemeral = generate_p256_private()
        q_u = p256_public_b64(ephemeral.public_key())
        payload = ka_u_payload(
            i_t=prepared.server_response["serverAuth"]["I_t"],
            q_u=q_u,
            bind_t=auth_response["Bind_t"],
            mode=CLASSICAL_MODE,
        )
        return (
            {
                "transactionId": prepared.request["transactionId"],
                "ctx_bind": auth_response["ctx_bind"],
                "Bind_t": auth_response["Bind_t"],
                "mode": CLASSICAL_MODE,
                "Q_U": q_u,
                "sigma_U_Q": ed25519_sign(prepared.one_time_private, payload),
            },
            ephemeral,
        )

    def build_hybrid_key_request(
        self,
        prepared: PreparedAuthentication,
        auth_response: dict[str, Any],
    ) -> tuple[dict[str, Any], Any, bytes]:
        if prepared.server_response["serverAuth"]["cap"]["selected"] != HYBRID_MODE:
            raise ValueError("HYBRID_NOT_NEGOTIATED")
        ephemeral = generate_p256_private()
        q_u = p256_public_b64(ephemeral.public_key())
        mlkem_public, mlkem_private = generate_mlkem_keypair(
            self.raw("hybrid:mlkem-key", 64)
        )
        mlkem_u = b64e(mlkem_public)
        payload = ka_u_payload(
            i_t=prepared.server_response["serverAuth"]["I_t"],
            q_u=q_u, bind_t=auth_response["Bind_t"],
            mode=HYBRID_MODE, mlkem_u=mlkem_u,
        )
        return (
            {
                "transactionId": prepared.request["transactionId"],
                "ctx_bind": auth_response["ctx_bind"],
                "Bind_t": auth_response["Bind_t"],
                "mode": HYBRID_MODE,
                "Q_U": q_u,
                "MLKEM_U": mlkem_u,
                "sigma_U_Q": ed25519_sign(prepared.one_time_private, payload),
            },
            ephemeral,
            mlkem_private,
        )

    def authenticate(self, request: dict[str, Any], praddr: str | None = None) -> dict:
        return self.service.authenticate(request, praddr or self.order.PRaddr)

    @staticmethod
    def capture(call) -> dict[str, Any]:
        try:
            response = call()
            return {"accepted": True, "status": 200, "reason": "OK", "stage": "authenticated", "response": response}
        except AuraProtocolError as exc:
            return {"accepted": False, "status": exc.http_status, "reason": exc.code, "stage": exc.stage, "response": None}

    def close(self) -> None:
        self.store.close()
