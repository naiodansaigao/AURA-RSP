"""Integrated software LPA/eUICC client for AURA-RSP Profile Download."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import time

from py_ecc.optimized_bls12_381 import multiply
import requests

from pySim.esim.measurement import RspMeasurements
from pySim.esim.software_euicc import install_profile

from .bbs import BBSSignature, public_key_from_dict
from .binding import verify_binding
from .codec import (
    b64d,
    b64e,
    canonical,
    g1_to_b64,
    load_json,
    save_json,
    scalar_from_b64,
    sha256_hex,
)
from .context import build_ctx_t, ctx_auth
from .key_agreement import (
    CLASSICAL_MODE,
    HYBRID_MODE,
    build_ctx_k,
    derive_profile_keys,
    generate_mlkem_keypair,
    ka_s_payload,
    ka_u_payload,
    mlkem_decapsulate,
)
from .local_ticket_log import (
    LocalTicketContextConflict,
    LocalTicketLogCorrupt,
    lookup_cached_auth_request,
    store_auth_request,
)
from .models import AuraOrderContext
from .primitives import (
    decrypt_profile,
    ed25519_public_b64,
    ed25519_sign,
    generate_ed25519_private,
    generate_p256_private,
    p256_public_b64,
    p256_public_from_pem,
    p256_verify,
)
from .proof import G_V, create_auth_proof, lph_base
from .profile_validation import verify_profile_plaintext
from .receipt import create_install_receipt, initial_last_hash


ROOT = Path(__file__).resolve().parents[3]


class AuraClientError(RuntimeError):
    pass


class AuraLpaClient:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.config = load_json(root / "config" / "aura.json")
        self.runtime = root / "runtime" / "aura"
        self.device_path = self.runtime / "device.json"
        self.device = load_json(self.device_path)
        public = load_json(self.runtime / "server-public.json")
        self.eum_public_key = public_key_from_dict(public["eum_public_key"])
        self.mno_public_key = public_key_from_dict(public["mno_public_key"])
        self.server_auth_public = p256_public_from_pem(
            public["server_auth_public_pem"].encode("ascii")
        )
        self.profile_binding_public = p256_public_from_pem(
            public["profile_binding_public_pem"].encode("ascii")
        )
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.verify = str(self.runtime / "pki" / "ca.pem")
        self.measurements = RspMeasurements("aura")

    def post(
        self,
        path: str,
        payload: dict,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[int, dict | None]:
        body = canonical(payload)
        response = self.http.post(
            self.config["relay_url"] + path,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Admin-Protocol": "aura/rsp/v14",
            },
            timeout=30,
        )
        self.measurements.add_wire(
            request_bytes=len(body), response_bytes=len(response.content)
        )
        parsed = response.json() if response.content else None
        if response.status_code not in expected:
            raise AuraClientError(
                f"{path} returned {response.status_code}: {parsed}"
            )
        return response.status_code, parsed

    def run(self, mode: str = "normal") -> dict:
        # Align the benchmark boundary with Standard RSP: client material is
        # loaded first, then timing begins immediately before online work.
        self.measurements = RspMeasurements("aura")
        ticket = self.device["ticket"]
        order = AuraOrderContext(
            I_ac=ticket["I_ac"],
            matching_id=self.device["matching_id"],
            sid=ticket["sid"],
            pid_h=ticket["pid_h"],
            op=ticket["op"],
            exp=int(ticket["exp"]),
            PRaddr=ticket["PRaddr"],
        )
        if order.exp < int(time.time()):
            raise AuraClientError("ticket expired; issue a new ticket")
        offered = list(self.config["capabilities"])
        n_u = b64e(secrets.token_bytes(32))
        init_request = {
            "I_ac": order.I_ac,
            "N_U": n_u,
            "capabilities": offered,
        }
        with self.measurements.stage("server_auth_ms"):
            _, init_response = self.post(
                "/aura/rsp/v1/initiateAuthentication", init_request
            )
        assert init_response is not None
        server_auth = init_response["serverAuth"]
        if not p256_verify(
            self.server_auth_public,
            server_auth,
            init_response["serverSignature"],
        ):
            raise AuraClientError("server authentication signature failed")
        selected_mode = str(server_auth["cap"].get("selected", ""))
        expected_cap = {
            "version": 1,
            "offered": sorted(set(offered)),
            "selected": selected_mode,
        }
        if selected_mode not in offered:
            raise AuraClientError("server selected an unoffered capability")
        if self.config.get("require_hybrid", False) and selected_mode != HYBRID_MODE:
            raise AuraClientError("HYBRID_REQUIRED")
        if (
            server_auth["N_U"] != n_u
            or server_auth["I_ac"] != order.I_ac
            or server_auth["PRaddr"] != order.PRaddr
            or server_auth["sid"] != order.sid
            or server_auth["cap"] != expected_cap
        ):
            raise AuraClientError("server authentication context mismatch")

        pid_h = order.pid_h
        salts = self.device.setdefault("salt_by_pid", {})
        if pid_h not in salts:
            salts[pid_h] = b64e(secrets.token_bytes(32))
            save_json(self.device_path, self.device)
        salt_p_b64 = salts[pid_h]
        salt_p = b64d(salt_p_b64)
        x = scalar_from_b64(self.device["x"])
        k = scalar_from_b64(self.device["k"])
        eta = scalar_from_b64(self.device["eta"])
        d_value = scalar_from_b64(self.device["d"])
        nu = g1_to_b64(multiply(G_V, eta))
        lph = g1_to_b64(multiply(lph_base(pid_h, salt_p), x))
        opid = b64e(secrets.token_bytes(16))
        one_time_private = generate_ed25519_private()
        vk_t = ed25519_public_b64(one_time_private.public_key())
        ctx_t = build_ctx_t(
            transaction_id=server_auth["transactionId"],
            i_t=server_auth["I_t"],
            n_s=server_auth["N_S"],
            n_u=server_auth["N_U"],
            server_oid=server_auth["serverOID"],
            order=order,
            salt_p=salt_p_b64,
            lph=lph,
            nu=nu,
            opid=opid,
            vk_t_hash=sha256_hex(b64d(vk_t)),
            cap=server_auth["cap"],
            cred_exp=int(self.device["cred_exp"]),
        )
        try:
            auth_request = lookup_cached_auth_request(
                self.device, v=nu, opid=opid, ctx_t=ctx_t
            )
        except (LocalTicketContextConflict, LocalTicketLogCorrupt) as exc:
            raise AuraClientError(str(exc)) from exc
        if auth_request is None:
            with self.measurements.stage("proof_generation_ms"):
                proof = create_auth_proof(
                    ctx_t=ctx_t,
                    eum_public_key=self.eum_public_key,
                    mno_public_key=self.mno_public_key,
                    cred_signature=BBSSignature.from_dict(
                        self.device["credential_signature"]
                    ),
                    token_signature=BBSSignature.from_dict(
                        self.device["token_signature"]
                    ),
                    x=x,
                    k=k,
                    eta=eta,
                    d_value=d_value,
                    cred_exp=int(self.device["cred_exp"]),
                    salt_p=salt_p,
                )
            if mode == "tamper-proof":
                proof = copy.deepcopy(proof)
                proof["c"] = proof["gamma"]
            tau_payload = ctx_auth(ctx_t, proof["gamma"], proof["c"])
            auth_request = {
                "transactionId": server_auth["transactionId"],
                "salt_p": salt_p_b64,
                "lph": lph,
                "nu": nu,
                "opid": opid,
                "vk_t": vk_t,
                "cred_exp": int(self.device["cred_exp"]),
                "gamma": proof["gamma"],
                "c": proof["c"],
                "tau_auth": ed25519_sign(one_time_private, tau_payload),
                "Pi_auth": proof,
            }
            store_auth_request(
                self.device,
                v=nu,
                opid=opid,
                ctx_t=ctx_t,
                auth_request=auth_request,
            )
            save_json(self.device_path, self.device)
        with self.measurements.stage("client_auth_ms"):
            expected_auth = (401,) if mode == "tamper-proof" else (200,)
            status, auth_response = self.post(
                "/aura/rsp/v1/authenticateClient",
                auth_request,
                expected=expected_auth,
            )
        assert auth_response is not None
        if mode == "tamper-proof":
            return {
                "status": "AURA_INTEGRATED_TAMPER_REJECTED",
                "rejected": status == 401,
                "reason": auth_response.get("error"),
                "metrics": self.measurements.finish(),
            }
        self.measurements.stages_ms["proof_verification_ms"] = float(
            auth_response["proofVerifyMs"]
        )
        self.measurements.stages_ms["binding_ms"] = float(
            auth_response["bindingMs"]
        )
        if not verify_binding(
            self.profile_binding_public,
            auth_response["ctx_bind"],
            auth_response["Bind_t"],
        ):
            raise AuraClientError("Bind_t verification failed")
        if mode == "replay-auth":
            _, replay = self.post(
                "/aura/rsp/v1/authenticateClient", auth_request
            )
            if not replay or not replay.get("replayed"):
                raise AuraClientError("exact replay was not idempotent")

        client_ephemeral = generate_p256_private()
        q_u = p256_public_b64(client_ephemeral.public_key())
        mlkem_private = None
        mlkem_u = None
        if selected_mode == HYBRID_MODE:
            mlkem_public, mlkem_private = generate_mlkem_keypair()
            mlkem_u = b64e(mlkem_public)
        ka_u = ka_u_payload(
            i_t=server_auth["I_t"],
            q_u=q_u,
            bind_t=auth_response["Bind_t"],
            mode=selected_mode,
            mlkem_u=mlkem_u,
        )
        key_request = {
            "transactionId": server_auth["transactionId"],
            "Bind_t": auth_response["Bind_t"],
            "ctx_bind": auth_response["ctx_bind"],
            "mode": selected_mode,
            "Q_U": q_u,
            "sigma_U_Q": ed25519_sign(one_time_private, ka_u),
        }
        if mlkem_u is not None:
            key_request["MLKEM_U"] = mlkem_u
        if mode == "tamper-bind":
            key_request["Bind_t"] = key_request["Bind_t"][:-2] + "AA"
        with self.measurements.stage("profile_delivery_ms"):
            expected_profile = (401,) if mode == "tamper-bind" else (200,)
            status, profile_response = self.post(
                "/aura/rsp/v1/getBoundProfilePackage",
                key_request,
                expected=expected_profile,
            )
        assert profile_response is not None
        if mode == "tamper-bind":
            return {
                "status": "AURA_INTEGRATED_BIND_REJECTED",
                "rejected": status == 401,
                "reason": profile_response.get("error"),
                "metrics": self.measurements.finish(),
            }
        self.measurements.stages_ms["profile_encryption_ms"] = float(
            profile_response["serverCryptoMs"]
        )

        expected_ctx_k = build_ctx_k(
            ctx_t=ctx_t,
            bind_t=auth_response["Bind_t"],
            q_u=q_u,
            q_s=profile_response["Q_S"],
            mode=selected_mode,
            mlkem_u=mlkem_u,
            mlkem_s=profile_response.get("MLKEM_S"),
        )
        if profile_response["ctx_K"] != expected_ctx_k:
            raise AuraClientError("ctx_K mismatch")
        ka_s = ka_s_payload(i_t=server_auth["I_t"], ctx_k=expected_ctx_k)
        if not p256_verify(
            self.profile_binding_public,
            ka_s,
            profile_response["sigma_S_Q"],
        ):
            raise AuraClientError("KA-S signature failed")
        with self.measurements.stage("key_agreement_ms"):
            pq_shared = None
            if selected_mode == HYBRID_MODE:
                if mlkem_private is None or not profile_response.get("MLKEM_S"):
                    raise AuraClientError("MISSING_MLKEM_KEY_MATERIAL")
                pq_shared = mlkem_decapsulate(
                    mlkem_private, b64d(profile_response["MLKEM_S"])
                )
            k_enc, k_mac = derive_profile_keys(
                client_ephemeral, profile_response["Q_S"], expected_ctx_k,
                pq_shared=pq_shared,
            )
        ciphertext_hash = hashlib.sha256(
            b64d(profile_response["ciphertext"])
        ).hexdigest()
        if ciphertext_hash != profile_response["ciphertextSha256"]:
            raise AuraClientError("ciphertext hash mismatch")
        aad = {
            "domain": "AURA-RSP-v14/profile",
            "ctx_K": expected_ctx_k,
            "profile_sha256": profile_response["profileSha256"],
        }
        with self.measurements.stage("install_ms"):
            profile = decrypt_profile(
                k_enc,
                profile_response["nonce"],
                profile_response["ciphertext"],
                aad,
            )
            profile_hash = verify_profile_plaintext(
                profile,
                response_sha256=profile_response["profileSha256"],
                order_pid_h=order.pid_h,
            )
            install = install_profile(
                profile,
                expected_sha256=order.pid_h,
                output_dir=self.runtime / "software-euicc-output",
                protocol_mode="aura",
                transaction_id=server_auth["transactionId"],
                matching_id=order.matching_id,
            )
        receipt = create_install_receipt(
            k_mac,
            lph=lph,
            ctx_t=ctx_t,
            bind_t=auth_response["Bind_t"],
            ciphertext_hash=ciphertext_hash,
        )
        with self.measurements.stage("notification_ms"):
            self.post(
                "/aura/rsp/v1/handleNotification",
                {
                    "transactionId": server_auth["transactionId"],
                    "InstallReceipt": receipt.to_dict(),
                },
                expected=(204,),
            )
        self.device.setdefault("lifecycle_by_lph", {})[lph] = {
            "lph": lph,
            "pid_h": order.pid_h,
            "salt_p": salt_p_b64,
            "state": 1,
            "state_name": "installed",
            "ctr": 1,
            "last_hash": initial_last_hash(receipt.to_dict()),
            "profile_present": True,
        }
        save_json(self.device_path, self.device)
        result = {
            "status": "AURA_INTEGRATED_DOWNLOAD_PASS",
            "transactionId": server_auth["transactionId"],
            "profile": install.to_dict(),
            "lph": lph,
            "nu": nu,
            "metrics": self.measurements.finish(),
        }
        save_json(self.runtime / "last-run.json", result)
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("normal", "replay-auth", "tamper-proof", "tamper-bind"),
        default="normal",
    )
    args = parser.parse_args()
    print(json.dumps(AuraLpaClient().run(args.mode), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
