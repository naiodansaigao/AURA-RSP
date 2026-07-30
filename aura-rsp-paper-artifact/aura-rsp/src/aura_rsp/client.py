from __future__ import annotations

import argparse
import copy
import hashlib
import json
import secrets
import time
from pathlib import Path

import requests
from py_ecc.optimized_bls12_381 import multiply

from .bbs import BBSSignature, public_key_from_dict
from .codec import (
    b64d,
    b64e,
    canonical,
    g1_to_b64,
    load_json,
    save_json,
    scalar_from_b64,
    scalar_to_b64,
    sha256_hex,
)
from .local_ticket_log import (
    LocalTicketContextConflict,
    LocalTicketLogCorrupt,
    lookup_cached_auth_request,
    store_auth_request,
)
from .primitives import (
    decrypt_profile,
    derive_session_keys,
    ed25519_private_b64,
    ed25519_public_b64,
    ed25519_sign,
    generate_ed25519_private,
    generate_p256_private,
    p256_public_b64,
    p256_public_from_pem,
    p256_sign,
    p256_verify,
    receipt_mac,
)
from .proof import (
    G_V,
    create_auth_proof,
    lph_base,
)


ROOT = Path(__file__).resolve().parents[2]


class AuraClientError(RuntimeError):
    pass


class AuraClient:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.config = load_json(root / "config" / "aura.json")
        self.device_path = root / "runtime" / "device.json"
        self.device = load_json(self.device_path)
        public = load_json(root / "runtime" / "server-public.json")
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
        self.ca = str(root / "runtime" / "pki" / "ca.pem")
        self.url = self.config["relay_url"]
        self.wire_request_bytes = 0
        self.wire_response_bytes = 0
        self.relay_ms = 0.0

    def post(
        self,
        path: str,
        payload: dict,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[requests.Response, dict | None]:
        encoded = canonical(payload)
        self.wire_request_bytes += len(encoded)
        response = self.http.post(
            self.url + path,
            data=encoded,
            headers={"Content-Type": "application/json"},
            timeout=180,
            verify=self.ca,
        )
        self.wire_response_bytes += len(response.content)
        self.relay_ms += float(response.headers.get("X-AURA-Relay-Ms", "0"))
        body = response.json() if response.content else None
        if response.status_code not in expected:
            raise AuraClientError(
                f"{path} returned {response.status_code}: {body}"
            )
        return response, body

    def run(self, mode: str = "normal") -> dict:
        total_started = time.perf_counter()
        metrics: dict[str, float | int | str | bool] = {}
        ticket = self.device["ticket"]
        if int(ticket["exp"]) < int(time.time()):
            raise AuraClientError("ticket expired; issue a new ticket")

        n_u = b64e(secrets.token_bytes(32))
        init_request = {
            "matchingId": self.config["matching_id"],
            "N_U": n_u,
            "capabilities": self.config["capabilities"],
        }
        step_started = time.perf_counter()
        _, init_response = self.post(
            "/aura/rsp/v1/initiateAuthentication", init_request
        )
        metrics["initiate_ms"] = (time.perf_counter() - step_started) * 1000
        server_auth = init_response["serverAuth"]
        if not p256_verify(
            self.server_auth_public,
            server_auth,
            init_response["serverSignature"],
        ):
            raise AuraClientError("server authentication signature failed")
        if (
            server_auth["N_U"] != n_u
            or server_auth["PRaddr"] != ticket["PRaddr"]
            or server_auth["sid"] != ticket["sid"]
        ):
            raise AuraClientError("server authentication context mismatch")

        pid_h = ticket["pid_h"]
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
        v_b64 = g1_to_b64(multiply(G_V, eta))
        lph_b64 = g1_to_b64(multiply(lph_base(pid_h, salt_p), x))
        opid = b64e(secrets.token_bytes(16))
        one_time_private = generate_ed25519_private()
        vk_t = ed25519_public_b64(one_time_private.public_key())
        ctx_t = {
            "transactionId": server_auth["transactionId"],
            "I_t": server_auth["I_t"],
            "N_U": server_auth["N_U"],
            "N_S": server_auth["N_S"],
            "sid": server_auth["sid"],
            "serverOID": server_auth["serverOID"],
            "PRaddr": server_auth["PRaddr"],
            "cap": server_auth["cap"],
            "ticket": ticket,
            "cred_exp": int(self.device["cred_exp"]),
            "salt_p": salt_p_b64,
            "lph": lph_b64,
            "v": v_b64,
            "opid": opid,
            "vk_t_hash": hashlib.sha256(b64d(vk_t)).hexdigest(),
        }
        try:
            auth_request = lookup_cached_auth_request(
                self.device,
                v=v_b64,
                opid=opid,
                ctx_t=ctx_t,
            )
        except LocalTicketContextConflict as exc:
            raise AuraClientError("local_ticket_context_conflict") from exc
        except LocalTicketLogCorrupt as exc:
            raise AuraClientError("local_ticket_log_corrupt") from exc

        if auth_request is None:
            proof_started = time.perf_counter()
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
            metrics["proof_generate_ms"] = (
                time.perf_counter() - proof_started
            ) * 1000
            metrics["proof_bytes"] = len(canonical(proof))
            if proof["v"] != v_b64 or proof["lph"] != lph_b64:
                raise AuraClientError("local proof/context point mismatch")
            if mode == "tamper-proof":
                tampered = copy.deepcopy(proof)
                tampered["responses"]["x"] = scalar_to_b64(
                    (scalar_from_b64(tampered["responses"]["x"]) + 1)
                )
                proof = tampered
            tau_payload = {
                "domain": "AURA-RSP-v14:tau_auth",
                "ctx_t": ctx_t,
                "proof_hash": sha256_hex(canonical(proof)),
            }
            auth_request = {
                "transactionId": server_auth["transactionId"],
                "ctx_t": ctx_t,
                "salt_p": salt_p_b64,
                "vk_t": vk_t,
                "tau_auth": ed25519_sign(one_time_private, tau_payload),
                "Pi_auth": proof,
            }
            store_auth_request(
                self.device,
                v=v_b64,
                opid=opid,
                ctx_t=ctx_t,
                auth_request=auth_request,
            )
            save_json(self.device_path, self.device)
            metrics["local_ticket_log_action"] = "stored"
        else:
            metrics["proof_generate_ms"] = 0.0
            metrics["proof_bytes"] = len(canonical(auth_request["Pi_auth"]))
            metrics["local_ticket_log_action"] = "cached"

        auth_started = time.perf_counter()
        expected_auth = (401,) if mode == "tamper-proof" else (409,) if mode == "double-spend" else (200,)
        _, auth_response = self.post(
            "/aura/rsp/v1/authenticateClient",
            auth_request,
            expected=expected_auth,
        )
        metrics["authenticate_ms"] = (
            time.perf_counter() - auth_started
        ) * 1000
        if mode == "tamper-proof":
            if auth_response.get("error") != "INVALID_PI_AUTH":
                raise AuraClientError("tampered proof was not rejected as expected")
            return {
                "status": "AURA_TAMPER_PROOF_REJECTED",
                "transactionId": server_auth["transactionId"],
                **self._finish_metrics(metrics, total_started),
            }
        if mode == "double-spend":
            if (
                auth_response.get("error") != "DOUBLE_SPEND_DETECTED"
                or not auth_response.get("traceRecovered")
            ):
                raise AuraClientError("double spend was not traced as expected")
            return {
                "status": "AURA_DOUBLE_SPEND_TRACE_PASS",
                "transactionId": server_auth["transactionId"],
                "traceEid": auth_response.get("traceEid"),
                **self._finish_metrics(metrics, total_started),
            }
        metrics["proof_verify_ms"] = float(auth_response["proofVerifyMs"])
        if not p256_verify(
            self.profile_binding_public,
            auth_response["ctx_bind"],
            auth_response["Bind_t"],
        ):
            raise AuraClientError("Bind_t verification failed")
        if mode == "replay-auth":
            _, replay_response = self.post(
                "/aura/rsp/v1/authenticateClient", auth_request
            )
            if not replay_response.get("replayed"):
                raise AuraClientError("identical authentication replay was not cached")
            metrics["auth_replay_cached"] = True

        client_ephemeral = generate_p256_private()
        key_request = {
            "transactionId": server_auth["transactionId"],
            "Bind_t": auth_response["Bind_t"],
            "ctx_bind": auth_response["ctx_bind"],
            "clientEphemeral": p256_public_b64(client_ephemeral.public_key()),
            "cap": server_auth["cap"],
            "vk_t": vk_t,
        }
        signed_key_request = copy.deepcopy(key_request)
        key_request["clientSignature"] = ed25519_sign(
            one_time_private, signed_key_request
        )
        if mode == "tamper-bind":
            key_request["Bind_t"] = key_request["Bind_t"][:-2] + "AA"
        profile_started = time.perf_counter()
        expected_profile = (400,) if mode == "tamper-bind" else (200,)
        _, profile_response = self.post(
            "/aura/rsp/v1/getBoundProfilePackage",
            key_request,
            expected=expected_profile,
        )
        metrics["profile_download_ms"] = (
            time.perf_counter() - profile_started
        ) * 1000
        if mode == "tamper-bind":
            if profile_response.get("error") != "BIND_T_MISMATCH":
                raise AuraClientError("tampered Bind_t was not rejected")
            return {
                "status": "AURA_TAMPER_BIND_REJECTED",
                "transactionId": server_auth["transactionId"],
                **self._finish_metrics(metrics, total_started),
            }

        ctx_k = profile_response["ctx_K"]
        if (
            ctx_k["clientEphemeral"] != signed_key_request["clientEphemeral"]
            or ctx_k["Bind_t"] != auth_response["Bind_t"]
            or ctx_k["transactionId"] != server_auth["transactionId"]
        ):
            raise AuraClientError("ctx_K mismatch")
        signed_profile_response = {
            "ctx_K": ctx_k,
            "nonce": profile_response["nonce"],
            "ciphertext_hash": hashlib.sha256(
                b64d(profile_response["ciphertext"])
            ).hexdigest(),
            "profile_sha256": profile_response["profileSha256"],
        }
        if not p256_verify(
            self.profile_binding_public,
            signed_profile_response,
            profile_response["serverSignature"],
        ):
            raise AuraClientError("server key exchange signature failed")
        k_enc, k_mac = derive_session_keys(
            client_ephemeral, ctx_k["serverEphemeral"], ctx_k
        )
        aad = {
            "ctx_K": ctx_k,
            "profile_sha256": profile_response["profileSha256"],
        }
        decrypt_started = time.perf_counter()
        profile = decrypt_profile(
            k_enc,
            profile_response["nonce"],
            profile_response["ciphertext"],
            aad,
        )
        metrics["profile_decrypt_ms"] = (
            time.perf_counter() - decrypt_started
        ) * 1000
        profile_hash = hashlib.sha256(profile).hexdigest()
        if profile_hash != profile_response["profileSha256"]:
            raise AuraClientError("decrypted profile hash mismatch")
        if profile_hash != ticket["pid_h"]:
            raise AuraClientError("decrypted profile does not match ticket pid_h")
        output_dir = self.root / "runtime" / "software-euicc-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / (
            self.config["matching_id"] + ".aura.upp.der"
        )
        output_path.write_bytes(profile)

        receipt_fields = {
            "transactionId": server_auth["transactionId"],
            "profileSha256": profile_hash,
            "status": "installed",
            "counter": 1,
        }
        receipt = {**receipt_fields, "mac": receipt_mac(k_mac, receipt_fields)}
        notify_started = time.perf_counter()
        self.post(
            "/aura/rsp/v1/handleNotification",
            receipt,
            expected=(204,),
        )
        metrics["notification_ms"] = (
            time.perf_counter() - notify_started
        ) * 1000
        metrics["server_crypto_ms"] = float(profile_response["serverCryptoMs"])
        result = {
            "status": "AURA_RSP_DOWNLOAD_PASS",
            "transactionId": server_auth["transactionId"],
            "activationCode": (
                f"LPA:1$127.0.0.1:{self.config['relay_port']}"
                f"${self.config['matching_id']}"
            ),
            "profilePath": str(output_path),
            "profileBytes": len(profile),
            "profileSha256": profile_hash,
            "lph": lph_b64,
            "v": v_b64,
            **self._finish_metrics(metrics, total_started),
        }
        save_json(self.root / "runtime" / "last-run.json", result)
        return result

    def _finish_metrics(self, metrics: dict, total_started: float) -> dict:
        metrics["relay_accumulated_ms"] = round(self.relay_ms, 3)
        metrics["wire_request_json_bytes"] = self.wire_request_bytes
        metrics["wire_response_json_bytes"] = self.wire_response_bytes
        metrics["total_ms"] = round(
            (time.perf_counter() - total_started) * 1000, 3
        )
        return {"metrics": metrics}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=(
            "normal",
            "replay-auth",
            "double-spend",
            "tamper-proof",
            "tamper-bind",
        ),
        default="normal",
    )
    args = parser.parse_args()
    result = AuraClient().run(args.mode)
    print(json.dumps(result, indent=2, sort_keys=True))
    print(result["status"])


if __name__ == "__main__":
    main()
