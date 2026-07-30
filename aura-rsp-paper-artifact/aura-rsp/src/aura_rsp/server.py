from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from py_ecc.optimized_bls12_381 import curve_order

from .bbs import BBSSignature, mod_inv, public_key_from_dict
from .codec import (
    b64d,
    b64e,
    canonical,
    load_json,
    save_json,
    scalar_from_b64,
    scalar_to_b64,
    sha256_hex,
)
from .primitives import (
    derive_session_keys,
    ed25519_public_from_b64,
    ed25519_verify,
    encrypt_profile,
    generate_p256_private,
    p256_private_from_pem,
    p256_public_b64,
    p256_sign,
    receipt_mac,
)
from .proof import verify_auth_proof
from .storage import connect, connect_trace


ROOT = Path(__file__).resolve().parents[2]
MAX_BODY = 1_000_000


def cert_common_name(peer_cert: dict) -> str | None:
    for rdn in peer_cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


class AuraServerState:
    def __init__(self, root: Path):
        self.root = root
        self.config = load_json(root / "config" / "aura.json")
        self.runtime = root / "runtime"
        public = load_json(self.runtime / "server-public.json")
        self.eum_public_key = public_key_from_dict(public["eum_public_key"])
        self.mno_public_key = public_key_from_dict(public["mno_public_key"])
        self.server_auth_key = p256_private_from_pem(
            (self.runtime / "server-auth-key.pem").read_bytes()
        )
        self.profile_binding_key = p256_private_from_pem(
            (self.runtime / "profile-binding-key.pem").read_bytes()
        )
        self.profile = (self.runtime / "profile.der").read_bytes()
        self.profile_sha256 = hashlib.sha256(self.profile).hexdigest()
        self.db_path = self.runtime / "aura.sqlite"
        self.trace_db_path = self.runtime / "eum-trace.sqlite"
        self.log_path = root / "logs" / "aura-smdpp.jsonl"
        self.lock = threading.RLock()

    def log(self, event: str, **fields) -> None:
        record = {"ts": time.time(), "event": event, **fields}
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    def initiate(self, content: dict, pr_identity: str) -> tuple[int, dict]:
        if pr_identity != self.config["praddr"]:
            return 403, {"error": "PR_IDENTITY_MISMATCH", "observed": pr_identity}
        if content.get("matchingId") != self.config["matching_id"]:
            return 404, {"error": "UNKNOWN_MATCHING_ID"}
        capabilities = content.get("capabilities", [])
        selected = next(
            (cap for cap in self.config["capabilities"] if cap in capabilities),
            None,
        )
        if selected is None:
            return 400, {"error": "NO_COMMON_CAPABILITY"}
        try:
            if len(b64d(content["N_U"])) != 32:
                raise ValueError
        except Exception:
            return 400, {"error": "INVALID_N_U"}

        transaction_id = secrets.token_hex(16).upper()
        payload = {
            "transactionId": transaction_id,
            "I_t": b64e(secrets.token_bytes(16)),
            "N_U": content["N_U"],
            "N_S": b64e(secrets.token_bytes(32)),
            "sid": self.config["sid"],
            "serverOID": self.config["server_oid"],
            "PRaddr": pr_identity,
            "cap": selected,
            "matchingId": self.config["matching_id"],
        }
        response = {
            "serverAuth": payload,
            "serverSignature": p256_sign(self.server_auth_key, payload),
        }
        with self.lock, connect(self.db_path) as db:
            db.execute(
                """
                INSERT INTO sessions(transaction_id,init_json,status,created_at)
                VALUES(?,?,?,?)
                """,
                (
                    transaction_id,
                    json.dumps(payload, sort_keys=True),
                    "initiated",
                    int(time.time()),
                ),
            )
            db.commit()
        self.log("initiateAuthentication", transactionId=transaction_id)
        return 200, response

    def authenticate(self, content: dict, pr_identity: str) -> tuple[int, dict]:
        transaction_id = content.get("transactionId", "")
        with self.lock, connect(self.db_path) as db:
            session = db.execute(
                "SELECT * FROM sessions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
        if session is None:
            return 404, {"error": "UNKNOWN_TRANSACTION"}
        init_data = json.loads(session["init_json"])
        ctx_t = content.get("ctx_t", {})
        immutable = {
            "transactionId": transaction_id,
            "I_t": init_data["I_t"],
            "N_U": init_data["N_U"],
            "N_S": init_data["N_S"],
            "sid": init_data["sid"],
            "serverOID": init_data["serverOID"],
            "PRaddr": init_data["PRaddr"],
            "cap": init_data["cap"],
        }
        if any(ctx_t.get(key) != value for key, value in immutable.items()):
            return 400, {"error": "CTX_SERVER_BINDING_MISMATCH"}
        if pr_identity != ctx_t.get("PRaddr"):
            return 403, {"error": "CTX_PR_IDENTITY_MISMATCH"}
        ticket = ctx_t.get("ticket", {})
        if (
            ticket.get("sid") != self.config["sid"]
            or ticket.get("PRaddr") != pr_identity
            or ticket.get("op") != "download"
            or int(ticket.get("exp", 0)) < int(time.time())
        ):
            return 403, {"error": "INVALID_OR_EXPIRED_TICKET"}
        if int(ctx_t.get("cred_exp", 0)) < int(time.time()):
            return 403, {"error": "EXPIRED_DEVICE_CREDENTIAL"}
        if ctx_t.get("salt_p") != content.get("salt_p"):
            return 400, {"error": "SALT_CONTEXT_MISMATCH"}
        proof = content.get("Pi_auth", {})
        if ctx_t.get("v") != proof.get("v") or ctx_t.get("lph") != proof.get("lph"):
            return 400, {"error": "PROOF_CONTEXT_POINT_MISMATCH"}
        try:
            vk_t_raw = b64d(content["vk_t"])
            if hashlib.sha256(vk_t_raw).hexdigest() != ctx_t.get("vk_t_hash"):
                return 400, {"error": "ONE_TIME_KEY_CONTEXT_MISMATCH"}
            salt_p = b64d(content["salt_p"])
            one_time_key = ed25519_public_from_b64(content["vk_t"])
        except Exception:
            return 400, {"error": "INVALID_CLIENT_KEY_OR_SALT"}

        tau_payload = {
            "domain": "AURA-RSP-v14:tau_auth",
            "ctx_t": ctx_t,
            "proof_hash": sha256_hex(canonical(proof)),
        }
        if not ed25519_verify(one_time_key, tau_payload, content.get("tau_auth", "")):
            return 401, {"error": "INVALID_TAU_AUTH"}

        verify_started = time.perf_counter()
        proof_ok, proof_reason = verify_auth_proof(
            ctx_t=ctx_t,
            proof=proof,
            eum_public_key=self.eum_public_key,
            mno_public_key=self.mno_public_key,
            salt_p=salt_p,
        )
        proof_verify_ms = (time.perf_counter() - verify_started) * 1000
        if not proof_ok:
            self.log(
                "authenticateClientRejected",
                transactionId=transaction_id,
                reason=proof_reason,
                proof_verify_ms=proof_verify_ms,
            )
            return 401, {"error": "INVALID_PI_AUTH", "reason": proof_reason}

        auth_hash = sha256_hex(canonical(content))
        v_value = proof["v"]
        gamma = scalar_from_b64(proof["gamma"])
        c_value = scalar_from_b64(proof["c"])
        with self.lock, connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute(
                "SELECT * FROM used_nullifiers WHERE v=?", (v_value,)
            ).fetchone()
            if used is not None:
                if used["auth_hash"] == auth_hash:
                    cached = json.loads(used["response_json"])
                    cached["replayed"] = True
                    db.commit()
                    self.log(
                        "authenticateClientReplay",
                        transactionId=transaction_id,
                        proof_verify_ms=proof_verify_ms,
                    )
                    return 200, cached
                old_gamma = scalar_from_b64(used["gamma"])
                old_c = scalar_from_b64(used["c_value"])
                denominator = (old_gamma - gamma) % curve_order
                if denominator == 0:
                    db.rollback()
                    return 409, {"error": "DOUBLE_SPEND_ZERO_DENOMINATOR"}
                recovered_k = ((old_c - c_value) * mod_inv(denominator)) % curve_order
                recovered_k_b64 = scalar_to_b64(recovered_k)
                with connect_trace(self.trace_db_path) as trace_db:
                    trace = trace_db.execute(
                        "SELECT eid FROM trace_index WHERE k=?",
                        (recovered_k_b64,),
                    ).fetchone()
                eid = trace["eid"] if trace else None
                db.execute(
                    """
                    INSERT INTO traces(
                        v,recovered_k,eid,first_transaction_id,
                        second_transaction_id,created_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        v_value,
                        recovered_k_b64,
                        eid,
                        used["transaction_id"],
                        transaction_id,
                        int(time.time()),
                    ),
                )
                db.commit()
                self.log(
                    "doubleSpendDetected",
                    transactionId=transaction_id,
                    firstTransactionId=used["transaction_id"],
                    trace_eid=eid,
                    proof_verify_ms=proof_verify_ms,
                )
                return 409, {
                    "error": "DOUBLE_SPEND_DETECTED",
                    "traceRecovered": eid is not None,
                    "traceEid": eid,
                    "recoveredK": recovered_k_b64,
                }

            auth_transcript = {
                "ctx_t": ctx_t,
                "M_U_auth_hash": auth_hash,
            }
            ctx_bind = {
                "domain": "AURA-RSP-v14:bind",
                "ctx_t_hash": sha256_hex(canonical(ctx_t)),
                "th_auth": sha256_hex(canonical(auth_transcript)),
            }
            bind_t = p256_sign(self.profile_binding_key, ctx_bind)
            response = {
                "transactionId": transaction_id,
                "ctx_bind": ctx_bind,
                "Bind_t": bind_t,
                "proofVerifyMs": round(proof_verify_ms, 3),
                "replayed": False,
            }
            response_json = json.dumps(response, sort_keys=True)
            db.execute(
                """
                INSERT INTO used_nullifiers(
                    v,auth_hash,gamma,c_value,transaction_id,response_json
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    v_value,
                    auth_hash,
                    proof["gamma"],
                    proof["c"],
                    transaction_id,
                    response_json,
                ),
            )
            db.execute(
                """
                UPDATE sessions
                SET ctx_json=?,auth_hash=?,auth_request_json=?,
                    auth_response_json=?,vk_t=?,bind_t=?,status='authenticated'
                WHERE transaction_id=?
                """,
                (
                    json.dumps(ctx_t, sort_keys=True),
                    auth_hash,
                    json.dumps(content, sort_keys=True),
                    response_json,
                    content["vk_t"],
                    bind_t,
                    transaction_id,
                ),
            )
            db.commit()
        self.log(
            "authenticateClient",
            transactionId=transaction_id,
            proof_verify_ms=proof_verify_ms,
            proof_bytes=len(canonical(proof)),
        )
        return 200, response

    def get_profile(self, content: dict, pr_identity: str) -> tuple[int, dict]:
        transaction_id = content.get("transactionId", "")
        with self.lock, connect(self.db_path) as db:
            session = db.execute(
                "SELECT * FROM sessions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
        if session is None or session["status"] != "authenticated":
            return 409, {"error": "SESSION_NOT_AUTHENTICATED"}
        if pr_identity != self.config["praddr"]:
            return 403, {"error": "PR_IDENTITY_MISMATCH"}
        if content.get("Bind_t") != session["bind_t"]:
            return 400, {"error": "BIND_T_MISMATCH"}
        if content.get("vk_t") != session["vk_t"]:
            return 400, {"error": "ONE_TIME_KEY_MISMATCH"}

        signed_request = {
            key: content[key]
            for key in (
                "transactionId",
                "Bind_t",
                "ctx_bind",
                "clientEphemeral",
                "cap",
                "vk_t",
            )
        }
        if not ed25519_verify(
            ed25519_public_from_b64(session["vk_t"]),
            signed_request,
            content.get("clientSignature", ""),
        ):
            return 401, {"error": "INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE"}
        auth_response = json.loads(session["auth_response_json"])
        if content.get("ctx_bind") != auth_response["ctx_bind"]:
            return 400, {"error": "CTX_BIND_MISMATCH"}

        crypto_started = time.perf_counter()
        server_ephemeral = generate_p256_private()
        server_ephemeral_b64 = p256_public_b64(server_ephemeral.public_key())
        ctx_k = {
            "domain": "AURA-RSP-v14:ctx_K",
            "transactionId": transaction_id,
            "Bind_t": session["bind_t"],
            "clientEphemeral": content["clientEphemeral"],
            "serverEphemeral": server_ephemeral_b64,
            "cap": content["cap"],
        }
        k_enc, k_mac = derive_session_keys(
            server_ephemeral, content["clientEphemeral"], ctx_k
        )
        aad = {
            "ctx_K": ctx_k,
            "profile_sha256": self.profile_sha256,
        }
        nonce, ciphertext = encrypt_profile(k_enc, self.profile, aad)
        signed_response = {
            "ctx_K": ctx_k,
            "nonce": nonce,
            "ciphertext_hash": hashlib.sha256(b64d(ciphertext)).hexdigest(),
            "profile_sha256": self.profile_sha256,
        }
        response = {
            "transactionId": transaction_id,
            "ctx_K": ctx_k,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "profileSha256": self.profile_sha256,
            "serverSignature": p256_sign(
                self.profile_binding_key, signed_response
            ),
            "serverCryptoMs": round(
                (time.perf_counter() - crypto_started) * 1000, 3
            ),
        }
        with self.lock, connect(self.db_path) as db:
            db.execute(
                """
                UPDATE sessions SET k_mac=?,profile_sha256=?,status='downloaded'
                WHERE transaction_id=?
                """,
                (b64e(k_mac), self.profile_sha256, transaction_id),
            )
            db.commit()
        self.log(
            "getBoundProfilePackage",
            transactionId=transaction_id,
            ciphertext_bytes=len(b64d(ciphertext)),
            server_crypto_ms=response["serverCryptoMs"],
        )
        return 200, response

    def notification(self, content: dict, pr_identity: str) -> tuple[int, dict | None]:
        transaction_id = content.get("transactionId", "")
        if pr_identity != self.config["praddr"]:
            return 403, {"error": "PR_IDENTITY_MISMATCH"}
        with self.lock, connect(self.db_path) as db:
            session = db.execute(
                "SELECT * FROM sessions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if session is None or session["status"] not in ("downloaded", "installed"):
                return 409, {"error": "PROFILE_NOT_DOWNLOADED"}
            receipt_fields = {
                "transactionId": transaction_id,
                "profileSha256": content.get("profileSha256"),
                "status": content.get("status"),
                "counter": content.get("counter"),
            }
            if (
                receipt_fields["profileSha256"] != session["profile_sha256"]
                or receipt_fields["status"] != "installed"
                or receipt_fields["counter"] != 1
            ):
                return 400, {"error": "INVALID_INSTALL_RECEIPT_FIELDS"}
            expected = receipt_mac(b64d(session["k_mac"]), receipt_fields)
            if not hmac.compare_digest(expected, content.get("mac", "")):
                return 401, {"error": "INVALID_INSTALL_RECEIPT_MAC"}
            db.execute(
                """
                INSERT OR REPLACE INTO notifications(
                    transaction_id,receipt_json,created_at
                ) VALUES(?,?,?)
                """,
                (transaction_id, json.dumps(content, sort_keys=True), int(time.time())),
            )
            db.execute(
                "UPDATE sessions SET status='installed' WHERE transaction_id=?",
                (transaction_id,),
            )
            db.commit()
        self.log("handleNotification", transactionId=transaction_id)
        return 204, None


class AuraRequestHandler(BaseHTTPRequestHandler):
    server_version = "AURA-SMDPP/0.1"

    @property
    def state(self) -> AuraServerState:
        return self.server.state

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, status: int, body: dict | None) -> None:
        data = b"" if body is None else canonical(body)
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok", "protocol": self.state.config["protocol"]})
        else:
            self._send(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self._send(413, {"error": "INVALID_BODY_LENGTH"})
                return
            content = json.loads(self.rfile.read(length))
            peer_cert = self.connection.getpeercert()
            pr_identity = cert_common_name(peer_cert)
            claimed_pr = self.headers.get("X-AURA-PRADDR")
            if claimed_pr != pr_identity:
                self._send(403, {"error": "PR_HEADER_CERT_MISMATCH"})
                return
            routes = {
                "/aura/rsp/v1/initiateAuthentication": self.state.initiate,
                "/aura/rsp/v1/authenticateClient": self.state.authenticate,
                "/aura/rsp/v1/getBoundProfilePackage": self.state.get_profile,
                "/aura/rsp/v1/handleNotification": self.state.notification,
            }
            handler = routes.get(self.path)
            if handler is None:
                self._send(404, {"error": "NOT_FOUND"})
                return
            status, body = handler(content, pr_identity)
            self._send(status, body)
        except Exception as exc:
            self.state.log(
                "serverException",
                path=self.path,
                error=f"{type(exc).__name__}: {exc}",
            )
            self._send(
                500,
                {"error": "SERVER_EXCEPTION", "detail": f"{type(exc).__name__}: {exc}"},
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    state = AuraServerState(ROOT)
    port = args.port or int(state.config["backend_port"])
    server = ThreadingHTTPServer((args.host, port), AuraRequestHandler)
    server.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pki = state.runtime / "pki"
    context.load_cert_chain(
        pki / "smdpp-server.pem", pki / "smdpp-server-key.pem"
    )
    context.load_verify_locations(pki / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"AURA_SMDPP_READY https://{args.host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
