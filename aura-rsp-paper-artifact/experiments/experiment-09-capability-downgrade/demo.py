from __future__ import annotations

import argparse
import base64
import copy
import csv
import hashlib
import json
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from kyber_py.ml_kem import ML_KEM_768

except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "缺少实验9依赖。请在WSL中运行 bash ./run_demo.sh；"
        f"原始错误: {exc}"
    ) from exc


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def p256_public_b64(public_key) -> str:
    return b64e(
        public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def p256_public_from_b64(value: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b64d(value)
    )


def p256_sign(private_key, value: dict[str, Any]) -> str:
    return b64e(
        private_key.sign(canonical(value), ec.ECDSA(hashes.SHA256()))
    )


def p256_verify(public_key, value: dict[str, Any], signature_b64: str) -> bool:
    try:
        public_key.verify(
            b64d(signature_b64),
            canonical(value),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


def ed25519_public_b64(public_key) -> str:
    return b64e(
        public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def ed25519_public_from_b64(value: str):
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(value))


def ed25519_sign(private_key, value: dict[str, Any]) -> str:
    return b64e(private_key.sign(canonical(value)))


def ed25519_verify(public_key, value: dict[str, Any], signature_b64: str) -> bool:
    try:
        public_key.verify(b64d(signature_b64), canonical(value))
        return True
    except Exception:
        return False


class ProtocolReject(Exception):
    def __init__(self, stage: str, reason: str):
        super().__init__(reason)
        self.stage = stage
        self.reason = reason


@dataclass
class ClientSession:
    label: str
    seed: int
    offered: list[str]
    policy: str
    hybrid_cap: str
    classical_cap: str
    n_u: str
    one_time_private: ed25519.Ed25519PrivateKey
    client_ephemeral: ec.EllipticCurvePrivateKey
    mlkem_public: bytes | None = None
    mlkem_private: bytes | None = None
    selected_cap: str | None = None
    server_auth: dict[str, Any] | None = None
    bind_response: dict[str, Any] | None = None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def seeded_bytes(seed: int, label: str, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(
            hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(out[:size])


def deterministic_p256(seed: int, label: str) -> ec.EllipticCurvePrivateKey:
    value = int.from_bytes(seeded_bytes(seed, label, 32), "big")
    value = (value % (P256_ORDER - 1)) + 1
    return ec.derive_private_key(value, ec.SECP256R1())


def deterministic_ed25519(seed: int, label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        seeded_bytes(seed, label, 32)
    )


def resolve_path(root: Path, value: str) -> Path:
    return (root / value).resolve()


def load_profile(
    root: Path, primary: str, fallback: str
) -> tuple[bytes, Path]:
    candidates = [resolve_path(root, primary), resolve_path(root, fallback)]
    for path in candidates:
        if path.is_file():
            return path.read_bytes(), path
    raise FileNotFoundError("profile not found: " + ", ".join(map(str, candidates)))


def prepare_output(path: Path, experiment_root: Path) -> Path:
    path = path.resolve()
    results_root = (experiment_root / "results").resolve()
    if not path.is_relative_to(results_root):
        raise ValueError(f"output must remain under {results_root}")
    if path.exists():
        shutil.rmtree(path)
    for name in ("raw", "evidence", "paper"):
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def offer_hash(capabilities: list[str]) -> str:
    return sha256_hex(
        canonical(
            {
                "domain": "AURA-RSP-v14:capability-offer",
                "capabilities": capabilities,
            }
        )
    )


def derive_mode_keys(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_b64: str,
    ctx_k: dict[str, Any],
    mlkem_shared: bytes | None,
) -> tuple[bytes, bytes]:
    peer_public = p256_public_from_b64(peer_public_b64)
    ecdh_shared = private_key.exchange(ec.ECDH(), peer_public)
    ikm = ecdh_shared if mlkem_shared is None else ecdh_shared + mlkem_shared
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(canonical(ctx_k)).digest(),
        info=b"AURA-RSP-v14:capability-bound-profile-keys",
    ).derive(ikm)
    return material[:32], material[32:]


def encrypt_profile(
    key: bytes, plaintext: bytes, aad: dict[str, Any], nonce: bytes
) -> str:
    return b64e(AESGCM(key).encrypt(nonce, plaintext, canonical(aad)))


def decrypt_profile(
    key: bytes, nonce_b64: str, ciphertext_b64: str, aad: dict[str, Any]
) -> bytes:
    return AESGCM(key).decrypt(
        b64d(nonce_b64), b64d(ciphertext_b64), canonical(aad)
    )


class CapabilityServer:
    def __init__(self, config: dict[str, Any], profile: bytes):
        self.config = config
        self.profile = profile
        self.profile_sha256 = hashlib.sha256(profile).hexdigest()
        self.hybrid_cap = config["hybrid_capability"]
        self.classical_cap = config["classical_capability"]
        self.supported = [self.hybrid_cap, self.classical_cap]
        self.seed = int(config["seed"])
        self.server_auth_key = deterministic_p256(self.seed, "server-auth")
        self.binding_key = deterministic_p256(self.seed, "profile-binding")
        self.sessions: dict[str, dict[str, Any]] = {}
        self.counter = 0

    @property
    def server_auth_public(self):
        return self.server_auth_key.public_key()

    @property
    def binding_public(self):
        return self.binding_key.public_key()

    def initiate(
        self, request: dict[str, Any], selected_cap: str
    ) -> dict[str, Any]:
        capabilities = request.get("capabilities", [])
        if selected_cap not in self.supported or selected_cap not in capabilities:
            raise ProtocolReject("capability_negotiation", "NO_COMMON_CAPABILITY")
        self.counter += 1
        transaction_id = hashlib.sha256(
            f"{self.seed}:tx:{self.counter}".encode("utf-8")
        ).hexdigest()[:32].upper()
        payload = {
            "transactionId": transaction_id,
            "N_U": request["N_U"],
            "N_S": b64e(
                seeded_bytes(self.seed, f"server-nonce:{self.counter}", 32)
            ),
            "sid": self.config["sid"],
            "serverOID": self.config["server_oid"],
            "PRaddr": self.config["praddr"],
            "cap": selected_cap,
            "capabilityOfferHash": offer_hash(capabilities),
        }
        response = {
            "serverAuth": payload,
            "serverSignature": p256_sign(self.server_auth_key, payload),
        }
        self.sessions[transaction_id] = {
            "serverAuth": copy.deepcopy(payload),
            "cap": selected_cap,
            "offerHash": payload["capabilityOfferHash"],
            "status": "initiated",
        }
        return response

    def issue_bind_t(self, transaction_id: str) -> dict[str, Any]:
        session = self.sessions.get(transaction_id)
        if session is None:
            raise ProtocolReject("profile_binding", "UNKNOWN_TRANSACTION")
        server_auth = session["serverAuth"]
        ctx_bind = {
            "domain": "AURA-RSP-v14:bind",
            "transactionId": transaction_id,
            "ctx_t_hash": sha256_hex(canonical(server_auth)),
            "capabilityTranscriptHash": sha256_hex(
                canonical(
                    {
                        "offerHash": session["offerHash"],
                        "selected": session["cap"],
                    }
                )
            ),
        }
        response = {
            "transactionId": transaction_id,
            "ctx_bind": ctx_bind,
            "Bind_t": p256_sign(self.binding_key, ctx_bind),
        }
        session["bind"] = copy.deepcopy(response)
        session["status"] = "authenticated"
        return response

    @staticmethod
    def signed_key_request(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "transactionId": request.get("transactionId"),
            "Bind_t": request.get("Bind_t"),
            "ctx_bind": request.get("ctx_bind"),
            "clientEphemeral": request.get("clientEphemeral"),
            "cap": request.get("cap"),
            "capabilityOfferHash": request.get("capabilityOfferHash"),
            "vk_t": request.get("vk_t"),
            "mlkemPublicKey": request.get("mlkemPublicKey"),
        }

    def get_profile(self, request: dict[str, Any]) -> dict[str, Any]:
        transaction_id = request.get("transactionId", "")
        session = self.sessions.get(transaction_id)
        if session is None or session.get("status") != "authenticated":
            raise ProtocolReject("session", "SESSION_NOT_AUTHENTICATED")
        try:
            one_time_key = ed25519_public_from_b64(request["vk_t"])
        except Exception as exc:
            raise ProtocolReject(
                "client_key_exchange_signature", "INVALID_ONE_TIME_KEY"
            ) from exc
        signed_request = self.signed_key_request(request)
        if not ed25519_verify(
            one_time_key, signed_request, request.get("clientSignature", "")
        ):
            raise ProtocolReject(
                "client_key_exchange_signature",
                "INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE",
            )
        bind = session["bind"]
        if request.get("Bind_t") != bind["Bind_t"]:
            raise ProtocolReject("profile_binding", "BIND_T_MISMATCH")
        if request.get("ctx_bind") != bind["ctx_bind"]:
            raise ProtocolReject("profile_binding", "CTX_BIND_MISMATCH")
        if request.get("cap") != session["cap"]:
            raise ProtocolReject("capability_binding", "KEY_REQUEST_MODE_MISMATCH")
        if request.get("capabilityOfferHash") != session["offerHash"]:
            raise ProtocolReject(
                "capability_binding", "KEY_REQUEST_OFFER_HASH_MISMATCH"
            )

        mlkem_shared: bytes | None = None
        mlkem_ciphertext: bytes | None = None
        mlkem_public_b64 = request.get("mlkemPublicKey")
        if session["cap"] == self.hybrid_cap:
            if not mlkem_public_b64:
                raise ProtocolReject(
                    "mlkem_client_material", "MISSING_MLKEM_PUBLIC_KEY"
                )
            try:
                mlkem_public = b64d(mlkem_public_b64)
                if len(mlkem_public) != 1184:
                    raise ValueError("wrong ML-KEM-768 public key length")
                mlkem_shared, mlkem_ciphertext = ML_KEM_768.encaps(mlkem_public)
            except Exception as exc:
                raise ProtocolReject(
                    "mlkem_client_material", "INVALID_MLKEM_PUBLIC_KEY"
                ) from exc
        elif mlkem_public_b64 is not None:
            raise ProtocolReject(
                "cross_mode_material", "UNEXPECTED_MLKEM_PUBLIC_KEY"
            )

        server_ephemeral = deterministic_p256(
            self.seed, f"server-ephemeral:{transaction_id}:{session['cap']}"
        )
        server_ephemeral_b64 = p256_public_b64(server_ephemeral.public_key())
        mlkem_ciphertext_b64 = (
            b64e(mlkem_ciphertext) if mlkem_ciphertext is not None else None
        )
        ctx_k = {
            "domain": "AURA-RSP-v14:ctx_K",
            "transactionId": transaction_id,
            "Bind_t": bind["Bind_t"],
            "capabilityOfferHash": session["offerHash"],
            "cap": session["cap"],
            "clientEphemeral": request["clientEphemeral"],
            "serverEphemeral": server_ephemeral_b64,
            "mlkemPublicKeyHash": (
                hashlib.sha256(b64d(mlkem_public_b64)).hexdigest()
                if mlkem_public_b64
                else None
            ),
            "mlkemCiphertextHash": (
                hashlib.sha256(mlkem_ciphertext).hexdigest()
                if mlkem_ciphertext is not None
                else None
            ),
        }
        k_enc, _ = derive_mode_keys(
            server_ephemeral,
            request["clientEphemeral"],
            ctx_k,
            mlkem_shared,
        )
        aad = {"ctx_K": ctx_k, "profile_sha256": self.profile_sha256}
        nonce = seeded_bytes(
            self.seed, f"profile-nonce:{transaction_id}:{session['cap']}", 12
        )
        ciphertext = encrypt_profile(k_enc, self.profile, aad, nonce)
        signed_response = {
            "ctx_K": ctx_k,
            "nonce": b64e(nonce),
            "ciphertext_hash": hashlib.sha256(b64d(ciphertext)).hexdigest(),
            "profile_sha256": self.profile_sha256,
        }
        response = {
            "transactionId": transaction_id,
            "ctx_K": ctx_k,
            "mlkemCiphertext": mlkem_ciphertext_b64,
            "nonce": b64e(nonce),
            "ciphertext": ciphertext,
            "profileSha256": self.profile_sha256,
            "serverSignature": p256_sign(self.binding_key, signed_response),
        }
        return response


def new_client(
    *,
    label: str,
    config: dict[str, Any],
    policy: str,
    offered: list[str] | None = None,
) -> ClientSession:
    seed = int(config["seed"])
    hybrid = config["hybrid_capability"]
    classical = config["classical_capability"]
    offer = offered or [hybrid, classical]
    return ClientSession(
        label=label,
        seed=seed,
        offered=offer,
        policy=policy,
        hybrid_cap=hybrid,
        classical_cap=classical,
        n_u=b64e(seeded_bytes(seed, f"{label}:N_U", 32)),
        one_time_private=deterministic_ed25519(seed, f"{label}:one-time"),
        client_ephemeral=deterministic_p256(seed, f"{label}:client-ephemeral"),
    )


def init_request(client: ClientSession) -> dict[str, Any]:
    return {"N_U": client.n_u, "capabilities": list(client.offered)}


def accept_server_auth(
    client: ClientSession,
    response: dict[str, Any],
    server_public,
) -> None:
    payload = response.get("serverAuth", {})
    if not p256_verify(
        server_public, payload, response.get("serverSignature", "")
    ):
        raise ProtocolReject(
            "server_authentication", "INVALID_SERVER_AUTH_SIGNATURE"
        )
    if payload.get("N_U") != client.n_u:
        raise ProtocolReject("server_authentication", "SERVER_NONCE_MISMATCH")
    if payload.get("capabilityOfferHash") != offer_hash(client.offered):
        raise ProtocolReject(
            "capability_transcript", "CAPABILITY_TRANSCRIPT_MISMATCH"
        )
    selected = payload.get("cap")
    if selected not in client.offered:
        raise ProtocolReject(
            "capability_selection", "UNSUPPORTED_SELECTED_CAPABILITY"
        )
    if client.policy == "require_hybrid" and selected != client.hybrid_cap:
        raise ProtocolReject("device_policy", "HYBRID_REQUIRED")
    client.selected_cap = selected
    client.server_auth = copy.deepcopy(payload)


def accept_bind_t(
    client: ClientSession, response: dict[str, Any], binding_public
) -> None:
    if client.server_auth is None or client.selected_cap is None:
        raise RuntimeError("server authentication has not been accepted")
    if response.get("transactionId") != client.server_auth["transactionId"]:
        raise ProtocolReject("profile_binding", "BIND_TRANSACTION_MISMATCH")
    if not p256_verify(
        binding_public, response.get("ctx_bind", {}), response.get("Bind_t", "")
    ):
        raise ProtocolReject("profile_binding", "INVALID_BIND_T_SIGNATURE")
    expected_transcript = sha256_hex(
        canonical(
            {
                "offerHash": offer_hash(client.offered),
                "selected": client.selected_cap,
            }
        )
    )
    ctx_bind = response["ctx_bind"]
    if (
        ctx_bind.get("ctx_t_hash")
        != sha256_hex(canonical(client.server_auth))
        or ctx_bind.get("capabilityTranscriptHash") != expected_transcript
    ):
        raise ProtocolReject(
            "profile_binding", "BIND_CAPABILITY_TRANSCRIPT_MISMATCH"
        )
    client.bind_response = copy.deepcopy(response)


def make_key_request(client: ClientSession) -> dict[str, Any]:
    if (
        client.server_auth is None
        or client.bind_response is None
        or client.selected_cap is None
    ):
        raise RuntimeError("client is not authenticated and bound")
    if client.selected_cap == client.hybrid_cap:
        seed = seeded_bytes(client.seed, f"{client.label}:mlkem-key", 64)
        client.mlkem_public, client.mlkem_private = ML_KEM_768.key_derive(seed)
        mlkem_public = b64e(client.mlkem_public)
    else:
        mlkem_public = None
    unsigned = {
        "transactionId": client.server_auth["transactionId"],
        "Bind_t": client.bind_response["Bind_t"],
        "ctx_bind": client.bind_response["ctx_bind"],
        "clientEphemeral": p256_public_b64(client.client_ephemeral.public_key()),
        "cap": client.selected_cap,
        "capabilityOfferHash": offer_hash(client.offered),
        "vk_t": ed25519_public_b64(client.one_time_private.public_key()),
        "mlkemPublicKey": mlkem_public,
    }
    return {
        **unsigned,
        "clientSignature": ed25519_sign(client.one_time_private, unsigned),
    }


def signed_profile_response(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "ctx_K": response.get("ctx_K"),
        "nonce": response.get("nonce"),
        "ciphertext_hash": hashlib.sha256(
            b64d(response.get("ciphertext", ""))
        ).hexdigest(),
        "profile_sha256": response.get("profileSha256"),
    }


def consume_profile(
    client: ClientSession,
    response: dict[str, Any],
    binding_public,
) -> bytes:
    if (
        client.server_auth is None
        or client.bind_response is None
        or client.selected_cap is None
    ):
        raise RuntimeError("client state incomplete")
    try:
        signed = signed_profile_response(response)
    except Exception as exc:
        raise ProtocolReject(
            "server_key_exchange_signature",
            "INVALID_SERVER_KEY_EXCHANGE_RESPONSE",
        ) from exc
    if not p256_verify(
        binding_public, signed, response.get("serverSignature", "")
    ):
        raise ProtocolReject(
            "server_key_exchange_signature",
            "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
        )
    ctx_k = response.get("ctx_K", {})
    expected = {
        "transactionId": client.server_auth["transactionId"],
        "Bind_t": client.bind_response["Bind_t"],
        "capabilityOfferHash": offer_hash(client.offered),
        "cap": client.selected_cap,
        "clientEphemeral": p256_public_b64(client.client_ephemeral.public_key()),
    }
    if any(ctx_k.get(key) != value for key, value in expected.items()):
        raise ProtocolReject("ctx_k_binding", "CTX_K_MISMATCH")
    if client.policy == "require_hybrid" and ctx_k["cap"] != client.hybrid_cap:
        raise ProtocolReject("device_policy", "HYBRID_REQUIRED")

    mlkem_shared: bytes | None = None
    if ctx_k["cap"] == client.hybrid_cap:
        if client.mlkem_public is None or client.mlkem_private is None:
            raise ProtocolReject("mlkem_client_state", "MISSING_LOCAL_MLKEM_KEY")
        if (
            ctx_k.get("mlkemPublicKeyHash")
            != hashlib.sha256(client.mlkem_public).hexdigest()
        ):
            raise ProtocolReject(
                "ctx_k_binding", "MLKEM_PUBLIC_KEY_HASH_MISMATCH"
            )
        ciphertext_b64 = response.get("mlkemCiphertext")
        if not ciphertext_b64:
            raise ProtocolReject(
                "mlkem_server_material", "MISSING_MLKEM_CIPHERTEXT"
            )
        try:
            mlkem_ciphertext = b64d(ciphertext_b64)
        except Exception as exc:
            raise ProtocolReject(
                "mlkem_server_material", "INVALID_MLKEM_CIPHERTEXT_ENCODING"
            ) from exc
        if (
            hashlib.sha256(mlkem_ciphertext).hexdigest()
            != ctx_k.get("mlkemCiphertextHash")
        ):
            raise ProtocolReject(
                "ctx_k_binding", "MLKEM_CIPHERTEXT_HASH_MISMATCH"
            )
        try:
            mlkem_shared = ML_KEM_768.decaps(
                client.mlkem_private, mlkem_ciphertext
            )
        except Exception as exc:
            raise ProtocolReject(
                "mlkem_decapsulation", "MLKEM_DECAPSULATION_FAILED"
            ) from exc
    else:
        if (
            response.get("mlkemCiphertext") is not None
            or ctx_k.get("mlkemPublicKeyHash") is not None
            or ctx_k.get("mlkemCiphertextHash") is not None
        ):
            raise ProtocolReject(
                "cross_mode_material", "UNEXPECTED_MLKEM_MATERIAL"
            )

    k_enc, _ = derive_mode_keys(
        client.client_ephemeral,
        ctx_k["serverEphemeral"],
        ctx_k,
        mlkem_shared,
    )
    aad = {"ctx_K": ctx_k, "profile_sha256": response["profileSha256"]}
    try:
        profile = decrypt_profile(
            k_enc, response["nonce"], response["ciphertext"], aad
        )
    except Exception as exc:
        raise ProtocolReject("aead", "PROFILE_AEAD_AUTHENTICATION_FAILED") from exc
    if hashlib.sha256(profile).hexdigest() != response["profileSha256"]:
        raise ProtocolReject("profile_digest", "PROFILE_DIGEST_MISMATCH")
    return profile


def build_honest_session(
    *,
    label: str,
    config: dict[str, Any],
    server: CapabilityServer,
    policy: str,
    selected_cap: str,
) -> dict[str, Any]:
    client = new_client(label=label, config=config, policy=policy)
    init = init_request(client)
    server_auth = server.initiate(init, selected_cap)
    accept_server_auth(client, server_auth, server.server_auth_public)
    bind = server.issue_bind_t(server_auth["serverAuth"]["transactionId"])
    accept_bind_t(client, bind, server.binding_public)
    key_request = make_key_request(client)
    response = server.get_profile(key_request)
    profile = consume_profile(client, response, server.binding_public)
    return {
        "client": client,
        "init": init,
        "server_auth": server_auth,
        "bind": bind,
        "key_request": key_request,
        "response": response,
        "profile": profile,
    }


def run_reject_case(
    *,
    scenario: str,
    category: str,
    action: Callable[[], None],
    request_bytes: int = 0,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        action()
    except ProtocolReject as exc:
        return {
            "scenario": scenario,
            "category": category,
            "accepted": False,
            "rejected": True,
            "rejection_stage": exc.stage,
            "reason": exc.reason,
            "session_key_established": False,
            "profile_delivered": False,
            "request_bytes": request_bytes,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    return {
        "scenario": scenario,
        "category": category,
        "accepted": True,
        "rejected": False,
        "rejection_stage": "none",
        "reason": "UNEXPECTED_ACCEPT",
        "session_key_established": True,
        "profile_delivered": True,
        "request_bytes": request_bytes,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def run_experiment(
    config: dict[str, Any], profile: bytes
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    server = CapabilityServer(config, profile)
    hybrid = config["hybrid_capability"]
    classical = config["classical_capability"]

    primitive_started = time.perf_counter()
    primitive_seed = seeded_bytes(int(config["seed"]), "mlkem-selftest", 64)
    ek, dk = ML_KEM_768.key_derive(primitive_seed)
    ss_a, ct = ML_KEM_768.encaps(ek)
    ss_b = ML_KEM_768.decaps(dk, ct)
    primitive_ms = (time.perf_counter() - primitive_started) * 1000

    hybrid_started = time.perf_counter()
    honest_hybrid = build_honest_session(
        label="honest-hybrid",
        config=config,
        server=server,
        policy="require_hybrid",
        selected_cap=hybrid,
    )
    hybrid_ms = (time.perf_counter() - hybrid_started) * 1000

    classical_started = time.perf_counter()
    honest_classical = build_honest_session(
        label="honest-classical",
        config=config,
        server=server,
        policy="allow_classical",
        selected_cap=classical,
    )
    classical_ms = (time.perf_counter() - classical_started) * 1000

    attacks: list[dict[str, Any]] = []

    def attack_offer_downgrade() -> None:
        client = new_client(
            label="attack-offer-downgrade",
            config=config,
            policy="allow_classical",
        )
        forwarded = init_request(client)
        forwarded["capabilities"] = [classical]
        response = server.initiate(forwarded, classical)
        accept_server_auth(client, response, server.server_auth_public)

    attacks.append(
        run_reject_case(
            scenario="mitm_offer_hybrid_to_classical",
            category="network_mitm",
            action=attack_offer_downgrade,
        )
    )

    def attack_signed_selection() -> None:
        response = copy.deepcopy(honest_hybrid["server_auth"])
        response["serverAuth"]["cap"] = classical
        accept_server_auth(
            honest_hybrid["client"], response, server.server_auth_public
        )

    attacks.append(
        run_reject_case(
            scenario="mitm_signed_selection_hybrid_to_classical",
            category="network_mitm",
            action=attack_signed_selection,
            request_bytes=len(canonical(honest_hybrid["server_auth"])),
        )
    )

    def attack_remove_mlkem_public() -> None:
        request = copy.deepcopy(honest_hybrid["key_request"])
        request.pop("mlkemPublicKey", None)
        server.get_profile(request)

    attacks.append(
        run_reject_case(
            scenario="remove_mlkem_public_key",
            category="network_mitm",
            action=attack_remove_mlkem_public,
            request_bytes=len(canonical(honest_hybrid["key_request"])),
        )
    )

    def attack_delete_mlkem_ciphertext() -> None:
        response = copy.deepcopy(honest_hybrid["response"])
        response.pop("mlkemCiphertext", None)
        consume_profile(
            honest_hybrid["client"], response, server.binding_public
        )

    attacks.append(
        run_reject_case(
            scenario="delete_mlkem_ciphertext",
            category="network_mitm",
            action=attack_delete_mlkem_ciphertext,
            request_bytes=len(canonical(honest_hybrid["response"])),
        )
    )

    def attack_replace_mlkem_ciphertext() -> None:
        response = copy.deepcopy(honest_hybrid["response"])
        replacement = bytearray(b64d(response["mlkemCiphertext"]))
        replacement[0] ^= 1
        response["mlkemCiphertext"] = b64e(bytes(replacement))
        consume_profile(
            honest_hybrid["client"], response, server.binding_public
        )

    attacks.append(
        run_reject_case(
            scenario="replace_mlkem_ciphertext",
            category="network_mitm",
            action=attack_replace_mlkem_ciphertext,
            request_bytes=len(canonical(honest_hybrid["response"])),
        )
    )

    def attack_classical_splice() -> None:
        response = copy.deepcopy(honest_hybrid["response"])
        response["ctx_K"]["serverEphemeral"] = honest_classical["response"][
            "ctx_K"
        ]["serverEphemeral"]
        consume_profile(
            honest_hybrid["client"], response, server.binding_public
        )

    attacks.append(
        run_reject_case(
            scenario="splice_classical_ephemeral_into_hybrid",
            category="network_mitm",
            action=attack_classical_splice,
            request_bytes=len(canonical(honest_hybrid["response"])),
        )
    )

    def attack_mark_hybrid_classical() -> None:
        response = copy.deepcopy(honest_hybrid["response"])
        response["ctx_K"]["cap"] = classical
        consume_profile(
            honest_hybrid["client"], response, server.binding_public
        )

    attacks.append(
        run_reject_case(
            scenario="mark_hybrid_response_as_classical",
            category="network_mitm",
            action=attack_mark_hybrid_classical,
            request_bytes=len(canonical(honest_hybrid["response"])),
        )
    )

    allow_started = time.perf_counter()
    allow_bundle = build_honest_session(
        label="legitimate-server-classical-allow",
        config=config,
        server=server,
        policy="allow_classical",
        selected_cap=classical,
    )
    allow_case = {
        "scenario": "legitimate_server_classical_allow",
        "category": "legitimate_server_policy",
        "accepted": True,
        "rejected": False,
        "rejection_stage": "none",
        "reason": "CLASSICAL_ALLOWED_BY_DEVICE_POLICY",
        "session_key_established": True,
        "profile_delivered": True,
        "request_bytes": len(canonical(allow_bundle["key_request"])),
        "elapsed_ms": round((time.perf_counter() - allow_started) * 1000, 3),
    }

    require_started = time.perf_counter()
    require_client = new_client(
        label="legitimate-server-classical-require",
        config=config,
        policy="require_hybrid",
    )
    require_init = init_request(require_client)
    require_response = server.initiate(require_init, classical)
    try:
        accept_server_auth(
            require_client, require_response, server.server_auth_public
        )
        require_case = {
            "scenario": "legitimate_server_classical_require_hybrid",
            "category": "legitimate_server_policy",
            "accepted": True,
            "rejected": False,
            "rejection_stage": "none",
            "reason": "UNEXPECTED_ACCEPT",
            "session_key_established": True,
            "profile_delivered": True,
        }
    except ProtocolReject as exc:
        require_case = {
            "scenario": "legitimate_server_classical_require_hybrid",
            "category": "legitimate_server_policy",
            "accepted": False,
            "rejected": True,
            "rejection_stage": exc.stage,
            "reason": exc.reason,
            "session_key_established": False,
            "profile_delivered": False,
        }
    require_case["request_bytes"] = len(canonical(require_response))
    require_case["elapsed_ms"] = round(
        (time.perf_counter() - require_started) * 1000, 3
    )

    positive = {
        "mlkem_primitive": {
            "algorithm": "ML-KEM-768",
            "public_key_bytes": len(ek),
            "private_key_bytes": len(dk),
            "ciphertext_bytes": len(ct),
            "shared_secret_bytes": len(ss_a),
            "shared_secret_match": ss_a == ss_b,
            "elapsed_ms": round(primitive_ms, 3),
        },
        "hybrid_require_hybrid": {
            "accepted": True,
            "profile_delivered": True,
            "profile_digest_match": hashlib.sha256(
                honest_hybrid["profile"]
            ).hexdigest()
            == hashlib.sha256(profile).hexdigest(),
            "mlkem_public_key_bytes": len(
                honest_hybrid["client"].mlkem_public or b""
            ),
            "mlkem_ciphertext_bytes": len(
                b64d(honest_hybrid["response"]["mlkemCiphertext"])
            ),
            "elapsed_ms": round(hybrid_ms, 3),
        },
        "classical_allow_classical": {
            "accepted": True,
            "profile_delivered": True,
            "profile_digest_match": hashlib.sha256(
                honest_classical["profile"]
            ).hexdigest()
            == hashlib.sha256(profile).hexdigest(),
            "mlkem_material_present": any(
                (
                    honest_classical["key_request"].get("mlkemPublicKey"),
                    honest_classical["response"].get("mlkemCiphertext"),
                )
            ),
            "elapsed_ms": round(classical_ms, 3),
        },
    }
    policy_cases = [allow_case, require_case]
    return positive, attacks + policy_cases


def find_line(path: Path, pattern: str) -> int | None:
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if pattern in line:
            return number
    return None


def build_source_audit(
    experiment_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    source = config["aura_source"]
    paths = {
        name: resolve_path(experiment_root, value)
        for name, value in source.items()
    }
    patterns = {
        "server_capability_selection": (
            "server",
            "capabilities = content.get(\"capabilities\", [])",
        ),
        "server_selected_cap_signed": ("server", "\"cap\": selected"),
        "server_auth_cap_immutable": ("server", "\"cap\": init_data[\"cap\"]"),
        "server_ctx_k": ("server", "\"domain\": \"AURA-RSP-v14:ctx_K\""),
        "server_session_kdf": ("server", "k_enc, k_mac = derive_session_keys("),
        "client_offers_capabilities": (
            "client",
            "\"capabilities\": self.config[\"capabilities\"]",
        ),
        "client_ctx_t_cap": ("client", "\"cap\": server_auth[\"cap\"]"),
        "client_ctx_k_check": ("client", "raise AuraClientError(\"ctx_K mismatch\")"),
        "client_server_kex_signature": (
            "client",
            "raise AuraClientError(\"server key exchange signature failed\")",
        ),
        "classical_kdf": ("primitives", "def derive_session_keys("),
    }
    checkpoints = {
        name: {
            "file": str(paths[file_key]),
            "line": find_line(paths[file_key], pattern),
            "pattern": pattern,
        }
        for name, (file_key, pattern) in patterns.items()
    }
    current_config = load_json(paths["config"])
    return {
        "current_aura_source_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in paths.items()
        },
        "checkpoints": checkpoints,
        "all_checkpoints_found": all(
            item["line"] is not None for item in checkpoints.values()
        ),
        "current_capabilities": current_config.get("capabilities", []),
        "current_source_has_mlkem": any(
            token in path.read_text(encoding="utf-8").lower()
            for path in paths.values()
            if path.suffix in {".py", ".json"}
            for token in ("ml-kem", "mlkem")
        ),
        "experiment_extension": {
            "scope": "independent capability and key-exchange layer demo",
            "ml_kem": "kyber-py 1.2.0 ML_KEM_768 educational implementation",
            "production_source_modified": False,
        },
    }


def make_assertion(
    name: str, expected: Any, observed: Any, passed: bool
) -> dict[str, Any]:
    return {
        "assertion": name,
        "expected": expected,
        "observed": observed,
        "passed": bool(passed),
    }


def build_assertions(
    positive: dict[str, Any],
    scenarios: list[dict[str, Any]],
    source_audit: dict[str, Any],
    profile_sha256: str,
) -> list[dict[str, Any]]:
    attacks = [row for row in scenarios if row["category"] == "network_mitm"]
    policy = {row["scenario"]: row for row in scenarios if row["category"] != "network_mitm"}
    allow = policy["legitimate_server_classical_allow"]
    require = policy["legitimate_server_classical_require_hybrid"]
    return [
        make_assertion(
            "mlkem768_real_encapsulation",
            "shared secrets match; FIPS 203 ML-KEM-768 lengths",
            positive["mlkem_primitive"],
            positive["mlkem_primitive"]["shared_secret_match"]
            and positive["mlkem_primitive"]["public_key_bytes"] == 1184
            and positive["mlkem_primitive"]["private_key_bytes"] == 2400
            and positive["mlkem_primitive"]["ciphertext_bytes"] == 1088
            and positive["mlkem_primitive"]["shared_secret_bytes"] == 32,
        ),
        make_assertion(
            "hybrid_positive_control",
            "Hybrid succeeds under require_hybrid",
            positive["hybrid_require_hybrid"],
            all(
                positive["hybrid_require_hybrid"][key]
                for key in (
                    "accepted",
                    "profile_delivered",
                    "profile_digest_match",
                )
            ),
        ),
        make_assertion(
            "classical_positive_control",
            "Classical succeeds under allow_classical without ML-KEM material",
            positive["classical_allow_classical"],
            positive["classical_allow_classical"]["accepted"]
            and positive["classical_allow_classical"]["profile_delivered"]
            and positive["classical_allow_classical"]["profile_digest_match"]
            and not positive["classical_allow_classical"][
                "mlkem_material_present"
            ],
        ),
        make_assertion(
            "mitm_attack_count",
            7,
            len(attacks),
            len(attacks) == 7,
        ),
        make_assertion(
            "all_network_downgrades_rejected",
            "all rejected",
            [row["accepted"] for row in attacks],
            all(not row["accepted"] for row in attacks),
        ),
        make_assertion(
            "no_attack_session_key",
            0,
            sum(row["session_key_established"] for row in attacks),
            not any(row["session_key_established"] for row in attacks),
        ),
        make_assertion(
            "no_attack_profile_delivery",
            0,
            sum(row["profile_delivered"] for row in attacks),
            not any(row["profile_delivered"] for row in attacks),
        ),
        make_assertion(
            "offer_downgrade_detected",
            "CAPABILITY_TRANSCRIPT_MISMATCH",
            attacks[0]["reason"],
            attacks[0]["reason"] == "CAPABILITY_TRANSCRIPT_MISMATCH",
        ),
        make_assertion(
            "signed_selection_tamper_detected",
            "INVALID_SERVER_AUTH_SIGNATURE",
            attacks[1]["reason"],
            attacks[1]["reason"] == "INVALID_SERVER_AUTH_SIGNATURE",
        ),
        make_assertion(
            "mlkem_public_key_deletion_detected",
            "INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE",
            attacks[2]["reason"],
            attacks[2]["reason"]
            == "INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE",
        ),
        make_assertion(
            "mlkem_ciphertext_delete_replace_detected",
            [
                "MISSING_MLKEM_CIPHERTEXT",
                "MLKEM_CIPHERTEXT_HASH_MISMATCH",
            ],
            [attacks[3]["reason"], attacks[4]["reason"]],
            attacks[3]["reason"] == "MISSING_MLKEM_CIPHERTEXT"
            and attacks[4]["reason"] == "MLKEM_CIPHERTEXT_HASH_MISMATCH",
        ),
        make_assertion(
            "cross_mode_splice_and_relabel_detected",
            [
                "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
                "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
            ],
            [attacks[5]["reason"], attacks[6]["reason"]],
            attacks[5]["reason"]
            == "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE"
            and attacks[6]["reason"]
            == "INVALID_SERVER_KEY_EXCHANGE_SIGNATURE",
        ),
        make_assertion(
            "legitimate_classical_allowed",
            "accepted and delivered",
            allow,
            allow["accepted"] and allow["profile_delivered"],
        ),
        make_assertion(
            "require_hybrid_rejects_legitimate_classical",
            "HYBRID_REQUIRED before key establishment and delivery",
            require,
            not require["accepted"]
            and require["reason"] == "HYBRID_REQUIRED"
            and not require["session_key_established"]
            and not require["profile_delivered"],
        ),
        make_assertion(
            "source_checkpoints_present",
            "all current AURA binding checkpoints found",
            source_audit["all_checkpoints_found"],
            source_audit["all_checkpoints_found"],
        ),
        make_assertion(
            "current_production_scope_disclosed",
            "current source has no ML-KEM; production source unchanged",
            {
                "current_source_has_mlkem": source_audit[
                    "current_source_has_mlkem"
                ],
                "production_source_modified": source_audit[
                    "experiment_extension"
                ]["production_source_modified"],
            },
            not source_audit["current_source_has_mlkem"]
            and not source_audit["experiment_extension"][
                "production_source_modified"
            ],
        ),
        make_assertion(
            "profile_digest_recorded",
            "64-char SHA-256",
            profile_sha256,
            len(profile_sha256) == 64,
        ),
        make_assertion(
            "public_transcripts_hide_eid",
            False,
            any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
            not any(
                "eid" in json.dumps(row, sort_keys=True).lower()
                for row in scenarios
            ),
        ),
    ]


ZH_NAMES = {
    "mitm_offer_hybrid_to_classical": "篡改能力提议",
    "mitm_signed_selection_hybrid_to_classical": "篡改已签名模式",
    "remove_mlkem_public_key": "删除ML-KEM公钥",
    "delete_mlkem_ciphertext": "删除ML-KEM密文",
    "replace_mlkem_ciphertext": "替换ML-KEM密文",
    "splice_classical_ephemeral_into_hybrid": "拼接Classic临时密钥",
    "mark_hybrid_response_as_classical": "Hybrid响应标成Classic",
    "legitimate_server_classical_allow": "合法服务器选Classic（允许）",
    "legitimate_server_classical_require_hybrid": "合法服务器选Classic（强制Hybrid）",
}

EN_NAMES = {
    "mitm_offer_hybrid_to_classical": "Tamper capability offer",
    "mitm_signed_selection_hybrid_to_classical": "Tamper signed selection",
    "remove_mlkem_public_key": "Remove ML-KEM public key",
    "delete_mlkem_ciphertext": "Delete ML-KEM ciphertext",
    "replace_mlkem_ciphertext": "Replace ML-KEM ciphertext",
    "splice_classical_ephemeral_into_hybrid": "Splice Classical ephemeral",
    "mark_hybrid_response_as_classical": "Relabel Hybrid as Classical",
    "legitimate_server_classical_allow": "Legitimate Classical / allow",
    "legitimate_server_classical_require_hybrid": "Legitimate Classical / require Hybrid",
}


def render_terminal(
    summary: dict[str, Any], lang: str, machine_json: bool
) -> None:
    if machine_json:
        compact = {
            "status": summary["status"],
            "network_attacks_rejected": summary["network_attacks_rejected"],
            "network_attacks_total": summary["network_attacks_total"],
            "attack_profile_deliveries": summary["attack_profile_deliveries"],
            "allow_classical_accepted": summary["allow_classical_accepted"],
            "require_hybrid_rejected": summary["require_hybrid_rejected"],
            "assertions": (
                f"{summary['assertions_passed']}/{summary['assertions_total']}"
            ),
            "results": summary["results_dir"],
        }
        print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")))
        return
    if lang in ("zh", "both"):
        print("\n实验9：能力协商降级攻击")
        print("=" * 92)
        print(
            f"{'场景':<31} {'类型':<12} {'结果':<8} {'拒绝阶段/原因'}"
        )
        print("-" * 92)
        for row in summary["scenarios"]:
            result = "接受" if row["accepted"] else "拒绝"
            category = "网络篡改" if row["category"] == "network_mitm" else "合法策略"
            detail = (
                row["reason"]
                if row["accepted"]
                else f"{row['rejection_stage']} / {row['reason']}"
            )
            print(
                f"{ZH_NAMES[row['scenario']]:<31} {category:<12} "
                f"{result:<8} {detail}"
            )
        print("-" * 92)
        print(
            f"网络攻击拒绝：{summary['network_attacks_rejected']}/"
            f"{summary['network_attacks_total']}；攻击Profile交付："
            f"{summary['attack_profile_deliveries']}"
        )
        print(
            "合法服务器选择Classical：allow_classical=接受，"
            "require_hybrid=拒绝"
        )
        print(
            f"机器断言：{summary['assertions_passed']}/"
            f"{summary['assertions_total']}；状态：{summary['status']}"
        )
    if lang in ("en", "both"):
        print("\nExperiment 9: Capability Negotiation Downgrade")
        print("=" * 100)
        print(
            f"{'Scenario':<39} {'Type':<17} {'Result':<9} {'Stage / reason'}"
        )
        print("-" * 100)
        for row in summary["scenarios"]:
            result = "ACCEPT" if row["accepted"] else "REJECT"
            category = "Network MITM" if row["category"] == "network_mitm" else "Policy"
            detail = (
                row["reason"]
                if row["accepted"]
                else f"{row['rejection_stage']} / {row['reason']}"
            )
            print(
                f"{EN_NAMES[row['scenario']]:<39} {category:<17} "
                f"{result:<9} {detail}"
            )
        print("-" * 100)
        print(
            f"Network attacks rejected: {summary['network_attacks_rejected']}/"
            f"{summary['network_attacks_total']}; attack Profile deliveries: "
            f"{summary['attack_profile_deliveries']}"
        )
        print(
            "Legitimate server selects Classical: allow_classical=ACCEPT, "
            "require_hybrid=REJECT"
        )
        print(
            f"Machine assertions: {summary['assertions_passed']}/"
            f"{summary['assertions_total']}; status: {summary['status']}"
        )


def render_report(
    output: Path,
    summary: dict[str, Any],
    assertions: list[dict[str, Any]],
    language: str,
) -> None:
    zh = language == "zh"
    names = ZH_NAMES if zh else EN_NAMES
    title = (
        "# 实验9：能力协商降级攻击结果"
        if zh
        else "# Experiment 9: Capability Downgrade Results"
    )
    lines = [title, ""]
    if zh:
        lines += [
            f"- 状态：**{summary['status']}**",
            (
                f"- 网络中间人攻击：{summary['network_attacks_rejected']}/"
                f"{summary['network_attacks_total']}拒绝"
            ),
            f"- 攻击路径Profile交付：{summary['attack_profile_deliveries']}",
            (
                f"- 机器断言：{summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "",
            "## 场景结果",
            "",
            "| 场景 | 类型 | 结果 | 阶段/原因 | Profile交付 |",
            "|---|---|---|---|---:|",
        ]
    else:
        lines += [
            f"- Status: **{summary['status']}**",
            (
                f"- Network MITM attacks: {summary['network_attacks_rejected']}/"
                f"{summary['network_attacks_total']} rejected"
            ),
            f"- Attack-path Profile deliveries: {summary['attack_profile_deliveries']}",
            (
                f"- Machine assertions: {summary['assertions_passed']}/"
                f"{summary['assertions_total']}"
            ),
            "",
            "## Scenario results",
            "",
            "| Scenario | Type | Result | Stage/reason | Profile delivered |",
            "|---|---|---|---|---:|",
        ]
    for row in summary["scenarios"]:
        if zh:
            kind = "网络中间人" if row["category"] == "network_mitm" else "合法服务器策略"
            result = "接受" if row["accepted"] else "拒绝"
        else:
            kind = "Network MITM" if row["category"] == "network_mitm" else "Legitimate server policy"
            result = "ACCEPT" if row["accepted"] else "REJECT"
        detail = (
            row["reason"]
            if row["accepted"]
            else f"{row['rejection_stage']} / {row['reason']}"
        )
        lines.append(
            f"| {names[row['scenario']]} | {kind} | {result} | "
            f"`{detail}` | {int(row['profile_delivered'])} |"
        )
    if zh:
        lines += [
            "",
            "## 结论与边界",
            "",
            (
                "所有网络篡改、材料删除、密文替换和跨模式拼接均未建立攻击会话密钥，"
                "也未交付Profile。"
            ),
            (
                "持合法签名密钥的服务器主动选择Classical时，允许Classical的设备正常"
                "接受；要求Hybrid的设备在Profile Binding和密钥协商前以"
                "`HYBRID_REQUIRED`拒绝。"
            ),
            (
                "ML-KEM部分使用`kyber-py 1.2.0`的真实ML-KEM-768实验实现，但该库不是"
                "常数时间生产库；当前AURA 9443生产原型仍只有Classical路径，本实验是"
                "独立能力层扩展。"
            ),
        ]
    else:
        lines += [
            "",
            "## Conclusion and scope",
            "",
            (
                "No network mutation, material deletion, ciphertext replacement, "
                "or cross-mode splice established an attacker session key or delivered "
                "a Profile."
            ),
            (
                "When a legitimately signing server selected Classical, a device that "
                "allowed Classical accepted it, while a device requiring Hybrid rejected "
                "with `HYBRID_REQUIRED` before Profile Binding and key establishment."
            ),
            (
                "ML-KEM uses the real ML-KEM-768 implementation in `kyber-py 1.2.0`, "
                "which is educational and not constant-time. The current AURA port 9443 "
                "prototype remains Classical-only; this is an independent capability-layer "
                "extension."
            ),
        ]
    passed = sum(item["passed"] for item in assertions)
    lines += [
        "",
        ("## 机器断言" if zh else "## Machine assertions"),
        "",
        f"{passed}/{len(assertions)} PASS",
        "",
    ]
    (output / f"report-{language}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def svg_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_matrix_svg(
    path: Path, scenarios: list[dict[str, Any]], language: str
) -> None:
    zh = language == "zh"
    names = ZH_NAMES if zh else EN_NAMES
    title = "实验9：能力协商降级与策略结果" if zh else "Experiment 9: Downgrade and Policy Results"
    headers = (
        ("场景", "类型", "结果", "Profile交付")
        if zh
        else ("Scenario", "Type", "Outcome", "Profile delivered")
    )
    width, row_h = 1420, 70
    height = 145 + row_h * len(scenarios)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;"
        "fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".head{font-size:22px;font-weight:700}",
        ".cell{font-size:21px}",
        ".small{font-size:19px}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="710" y="48" text-anchor="middle" class="title">{svg_escape(title)}</text>',
        '<rect x="30" y="78" width="1360" height="54" rx="8" fill="#e8eef8"/>',
    ]
    xs = (50, 680, 930, 1165)
    for x, label in zip(xs, headers):
        parts.append(
            f'<text x="{x}" y="113" class="head">{svg_escape(label)}</text>'
        )
    for index, row in enumerate(scenarios):
        y = 132 + index * row_h
        fill = "#f7f9fc" if index % 2 == 0 else "#ffffff"
        parts.append(
            f'<rect x="30" y="{y}" width="1360" height="{row_h}" fill="{fill}"/>'
        )
        kind = (
            ("网络篡改" if row["category"] == "network_mitm" else "合法策略")
            if zh
            else ("Network MITM" if row["category"] == "network_mitm" else "Policy")
        )
        outcome = (
            ("接受" if row["accepted"] else "拒绝")
            if zh
            else ("ACCEPT" if row["accepted"] else "REJECT")
        )
        delivery = "1" if row["profile_delivered"] else "0"
        parts += [
            f'<text x="50" y="{y + 43}" class="cell">{svg_escape(names[row["scenario"]])}</text>',
            f'<text x="680" y="{y + 43}" class="cell">{svg_escape(kind)}</text>',
            f'<text x="930" y="{y + 43}" class="cell" fill="'
            f'{"#16794a" if row["accepted"] else "#b42318"}">{outcome}</text>',
            f'<text x="1225" y="{y + 43}" text-anchor="middle" class="cell">{delivery}</text>',
        ]
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_flow_svg(path: Path, language: str) -> None:
    zh = language == "zh"
    title = "AURA能力与Hybrid密钥协商绑定链" if zh else "AURA Capability and Hybrid Key Binding Chain"
    labels = (
        [
            ("能力提议", "Hybrid + Classical"),
            ("服务器选择签名", "cap + offer hash"),
            ("Profile Binding", "Bind_t + transcript hash"),
            ("Hybrid密钥材料", "P-256 ECDH + ML-KEM-768"),
            ("安全交付", "ctx_K + signature + AEAD"),
        ]
        if zh
        else [
            ("Capability offer", "Hybrid + Classical"),
            ("Signed selection", "cap + offer hash"),
            ("Profile Binding", "Bind_t + transcript hash"),
            ("Hybrid key material", "P-256 ECDH + ML-KEM-768"),
            ("Secure delivery", "ctx_K + signature + AEAD"),
        ]
    )
    width, height = 1500, 360
    box_w, box_h, gap = 250, 126, 42
    start_x, y = 38, 126
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<defs>",
        '<marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">',
        '<path d="M0,0 L12,6 L0,12 z" fill="#486581"/>',
        "</marker>",
        "</defs>",
        "<style>",
        "text{font-family:'Microsoft YaHei','Noto Sans CJK SC','Arial',sans-serif;fill:#172033}",
        ".title{font-size:34px;font-weight:700}",
        ".main{font-size:24px;font-weight:700}",
        ".sub{font-size:19px}",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="750" y="52" text-anchor="middle" class="title">{svg_escape(title)}</text>',
    ]
    for index, (main, sub) in enumerate(labels):
        x = start_x + index * (box_w + gap)
        if index:
            previous_end = x - gap
            parts.append(
                f'<line x1="{previous_end + 6}" y1="{y + box_h / 2}" '
                f'x2="{x - 10}" y2="{y + box_h / 2}" stroke="#486581" '
                'stroke-width="4" marker-end="url(#arrow)"/>'
            )
        fill = "#e8f2ff" if index in (0, 1, 2) else "#eaf8f0"
        parts += [
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="16" '
            f'fill="{fill}" stroke="#9fb3c8" stroke-width="2"/>',
            f'<text x="{x + box_w/2}" y="{y + 48}" text-anchor="middle" '
            f'class="main">{svg_escape(main)}</text>',
        ]
        if index == 3:
            parts += [
                f'<text x="{x + box_w/2}" y="{y + 82}" text-anchor="middle" '
                'class="sub">P-256 ECDH +</text>',
                f'<text x="{x + box_w/2}" y="{y + 108}" text-anchor="middle" '
                'class="sub">ML-KEM-768</text>',
            ]
        else:
            parts.append(
                f'<text x="{x + box_w/2}" y="{y + 87}" text-anchor="middle" '
                f'class="sub">{svg_escape(sub)}</text>'
            )
    footer = (
        "任一字段被修改都会破坏后续签名、摘要、KDF上下文或AEAD验证"
        if zh
        else "Any mutation breaks a downstream signature, hash, KDF context, or AEAD check"
    )
    parts += [
        f'<text x="750" y="310" text-anchor="middle" class="sub">{svg_escape(footer)}</text>',
        "</svg>",
    ]
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lang", choices=("zh", "en", "both"), default="both")
    parser.add_argument("--machine-json", action="store_true")
    args = parser.parse_args()

    experiment_root = Path(__file__).resolve().parent
    config = load_json(Path(args.config))
    output = prepare_output(Path(args.output), experiment_root)
    profile, profile_path = load_profile(
        experiment_root,
        config["profile_path"],
        config["profile_fallback_path"],
    )
    profile_sha256 = hashlib.sha256(profile).hexdigest()

    positive, scenarios = run_experiment(config, profile)
    source_audit = build_source_audit(experiment_root, config)
    assertions = build_assertions(
        positive, scenarios, source_audit, profile_sha256
    )
    assertions_passed = sum(item["passed"] for item in assertions)
    attacks = [row for row in scenarios if row["category"] == "network_mitm"]
    allow = next(
        row
        for row in scenarios
        if row["scenario"] == "legitimate_server_classical_allow"
    )
    require = next(
        row
        for row in scenarios
        if row["scenario"]
        == "legitimate_server_classical_require_hybrid"
    )
    status = (
        "PASS" if assertions_passed == len(assertions) else "FAIL"
    )
    summary = {
        "experiment": config["experiment_name"],
        "status": status,
        "seed": config["seed"],
        "profile_path": str(profile_path),
        "profile_bytes": len(profile),
        "profile_sha256": profile_sha256,
        "positive_controls": positive,
        "scenarios": scenarios,
        "network_attacks_total": len(attacks),
        "network_attacks_rejected": sum(not row["accepted"] for row in attacks),
        "attack_session_keys_established": sum(
            row["session_key_established"] for row in attacks
        ),
        "attack_profile_deliveries": sum(
            row["profile_delivered"] for row in attacks
        ),
        "allow_classical_accepted": allow["accepted"],
        "require_hybrid_rejected": not require["accepted"],
        "assertions": assertions,
        "assertions_passed": assertions_passed,
        "assertions_total": len(assertions),
        "results_dir": str(output),
        "scope": {
            "current_aura": "Classical-only production prototype",
            "experiment": "independent real ML-KEM-768 capability-layer extension",
            "mlkem_library": "kyber-py 1.2.0 educational, non-constant-time",
            "server_threat_boundary": (
                "legitimate server selection is constrained by device policy, "
                "not classified as a network MITM"
            ),
        },
    }
    write_json(output / "summary.json", summary)
    write_json(output / "evidence" / "source-audit.json", source_audit)
    write_jsonl(output / "raw" / "transcripts.jsonl", scenarios)
    write_csv(output / "scenarios.csv", scenarios)
    write_csv(output / "assertions.csv", assertions)
    write_csv(
        output / "paper" / "table-capability-downgrade.csv", scenarios
    )
    render_report(output, summary, assertions, "zh")
    render_report(output, summary, assertions, "en")
    render_matrix_svg(
        output / "paper" / "capability-downgrade-matrix-zh.svg",
        scenarios,
        "zh",
    )
    render_matrix_svg(
        output / "paper" / "capability-downgrade-matrix-en.svg",
        scenarios,
        "en",
    )
    render_flow_svg(
        output / "paper" / "capability-binding-flow-zh.svg", "zh"
    )
    render_flow_svg(
        output / "paper" / "capability-binding-flow-en.svg", "en"
    )
    write_json(
        output / "paper" / "captions.json",
        {
            "zh": {
                "matrix": "图：AURA-RSP能力协商降级、跨模式拼接与设备策略结果。",
                "flow": "图：能力提议、服务器选择、Bind_t、Hybrid密钥材料与ctx_K的绑定链。",
            },
            "en": {
                "matrix": "Figure: AURA-RSP downgrade, cross-mode splice, and device-policy outcomes.",
                "flow": "Figure: Binding chain from capability offer through Bind_t and Hybrid key material to ctx_K.",
            },
        },
    )
    render_terminal(summary, args.lang, args.machine_json)
    if not args.machine_json:
        print(f"\nRESULTS={output}")
        print("CAPABILITY_DOWNGRADE_EXPERIMENT_PASS" if status == "PASS" else "CAPABILITY_DOWNGRADE_EXPERIMENT_FAIL")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
