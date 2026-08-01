"""HTTP-independent AURA-RSP SM-DP+ Profile Download service."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import secrets
import time

from pySim.esim.profile_store import ProfileRepository

from .bbs import public_key_from_dict
from .binding import build_binding, sign_binding
from .codec import (
    b64d,
    b64e,
    canonical,
    load_json,
    sha256_hex,
)
from .context import (
    auth_message_hash,
    build_ctx_t,
    capability_transcript,
    ctx_auth,
    gamma_for,
)
from .double_spend import classify_nullifier
from .errors import (
    AuraAuthenticationError,
    AuraPolicyError,
    AuraProtocolError,
    AuraStateError,
)
from .key_agreement import (
    CLASSICAL_MODE,
    HYBRID_MODE,
    build_ctx_k,
    derive_profile_keys,
    ka_s_payload,
    ka_u_payload,
    mlkem_encapsulate,
)
from .lifecycle import (
    LEGAL_TRANSITIONS,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_INSTALLED,
    STATE_PENDING_DELETE,
    STATE_TOMBSTONE,
    LifecycleError,
    LifecycleRepository,
    operation_rid,
)
from .models import (
    AuraAuthTranscript,
    AuraBindingState,
    AuraKeyState,
    AuraSessionState,
)
from .primitives import (
    ed25519_public_from_b64,
    ed25519_verify,
    encrypt_profile,
    generate_p256_private,
    p256_private_from_pem,
    p256_public_b64,
    p256_sign,
)
from .proof import verify_auth_proof
from .receipt import initial_last_hash, verify_install_receipt
from .store import AuraStore


logger = logging.getLogger(__name__)


class AuraService:
    def __init__(
        self,
        *,
        root: str | Path,
        profile_repository: ProfileRepository,
        store: AuraStore,
    ):
        self.root = Path(root)
        self.config = load_json(self.root / "config" / "aura.json")
        self.runtime = self.root / "runtime" / "aura"
        self.profile_repository = profile_repository
        self.store = store
        public = load_json(self.runtime / "server-public.json")
        self.eum_public_key = public_key_from_dict(public["eum_public_key"])
        self.mno_public_key = public_key_from_dict(public["mno_public_key"])
        self.server_auth_key = p256_private_from_pem(
            (self.runtime / "server-auth-key.pem").read_bytes()
        )
        self.profile_binding_key = p256_private_from_pem(
            (self.runtime / "profile-binding-key.pem").read_bytes()
        )
        self.lifecycle = LifecycleRepository(
            self.runtime / "lifecycle.sqlite"
        )

    def _profile_for_order(self, order):
        profile = self.profile_repository.load(order.matching_id)
        if profile.sha256 != order.pid_h:
            raise AuraPolicyError("ORDER_PROFILE_DIGEST_MISMATCH", "order")
        return profile

    def _require_pr(self, order, pr_identity: str) -> None:
        if not pr_identity or pr_identity != order.PRaddr:
            raise AuraPolicyError("PR_IDENTITY_MISMATCH", "transport")

    def initiate(self, content: dict, pr_identity: str) -> dict:
        i_ac = str(content.get("I_ac", ""))
        order = self.store.get_order(i_ac)
        if order is None:
            # Offline ticket issuance may occur while an in-memory benchmark
            # server is already running.  Import only the newly issued public
            # order; hidden ticket values remain on the eUICC side.
            from .models import AuraOrderContext

            orders_path = self.runtime / "orders.json"
            if orders_path.is_file():
                public_orders = load_json(orders_path)
                if i_ac in public_orders:
                    order = AuraOrderContext.from_dict(public_orders[i_ac])
                    self.store.put_order(order)
        if order is None:
            raise AuraPolicyError("UNKNOWN_ORDER", "initiateAuthentication")
        self._require_pr(order, pr_identity)
        if (
            order.op
            not in ("download", "enable", "disable", "delete", "reinstall")
            or order.exp < int(time.time())
        ):
            raise AuraPolicyError("INVALID_OR_EXPIRED_ORDER", "initiateAuthentication")
        self._profile_for_order(order)
        try:
            if len(b64d(content["N_U"])) != 32:
                raise ValueError
        except Exception as exc:
            raise AuraProtocolError(
                "INVALID_N_U", "initiateAuthentication", 400
            ) from exc
        offered = content.get("capabilities")
        if not isinstance(offered, list) or not all(
            isinstance(item, str) for item in offered
        ):
            raise AuraProtocolError(
                "INVALID_CAPABILITIES", "initiateAuthentication", 400
            )
        selected = next(
            (
                item
                for item in self.config["capabilities"]
                if item in offered
            ),
            None,
        )
        if selected is None:
            raise AuraPolicyError("NO_COMMON_CAPABILITY", "initiateAuthentication")
        cap = capability_transcript(offered, selected)
        transaction_id = secrets.token_hex(16).upper()
        server_auth = {
            "domain": "AURA-RSP-v14/server-auth",
            "transactionId": transaction_id,
            "I_t": b64e(secrets.token_bytes(16)),
            "N_U": content["N_U"],
            "N_S": b64e(secrets.token_bytes(32)),
            "sid": order.sid,
            "serverOID": self.config["server_oid"],
            "PRaddr": order.PRaddr,
            "cap": cap,
            "I_ac": order.I_ac,
        }
        session = AuraSessionState(
            transaction_id=transaction_id,
            order=order,
            server_auth=server_auth,
            created_at=int(time.time()),
        )
        self.store.put_session(session)
        logger.info(
            "AURA initiate transaction=%s order=%s cap=%s",
            transaction_id,
            order.I_ac,
            selected,
        )
        return {
            "serverAuth": server_auth,
            "serverSignature": p256_sign(self.server_auth_key, server_auth),
        }

    def _build_auth_context(
        self, session: AuraSessionState, content: dict
    ) -> dict:
        auth = session.server_auth
        return build_ctx_t(
            transaction_id=session.transaction_id,
            i_t=auth["I_t"],
            n_s=auth["N_S"],
            n_u=auth["N_U"],
            server_oid=auth["serverOID"],
            order=session.order,
            salt_p=str(content["salt_p"]),
            lph=str(content["lph"]),
            nu=str(content["nu"]),
            opid=str(content["opid"]),
            vk_t_hash=sha256_hex(b64d(content["vk_t"])),
            cap=auth["cap"],
            cred_exp=int(content["cred_exp"]),
        )

    def authenticate(self, content: dict, pr_identity: str) -> dict:
        transaction_id = str(content.get("transactionId", ""))
        session = self.store.get_session(transaction_id)
        if session is None:
            raise AuraStateError("UNKNOWN_TRANSACTION", "authenticateClient")
        if session.status not in ("initiated", "authenticated"):
            raise AuraStateError("INVALID_SESSION_STATE", "authenticateClient")
        self._require_pr(session.order, pr_identity)
        if session.order.exp < int(time.time()):
            raise AuraPolicyError("EXPIRED_TICKET", "authenticateClient")
        if int(content.get("cred_exp", 0)) < int(time.time()):
            raise AuraPolicyError("EXPIRED_DEVICE_CREDENTIAL", "authenticateClient")
        self._profile_for_order(session.order)
        try:
            salt_p = b64d(content["salt_p"])
            if len(salt_p) != 32:
                raise ValueError
            one_time_public = ed25519_public_from_b64(content["vk_t"])
            ctx_t = self._build_auth_context(session, content)
        except AuraProtocolError:
            raise
        except Exception as exc:
            raise AuraProtocolError(
                "INVALID_AUTH_ENCODING", "authenticateClient", 400
            ) from exc

        proof = content["Pi_auth"]
        if (
            proof.get("v") != content["nu"]
            or proof.get("lph") != content["lph"]
            or proof.get("gamma") != content["gamma"]
            or proof.get("c") != content["c"]
        ):
            raise AuraAuthenticationError("PROOF_PUBLIC_FIELD_MISMATCH")
        expected_gamma = gamma_for(ctx_t)
        if content["gamma"] != expected_gamma:
            raise AuraAuthenticationError("GAMMA_CONTEXT_MISMATCH")
        tau_payload = ctx_auth(ctx_t, content["gamma"], content["c"])
        if not ed25519_verify(
            one_time_public, tau_payload, content.get("tau_auth", "")
        ):
            raise AuraAuthenticationError("INVALID_TAU_AUTH")

        verify_started = time.perf_counter_ns()
        proof_ok, proof_reason = verify_auth_proof(
            ctx_t=ctx_t,
            proof=proof,
            eum_public_key=self.eum_public_key,
            mno_public_key=self.mno_public_key,
            salt_p=salt_p,
        )
        proof_verify_ms = round(
            (time.perf_counter_ns() - verify_started) / 1_000_000, 3
        )
        if not proof_ok:
            logger.warning(
                "AURA proof rejected transaction=%s reason=%s",
                transaction_id,
                proof_reason,
            )
            raise AuraAuthenticationError("INVALID_PI_AUTH:" + proof_reason)

        if session.order.op != "download":
            try:
                lifecycle_snapshot = self.lifecycle.snapshot(content["lph"])
            except LifecycleError as exc:
                raise AuraStateError(exc.code, exc.stage) from exc
            if (
                lifecycle_snapshot["pid_h"] != session.order.pid_h
                or lifecycle_snapshot["salt_p"] != content["salt_p"]
            ):
                raise AuraStateError(
                    "PROFILE_CONTEXT_MISMATCH", "profile_context"
                )
            allowed_predecessors = {
                "enable": {STATE_INSTALLED, STATE_DISABLED},
                "disable": {STATE_ENABLED},
                "delete": {
                    STATE_INSTALLED,
                    STATE_ENABLED,
                    STATE_DISABLED,
                },
                "reinstall": {STATE_TOMBSTONE},
            }
            if lifecycle_snapshot["state"] not in allowed_predecessors[
                session.order.op
            ]:
                raise AuraStateError(
                    "INVALID_OPERATION_PREDECESSOR", "state_predecessor"
                )

        auth_message = {
            key: content[key]
            for key in (
                "transactionId",
                "salt_p",
                "lph",
                "nu",
                "opid",
                "vk_t",
                "cred_exp",
                "gamma",
                "c",
                "tau_auth",
                "Pi_auth",
            )
        }
        auth_hash = auth_message_hash(auth_message)
        nu = content["nu"]
        with self.store.locked():
            used = self.store.get_nullifier(nu)
            if used is not None:
                decision = classify_nullifier(
                    existing=used,
                    auth_hash=auth_hash,
                    opid=content["opid"],
                    gamma=content["gamma"],
                    c_value=content["c"],
                    trace_lookup=self.store.lookup_trace,
                )
                if decision.outcome == "exact_replay":
                    response = dict(used["response"])
                    response["replayed"] = True
                    return response
                if decision.outcome == "opid_context_conflict":
                    raise AuraStateError(
                        decision.error_code, "authenticateClient"
                    )
                if decision.outcome == "zero_denominator":
                    raise AuraStateError(
                        decision.error_code, "authenticateClient"
                    )
                raise AuraStateError(
                    decision.error_code,
                    "authenticateClient",
                )

            binding_started = time.perf_counter_ns()
            th_auth, ctx_bind = build_binding(ctx_t, auth_message)
            bind_t = sign_binding(self.profile_binding_key, ctx_bind)
            binding_ms = round(
                (time.perf_counter_ns() - binding_started) / 1_000_000, 3
            )
            response = {
                "transactionId": transaction_id,
                "ctx_bind": ctx_bind,
                "Bind_t": bind_t,
                "proofVerifyMs": proof_verify_ms,
                "bindingMs": binding_ms,
                "replayed": False,
            }
            transcript = AuraAuthTranscript(
                ctx_t=ctx_t,
                auth_request=auth_message,
                auth_hash=auth_hash,
                nu=nu,
                gamma=content["gamma"],
                c_value=content["c"],
                opid=content["opid"],
                vk_t=content["vk_t"],
            )
            session.auth = transcript
            session.binding = AuraBindingState(
                th_auth=th_auth,
                ctx_bind=ctx_bind,
                bind_t=bind_t,
            )
            session.cached_auth_response = response
            session.status = "authenticated"
            self.store.put_nullifier(
                nu,
                {
                    "auth_hash": auth_hash,
                    "gamma": content["gamma"],
                    "c": content["c"],
                    "opid": content["opid"],
                    "transaction_id": transaction_id,
                    "response": response,
                },
            )
            self.store.put_session(session)
        logger.info(
            "AURA authenticate transaction=%s proof_ms=%.3f",
            transaction_id,
            proof_verify_ms,
        )
        return response

    def _prepare_keys(
        self,
        content: dict,
        pr_identity: str,
        *,
        allowed_ops: tuple[str, ...],
    ):
        transaction_id = str(content.get("transactionId", ""))
        session = self.store.get_session(transaction_id)
        if (
            session is None
            or session.status != "authenticated"
            or session.auth is None
            or session.binding is None
        ):
            raise AuraStateError("SESSION_NOT_AUTHENTICATED", "profile")
        if session.order.op not in allowed_ops:
            raise AuraPolicyError("OPERATION_ENDPOINT_MISMATCH", "profile")
        self._require_pr(session.order, pr_identity)
        if content.get("Bind_t") != session.binding.bind_t:
            raise AuraAuthenticationError("BIND_T_MISMATCH")
        if content.get("ctx_bind") != session.binding.ctx_bind:
            raise AuraAuthenticationError("CTX_BIND_MISMATCH")
        mode = str(content.get("mode", ""))
        selected = session.server_auth["cap"]["selected"]
        if mode not in (CLASSICAL_MODE, HYBRID_MODE):
            raise AuraPolicyError("UNSUPPORTED_KEY_MODE", "profile")
        if selected != mode:
            raise AuraPolicyError("CAPABILITY_MODE_MISMATCH", "profile")
        q_u = str(content.get("Q_U", ""))
        mlkem_u = content.get("MLKEM_U")
        try:
            ka_u = ka_u_payload(
                i_t=session.server_auth["I_t"], q_u=q_u,
                bind_t=session.binding.bind_t, mode=mode, mlkem_u=mlkem_u,
            )
        except (ValueError, RuntimeError) as exc:
            raise AuraPolicyError(str(exc), "profile") from exc
        if not ed25519_verify(
            ed25519_public_from_b64(session.auth.vk_t),
            ka_u,
            content.get("sigma_U_Q", ""),
        ):
            raise AuraAuthenticationError("INVALID_KA_U_SIGNATURE")
        server_ephemeral = generate_p256_private()
        q_s = p256_public_b64(server_ephemeral.public_key())
        pq_shared = None
        mlkem_s = None
        if mode == HYBRID_MODE:
            try:
                pq_shared, mlkem_ciphertext = mlkem_encapsulate(b64d(mlkem_u))
                mlkem_s = b64e(mlkem_ciphertext)
            except Exception as exc:
                raise AuraAuthenticationError("INVALID_MLKEM_PUBLIC_KEY") from exc
        try:
            ctx_k = build_ctx_k(
                ctx_t=session.auth.ctx_t, bind_t=session.binding.bind_t,
                q_u=q_u, q_s=q_s, mode=mode,
                mlkem_u=mlkem_u, mlkem_s=mlkem_s,
            )
            k_enc, k_mac = derive_profile_keys(
                server_ephemeral, q_u, ctx_k, pq_shared=pq_shared
            )
        except ValueError as exc:
            raise AuraAuthenticationError(str(exc)) from exc
        return session, q_u, q_s, ctx_k, k_enc, k_mac, mode, mlkem_s

    def get_profile(self, content: dict, pr_identity: str) -> dict:
        crypto_started = time.perf_counter_ns()
        session, q_u, q_s, ctx_k, k_enc, k_mac, mode, mlkem_s = self._prepare_keys(
            content,
            pr_identity,
            allowed_ops=("download", "reinstall"),
        )
        profile = self._profile_for_order(session.order)
        aad = {
            "domain": "AURA-RSP-v14/profile",
            "ctx_K": ctx_k,
            "profile_sha256": profile.sha256,
        }
        nonce, ciphertext = encrypt_profile(k_enc, profile.data, aad)
        ciphertext_hash = hashlib.sha256(b64d(ciphertext)).hexdigest()
        ka_s = ka_s_payload(i_t=session.server_auth["I_t"], ctx_k=ctx_k)
        response = {
            "transactionId": session.transaction_id,
            "ctx_K": ctx_k,
            "Q_S": q_s,
            "mode": mode,
            "sigma_S_Q": p256_sign(self.profile_binding_key, ka_s),
            "nonce": nonce,
            "ciphertext": ciphertext,
            "ciphertextSha256": ciphertext_hash,
            "profileSha256": profile.sha256,
            "serverCryptoMs": round(
                (time.perf_counter_ns() - crypto_started) / 1_000_000, 3
            ),
        }
        if mlkem_s is not None:
            response["MLKEM_S"] = mlkem_s
        session.key_state = AuraKeyState(
            mode=mode,
            q_u=q_u,
            q_s=q_s,
            ctx_k=ctx_k,
            k_mac=k_mac,
            k_enc=None,
        )
        session.profile_ciphertext_hash = ciphertext_hash
        session.status = (
            "downloaded"
            if session.order.op == "download"
            else "reinstall-downloaded"
        )
        self.store.put_session(session)
        logger.info(
            "AURA profile transaction=%s bytes=%d",
            session.transaction_id,
            len(profile.data),
        )
        return response

    def prepare_lifecycle(self, content: dict, pr_identity: str) -> dict:
        crypto_started = time.perf_counter_ns()
        session, q_u, q_s, ctx_k, _k_enc, k_mac, mode, mlkem_s = self._prepare_keys(
            content,
            pr_identity,
            allowed_ops=("enable", "disable", "delete"),
        )
        session.key_state = AuraKeyState(
            mode=mode,
            q_u=q_u,
            q_s=q_s,
            ctx_k=ctx_k,
            k_mac=k_mac,
            k_enc=None,
        )
        session.status = "lifecycle-prepared"
        self.store.put_session(session)
        ka_s = ka_s_payload(i_t=session.server_auth["I_t"], ctx_k=ctx_k)
        response = {
            "transactionId": session.transaction_id,
            "operation": session.order.op,
            "ctx_K": ctx_k,
            "Q_S": q_s,
            "mode": mode,
            "sigma_S_Q": p256_sign(self.profile_binding_key, ka_s),
            "serverCryptoMs": round(
                (time.perf_counter_ns() - crypto_started) / 1_000_000, 3
            ),
        }
        if mlkem_s is not None:
            response["MLKEM_S"] = mlkem_s
        return response

    def notification(self, content: dict, pr_identity: str) -> None:
        transaction_id = str(content.get("transactionId", ""))
        receipt = content.get("InstallReceipt")
        session = self.store.get_session(transaction_id)
        if (
            session is None
            or session.auth is None
            or session.binding is None
            or session.key_state is None
            or session.profile_ciphertext_hash is None
        ):
            raise AuraStateError("PROFILE_NOT_DOWNLOADED", "notification")
        if session.order.op != "download":
            raise AuraPolicyError("OPERATION_ENDPOINT_MISMATCH", "notification")
        self._require_pr(session.order, pr_identity)
        if not isinstance(receipt, dict):
            raise AuraProtocolError("INVALID_INSTALL_RECEIPT", "notification", 400)
        existing = self.store.get_profile_state(session.auth.ctx_t["lph"])
        if session.status == "installed":
            if existing and existing.get("receipt") == receipt:
                return
            raise AuraStateError("INSTALL_RECEIPT_CONFLICT", "notification")
        if session.status != "downloaded":
            raise AuraStateError("PROFILE_NOT_DOWNLOADED", "notification")
        if not verify_install_receipt(
            session.key_state.k_mac,
            receipt,
            lph=session.auth.ctx_t["lph"],
            ctx_t=session.auth.ctx_t,
            bind_t=session.binding.bind_t,
            ciphertext_hash=session.profile_ciphertext_hash,
        ):
            raise AuraAuthenticationError("INVALID_INSTALL_RECEIPT")
        state = {
            "pid_h": session.order.pid_h,
            "salt_p": session.auth.ctx_t["salt_p"],
            "state": 1,
            "ctr": 1,
            "last_hash": initial_last_hash(receipt),
            "receipt": receipt,
        }
        try:
            lifecycle_state = self.lifecycle.initialize_install(
                lph=session.auth.ctx_t["lph"],
                pid_h=session.order.pid_h,
                salt_p=session.auth.ctx_t["salt_p"],
                receipt=receipt,
                last_hash=initial_last_hash(receipt),
            )
        except LifecycleError as exc:
            raise AuraStateError(exc.code, exc.stage) from exc
        state.update(
            {
                "state": lifecycle_state["state"],
                "ctr": lifecycle_state["ctr"],
                "last_hash": lifecycle_state["last_hash"],
            }
        )
        self.store.put_profile_state(session.auth.ctx_t["lph"], state)
        session.status = "installed"
        self.store.put_session(session)
        logger.info("AURA installed transaction=%s", transaction_id)

    def lifecycle_receipt(self, content: dict, pr_identity: str) -> dict:
        transaction_id = str(content.get("transactionId", ""))
        receipt = content.get("StateReceipt")
        session = self.store.get_session(transaction_id)
        if (
            session is None
            or session.auth is None
            or session.binding is None
            or session.key_state is None
            or session.status
            not in (
                "lifecycle-prepared",
                "lifecycle-complete",
                "pending-delete",
            )
        ):
            raise AuraStateError("LIFECYCLE_SESSION_NOT_PREPARED", "lifecycle")
        self._require_pr(session.order, pr_identity)
        if session.order.op not in ("enable", "disable", "delete"):
            raise AuraPolicyError("OPERATION_ENDPOINT_MISMATCH", "lifecycle")
        if not isinstance(receipt, dict):
            raise AuraProtocolError("INVALID_STATE_RECEIPT", "lifecycle", 400)
        expected_rid = operation_rid(
            session.order.op,
            ctx_t=session.auth.ctx_t,
            bind_t=session.binding.bind_t,
        )
        if receipt.get("rid_op") != expected_rid:
            raise AuraStateError("OPERATION_RID_MISMATCH", "operation_context")
        try:
            if session.order.op == "delete":
                response = self.lifecycle.prepare_delete(
                    transaction_id=transaction_id,
                    pid_h=session.order.pid_h,
                    salt_p=session.auth.ctx_t["salt_p"],
                    ticket_expires_at=session.order.exp,
                    ctx_t=session.auth.ctx_t,
                    k_mac=session.key_state.k_mac,
                    signing_key=self.profile_binding_key,
                    receipt=receipt,
                )
                session.status = "pending-delete"
            else:
                response = self.lifecycle.apply_state(
                    transaction_id=transaction_id,
                    op=session.order.op,
                    pid_h=session.order.pid_h,
                    salt_p=session.auth.ctx_t["salt_p"],
                    k_mac=session.key_state.k_mac,
                    receipt=receipt,
                )
                session.status = "lifecycle-complete"
        except LifecycleError as exc:
            raise AuraStateError(exc.code, exc.stage) from exc
        self.store.put_session(session)
        return response

    def commit_delete(self, content: dict, pr_identity: str) -> dict:
        transaction_id = str(content.get("transactionId", ""))
        receipt = content.get("CommitReceipt")
        session = self.store.get_session(transaction_id)
        if (
            session is None
            or session.order.op != "delete"
            or session.auth is None
            or session.key_state is None
            or session.status not in ("pending-delete", "tombstone")
        ):
            raise AuraStateError("DELETE_SESSION_NOT_PENDING", "commit-delete")
        self._require_pr(session.order, pr_identity)
        if not isinstance(receipt, dict):
            raise AuraProtocolError(
                "INVALID_COMMIT_RECEIPT", "commit-delete", 400
            )
        try:
            response = self.lifecycle.commit_delete(
                transaction_id=transaction_id,
                ctx_t=session.auth.ctx_t,
                k_mac=session.key_state.k_mac,
                rprep_public_key=self.profile_binding_key.public_key(),
                receipt=receipt,
            )
        except LifecycleError as exc:
            raise AuraStateError(exc.code, exc.stage) from exc
        session.status = "tombstone"
        self.store.put_session(session)
        return response

    def reinstall_receipt(self, content: dict, pr_identity: str) -> dict:
        transaction_id = str(content.get("transactionId", ""))
        receipt = content.get("ReinstallReceipt")
        session = self.store.get_session(transaction_id)
        if (
            session is None
            or session.order.op != "reinstall"
            or session.auth is None
            or session.binding is None
            or session.key_state is None
            or session.profile_ciphertext_hash is None
            or session.status not in ("reinstall-downloaded", "installed")
        ):
            raise AuraStateError("REINSTALL_SESSION_NOT_READY", "reinstall")
        self._require_pr(session.order, pr_identity)
        if not isinstance(receipt, dict):
            raise AuraProtocolError(
                "INVALID_REINSTALL_RECEIPT", "reinstall", 400
            )
        expected_rid = operation_rid(
            "reinstall",
            ctx_t=session.auth.ctx_t,
            bind_t=session.binding.bind_t,
            ciphertext_hash=session.profile_ciphertext_hash,
        )
        if receipt.get("rid_op") != expected_rid:
            raise AuraStateError("REINSTALL_RID_MISMATCH", "operation_context")
        try:
            response = self.lifecycle.apply_state(
                transaction_id=transaction_id,
                op="reinstall",
                pid_h=session.order.pid_h,
                salt_p=session.auth.ctx_t["salt_p"],
                k_mac=session.key_state.k_mac,
                receipt=receipt,
            )
        except LifecycleError as exc:
            raise AuraStateError(exc.code, exc.stage) from exc
        session.status = "installed"
        self.store.put_session(session)
        return response

    def lifecycle_snapshot(self, lph: str) -> dict:
        try:
            return self.lifecycle.snapshot(lph)
        except LifecycleError as exc:
            raise AuraStateError(exc.code, exc.stage) from exc

    def get_lifecycle_state(self, content: dict, pr_identity: str) -> dict:
        if pr_identity != self.config["praddr"]:
            raise AuraPolicyError("PR_IDENTITY_MISMATCH", "transport")
        return self.lifecycle_snapshot(str(content.get("lph", "")))
