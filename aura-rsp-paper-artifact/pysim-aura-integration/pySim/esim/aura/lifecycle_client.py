"""Software eUICC/LPA client for the integrated AURA lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import time

from py_ecc.optimized_bls12_381 import multiply

from pySim.esim.software_euicc import install_profile

from .bbs import BBSSignature
from .binding import verify_binding
from .client import AuraClientError, AuraLpaClient
from .codec import (
    b64d,
    b64e,
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
from .lifecycle import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_INSTALLED,
    STATE_PENDING_DELETE,
    STATE_TOMBSTONE,
    STATE_NAMES,
    create_commit_receipt,
    create_state_receipt,
    operation_rid,
    state_last_hash,
    verify_rprep,
)
from .models import AuraOrderContext
from .primitives import (
    decrypt_profile,
    ed25519_public_b64,
    ed25519_sign,
    generate_ed25519_private,
    generate_p256_private,
    p256_public_b64,
    p256_verify,
)
from .proof import G_V, create_auth_proof, lph_base
from .profile_validation import verify_profile_plaintext
from .ticket import issue_ticket


ROOT = Path(__file__).resolve().parents[3]


class AuraLifecycleClient(AuraLpaClient):
    def _save_local_state(
        self,
        local: dict,
        *,
        state: int,
        ctr: int,
        last_hash: str,
        profile_present: bool | None = None,
    ) -> dict:
        local.update(
            {
                "state": int(state),
                "state_name": STATE_NAMES[int(state)],
                "ctr": int(ctr),
                "last_hash": last_hash,
            }
        )
        if profile_present is not None:
            local["profile_present"] = bool(profile_present)
        self.device.setdefault("lifecycle_by_lph", {})[local["lph"]] = local
        save_json(self.device_path, self.device)
        return local

    def _authenticate_and_prepare(self, op: str) -> dict:
        self.device = load_json(self.device_path)
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
        if order.op != op:
            raise AuraClientError("issued ticket operation mismatch")
        if order.exp < int(time.time()):
            raise AuraClientError("ticket expired")

        offered = list(self.config["capabilities"])
        n_u = b64e(secrets.token_bytes(32))
        _, init_response = self.post(
            "/aura/rsp/v1/initiateAuthentication",
            {"I_ac": order.I_ac, "N_U": n_u, "capabilities": offered},
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

        salts = self.device.setdefault("salt_by_pid", {})
        if order.pid_h not in salts:
            raise AuraClientError("lifecycle operation has no saved salt_p")
        salt_p_b64 = salts[order.pid_h]
        salt_p = b64d(salt_p_b64)
        x = scalar_from_b64(self.device["x"])
        k = scalar_from_b64(self.device["k"])
        eta = scalar_from_b64(self.device["eta"])
        d_value = scalar_from_b64(self.device["d"])
        nu = g1_to_b64(multiply(G_V, eta))
        lph = g1_to_b64(multiply(lph_base(order.pid_h, salt_p), x))
        local = self.device.get("lifecycle_by_lph", {}).get(lph)
        if local is None:
            raise AuraClientError("local lifecycle state not found")

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
        if auth_request is not None:
            raise AuraClientError(
                "unexpected cached lifecycle authentication context"
            )
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
        _, auth_response = self.post(
            "/aura/rsp/v1/authenticateClient", auth_request
        )
        assert auth_response is not None
        if not verify_binding(
            self.profile_binding_public,
            auth_response["ctx_bind"],
            auth_response["Bind_t"],
        ):
            raise AuraClientError("Bind_t verification failed")

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
        endpoint = (
            "/aura/rsp/v1/getBoundProfilePackage"
            if op == "reinstall"
            else "/aura/rsp/v1/prepareLifecycleOperation"
        )
        _, key_response = self.post(endpoint, key_request)
        assert key_response is not None
        expected_ctx_k = build_ctx_k(
            ctx_t=ctx_t,
            bind_t=auth_response["Bind_t"],
            q_u=q_u,
            q_s=key_response["Q_S"],
            mode=selected_mode,
            mlkem_u=mlkem_u,
            mlkem_s=key_response.get("MLKEM_S"),
        )
        if key_response["ctx_K"] != expected_ctx_k:
            raise AuraClientError("ctx_K mismatch")
        ka_s = ka_s_payload(i_t=server_auth["I_t"], ctx_k=expected_ctx_k)
        if not p256_verify(
            self.profile_binding_public,
            ka_s,
            key_response["sigma_S_Q"],
        ):
            raise AuraClientError("KA-S signature failed")
        pq_shared = None
        if selected_mode == HYBRID_MODE:
            if mlkem_private is None or not key_response.get("MLKEM_S"):
                raise AuraClientError("MISSING_MLKEM_KEY_MATERIAL")
            pq_shared = mlkem_decapsulate(
                mlkem_private, b64d(key_response["MLKEM_S"])
            )
        k_enc, k_mac = derive_profile_keys(
            client_ephemeral, key_response["Q_S"], expected_ctx_k,
            pq_shared=pq_shared,
        )
        return {
            "order": order,
            "transaction_id": server_auth["transactionId"],
            "ctx_t": ctx_t,
            "bind_t": auth_response["Bind_t"],
            "lph": lph,
            "local": local,
            "k_enc": k_enc,
            "k_mac": k_mac,
            "key_response": key_response,
        }

    @staticmethod
    def _target_state(op: str, old_state: int) -> int:
        if op == "enable" and old_state in (STATE_INSTALLED, STATE_DISABLED):
            return STATE_ENABLED
        if op == "disable" and old_state == STATE_ENABLED:
            return STATE_DISABLED
        if op == "delete" and old_state in (
            STATE_INSTALLED,
            STATE_ENABLED,
            STATE_DISABLED,
        ):
            return STATE_PENDING_DELETE
        if op == "reinstall" and old_state == STATE_TOMBSTONE:
            return STATE_INSTALLED
        raise AuraClientError(f"illegal local transition: {old_state} --{op}--> ?")

    def run_operation(
        self,
        op: str,
        *,
        replay_receipt: bool = False,
        stop_after_prepare: bool = False,
    ) -> dict:
        if op not in ("enable", "disable", "delete", "reinstall"):
            raise AuraClientError(f"unsupported lifecycle operation: {op}")
        issue_ticket(self.root, op=op)
        prepared = self._authenticate_and_prepare(op)
        local = dict(prepared["local"])
        target = self._target_state(op, int(local["state"]))

        if op == "reinstall":
            key_response = prepared["key_response"]
            ciphertext_hash = hashlib.sha256(
                b64d(key_response["ciphertext"])
            ).hexdigest()
            if ciphertext_hash != key_response["ciphertextSha256"]:
                raise AuraClientError("reinstall ciphertext hash mismatch")
            aad = {
                "domain": "AURA-RSP-v14/profile",
                "ctx_K": key_response["ctx_K"],
                "profile_sha256": key_response["profileSha256"],
            }
            profile = decrypt_profile(
                prepared["k_enc"],
                key_response["nonce"],
                key_response["ciphertext"],
                aad,
            )
            profile_hash = verify_profile_plaintext(
                profile,
                response_sha256=key_response["profileSha256"],
                order_pid_h=prepared["order"].pid_h,
            )
            install_profile(
                profile,
                expected_sha256=prepared["order"].pid_h,
                output_dir=self.runtime / "software-euicc-output",
                protocol_mode="aura",
                transaction_id=prepared["transaction_id"],
                matching_id=prepared["order"].matching_id,
            )
            rid = operation_rid(
                "reinstall",
                ctx_t=prepared["ctx_t"],
                bind_t=prepared["bind_t"],
                ciphertext_hash=ciphertext_hash,
            )
            receipt = create_state_receipt(
                prepared["k_mac"],
                op="reinstall",
                snapshot=local,
                st_new=target,
                rid_op=rid,
            )
            _, response = self.post(
                "/aura/rsp/v1/handleReinstallReceipt",
                {
                    "transactionId": prepared["transaction_id"],
                    "ReinstallReceipt": receipt,
                },
            )
            assert response is not None
            if replay_receipt:
                _, replay = self.post(
                    "/aura/rsp/v1/handleReinstallReceipt",
                    {
                        "transactionId": prepared["transaction_id"],
                        "ReinstallReceipt": receipt,
                    },
                )
                if not replay or not replay.get("idempotent"):
                    raise AuraClientError(
                        "latest ReinstallReceipt replay not idempotent"
                    )
            self._save_local_state(
                local,
                state=response["state"],
                ctr=response["ctr"],
                last_hash=response["last_hash"],
                profile_present=True,
            )
            return {
                "status": "AURA_LIFECYCLE_REINSTALL_PASS",
                "operation": op,
                "response": response,
            }

        rid = operation_rid(
            op,
            ctx_t=prepared["ctx_t"],
            bind_t=prepared["bind_t"],
        )
        receipt = create_state_receipt(
            prepared["k_mac"],
            op=op,
            snapshot=local,
            st_new=target,
            rid_op=rid,
        )
        _, response = self.post(
            "/aura/rsp/v1/handleLifecycleReceipt",
            {
                "transactionId": prepared["transaction_id"],
                "StateReceipt": receipt,
            },
        )
        assert response is not None
        if replay_receipt:
            _, replay = self.post(
                "/aura/rsp/v1/handleLifecycleReceipt",
                {
                    "transactionId": prepared["transaction_id"],
                    "StateReceipt": receipt,
                },
            )
            if not replay or not replay.get("idempotent"):
                raise AuraClientError("latest StateReceipt replay not idempotent")

        if op != "delete":
            self._save_local_state(
                local,
                state=response["state"],
                ctr=response["ctr"],
                last_hash=response["last_hash"],
            )
            return {
                "status": "AURA_LIFECYCLE_OPERATION_PASS",
                "operation": op,
                "response": response,
            }

        rprep = response["R_prep"]
        payload = verify_rprep(self.profile_binding_public, rprep)
        pending_hash = state_last_hash(receipt)
        if (
            payload["transactionId"] != prepared["transaction_id"]
            or payload["rid_del"] != rid
            or int(payload["ctr_pending"]) != int(receipt["ctr_new"])
            or payload["last_hash_pending"] != pending_hash
        ):
            raise AuraClientError("R_prep context mismatch")
        self._save_local_state(
            local,
            state=STATE_PENDING_DELETE,
            ctr=int(receipt["ctr_new"]),
            last_hash=pending_hash,
        )
        commit_receipt = create_commit_receipt(
            prepared["k_mac"],
            snapshot=local,
            ctx_t=prepared["ctx_t"],
            rprep=rprep,
        )
        self.device["pending_delete"] = {
            "transactionId": prepared["transaction_id"],
            "ctx_t": prepared["ctx_t"],
            "R_prep": rprep,
            "CommitReceipt": commit_receipt,
            "lph": prepared["lph"],
        }
        save_json(self.device_path, self.device)

        profile_path = (
            self.runtime
            / "software-euicc-output"
            / f"{prepared['order'].matching_id}.aura.upp.der"
        )
        profile_path.unlink(missing_ok=True)
        local["profile_present"] = False
        self.device["lifecycle_by_lph"][local["lph"]] = local
        save_json(self.device_path, self.device)
        if stop_after_prepare:
            return {
                "status": "AURA_LIFECYCLE_DELETE_PREPARED",
                "operation": op,
                "prepare": response,
                "server_restart_safe": True,
            }

        _, commit_response = self.post(
            "/aura/rsp/v1/commitDelete",
            {
                "transactionId": prepared["transaction_id"],
                "CommitReceipt": commit_receipt,
            },
        )
        assert commit_response is not None
        if replay_receipt:
            _, replay_commit = self.post(
                "/aura/rsp/v1/commitDelete",
                {
                    "transactionId": prepared["transaction_id"],
                    "CommitReceipt": commit_receipt,
                },
            )
            if not replay_commit or not replay_commit.get("idempotent"):
                raise AuraClientError("CommitReceipt replay not idempotent")
        self._save_local_state(
            local,
            state=commit_response["state"],
            ctr=commit_response["ctr"],
            last_hash=commit_response["last_hash"],
            profile_present=False,
        )
        self.device.pop("pending_delete", None)
        save_json(self.device_path, self.device)
        return {
            "status": "AURA_LIFECYCLE_DELETE_PASS",
            "operation": op,
            "prepare": response,
            "commit": commit_response,
        }

    def resume_pending_delete(self, *, replay_commit: bool = True) -> dict:
        self.device = load_json(self.device_path)
        pending = self.device.get("pending_delete")
        if not isinstance(pending, dict):
            raise AuraClientError("no pending delete transaction")
        lph = str(pending.get("lph", ""))
        local = self.device.get("lifecycle_by_lph", {}).get(lph)
        if not isinstance(local, dict):
            raise AuraClientError("pending delete has no local lifecycle state")
        if (
            int(local.get("state", -1)) != STATE_PENDING_DELETE
            or local.get("profile_present") is not False
        ):
            raise AuraClientError("local delete precondition mismatch")
        request = {
            "transactionId": pending["transactionId"],
            "CommitReceipt": pending["CommitReceipt"],
        }
        _, response = self.post("/aura/rsp/v1/commitDelete", request)
        assert response is not None
        if replay_commit:
            _, replay = self.post("/aura/rsp/v1/commitDelete", request)
            if not replay or not replay.get("idempotent"):
                raise AuraClientError(
                    "resumed CommitReceipt replay not idempotent"
                )
        self._save_local_state(
            local,
            state=response["state"],
            ctr=response["ctr"],
            last_hash=response["last_hash"],
            profile_present=False,
        )
        self.device.pop("pending_delete", None)
        save_json(self.device_path, self.device)
        return {
            "status": "AURA_LIFECYCLE_DELETE_RECOVERY_PASS",
            "commit": response,
            "replay_idempotent": replay_commit,
        }


def run_full_demo(root: Path = ROOT) -> dict:
    download = AuraLpaClient(root).run("normal")
    steps = [download]
    for op, replay in (
        ("enable", True),
        ("disable", False),
        ("enable", False),
        ("delete", True),
        ("reinstall", True),
    ):
        steps.append(
            AuraLifecycleClient(root).run_operation(
                op, replay_receipt=replay
            )
        )
    device = load_json(root / "runtime" / "aura" / "device.json")
    local_states = list(device.get("lifecycle_by_lph", {}).values())
    if len(local_states) != 1:
        raise AuraClientError("expected exactly one local lifecycle")
    local = local_states[0]
    client = AuraLifecycleClient(root)
    _, server = client.post(
        "/aura/rsp/v1/getLifecycleState", {"lph": local["lph"]}
    )
    if server is None or any(
        local[key] != server[key]
        for key in ("state", "ctr", "last_hash", "pid_h", "salt_p")
    ):
        raise AuraClientError("device/server lifecycle state did not converge")
    result = {
        "status": "AURA_INTEGRATED_LIFECYCLE_ALL_PASS",
        "steps": [step["status"] for step in steps],
        "final_device_state": local,
        "final_server_state": server,
    }
    save_json(root / "results" / "aura-lifecycle-demo.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--op",
        choices=("enable", "disable", "delete", "reinstall"),
    )
    parser.add_argument("--full-demo", action="store_true")
    parser.add_argument("--replay-receipt", action="store_true")
    parser.add_argument("--prepare-delete-only", action="store_true")
    parser.add_argument("--resume-delete", action="store_true")
    args = parser.parse_args()
    if args.full_demo:
        result = run_full_demo()
    elif args.prepare_delete_only:
        result = AuraLifecycleClient().run_operation(
            "delete",
            replay_receipt=True,
            stop_after_prepare=True,
        )
    elif args.resume_delete:
        result = AuraLifecycleClient().resume_pending_delete(
            replay_commit=True
        )
    elif args.op:
        result = AuraLifecycleClient().run_operation(
            args.op, replay_receipt=args.replay_receipt
        )
    else:
        raise SystemExit("choose --full-demo or --op")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
