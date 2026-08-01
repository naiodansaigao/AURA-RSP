"""Generate local research credentials and server keys for AURA mode."""

from __future__ import annotations

import hashlib
from pathlib import Path
import secrets
import time

from pySim.esim.profile_store import ProfileRepository

from .bbs import (
    blind_sign,
    create_blind_commitment,
    finalize_blind_signature,
    keygen,
    public_key_to_dict,
    random_scalar,
    verify_signature,
)
from .codec import (
    b64e,
    hash_to_scalar,
    load_json,
    save_json,
    scalar_to_b64,
    sha256_hex,
)
from .models import AuraOrderContext
from .primitives import (
    generate_p256_private,
    p256_private_to_pem,
    p256_public_to_pem,
    write_test_pki,
)
from .proof import CRED_PARAMS, credential_messages
from .store import AuraStore
from .ticket import issue_ticket


ROOT = Path(__file__).resolve().parents[3]


def seed_store(store: AuraStore, root: Path = ROOT) -> None:
    runtime = root / "runtime" / "aura"
    orders = load_json(runtime / "orders.json")
    for value in orders.values():
        store.put_order(AuraOrderContext.from_dict(value))
    trace = load_json(runtime / "trace-index.json")
    for k_value, entry in trace.items():
        store.put_trace_index(k_value, entry["eid"], entry["r_tr"])


def bootstrap(root: Path = ROOT) -> dict:
    config = load_json(root / "config" / "aura.json")
    runtime = root / "runtime" / "aura"
    runtime.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (runtime / "software-euicc-output").mkdir(parents=True, exist_ok=True)
    profile = ProfileRepository(root / "smdpp-data" / "upp").load(
        config["matching_id"]
    )
    # Bootstrap is the explicit experiment reset boundary.  Remove only the
    # dedicated AURA lifecycle/session databases; never touch Standard state.
    for name in (
        "lifecycle.sqlite",
        "lifecycle.sqlite-wal",
        "lifecycle.sqlite-shm",
        "sessions",
        "sessions.db",
        "sessions.dat",
        "sessions.bak",
        "sessions.dir",
    ):
        path = runtime / name
        if path.is_file():
            path.unlink()

    write_test_pki(runtime / "pki")
    (runtime / "pr-shared-key.bin").write_bytes(secrets.token_bytes(32))
    eum_sk, eum_pk = keygen()
    mno_sk, mno_pk = keygen()
    server_auth_key = generate_p256_private()
    profile_binding_key = generate_p256_private()
    (runtime / "server-auth-key.pem").write_bytes(
        p256_private_to_pem(server_auth_key)
    )
    (runtime / "server-auth-public.pem").write_bytes(
        p256_public_to_pem(server_auth_key.public_key())
    )
    (runtime / "profile-binding-key.pem").write_bytes(
        p256_private_to_pem(profile_binding_key)
    )
    (runtime / "profile-binding-public.pem").write_bytes(
        p256_public_to_pem(profile_binding_key.public_key())
    )
    authority = {
        "eum": {
            "secret_key": scalar_to_b64(eum_sk),
            "public_key": public_key_to_dict(eum_pk),
        },
        "mno": {
            "secret_key": scalar_to_b64(mno_sk),
            "public_key": public_key_to_dict(mno_pk),
        },
    }
    save_json(runtime / "authority.json", authority)
    save_json(
        runtime / "server-public.json",
        {
            "eum_public_key": authority["eum"]["public_key"],
            "mno_public_key": authority["mno"]["public_key"],
            "server_auth_public_pem": (
                runtime / "server-auth-public.pem"
            ).read_text(encoding="ascii"),
            "profile_binding_public_pem": (
                runtime / "profile-binding-public.pem"
            ).read_text(encoding="ascii"),
        },
    )

    eid = "89049032123451234512345678901235"
    x = random_scalar(nonzero=True)
    r_tr = secrets.token_bytes(32)
    k = hash_to_scalar("AURA-RSP-v14:H_tr", eid.encode("ascii") + r_tr)
    cred_exp = int(time.time()) + int(config["credential_valid_days"]) * 86400
    cred_context = {"type": "Cred_D", "cred_exp": cred_exp}
    blind_proof, s_user = create_blind_commitment(
        CRED_PARAMS, {0: x}, cred_context
    )
    blind_signature = blind_sign(
        CRED_PARAMS,
        eum_sk,
        blind_proof,
        {1: k, 2: cred_exp},
        cred_context,
    )
    credential = finalize_blind_signature(blind_signature, s_user)
    if not verify_signature(
        CRED_PARAMS,
        eum_pk,
        credential_messages(x, k, cred_exp),
        credential,
    ):
        raise RuntimeError("issued Cred_D failed holder verification")
    trace_index = {
        scalar_to_b64(k): {
            "eid": eid,
            "r_tr": b64e(r_tr),
        }
    }
    save_json(runtime / "trace-index.json", trace_index)
    save_json(
        runtime / "device.json",
        {
            "eid": eid,
            "x": scalar_to_b64(x),
            "k": scalar_to_b64(k),
            "cred_exp": cred_exp,
            "credential_signature": credential.to_dict(),
            "salt_by_pid": {},
            "lifecycle_by_lph": {},
            "local_ticket_log": {},
        },
    )
    ticket_report = issue_ticket(root)
    report = {
        "status": "AURA_INTEGRATED_BOOTSTRAP_PASS",
        "profile_bytes": len(profile.data),
        "profile_sha256": profile.sha256,
        "eid_kept_only_in_device_and_trace_index": True,
        "cred_blind_proof_hash": sha256_hex(str(blind_proof).encode("utf-8")),
        "eum_received_x_plaintext": False,
        "ticket": ticket_report,
    }
    save_json(runtime / "bootstrap-report.json", report)
    return report


def main() -> None:
    report = bootstrap()
    print(report["status"])
    print("PROFILE_SHA256=" + report["profile_sha256"])


if __name__ == "__main__":
    main()
