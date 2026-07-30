from __future__ import annotations

import argparse
import hashlib
import secrets
import shutil
import time
from pathlib import Path

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
from .primitives import (
    generate_p256_private,
    p256_private_to_pem,
    p256_public_to_pem,
    write_test_pki,
)
from .proof import CRED_PARAMS, credential_messages
from .storage import connect, connect_trace
from .ticket import issue_ticket


ROOT = Path(__file__).resolve().parents[2]


def bootstrap(root: Path = ROOT) -> dict:
    config = load_json(root / "config" / "aura.json")
    runtime = root / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (runtime / "software-euicc-output").mkdir(parents=True, exist_ok=True)

    profile_source = (root / config["profile_source"]).resolve()
    if not profile_source.is_file():
        raise FileNotFoundError(f"baseline profile not found: {profile_source}")
    profile_target = runtime / "profile.der"
    shutil.copyfile(profile_source, profile_target)

    write_test_pki(runtime / "pki")
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

    trace_db_path = runtime / "eum-trace.sqlite"
    trace_db_path.unlink(missing_ok=True)
    with connect_trace(trace_db_path) as trace_db:
        trace_db.execute(
            "INSERT INTO trace_index(k,eid,r_tr) VALUES(?,?,?)",
            (scalar_to_b64(k), eid, b64e(r_tr)),
        )
        trace_db.commit()

    device = {
        "eid": eid,
        "x": scalar_to_b64(x),
        "k": scalar_to_b64(k),
        "cred_exp": cred_exp,
        "credential_signature": credential.to_dict(),
        "eum_public_key": authority["eum"]["public_key"],
        "mno_public_key": authority["mno"]["public_key"],
        "salt_by_pid": {},
        "local_ticket_log": {},
    }
    save_json(runtime / "device.json", device)
    db_path = runtime / "aura.sqlite"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    with connect(db_path):
        pass
    ticket_report = issue_ticket(root)
    report = {
        "status": "AURA_BOOTSTRAP_PASS",
        "profile_source": str(profile_source),
        "profile_bytes": profile_target.stat().st_size,
        "profile_sha256": hashlib.sha256(profile_target.read_bytes()).hexdigest(),
        "eid_kept_only_in_device_and_eum_trace_db": True,
        "cred_blind_proof_hash": sha256_hex(str(blind_proof).encode("utf-8")),
        "eum_received_x_plaintext": False,
        "ticket": ticket_report,
    }
    save_json(runtime / "bootstrap-report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    report = bootstrap()
    print(report["status"])
    print("PROFILE_SHA256=" + report["profile_sha256"])


if __name__ == "__main__":
    main()
