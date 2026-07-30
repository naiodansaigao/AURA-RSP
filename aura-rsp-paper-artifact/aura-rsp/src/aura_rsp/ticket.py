from __future__ import annotations

import argparse
import hashlib
import secrets
import time
from pathlib import Path

from .bbs import (
    blind_sign,
    create_blind_commitment,
    finalize_blind_signature,
    public_key_from_dict,
    random_scalar,
    verify_signature,
)
from .codec import (
    canonical,
    load_json,
    save_json,
    scalar_from_b64,
    scalar_to_b64,
    sha256_hex,
)
from .proof import TOKEN_PARAMS, token_messages, token_public_messages


ROOT = Path(__file__).resolve().parents[2]


def issue_ticket(root: Path = ROOT) -> dict:
    config = load_json(root / "config" / "aura.json")
    authority = load_json(root / "runtime" / "authority.json")
    device_path = root / "runtime" / "device.json"
    device = load_json(device_path)
    profile = (root / "runtime" / "profile.der").read_bytes()
    now = int(time.time())
    ticket = {
        "I_ac": "IAC-" + secrets.token_hex(16).upper(),
        "sid": config["sid"],
        "pid_h": hashlib.sha256(profile).hexdigest(),
        "op": "download",
        "exp": now + int(config["ticket_valid_minutes"]) * 60,
        "PRaddr": config["praddr"],
    }
    x = scalar_from_b64(device["x"])
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": ticket}
    blind_proof, s_user = create_blind_commitment(
        TOKEN_PARAMS,
        {6: x, 7: eta, 8: d_value},
        context,
    )
    mno_sk = scalar_from_b64(authority["mno"]["secret_key"])
    blind_signature = blind_sign(
        TOKEN_PARAMS,
        mno_sk,
        blind_proof,
        {i: value for i, value in enumerate(token_public_messages(ticket))},
        context,
    )
    signature = finalize_blind_signature(blind_signature, s_user)
    mno_pk = public_key_from_dict(authority["mno"]["public_key"])
    if not verify_signature(
        TOKEN_PARAMS,
        mno_pk,
        token_messages(ticket, x, eta, d_value),
        signature,
    ):
        raise RuntimeError("issued Tok_op failed holder verification")

    device["ticket"] = ticket
    device["eta"] = scalar_to_b64(eta)
    device["d"] = scalar_to_b64(d_value)
    device["token_signature"] = signature.to_dict()
    save_json(device_path, device)
    report = {
        "status": "AURA_TICKET_ISSUED",
        "I_ac": ticket["I_ac"],
        "exp": ticket["exp"],
        "PRaddr": ticket["PRaddr"],
        "blind_commitment_hash": sha256_hex(canonical(blind_proof)),
        "issuer_view_hidden_indices": blind_proof["hidden_indices"],
        "issuer_received_hidden_plaintext": False,
    }
    save_json(root / "runtime" / "last-ticket-report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    report = issue_ticket()
    print(report["status"], report["I_ac"])


if __name__ == "__main__":
    main()
