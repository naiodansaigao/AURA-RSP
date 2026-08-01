"""Offline test operation-ticket issuance for the integrated demo."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import secrets
import time

from pySim.esim.profile_store import ProfileRepository

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
from .models import AuraOrderContext
from .proof import TOKEN_PARAMS, token_messages, token_public_messages


ROOT = Path(__file__).resolve().parents[3]


SUPPORTED_OPERATIONS = ("download", "enable", "disable", "delete", "reinstall")


def issue_ticket(
    root: Path = ROOT,
    *,
    op: str = "download",
    fresh_profile_lifecycle: bool = False,
) -> dict:
    if op not in SUPPORTED_OPERATIONS:
        raise ValueError(f"unsupported AURA operation: {op}")
    config = load_json(root / "config" / "aura.json")
    runtime = root / "runtime" / "aura"
    authority = load_json(runtime / "authority.json")
    device_path = runtime / "device.json"
    device = load_json(device_path)
    profile = ProfileRepository(root / "smdpp-data" / "upp").load(
        config["matching_id"]
    )
    if fresh_profile_lifecycle:
        if op != "download":
            raise ValueError(
                "fresh_profile_lifecycle is only valid for independent download samples"
            )
        lifecycle_by_lph = device.setdefault("lifecycle_by_lph", {})
        old_lphs = [
            lph
            for lph, lifecycle in lifecycle_by_lph.items()
            if lifecycle.get("pid_h") == profile.sha256
        ]
        pending_delete = device.get("pending_delete")
        if pending_delete and pending_delete.get("lph") in old_lphs:
            raise RuntimeError(
                "cannot reset a profile lifecycle while delete is pending"
            )
        for lph in old_lphs:
            lifecycle_by_lph.pop(lph, None)
        device.setdefault("salt_by_pid", {}).pop(profile.sha256, None)
        device["local_ticket_log"] = {}
    now = int(time.time())
    order = AuraOrderContext(
        I_ac="IAC-" + secrets.token_hex(16).upper(),
        matching_id=config["matching_id"],
        sid=config["sid"],
        pid_h=profile.sha256,
        op=op,
        exp=now + int(config["ticket_valid_minutes"]) * 60,
        PRaddr=config["praddr"],
    )
    ticket = order.ticket_public()
    x = scalar_from_b64(device["x"])
    eta = random_scalar(nonzero=True)
    d_value = random_scalar()
    context = {"type": "Tok_op", "ticket": ticket}
    blind_proof, s_user = create_blind_commitment(
        TOKEN_PARAMS, {6: x, 7: eta, 8: d_value}, context
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

    device.update(
        {
            "ticket": ticket,
            "matching_id": order.matching_id,
            "eta": scalar_to_b64(eta),
            "d": scalar_to_b64(d_value),
            "token_signature": signature.to_dict(),
        }
    )
    save_json(device_path, device)
    save_json(runtime / "orders.json", {order.I_ac: order.to_dict()})
    report = {
        "status": "AURA_INTEGRATED_TICKET_ISSUED",
        "I_ac": order.I_ac,
        "exp": order.exp,
        "PRaddr": order.PRaddr,
        "pid_h": order.pid_h,
        "op": order.op,
        "fresh_profile_lifecycle": fresh_profile_lifecycle,
        "blind_commitment_hash": sha256_hex(canonical(blind_proof)),
        "issuer_received_hidden_plaintext": False,
    }
    save_json(runtime / "last-ticket-report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--op", choices=SUPPORTED_OPERATIONS, default="download")
    parser.add_argument(
        "--fresh-profile-lifecycle",
        action="store_true",
        help=(
            "start an independent profile lifecycle before issuing a download "
            "ticket; intended for isolated benchmark samples"
        ),
    )
    args = parser.parse_args()
    report = issue_ticket(
        op=args.op,
        fresh_profile_lifecycle=args.fresh_profile_lifecycle,
    )
    print(report["status"], report["I_ac"])


if __name__ == "__main__":
    main()
