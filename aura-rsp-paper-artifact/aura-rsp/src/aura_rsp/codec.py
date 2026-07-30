from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import (
    compress_G1,
    compress_G2,
    decompress_G1,
    decompress_G2,
)
from py_ecc.optimized_bls12_381 import curve_order


BLS_SCALAR_BYTES = 32
BLS_BASE_BYTES = 48
HASH_TO_G1_DST = b"AURA_RSP_V14_BBSPLUS_BLS12381G1_XMD:SHA-256_SSWU_RO_"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def scalar_to_b64(value: int) -> str:
    return b64e((value % curve_order).to_bytes(BLS_SCALAR_BYTES, "big"))


def scalar_from_b64(value: str) -> int:
    raw = b64d(value)
    if len(raw) != BLS_SCALAR_BYTES:
        raise ValueError("invalid scalar length")
    result = int.from_bytes(raw, "big")
    if result >= curve_order:
        raise ValueError("non-canonical scalar")
    return result


def hash_to_scalar(label: str, data: bytes) -> int:
    framed = (
        len(label).to_bytes(2, "big")
        + label.encode("ascii")
        + len(data).to_bytes(8, "big")
        + data
    )
    return int.from_bytes(hashlib.sha256(framed).digest(), "big") % curve_order


def nonzero_hash_to_scalar(label: str, data: bytes) -> int:
    value = hash_to_scalar(label, data)
    return value or 1


def hash_g1(label: str, data: bytes = b""):
    msg = (
        len(label).to_bytes(2, "big")
        + label.encode("ascii")
        + len(data).to_bytes(8, "big")
        + data
    )
    return hash_to_G1(msg, HASH_TO_G1_DST, hashlib.sha256)


def g1_to_b64(point) -> str:
    compressed = compress_G1(point)
    return b64e(int(compressed).to_bytes(BLS_BASE_BYTES, "big"))


def g1_from_b64(value: str):
    raw = b64d(value)
    if len(raw) != BLS_BASE_BYTES:
        raise ValueError("invalid G1 compressed length")
    return decompress_G1(int.from_bytes(raw, "big"))


def g2_to_b64(point) -> str:
    z1, z2 = compress_G2(point)
    raw = int(z1).to_bytes(BLS_BASE_BYTES, "big") + int(z2).to_bytes(
        BLS_BASE_BYTES, "big"
    )
    return b64e(raw)


def g2_from_b64(value: str):
    raw = b64d(value)
    if len(raw) != 2 * BLS_BASE_BYTES:
        raise ValueError("invalid G2 compressed length")
    return decompress_G2(
        (
            int.from_bytes(raw[:BLS_BASE_BYTES], "big"),
            int.from_bytes(raw[BLS_BASE_BYTES:], "big"),
        )
    )


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
