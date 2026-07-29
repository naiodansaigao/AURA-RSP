#!/usr/bin/env python3
"""
AURA-RSP cryptographic primitive benchmark.

Purpose
-------
Benchmark every timing symbol used in the comparison table:
    T_P, T_E1, T_Ea, T_DH, T_S, T_V,
    T_PE, T_PD, T_AE, T_AD,
    T_DG, T_DV, T_MG, T_MV, T_KE, T_KD.

Each available operation is warmed up and then executed 10,000 times
by default. The program reports:
  1. raw average Python API-call time;
  2. no-op-baseline-corrected average time;
  3. scheme totals calculated from the formulas used in the table.

Important
---------
- Key generation and one-time setup are intentionally outside the measured
  region unless the table symbol itself denotes key generation.
- T_AE/T_AD depend on Profile size. Set --payload-bytes to the actual |P|.
- The Di5Guise design-level DAA terms are imported from the companion native
  Intel EPID benchmark. They are direct EpidSign/EpidVerify measurements, not
  conventional-signature replacements or simulated work.
- Fixed benchmark nonces are used only to isolate primitive execution time.
  Never reuse a nonce in a real protocol.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.util
import gc
import hashlib
import hmac
import importlib
import importlib.metadata
import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional, Any


Operation = Callable[[], Any]


@dataclass
class BenchmarkResult:
    symbol: str
    operation: str
    implementation: str
    security_or_parameter: str
    input_bytes: Optional[int]
    iterations: int
    warmup_iterations: int
    raw_average_ns: Optional[float]
    corrected_average_ns: Optional[float]
    raw_average_us: Optional[float]
    corrected_average_us: Optional[float]
    raw_average_ms: Optional[float]
    corrected_average_ms: Optional[float]
    status: str
    note: str
    metadata_json: str = ""


@dataclass
class OperationSpec:
    symbol: str
    operation: str
    implementation: str
    security_or_parameter: str
    input_bytes: Optional[int]
    fn: Optional[Operation]
    note: str = ""


def package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def cpu_model() -> str:
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or "unknown"


def pin_cpu(cpu: Optional[int]) -> str:
    """Pin the current process to one logical CPU on Linux or Windows."""
    if cpu is None:
        return "not requested"
    if cpu < 0:
        return "pinning failed: CPU index must be non-negative"

    if sys.platform.startswith("win"):
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.SetProcessAffinityMask.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            kernel32.SetProcessAffinityMask.restype = ctypes.c_int

            process = kernel32.GetCurrentProcess()
            mask = ctypes.c_size_t(1 << cpu)
            if not kernel32.SetProcessAffinityMask(process, mask):
                error_code = ctypes.get_last_error()
                raise OSError(error_code, "SetProcessAffinityMask failed")
            return f"pinned to logical CPU {cpu} on Windows"
        except (OSError, ValueError, OverflowError) as exc:
            return f"pinning failed: {exc}"

    if hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {cpu})
            return f"pinned to logical CPU {cpu} on Linux"
        except (OSError, ValueError) as exc:
            return f"pinning failed: {exc}"

    return "unsupported on this platform"


def run_loop(fn: Operation, iterations: int) -> int:
    local_fn = fn
    start = time.perf_counter_ns()
    for _ in range(iterations):
        local_fn()
    return time.perf_counter_ns() - start


def benchmark(
    spec: OperationSpec,
    iterations: int,
    warmup: int,
    noop_total_ns: int,
) -> BenchmarkResult:
    if spec.fn is None:
        return BenchmarkResult(
            symbol=spec.symbol,
            operation=spec.operation,
            implementation=spec.implementation,
            security_or_parameter=spec.security_or_parameter,
            input_bytes=spec.input_bytes,
            iterations=iterations,
            warmup_iterations=warmup,
            raw_average_ns=None,
            corrected_average_ns=None,
            raw_average_us=None,
            corrected_average_us=None,
            raw_average_ms=None,
            corrected_average_ms=None,
            status="N/A",
            note=spec.note,
        )

    for _ in range(warmup):
        spec.fn()

    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        total_ns = run_loop(spec.fn, iterations)
    finally:
        if was_enabled:
            gc.enable()

    raw_ns = total_ns / iterations
    corrected_total = max(0, total_ns - noop_total_ns)
    corrected_ns = corrected_total / iterations

    return BenchmarkResult(
        symbol=spec.symbol,
        operation=spec.operation,
        implementation=spec.implementation,
        security_or_parameter=spec.security_or_parameter,
        input_bytes=spec.input_bytes,
        iterations=iterations,
        warmup_iterations=warmup,
        raw_average_ns=raw_ns,
        corrected_average_ns=corrected_ns,
        raw_average_us=raw_ns / 1_000,
        corrected_average_us=corrected_ns / 1_000,
        raw_average_ms=raw_ns / 1_000_000,
        corrected_average_ms=corrected_ns / 1_000_000,
        status="OK",
        note=spec.note,
    )


def unavailable(
    symbol: str,
    operation: str,
    implementation: str,
    parameter: str,
    note: str,
    input_bytes: Optional[int] = None,
) -> OperationSpec:
    return OperationSpec(
        symbol=symbol,
        operation=operation,
        implementation=implementation,
        security_or_parameter=parameter,
        input_bytes=input_bytes,
        fn=None,
        note=note,
    )


def setup_bls12381() -> list[OperationSpec]:
    """T_P and T_E1 using native blst through pyblst."""
    try:
        import pyblst
    except Exception as exc:
        note = f"pyblst unavailable: {exc}"
        return [
            unavailable(
                "T_P",
                "BLS12-381 pairing evaluation",
                "pyblst/blst",
                "BLS12-381, approximately 128-bit security",
                note,
            ),
            unavailable(
                "T_E1",
                "Scalar multiplication in BLS12-381 G1",
                "pyblst/blst",
                "BLS12-381 G1, 255-bit scalar",
                note,
            ),
        ]

    # pyblst's Python method takes (message, DST), despite the Rust local
    # variable names in the binding source.
    g1 = pyblst.BlstP1Element.hash_to_group(
        b"AURA-RSP G1 benchmark point",
        b"AURA_RSP_BLS12381G1_XMD:SHA-256_SSWU_RO_",
    )
    g2 = pyblst.BlstP2Element.hash_to_group(
        b"AURA-RSP G2 benchmark point",
        b"AURA_RSP_BLS12381G2_XMD:SHA-256_SSWU_RO_",
    )

    # A fixed Miller-loop result is used as the expected pairing value.
    # Each measured call computes a fresh Miller loop and executes a final
    # pairing equality check, so T_P includes final verification rather than
    # measuring only the Miller loop.
    pairing_reference = pyblst.miller_loop(g1, g2)
    if not pyblst.final_verify(pairing_reference, pairing_reference):
        raise RuntimeError("BLS12-381 pairing self-check failed")

    def pairing_evaluation() -> bool:
        candidate = pyblst.miller_loop(g1, g2)
        return pyblst.final_verify(candidate, pairing_reference)

    bls_order = int(
        "73eda753299d7d483339d80809a1d805"
        "53bda402fffe5bfeffffffff00000001",
        16,
    )
    scalar = int.from_bytes(os.urandom(32), "big") % bls_order
    scalar = scalar or 1

    def g1_scalar_multiplication():
        return g1.scalar_mul(scalar)

    return [
        OperationSpec(
            symbol="T_P",
            operation="BLS12-381 pairing evaluation",
            implementation="pyblst 0.3.x / native blst",
            security_or_parameter="BLS12-381, approximately 128-bit security",
            input_bytes=48 + 96,
            fn=pairing_evaluation,
            note=(
                "One fresh Miller loop plus final pairing equality verification "
                "against a precomputed valid reference."
            ),
        ),
        OperationSpec(
            symbol="T_E1",
            operation="Scalar multiplication in BLS12-381 G1",
            implementation="pyblst 0.3.x / native blst",
            security_or_parameter="48-byte compressed G1 point; 32-byte scalar",
            input_bytes=48 + 32,
            fn=g1_scalar_multiplication,
            note="Implements the G1 exponentiation/scalar multiplication counted in the table.",
        ),
    ]


def load_libsodium() -> ctypes.CDLL:
    candidates: list[str] = []
    found = ctypes.util.find_library("sodium")
    if found:
        candidates.append(found)

    # Common WSL/Linux/macOS paths.
    candidates.extend(
        [
            "/usr/lib/x86_64-linux-gnu/libsodium.so",
            "/usr/lib/x86_64-linux-gnu/libsodium.so.23",
            "/usr/local/lib/libsodium.so",
            "/opt/homebrew/lib/libsodium.dylib",
            "/usr/local/lib/libsodium.dylib",
        ]
    )

    # PyNaCl's extension may dynamically expose libsodium symbols.
    try:
        import nacl._sodium  # type: ignore

        candidates.append(nacl._sodium.__file__)
    except Exception:
        pass

    errors: list[str] = []
    for candidate in dict.fromkeys(candidates):
        if not candidate:
            continue
        try:
            lib = ctypes.CDLL(candidate)
            required = (
                "sodium_init",
                "crypto_core_ristretto255_random",
                "crypto_core_ristretto255_scalar_random",
                "crypto_scalarmult_ristretto255",
            )
            if all(hasattr(lib, name) for name in required):
                return lib
            errors.append(f"{candidate}: missing Ristretto symbols")
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")

    raise RuntimeError(
        "Could not load libsodium >= 1.0.18 with Ristretto255 support. "
        "On Ubuntu/WSL run: sudo apt install libsodium-dev. "
        + " | ".join(errors)
    )


def setup_ristretto255() -> list[OperationSpec]:
    """
    T_Ea: scalar multiplication in the 32-byte auxiliary prime-order group.

    On Windows, the preferred implementation is oblivious + rbcl.  rbcl
    bundles a compiled subset of libsodium and provides a native Windows
    wheel, so no separate libsodium installation is required.
    """
    try:
        from oblivious.ristretto import sodium

        if sodium is None:
            raise RuntimeError(
                "oblivious did not load the rbcl/libsodium backend"
            )

        point = sodium.point.hash(b"AURA-RSP Ristretto255 benchmark point")
        scalar = sodium.scalar.hash(b"AURA-RSP Ristretto255 benchmark scalar")
        check = scalar * point
        if len(bytes(check)) != 32:
            raise RuntimeError("Ristretto255 self-check failed")

        def ristretto_scalar_multiplication():
            return scalar * point

        return [
            OperationSpec(
                symbol="T_Ea",
                operation="Scalar multiplication in auxiliary group G_aux",
                implementation=(
                    "oblivious.ristretto sodium backend / rbcl / libsodium"
                ),
                security_or_parameter=(
                    "ristretto255; 32-byte point and 32-byte scalar"
                ),
                input_bytes=64,
                fn=ristretto_scalar_multiplication,
                note=(
                    "Native crypto_scalarmult_ristretto255 through the "
                    "Windows rbcl wheel."
                ),
            )
        ]
    except Exception as oblivious_exc:
        # Fallback for systems where a standalone libsodium DLL is available.
        try:
            lib = load_libsodium()

            lib.sodium_init.argtypes = []
            lib.sodium_init.restype = ctypes.c_int
            lib.crypto_core_ristretto255_random.argtypes = [ctypes.c_void_p]
            lib.crypto_core_ristretto255_random.restype = None
            lib.crypto_core_ristretto255_scalar_random.argtypes = [
                ctypes.c_void_p
            ]
            lib.crypto_core_ristretto255_scalar_random.restype = None
            lib.crypto_scalarmult_ristretto255.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            lib.crypto_scalarmult_ristretto255.restype = ctypes.c_int

            if lib.sodium_init() < 0:
                raise RuntimeError("sodium_init() failed")

            Buffer32 = ctypes.c_ubyte * 32
            point = Buffer32()
            scalar = Buffer32()
            output = Buffer32()
            lib.crypto_core_ristretto255_random(point)
            lib.crypto_core_ristretto255_scalar_random(scalar)

            if lib.crypto_scalarmult_ristretto255(
                output, scalar, point
            ) != 0:
                raise RuntimeError(
                    "Initial Ristretto255 scalar multiplication failed"
                )

            def ristretto_scalar_multiplication() -> int:
                return lib.crypto_scalarmult_ristretto255(
                    output, scalar, point
                )

            return [
                OperationSpec(
                    symbol="T_Ea",
                    operation=(
                        "Scalar multiplication in auxiliary group G_aux"
                    ),
                    implementation=(
                        "standalone libsodium "
                        "crypto_scalarmult_ristretto255"
                    ),
                    security_or_parameter=(
                        "ristretto255; 32-byte point and 32-byte scalar"
                    ),
                    input_bytes=64,
                    fn=ristretto_scalar_multiplication,
                    note=(
                        "Fallback standalone-libsodium implementation."
                    ),
                )
            ]
        except Exception as sodium_exc:
            return [
                unavailable(
                    "T_Ea",
                    "Scalar multiplication in auxiliary group G_aux",
                    "oblivious/rbcl or standalone libsodium",
                    "ristretto255; 32-byte point and 32-byte scalar",
                    (
                        f"oblivious/rbcl error: {oblivious_exc}; "
                        f"libsodium fallback error: {sodium_exc}"
                    ),
                    64,
                )
            ]


def setup_ed25519_x25519() -> list[OperationSpec]:
    """T_S, T_V and T_DH at the 128-bit classical security level."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    except Exception as exc:
        note = f"cryptography unavailable: {exc}"
        return [
            unavailable("T_S", "Ed25519 signature generation", "cryptography", "Ed25519", note, 32),
            unavailable("T_V", "Ed25519 signature verification", "cryptography", "Ed25519", note, 96),
            unavailable("T_DH", "X25519 shared-secret computation", "cryptography", "X25519", note, 64),
        ]

    message = os.urandom(32)
    signing_key = ed25519.Ed25519PrivateKey.generate()
    verification_key = signing_key.public_key()
    signature = signing_key.sign(message)
    verification_key.verify(signature, message)

    def sign():
        return signing_key.sign(message)

    def verify():
        return verification_key.verify(signature, message)

    x_sk_a = x25519.X25519PrivateKey.generate()
    x_sk_b = x25519.X25519PrivateKey.generate()
    x_pk_b = x_sk_b.public_key()
    expected = x_sk_a.exchange(x_pk_b)
    if len(expected) != 32:
        raise RuntimeError("X25519 self-check failed")

    def x25519_exchange():
        return x_sk_a.exchange(x_pk_b)

    return [
        OperationSpec(
            symbol="T_S",
            operation="Conventional signature generation",
            implementation="cryptography Ed25519",
            security_or_parameter="Ed25519; 32-byte message; 64-byte signature",
            input_bytes=32,
            fn=sign,
        ),
        OperationSpec(
            symbol="T_V",
            operation="Conventional signature verification",
            implementation="cryptography Ed25519",
            security_or_parameter="Ed25519; 32-byte message; 64-byte signature",
            input_bytes=96,
            fn=verify,
        ),
        OperationSpec(
            symbol="T_DH",
            operation="ECDH shared-secret computation",
            implementation="cryptography X25519",
            security_or_parameter="X25519; 32-byte public key; 32-byte shared secret",
            input_bytes=32,
            fn=x25519_exchange,
            note="Key-pair generation is outside the measured region.",
        ),
    ]


def setup_public_key_encryption() -> list[OperationSpec]:
    """T_PE and T_PD using Curve25519 sealed boxes on a 64-byte plaintext."""
    try:
        from nacl.public import PrivateKey, SealedBox
    except Exception as exc:
        note = f"PyNaCl unavailable: {exc}"
        return [
            unavailable(
                "T_PE",
                "Public-key encryption",
                "PyNaCl SealedBox",
                "Curve25519 sealed box; 64-byte plaintext",
                note,
                64,
            ),
            unavailable(
                "T_PD",
                "Public-key decryption",
                "PyNaCl SealedBox",
                "Curve25519 sealed box; 112-byte ciphertext",
                note,
                112,
            ),
        ]

    plaintext = os.urandom(64)
    recipient_private = PrivateKey.generate()
    encrypt_box = SealedBox(recipient_private.public_key)
    decrypt_box = SealedBox(recipient_private)
    ciphertext = encrypt_box.encrypt(plaintext)
    if decrypt_box.decrypt(ciphertext) != plaintext:
        raise RuntimeError("SealedBox self-check failed")

    def public_encrypt():
        return encrypt_box.encrypt(plaintext)

    def public_decrypt():
        return decrypt_box.decrypt(ciphertext)

    return [
        OperationSpec(
            symbol="T_PE",
            operation="Public-key encryption",
            implementation="PyNaCl SealedBox / Curve25519-XSalsa20-Poly1305",
            security_or_parameter=(
                f"64-byte plaintext; {len(ciphertext)}-byte sealed ciphertext"
            ),
            input_bytes=len(plaintext),
            fn=public_encrypt,
            note="Sealed-box ephemeral-key generation is included in encryption time.",
        ),
        OperationSpec(
            symbol="T_PD",
            operation="Public-key decryption",
            implementation="PyNaCl SealedBox / Curve25519-XSalsa20-Poly1305",
            security_or_parameter=(
                f"{len(ciphertext)}-byte sealed ciphertext; 64-byte plaintext"
            ),
            input_bytes=len(ciphertext),
            fn=public_decrypt,
        ),
    ]


def setup_aead(payload_bytes: int) -> list[OperationSpec]:
    """T_AE and T_AD using XChaCha20-Poly1305 with the selected |P|."""
    try:
        from nacl.bindings import (
            crypto_aead_xchacha20poly1305_ietf_encrypt,
            crypto_aead_xchacha20poly1305_ietf_decrypt,
        )
    except Exception as exc:
        note = f"PyNaCl XChaCha20-Poly1305 unavailable: {exc}"
        return [
            unavailable(
                "T_AE",
                "Authenticated encryption",
                "PyNaCl/libsodium XChaCha20-Poly1305",
                f"256-bit key; {payload_bytes}-byte payload",
                note,
                payload_bytes,
            ),
            unavailable(
                "T_AD",
                "Authenticated decryption",
                "PyNaCl/libsodium XChaCha20-Poly1305",
                f"256-bit key; {payload_bytes + 16}-byte ciphertext",
                note,
                payload_bytes + 16,
            ),
        ]

    key = os.urandom(32)
    nonce = os.urandom(24)
    aad = os.urandom(32)
    plaintext = os.urandom(payload_bytes)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key
    )
    recovered = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, aad, nonce, key
    )
    if recovered != plaintext:
        raise RuntimeError("XChaCha20-Poly1305 self-check failed")

    def authenticated_encrypt():
        # Fixed nonce is used only to exclude random-number generation from
        # the primitive timing. Never do this in production.
        return crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )

    def authenticated_decrypt():
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key
        )

    return [
        OperationSpec(
            symbol="T_AE",
            operation="Authenticated encryption",
            implementation="PyNaCl/libsodium XChaCha20-Poly1305-IETF",
            security_or_parameter=(
                f"32-byte key; 24-byte nonce; 16-byte tag; "
                f"{payload_bytes}-byte payload"
            ),
            input_bytes=payload_bytes,
            fn=authenticated_encrypt,
            note="Set --payload-bytes to the measured encrypted Profile size |P|.",
        ),
        OperationSpec(
            symbol="T_AD",
            operation="Authenticated decryption",
            implementation="PyNaCl/libsodium XChaCha20-Poly1305-IETF",
            security_or_parameter=(
                f"32-byte key; 24-byte nonce; 16-byte tag; "
                f"{len(ciphertext)}-byte ciphertext"
            ),
            input_bytes=len(ciphertext),
            fn=authenticated_decrypt,
            note="Set --payload-bytes to the measured encrypted Profile size |P|.",
        ),
    ]


def setup_hmac(mac_bytes: int) -> list[OperationSpec]:
    """T_MG and T_MV using HMAC-SHA-256."""
    key = os.urandom(32)
    message = os.urandom(mac_bytes)
    tag = hmac.digest(key, message, "sha256")

    def mac_generate():
        return hmac.digest(key, message, "sha256")

    def mac_verify() -> bool:
        candidate = hmac.digest(key, message, "sha256")
        return hmac.compare_digest(candidate, tag)

    if not mac_verify():
        raise RuntimeError("HMAC self-check failed")

    return [
        OperationSpec(
            symbol="T_MG",
            operation="MAC generation",
            implementation="Python/OpenSSL HMAC-SHA-256",
            security_or_parameter=f"32-byte key; {mac_bytes}-byte message; 32-byte tag",
            input_bytes=mac_bytes,
            fn=mac_generate,
        ),
        OperationSpec(
            symbol="T_MV",
            operation="MAC verification",
            implementation="Python/OpenSSL HMAC-SHA-256",
            security_or_parameter=f"32-byte key; {mac_bytes}-byte message; 32-byte tag",
            input_bytes=mac_bytes + 32,
            fn=mac_verify,
            note="Includes tag recomputation and constant-time comparison.",
        ),
    ]


def setup_mlkem768() -> list[OperationSpec]:
    """T_KE and T_KD using ML-KEM-768."""
    try:
        from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
    except Exception as exc:
        note = f"pqcrypto ML-KEM-768 unavailable: {exc}"
        return [
            unavailable(
                "T_KE",
                "ML-KEM encapsulation",
                "pqcrypto/PQClean ML-KEM-768",
                "1184-byte public key; 1088-byte ciphertext",
                note,
                1184,
            ),
            unavailable(
                "T_KD",
                "ML-KEM decapsulation",
                "pqcrypto/PQClean ML-KEM-768",
                "2400-byte secret key; 1088-byte ciphertext",
                note,
                1088,
            ),
        ]

    public_key, secret_key = generate_keypair()
    ciphertext, shared_secret = encrypt(public_key)
    recovered_secret = decrypt(secret_key, ciphertext)
    if not hmac.compare_digest(shared_secret, recovered_secret):
        raise RuntimeError("ML-KEM-768 self-check failed")

    def kem_encapsulate():
        return encrypt(public_key)

    def kem_decapsulate():
        return decrypt(secret_key, ciphertext)

    return [
        OperationSpec(
            symbol="T_KE",
            operation="ML-KEM encapsulation",
            implementation="pqcrypto/PQClean ML-KEM-768",
            security_or_parameter=(
                f"{len(public_key)}-byte public key; "
                f"{len(ciphertext)}-byte ciphertext; "
                f"{len(shared_secret)}-byte shared secret"
            ),
            input_bytes=len(public_key),
            fn=kem_encapsulate,
            note="ML-KEM key-pair generation is outside the measured region.",
        ),
        OperationSpec(
            symbol="T_KD",
            operation="ML-KEM decapsulation",
            implementation="pqcrypto/PQClean ML-KEM-768",
            security_or_parameter=(
                f"{len(secret_key)}-byte secret key; "
                f"{len(ciphertext)}-byte ciphertext"
            ),
            input_bytes=len(ciphertext),
            fn=kem_decapsulate,
        ),
    ]


def load_native_daa_results(
    path: Path, expected_iterations: int, expected_warmup: int
) -> tuple[list[BenchmarkResult], dict[str, Any]]:
    """Load genuine native EpidSign/EpidVerify measurements.

    The native process performs all correctness checks and emits both raw and
    baseline-corrected QueryPerformanceCounter averages.  Python only imports
    those measured values; it never times a subprocess or substitutes another
    signature primitive for DAA.
    """
    if not path.is_file():
        raise RuntimeError(
            f"Native DAA result file not found: {path}. "
            "Run run_epid_benchmark_windows.ps1 first."
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read native DAA result {path}: {exc}") from exc

    required_identity = {
        "schema_version": 2,
        "repository": "https://github.com/Intel-EPID-SDK/epid-sdk",
        "commit": "389426ff4ba2286d2e133bec29d178427d434d8c",
        "epid_version": "2.0",
    }
    for field, expected in required_identity.items():
        if payload.get(field) != expected:
            raise RuntimeError(
                f"Native DAA result has unexpected {field}: "
                f"{payload.get(field)!r}; expected {expected!r}"
            )
    if payload.get("measurement_iterations") != expected_iterations:
        raise RuntimeError(
            "Native DAA iteration count does not match --iterations: "
            f"{payload.get('measurement_iterations')} != {expected_iterations}"
        )
    if payload.get("warmup_iterations") != expected_warmup:
        raise RuntimeError(
            "Native DAA warmup count does not match --warmup: "
            f"{payload.get('warmup_iterations')} != {expected_warmup}"
        )

    correctness = payload.get("correctness", {})
    required_checks = (
        "initial_self_check",
        "all_measured_signatures_verified",
        "all_timed_verifications_valid",
    )
    if not all(correctness.get(check) is True for check in required_checks):
        raise RuntimeError(
            "Native DAA correctness checks are incomplete or failed: "
            f"{correctness}"
        )
    if correctness.get("measured_signatures_verified_count") != expected_iterations:
        raise RuntimeError(
            "Not every measured EPID signature was verified successfully."
        )
    if (
        correctness.get("measured_presignatures_generated_count")
        != expected_iterations
        or correctness.get("presignature_pool_before_each_T_DG") != 1
        or correctness.get("presignature_pool_after_each_T_DG") != 0
        or correctness.get("one_presignature_consumed_per_signature") is not True
    ):
        raise RuntimeError(
            "Native DAA result does not prove one-to-one pre-signature "
            f"consumption: {correctness}"
        )
    if payload.get("basename_mode") != "random basename (anonymous/unlinkable)":
        raise RuntimeError(
            "Native DAA result is not using random unlinkable basename mode."
        )
    presig_policy = payload.get("presignature_policy", {})
    if (
        presig_policy.get("api") != "EpidAddPreSigs"
        or presig_policy.get("pool_filled_before_each_timed_sign") is not True
        or presig_policy.get("pool_empty_after_each_timed_sign") is not True
        or presig_policy.get("offline_cost_excluded_from_T_DG") is not True
    ):
        raise RuntimeError(
            f"Native DAA pre-signature policy is invalid: {presig_policy}"
        )
    if not isinstance(payload.get("offline_precomputation"), dict):
        raise RuntimeError(
            "Native DAA result does not disclose offline EpidAddPreSigs cost."
        )

    operations = payload.get("operations", {})
    metadata_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    implementation = str(payload["implementation"])
    signature_length = int(payload["signature_length_bytes"])
    message_length = int(payload["message_length_bytes"])
    parameter = (
        f"Intel EPID {payload['epid_version']}; {payload['curve']}; "
        f"{payload['security_level_bits']}-bit security; "
        f"{payload['hash_algorithm']}; {payload['basename_mode']}; "
        "GroupRL/PrivRL/SigRL empty; VerifierRL N/A for random base"
    )

    def convert(symbol: str, operation_name: str, input_bytes: int) -> BenchmarkResult:
        source = operations.get(symbol)
        if not isinstance(source, dict):
            raise RuntimeError(f"Native DAA result is missing {symbol}")
        raw_ns = float(source["raw_avg_ns"])
        corrected_ns = float(source["corrected_avg_ns"])
        return BenchmarkResult(
            symbol=symbol,
            operation=operation_name,
            implementation=implementation,
            security_or_parameter=parameter,
            input_bytes=input_bytes,
            iterations=expected_iterations,
            warmup_iterations=expected_warmup,
            raw_average_ns=raw_ns,
            corrected_average_ns=corrected_ns,
            raw_average_us=raw_ns / 1_000,
            corrected_average_us=corrected_ns / 1_000,
            raw_average_ms=raw_ns / 1_000_000,
            corrected_average_ms=corrected_ns / 1_000_000,
            status="OK",
            note=(
                f"Direct native {symbol == 'T_DG' and 'EpidSign' or 'EpidVerify'} "
                "call; setup, key/RL loading, contexts, pairing precomputation "
                "and buffers are outside the timed region. Each EpidSign "
                "consumes exactly one fresh pre-signature generated by "
                "EpidAddPreSigs; the disclosed offline cost is excluded. "
                f"Repository commit {payload['commit']}."
            ),
            metadata_json=metadata_json,
        )

    results = [
        convert(
            "T_DG",
            "DAA attestation quote generation (Intel EPID signing)",
            message_length,
        ),
        convert(
            "T_DV",
            "DAA attestation quote verification (Intel EPID verification)",
            message_length + signature_length,
        ),
    ]
    return results, payload


def write_operations_csv(path: Path, results: list[BenchmarkResult]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def operation_time_map(
    results: list[BenchmarkResult], use_raw: bool = False
) -> dict[str, Optional[float]]:
    field = "raw_average_us" if use_raw else "corrected_average_us"
    output: dict[str, Optional[float]] = {}
    for result in results:
        output[result.symbol] = getattr(result, field)
    return output


SCHEME_FORMULAS: dict[str, dict[str, int]] = {
    "Standard RSP": {
        "T_S": 3,
        "T_V": 3,
        "T_AE": 1,
        "T_AD": 1,
    },
    "AAKA": {
        "T_DH": 2,
        "T_PE": 1,
        "T_PD": 1,
        "T_S": 1,
        "T_V": 1,
        "T_P": 2,
        "T_E1": 24,
        "T_AE": 1,
        "T_AD": 1,
    },
    # Design-level Di5Guise model instantiated with genuine Intel EPID 2.0:
    # 2T_DH + T_PE + T_PD + T_S + T_V + T_DG + T_DV + 2T_AE + 2T_AD.
    "Di5Guise": {
        "T_DH": 2,
        "T_PE": 1,
        "T_PD": 1,
        "T_S": 1,
        "T_V": 1,
        "T_DG": 1,
        "T_DV": 1,
        "T_AE": 2,
        "T_AD": 2,
    },
    "AURA-RSP classical": {
        "T_DH": 2,
        "T_S": 5,
        "T_V": 5,
        "T_P": 4,
        "T_E1": 17,
        "T_Ea": 4,
        "T_AE": 1,
        "T_AD": 1,
        "T_MG": 1,
        "T_MV": 1,
    },
    "AURA-RSP hybrid": {
        "T_DH": 2,
        "T_S": 5,
        "T_V": 5,
        "T_P": 4,
        "T_E1": 17,
        "T_Ea": 4,
        "T_AE": 1,
        "T_AD": 1,
        "T_MG": 1,
        "T_MV": 1,
        "T_KE": 1,
        "T_KD": 1,
    },
}

SCHEME_MODEL_NOTES: dict[str, str] = {
    "Di5Guise": (
        "Design-level DAA model instantiated by genuine Intel EPID 2.0. "
        "T_DG and T_DV are direct native EpidSign and EpidVerify timings; "
        "no conventional signature or simulated loop replaces DAA."
    )
}


def calculate_scheme_totals(
    results: list[BenchmarkResult], use_raw: bool = False
) -> list[dict[str, Any]]:
    times = operation_time_map(results, use_raw=use_raw)
    rows: list[dict[str, Any]] = []

    for scheme, formula in SCHEME_FORMULAS.items():
        missing = [
            symbol
            for symbol, count in formula.items()
            if count and times.get(symbol) is None
        ]
        if missing:
            rows.append(
                {
                    "scheme": scheme,
                    "time_basis": "raw" if use_raw else "baseline-corrected",
                    "total_us": None,
                    "total_ms": None,
                    "status": "N/A",
                    "missing_symbols": ", ".join(missing),
                    "formula": " + ".join(
                        f"{count}{symbol}" for symbol, count in formula.items()
                    ),
                    "model_note": SCHEME_MODEL_NOTES.get(scheme, ""),
                }
            )
            continue

        total_us = sum(
            count * float(times[symbol]) for symbol, count in formula.items()
        )
        rows.append(
            {
                "scheme": scheme,
                "time_basis": "raw" if use_raw else "baseline-corrected",
                "total_us": total_us,
                "total_ms": total_us / 1000,
                "status": "OK",
                "missing_symbols": "",
                "formula": " + ".join(
                    f"{count}{symbol}" for symbol, count in formula.items()
                ),
                "model_note": SCHEME_MODEL_NOTES.get(scheme, ""),
            }
        )
    return rows


def write_scheme_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def print_results(results: list[BenchmarkResult]) -> None:
    print("\nPer-operation results")
    print("-" * 104)
    print(
        f"{'Symbol':<8} {'Operation':<42} "
        f"{'Raw avg (us)':>14} {'Corrected (us)':>16} {'Status':>10}"
    )
    print("-" * 104)
    for result in results:
        if result.status == "OK":
            raw = f"{result.raw_average_us:.6f}"
            corrected = f"{result.corrected_average_us:.6f}"
        else:
            raw = "-"
            corrected = "-"
        print(
            f"{result.symbol:<8} {result.operation[:42]:<42} "
            f"{raw:>14} {corrected:>16} {result.status:>10}"
        )
    print("-" * 104)


def print_scheme_totals(rows: list[dict[str, Any]]) -> None:
    print("\nScheme totals calculated from the comparison-table formulas")
    print("-" * 80)
    print(f"{'Scheme':<25} {'Total (us)':>16} {'Total (ms)':>16} {'Status':>10}")
    print("-" * 80)
    for row in rows:
        if row["status"] == "OK":
            us = f"{row['total_us']:.6f}"
            ms = f"{row['total_ms']:.6f}"
        else:
            us = "-"
            ms = "-"
        print(f"{row['scheme']:<25} {us:>16} {ms:>16} {row['status']:>10}")
        if row["missing_symbols"]:
            print(f"  missing: {row['missing_symbols']}")
    print("-" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark the cryptographic timing symbols used in the "
            "AURA-RSP comparison table."
        )
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10_000,
        help="Measured executions per operation (default: 10000).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1_000,
        help="Unmeasured warm-up executions per operation (default: 1000).",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=1_024,
        help=(
            "AEAD plaintext/Profile size |P| in bytes. "
            "Use the actual package size for paper results (default: 1024)."
        ),
    )
    parser.add_argument(
        "--mac-bytes",
        type=int,
        default=128,
        help="HMAC input length in bytes (default: 128).",
    )
    parser.add_argument(
        "--cpu",
        type=int,
        default=None,
        help="Optionally pin the process to this logical CPU on Windows or Linux.",
    )
    parser.add_argument(
        "--output-prefix",
        default="crypto_benchmark",
        help="Prefix for CSV and JSON result files.",
    )
    parser.add_argument(
        "--daa-results",
        default="epid_daa_results.json",
        help=(
            "JSON emitted by the native Intel EPID benchmark "
            "(default: epid_daa_results.json)."
        ),
    )
    args = parser.parse_args()

    if args.iterations <= 0 or args.warmup < 0:
        parser.error("iterations must be positive and warmup must be non-negative")
    if args.payload_bytes < 0 or args.mac_bytes < 0:
        parser.error("payload and MAC lengths must be non-negative")

    affinity_status = pin_cpu(args.cpu)

    specs: list[OperationSpec] = []
    specs.extend(setup_bls12381())
    specs.extend(setup_ristretto255())
    specs.extend(setup_ed25519_x25519())
    specs.extend(setup_public_key_encryption())
    specs.extend(setup_aead(args.payload_bytes))
    specs.extend(setup_hmac(args.mac_bytes))
    specs.extend(setup_mlkem768())

    # Keep the output order aligned with the notation paragraph/table.
    order = {
        symbol: index
        for index, symbol in enumerate(
            [
                "T_P",
                "T_E1",
                "T_Ea",
                "T_DH",
                "T_S",
                "T_V",
                "T_DG",
                "T_DV",
                "T_PE",
                "T_PD",
                "T_AE",
                "T_AD",
                "T_MG",
                "T_MV",
                "T_KE",
                "T_KD",
            ]
        )
    }
    specs.sort(key=lambda item: order[item.symbol])

    def noop():
        return None

    for _ in range(args.warmup):
        noop()
    noop_total_ns = run_loop(noop, args.iterations)

    results = [
        benchmark(spec, args.iterations, args.warmup, noop_total_ns)
        for spec in specs
    ]
    try:
        daa_results, daa_metadata = load_native_daa_results(
            Path(args.daa_results), args.iterations, args.warmup
        )
    except RuntimeError as exc:
        parser.error(str(exc))
    results.extend(daa_results)
    results.sort(key=lambda item: order[item.symbol])

    scheme_corrected = calculate_scheme_totals(results, use_raw=False)
    scheme_raw = calculate_scheme_totals(results, use_raw=True)

    prefix = Path(args.output_prefix)
    operations_csv = prefix.with_name(prefix.name + "_operations.csv")
    schemes_csv = prefix.with_name(prefix.name + "_schemes.csv")
    json_path = prefix.with_suffix(".json")

    write_operations_csv(operations_csv, results)
    write_scheme_csv(schemes_csv, scheme_corrected)

    metadata = {
        "timestamp_local": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu_model(),
        "cpu_affinity": affinity_status,
        "iterations": args.iterations,
        "warmup_iterations": args.warmup,
        "payload_bytes": args.payload_bytes,
        "mac_bytes": args.mac_bytes,
        "timer": "time.perf_counter_ns",
        "daa_timer": "Windows QueryPerformanceCounter (native C benchmark)",
        "daa_results_file": str(Path(args.daa_results)),
        "daa_implementation": daa_metadata,
        "packages": {
            "pyblst": package_version("pyblst"),
            "cryptography": package_version("cryptography"),
            "PyNaCl": package_version("PyNaCl"),
            "pqcrypto": package_version("pqcrypto"),
            "oblivious": package_version("oblivious"),
            "rbcl": package_version("rbcl"),
        },
        "measurement_notes": [
            "Raw average includes Python loop and callable overhead.",
            "Corrected average subtracts a no-op callable-loop baseline.",
            "Key generation is excluded unless explicitly represented by a timing symbol.",
            "AEAD timing depends on --payload-bytes.",
            (
                "Di5Guise uses the design-level DAA formula. T_DG and T_DV "
                "come from direct Intel EPID EpidSign/EpidVerify calls in the "
                "native companion benchmark; no ordinary signature substitutes "
                "for DAA. T_DG uses random unlinkable basename and consumes "
                "one fresh EpidAddPreSigs item; offline pre-signature cost is "
                "reported separately in daa_implementation."
            ),
        ],
    }

    json_payload = {
        "metadata": metadata,
        "operations": [asdict(result) for result in results],
        "scheme_totals_corrected": scheme_corrected,
        "scheme_totals_raw": scheme_raw,
        "scheme_formulas": SCHEME_FORMULAS,
        "scheme_model_notes": SCHEME_MODEL_NOTES,
    }
    json_path.write_text(
        json.dumps(json_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("Environment")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    print_results(results)
    print_scheme_totals(scheme_corrected)
    print(
        "\nSaved:\n"
        f"  {operations_csv}\n"
        f"  {schemes_csv}\n"
        f"  {json_path}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
