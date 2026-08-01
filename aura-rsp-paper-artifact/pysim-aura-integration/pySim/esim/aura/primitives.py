from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .codec import b64d, b64e, canonical


def generate_p256_private():
    return ec.generate_private_key(ec.SECP256R1())


def p256_public_b64(public_key) -> str:
    return b64e(
        public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def p256_public_from_b64(value: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64d(value))


def p256_private_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def p256_private_from_pem(data: bytes):
    return serialization.load_pem_private_key(data, password=None)


def p256_public_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def p256_public_from_pem(data: bytes):
    return serialization.load_pem_public_key(data)


def p256_sign(private_key, value: dict) -> str:
    signature = private_key.sign(canonical(value), ec.ECDSA(hashes.SHA256()))
    return b64e(signature)


def p256_verify(public_key, value: dict, signature_b64: str) -> bool:
    try:
        public_key.verify(
            b64d(signature_b64), canonical(value), ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


def generate_ed25519_private():
    return ed25519.Ed25519PrivateKey.generate()


def ed25519_private_b64(private_key) -> str:
    return b64e(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )


def ed25519_private_from_b64(value: str):
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(value))


def ed25519_public_b64(public_key) -> str:
    return b64e(
        public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def ed25519_public_from_b64(value: str):
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(value))


def ed25519_sign(private_key, value: dict) -> str:
    return b64e(private_key.sign(canonical(value)))


def ed25519_verify(public_key, value: dict, signature_b64: str) -> bool:
    try:
        public_key.verify(b64d(signature_b64), canonical(value))
        return True
    except Exception:
        return False


def derive_session_keys(private_key, peer_public_b64: str, context: dict):
    peer_public = p256_public_from_b64(peer_public_b64)
    shared = private_key.exchange(ec.ECDH(), peer_public)
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(canonical(context)).digest(),
        info=b"AURA-RSP-v14:profile-download-keys",
    ).derive(shared)
    return key_material[:32], key_material[32:]


def encrypt_profile(key: bytes, plaintext: bytes, aad: dict) -> tuple[str, str]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, canonical(aad))
    return b64e(nonce), b64e(ciphertext)


def decrypt_profile(
    key: bytes, nonce_b64: str, ciphertext_b64: str, aad: dict
) -> bytes:
    return AESGCM(key).decrypt(
        b64d(nonce_b64),
        b64d(ciphertext_b64),
        canonical(aad),
    )


def receipt_mac(key: bytes, receipt_fields: dict) -> str:
    return b64e(hmac.new(key, canonical(receipt_fields), hashlib.sha256).digest())


def write_test_pki(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    ca_key = generate_p256_private()
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AURA-RSP Research"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AURA-RSP Test CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (output_dir / "ca.pem").write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    (output_dir / "ca-key.pem").write_bytes(p256_private_to_pem(ca_key))

    def issue(name: str, common_name: str, *, server: bool, client: bool) -> None:
        key = generate_p256_private()
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AURA-RSP Research"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        usages = []
        if server:
            usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client:
            usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage(usages), False)
        )
        if server:
            import ipaddress

            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(common_name),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        (output_dir / f"{name}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        (output_dir / f"{name}-key.pem").write_bytes(p256_private_to_pem(key))

    issue("smdpp-server", "aura-smdpp.test", server=True, client=False)
    issue("relay-server", "aura-pr.test", server=True, client=False)
    issue("relay-client", "aura-pr.test", server=False, client=True)
