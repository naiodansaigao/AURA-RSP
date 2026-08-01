"""Client-side validation for decrypted AURA Profile plaintext."""

from __future__ import annotations

import hashlib


class ProfileDigestMismatch(ValueError):
    """The authenticated order and decrypted Profile identify different data."""

    code = "PROFILE_ORDER_DIGEST_MISMATCH"


def verify_profile_plaintext(
    profile: bytes,
    *,
    response_sha256: str,
    order_pid_h: str,
) -> str:
    """Require the plaintext digest to match response metadata and the order."""

    actual = hashlib.sha256(profile).hexdigest()
    if actual != response_sha256 or actual != order_pid_h:
        raise ProfileDigestMismatch(ProfileDigestMismatch.code)
    return actual
