"""Shared software-eUICC installation evidence for RSP research modes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import time


class SoftwareInstallError(RuntimeError):
    """Profile installation evidence could not be produced safely."""


@dataclass(frozen=True)
class InstallResult:
    protocol_mode: str
    transaction_id: str
    matching_id: str
    profile_path: str
    profile_bytes: int
    profile_sha256: str
    installed_at_ns: int

    def to_dict(self) -> dict:
        return asdict(self)


def install_profile(
    profile: bytes,
    *,
    expected_sha256: str,
    output_dir: str | Path,
    protocol_mode: str,
    transaction_id: str,
    matching_id: str,
) -> InstallResult:
    """Validate and atomically store the Profile used as software install evidence."""

    actual_sha256 = hashlib.sha256(profile).hexdigest()
    if actual_sha256 != expected_sha256:
        raise SoftwareInstallError("Profile digest does not match the order")
    destination_dir = Path(output_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    profile_path = destination_dir / f"{matching_id}.{protocol_mode}.upp.der"
    temporary = profile_path.with_suffix(profile_path.suffix + ".tmp")
    temporary.write_bytes(profile)
    temporary.replace(profile_path)
    result = InstallResult(
        protocol_mode=protocol_mode,
        transaction_id=transaction_id,
        matching_id=matching_id,
        profile_path=str(profile_path),
        profile_bytes=len(profile),
        profile_sha256=actual_sha256,
        installed_at_ns=time.time_ns(),
    )
    result_path = destination_dir / f"{matching_id}.{protocol_mode}.install.json"
    result_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result
