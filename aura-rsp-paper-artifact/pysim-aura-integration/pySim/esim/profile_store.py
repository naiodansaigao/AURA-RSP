"""Shared Profile lookup and loading for Standard RSP and AURA-RSP.

This module deliberately stops at the unprotected Profile package (UPP).
Standard mode protects it as a GSMA BPP, while AURA mode protects the same
bytes as an AURA encrypted Profile package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path

from osmocom.utils import b2h, h2b, swap_nibbles

from pySim.esim import saip
from pySim.esim.es8p import ProfileMetadata, UnprotectedProfilePackage


class ProfileStoreError(RuntimeError):
    """Base class for Profile repository errors."""


class InvalidMatchingId(ProfileStoreError):
    """The requested matching ID is empty or escapes the configured root."""


class ProfileNotFound(ProfileStoreError):
    """No readable UPP exists for the requested matching ID."""


@dataclass(frozen=True)
class ProfileRecord:
    matching_id: str
    path: Path
    data: bytes = field(repr=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def profile_elements(self) -> saip.ProfileElementSequence:
        return saip.ProfileElementSequence.from_der(self.data)

    @property
    def iccid_hex(self) -> str:
        return b2h(self.profile_elements.get_pe_for_type("header").decoded["iccid"])

    @property
    def iccid(self) -> str:
        return swap_nibbles(self.iccid_hex)

    def standard_metadata(self, notification_address: str) -> ProfileMetadata:
        metadata = ProfileMetadata(
            iccid_bin=h2b(self.iccid),
            spn="OsmocomSPN",
            profile_name=self.matching_id,
        )
        for event in ("enable", "disable", "delete"):
            metadata.add_notification(event, notification_address)
        return metadata

    def as_upp(
        self, notification_address: str | None = None
    ) -> UnprotectedProfilePackage:
        metadata = (
            self.standard_metadata(notification_address)
            if notification_address is not None
            else None
        )
        return UnprotectedProfilePackage.from_der(self.data, metadata=metadata)


class ProfileRepository:
    """Read-only repository of ``<matchingId>.der`` UPP fixtures."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def resolve(self, matching_id: str) -> Path:
        if not matching_id or "\x00" in matching_id:
            raise InvalidMatchingId("matching ID is empty or malformed")
        candidate = (self.root / f"{matching_id}.der").resolve()
        try:
            common = Path(os.path.commonpath((candidate, self.root)))
        except ValueError as exc:
            raise InvalidMatchingId("matching ID is outside the Profile root") from exc
        if common != self.root:
            raise InvalidMatchingId("matching ID is outside the Profile root")
        return candidate

    def load(self, matching_id: str) -> ProfileRecord:
        path = self.resolve(matching_id)
        if not path.is_file() or not os.access(path, os.R_OK):
            raise ProfileNotFound(f"Profile not found: {matching_id}")
        return ProfileRecord(matching_id=matching_id, path=path, data=path.read_bytes())
