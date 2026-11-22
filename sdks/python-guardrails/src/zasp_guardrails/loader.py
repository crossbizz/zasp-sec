"""Verify the exact immutable skill bytes supplied to an application.

The host configures the source identity and review lookup. The skill cannot
choose either. No file is executed and no external references are resolved.
"""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from types import MappingProxyType

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_ENTRIES = 1024
_MAX_FILE = 2 << 20
_MAX_TOTAL = 12 << 20


class AdmissionDenied(Exception):
    """A machine-readable denial. It contains no artifact contents."""

    def __init__(self, reason: str, digest: str | None = None) -> None:
        self.reason = reason
        self.digest = digest
        super().__init__(reason)


@dataclass(frozen=True)
class Source:
    """Application-configured origin and fetcher for a self-contained artifact."""

    origin: str
    fetch: Callable[[], Mapping[str, bytes]]


@dataclass(frozen=True)
class Review:
    environment: str
    origin: str
    digest: str
    revision: int
    state: str
    expires_at: datetime


class LocalReviews:
    """In-process private policy installed by the trusted application owner.

    An application using durable policy should hydrate its latest revisions
    before serving or supply its own authenticated lookup to load_reviewed.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], Review] = {}
        self._lock = Lock()

    def install(self, review: Review) -> None:
        if (not review.environment or not review.origin or not _DIGEST.fullmatch(review.digest)
                or type(review.revision) is not int or review.revision < 1
                or review.state not in {"approved", "revoked", "rejected"}
                or not isinstance(review.expires_at, datetime) or review.expires_at.utcoffset() is None):
            raise ValueError("invalid_review")
        key = (review.environment, review.origin, review.digest)
        with self._lock:
            previous = self._records.get(key)
            if previous == review:
                return
            if previous is not None and review.revision <= previous.revision:
                raise ValueError("stale_review_revision")
            self._records[key] = review

    def lookup(self, environment: str, origin: str, digest: str) -> Review | None:
        with self._lock:
            return self._records.get((environment, origin, digest))


@dataclass(frozen=True)
class VerifiedSkill:
    digest: str
    review_revision: int
    files: Mapping[str, bytes]

    @property
    def instructions(self) -> bytes:
        return self.files["SKILL.md"]


def _snapshot(bundle: Mapping[str, bytes]) -> tuple[Mapping[str, bytes], str]:
    if not isinstance(bundle, Mapping) or not 0 < len(bundle) <= _MAX_ENTRIES:
        raise AdmissionDenied("incomplete_artifact")
    frozen: dict[str, bytes] = {}
    total = 0
    for name, contents in bundle.items():
        if len(frozen) >= _MAX_ENTRIES:
            raise AdmissionDenied("artifact_limit")
        if type(name) is not str or type(contents) is not bytes:
            raise AdmissionDenied("invalid_artifact")
        if not name or name in frozen or len(name) > 4096:
            raise AdmissionDenied("invalid_manifest_path")
        parts = name.split("/")
        if len(parts) > 21 or any(
            not part or part in {".", ".."} or part.endswith((" ", "."))
            or any(c in '\\:<>"|*?' or unicodedata.category(c) in {"Cc", "Cf", "Cs"}
                   or unicodedata.category(c).startswith("M") for c in part)
            for part in parts
        ):
            raise AdmissionDenied("invalid_manifest_path")
        if len(contents) > _MAX_FILE or len(name.encode("utf-8")) > 4096:
            raise AdmissionDenied("artifact_limit")
        total += len(contents)
        if total > _MAX_TOTAL:
            raise AdmissionDenied("artifact_limit")
        frozen[name] = contents  # Immutable bytes, detached from any mutable source mapping.
    if "SKILL.md" not in frozen:
        raise AdmissionDenied("missing_entry")
    # Reject ambiguous file/directory aliases before deriving either identity.
    seen: dict[str, str] = {}
    for path in frozen:
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            entry = "/".join(parts[:i])
            if seen.setdefault(entry.casefold(), entry) != entry or (i < len(parts) and entry in frozen):
                raise AdmissionDenied("ambiguous_manifest_path")
    if len(seen) > _MAX_ENTRIES:
        raise AdmissionDenied("artifact_limit")
    digest = hashlib.sha256(b"addon-manifest.v1\0")
    for name in sorted(frozen):
        encoded = name.encode("utf-8")
        contents = frozen[name]
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack(">Q", len(contents)))
        digest.update(hashlib.sha256(contents).digest())
    return MappingProxyType(frozen), "sha256:" + digest.hexdigest()


def load_reviewed(
    source: Source,
    *,
    environment: str,
    lookup: Callable[[str, str, str], Review | None],
) -> VerifiedSkill:
    """Read once, check a fresh authoritative review, then return those bytes.

    Supply lookup from the deployment's trusted policy layer. The return value
    is the complete artifact available to this loader. Feed its bytes directly
    to the consumer instead of reopening a path or resolving external content.
    """
    if not environment or not source.origin:
        raise AdmissionDenied("missing_binding")
    try:
        files, digest = _snapshot(source.fetch())
    except AdmissionDenied:
        raise
    except Exception:
        raise AdmissionDenied("source_unavailable") from None
    try:
        review = lookup(environment, source.origin, digest)
    except Exception:
        raise AdmissionDenied("review_unavailable", digest) from None
    if review is None:
        raise AdmissionDenied("version_unreviewed", digest)
    if not isinstance(review, Review) or (review.environment, review.origin, review.digest) != (
        environment, source.origin, digest
    ):
        raise AdmissionDenied("review_binding_mismatch", digest)
    if type(review.revision) is not int or review.revision < 1:
        raise AdmissionDenied("invalid_review", digest)
    if review.state != "approved":
        reason = {"revoked": "version_revoked", "rejected": "version_rejected"}.get(review.state, "invalid_review")
        raise AdmissionDenied(reason, digest)
    if not isinstance(review.expires_at, datetime) or review.expires_at.utcoffset() is None:
        raise AdmissionDenied("invalid_review", digest)
    if review.expires_at <= datetime.now(timezone.utc):
        raise AdmissionDenied("review_expired", digest)
    return VerifiedSkill(digest, review.revision, files)
