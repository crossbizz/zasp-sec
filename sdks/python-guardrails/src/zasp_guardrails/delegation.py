"""Offline verification of Zasp Ed25519 task grants."""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field

from .transport import ProtocolError

_HEADER = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"zasp-task-delegation.v1+jwt"}').rstrip(b"=").decode()
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")


class DelegationDenied(ProtocolError):
    """The requested tool or resource is outside a verified task grant."""


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError
    return decoded


def _scope(values: object, expected: str) -> bool:
    return (isinstance(values, list) and 1 <= len(values) <= 32
            and all(isinstance(v, str) and _LABEL.fullmatch(v) for v in values)
            and len(set(values)) == len(values) and expected in values)


@dataclass(frozen=True)
class TaskDelegation:
    """Pin the authenticated deployment and task separately from the signed grant."""

    public_key: bytes
    organization_id: str
    workspace_id: str
    environment_id: str
    parent_task_id: str
    child_agent_id: str
    token: str = field(repr=False)

    # Tier: 1 | Purpose: check the signed task scope before tool dispatch.
    # Model: none.
    # Authority: pinned Ed25519 key and trusted host identity.
    # Fallback: deny when the signature, task, resource, operation or lifetime is invalid.
    def check(self, operation: str, resource: str | None) -> None:
        if not self.token:
            raise DelegationDenied("delegation_unverified")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise DelegationDenied("Install zasp-guardrails[delegation] for local verification") from None
        try:
            if not isinstance(self.token, str) or len(self.token) > 16384 or resource is None:
                raise ValueError
            header, payload, sig = self.token.split(".")
            if header != _HEADER:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(_decode(sig), f"{header}.{payload}".encode("ascii"))
            claims = json.loads(_decode(payload))
            expected = {k: getattr(self, k) for k in ("organization_id", "workspace_id", "environment_id",
                                                       "parent_task_id", "child_agent_id")}
            if not all(isinstance(v, str) and _LABEL.fullmatch(v) and claims[k] == v for k, v in expected.items()):
                raise ValueError
            if not self._permits(claims, operation, resource):
                raise ValueError
        except (AttributeError, InvalidSignature, KeyError, TypeError, ValueError, RecursionError, binascii.Error):
            raise DelegationDenied("delegation_denied") from None

    def _permits(self, claims: dict, operation: str, resource: str) -> bool:
        issued, expires = claims["iat"], claims["exp"]
        depth, maximum = claims["depth"], claims["max_depth"]
        return (
            all(type(value) is int for value in (issued, expires, depth, maximum))
            and 0 < issued <= int(time.time()) < expires <= issued + 300 and 1 <= depth <= maximum <= 8
            and isinstance(claims["parent_agent_id"], str) and bool(_LABEL.fullmatch(claims["parent_agent_id"]))
            and claims["parent_agent_id"] != self.child_agent_id
            and _scope(claims["allowed_operations"], operation) and _scope(claims["allowed_resources"], resource)
        )

    def headers(self, operation: str, resource: str | None) -> dict[str, str]:
        self.check(operation, resource)
        assert resource is not None
        return {"X-Zasp-Delegation": self.token, "X-Zasp-Parent-Task-Id": self.parent_task_id,
                "X-Zasp-Delegation-Resource": resource}
