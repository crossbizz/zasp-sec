from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import unicodedata
from datetime import datetime, timezone
from typing import BinaryIO


MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_STRING_BYTES = 16 * 1024
MAX_COLLECTION_ITEMS = 20_000
MAX_JSON_DEPTH = 16
MODE_CARTOGRAPHY = "cartography-aws-v1"
MODE_PROWLER = "prowler-aws-v1"

_PRODUCT_ID = re.compile(
    r"pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_CREDENTIAL = re.compile(r"[A-Za-z0-9_-]{16,32768}\Z")

_REQUEST_KEYS = frozenset(("authority", "protocol_version", "source"))
_PROWLER_REQUEST_KEYS = frozenset(
    ("authority", "credential", "protocol_version", "source")
)
_AUTHORITY_KEYS = frozenset(
    (
        "attempt",
        "cartography_version",
        "connection_id",
        "credential_expires_at",
        "cursor_lineage",
        "environment_id",
        "integration_id",
        "job_id",
        "observed_at",
        "organization_id",
        "phase",
        "prowler_version",
        "remaining_bytes",
        "remaining_entities",
        "remaining_relationships",
        "source_digest",
        "subject_id",
        "subject_kind",
        "workspace_id",
    )
)
_RESPONSE_KEYS = frozenset(
    ("authority", "protocol_version", "result", "source_digest")
)


class ProtocolError(ValueError):
    pass


def read_request(stream: BinaryIO, mode: str) -> dict[str, object]:
    if mode not in (MODE_CARTOGRAPHY, MODE_PROWLER):
        raise ProtocolError("invalid protocol")
    document = _read_document(stream)
    expected_keys = _PROWLER_REQUEST_KEYS if mode == MODE_PROWLER else _REQUEST_KEYS
    _exact_keys(document, expected_keys)
    if document["protocol_version"] != 1:
        raise ProtocolError("invalid protocol")
    authority = _authority(document["authority"])
    source = document["source"]
    if type(source) is not dict:
        raise ProtocolError("invalid protocol")
    _bounded_json(source, 1)
    if hashlib.sha256(_canonical(source)).hexdigest() != authority["source_digest"]:
        raise ProtocolError("invalid protocol")
    if mode == MODE_PROWLER:
        credential = document["credential"]
        if type(credential) is not str or _CREDENTIAL.fullmatch(credential) is None:
            raise ProtocolError("invalid protocol")
        try:
            decoded = base64.b64decode(
                credential + "=" * (-len(credential) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, base64.binascii.Error) as exc:
            raise ProtocolError("invalid protocol") from exc
        if len(decoded) < 12 or len(decoded) > MAX_STRING_BYTES:
            raise ProtocolError("invalid protocol")
    document["authority"] = authority
    return document


def write_response(stream: BinaryIO, response: dict[str, object]) -> None:
    if type(response) is not dict:
        raise ProtocolError("invalid protocol")
    _exact_keys(response, _RESPONSE_KEYS)
    if response["protocol_version"] != 1:
        raise ProtocolError("invalid protocol")
    authority = _authority(response["authority"])
    if response["source_digest"] != authority["source_digest"]:
        raise ProtocolError("invalid protocol")
    if type(response["result"]) is not dict:
        raise ProtocolError("invalid protocol")
    _bounded_json(response["result"], 1)
    body = _canonical(response)
    if len(body) < 2 or len(body) > MAX_FRAME_BYTES:
        raise ProtocolError("invalid protocol")
    stream.write(struct.pack(">I", len(body)))
    stream.write(body)


def _read_document(stream: BinaryIO) -> dict[str, object]:
    if stream is None or not hasattr(stream, "read"):
        raise ProtocolError("invalid protocol")
    header = _read_exact(stream, 4)
    length = struct.unpack(">I", header)[0]
    if length < 2 or length > MAX_FRAME_BYTES:
        raise ProtocolError("invalid protocol")
    body = _read_exact(stream, length)
    if stream.read(1) != b"":
        raise ProtocolError("invalid protocol")
    try:
        text = body.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ProtocolError) as exc:
        raise ProtocolError("invalid protocol") from exc
    if type(document) is not dict or _canonical(document) != body:
        raise ProtocolError("invalid protocol")
    _bounded_json(document, 0)
    return document


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if type(chunk) is not bytes or len(chunk) == 0:
            raise ProtocolError("invalid protocol")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _authority(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ProtocolError("invalid protocol")
    _exact_keys(value, _AUTHORITY_KEYS)
    product_ids = (
        "organization_id",
        "workspace_id",
        "environment_id",
        "integration_id",
        "connection_id",
        "job_id",
    )
    if any(
        type(value[key]) is not str or _PRODUCT_ID.fullmatch(value[key]) is None
        for key in product_ids
    ):
        raise ProtocolError("invalid protocol")
    if (
        type(value["attempt"]) is not int
        or not 1 <= value["attempt"] <= 100
        or type(value["cursor_lineage"]) is not int
        or not 1 <= value["cursor_lineage"] <= 1_000_000
        or value["subject_kind"] != "aws_account"
        or type(value["subject_id"]) is not str
        or _ACCOUNT_ID.fullmatch(value["subject_id"]) is None
        or value["phase"] not in ("iam", "ec2", "posture")
        or value["cartography_version"] != "0.139.1"
        or value["prowler_version"] != "5.39.1"
        or type(value["source_digest"]) is not str
        or _DIGEST.fullmatch(value["source_digest"]) is None
    ):
        raise ProtocolError("invalid protocol")
    for key, maximum in (
        ("remaining_entities", 1_000),
        ("remaining_relationships", 2_000),
        ("remaining_bytes", 64 * 1024 * 1024),
    ):
        if type(value[key]) is not int or not 0 <= value[key] <= maximum:
            raise ProtocolError("invalid protocol")
    observed = _timestamp(value["observed_at"])
    expires = _timestamp(value["credential_expires_at"])
    if expires <= observed:
        raise ProtocolError("invalid protocol")
    return dict(value)


def _timestamp(value: object) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ProtocolError("invalid protocol")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ProtocolError("invalid protocol") from exc
    return parsed


def _exact_keys(value: dict[str, object], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        raise ProtocolError("invalid protocol")


def _bounded_json(value: object, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("invalid protocol")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > (1 << 63) - 1:
            raise ProtocolError("invalid protocol")
        return
    if type(value) is str:
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_STRING_BYTES or any(
            unicodedata.category(character) == "Cc" for character in value
        ):
            raise ProtocolError("invalid protocol")
        return
    if type(value) is list:
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProtocolError("invalid protocol")
        for item in value:
            _bounded_json(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProtocolError("invalid protocol")
        for key, item in value.items():
            if type(key) is not str or len(key.encode("utf-8")) > 256:
                raise ProtocolError("invalid protocol")
            _bounded_json(item, depth + 1)
        return
    raise ProtocolError("invalid protocol")


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        # Match Go encoding/json canonical output at the cross-language boundary.
        encoded = (
            encoded.replace("&", r"\u0026")
            .replace("<", r"\u003c")
            .replace(">", r"\u003e")
            .replace("\u2028", r"\u2028")
            .replace("\u2029", r"\u2029")
        )
        return encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid protocol") from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("invalid protocol")
        result[key] = value
    return result


def _reject_number(_: str) -> object:
    raise ProtocolError("invalid protocol")
