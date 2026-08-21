from __future__ import annotations

import io
import hashlib
import json
import struct
import unittest

from security_worker import protocol


AUTHORITY = {
    "attempt": 2,
    "cartography_version": "0.139.1",
    "connection_id": "pid_20000002-0000-4000-8000-000000000002",
    "credential_expires_at": "2026-08-20T22:00:00Z",
    "cursor_lineage": 4,
    "environment_id": "pid_10000003-0000-4000-8000-000000000003",
    "integration_id": "pid_20000001-0000-4000-8000-000000000001",
    "job_id": "pid_20000003-0000-4000-8000-000000000003",
    "observed_at": "2026-08-20T21:00:00Z",
    "organization_id": "pid_10000001-0000-4000-8000-000000000001",
    "phase": "posture",
    "prowler_version": "5.39.1",
    "remaining_bytes": 1048576,
    "remaining_entities": 100,
    "remaining_relationships": 200,
    "source_digest": "0" * 64,
    "subject_id": "123456789012",
    "subject_kind": "aws_account",
    "workspace_id": "pid_10000002-0000-4000-8000-000000000002",
}


def request_document(*, credential: bool = False) -> dict[str, object]:
    source = {
        "instances": [],
        "roles": [
            {
                "arn": "arn:aws:iam::123456789012:role/reader",
                "name": "reader",
            }
        ],
    }
    authority = dict(AUTHORITY)
    authority["source_digest"] = hashlib.sha256(protocol._canonical(source)).hexdigest()
    value: dict[str, object] = {
        "authority": authority,
        "protocol_version": 1,
        "source": source,
    }
    if credential:
        value["credential"] = "ZXBoZW1lcmFsLWF3cy1zZXNzaW9u"
    return value


def canonical(value: object) -> bytes:
    return protocol._canonical(value)


def frame(value: object) -> bytes:
    body = canonical(value)
    return struct.pack(">I", len(body)) + body


class FragmentedReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 1
        return super().read(min(size, 3))


class ProtocolTests(unittest.TestCase):
    def test_canonical_json_matches_go_html_and_line_separator_escaping(self) -> None:
        self.assertEqual(
            protocol._canonical({"value": "<tag>&\u2028\u2029"}),
            b'{"value":"\\u003ctag\\u003e\\u0026\\u2028\\u2029"}',
        )

    def test_reads_fragmented_canonical_request_and_writes_exact_frame(self) -> None:
        parsed = protocol.read_request(
            FragmentedReader(frame(request_document(credential=True))),
            protocol.MODE_PROWLER,
        )

        self.assertEqual(parsed["authority"], request_document(credential=True)["authority"])
        self.assertEqual(parsed["credential"], "ZXBoZW1lcmFsLWF3cy1zZXNzaW9u")
        output = io.BytesIO()
        response = {
            "authority": parsed["authority"],
            "protocol_version": 1,
            "result": {"findings": []},
            "source_digest": parsed["authority"]["source_digest"],
        }
        protocol.write_response(output, response)
        self.assertEqual(output.getvalue(), frame(response))

    def test_rejects_frame_boundary_and_json_ambiguity(self) -> None:
        valid = request_document()
        body = canonical(valid)
        cases = {
            "zero length": struct.pack(">I", 0),
            "oversized length": struct.pack(">I", protocol.MAX_FRAME_BYTES + 1),
            "truncated": struct.pack(">I", len(body) + 1) + body,
            "trailing byte": frame(valid) + b"x",
            "second frame": frame(valid) + frame(valid),
            "invalid utf8": struct.pack(">I", 2) + b"\xff\xfe",
            "noncanonical whitespace": struct.pack(">I", len(body) + 1) + b" " + body,
            "duplicate key": self._raw_frame(
                b'{"authority":{},"authority":{},"protocol_version":1,"source":{}}'
            ),
            "float": self._raw_frame(
                canonical(valid).replace(b'"attempt":2', b'"attempt":2.0')
            ),
        }
        for name, payload in cases.items():
            with self.subTest(name=name), self.assertRaises(protocol.ProtocolError):
                protocol.read_request(io.BytesIO(payload), protocol.MODE_CARTOGRAPHY)

    def test_rejects_unknown_keys_and_authority_drift(self) -> None:
        cases: dict[str, dict[str, object]] = {}
        unknown = request_document()
        unknown["unexpected"] = True
        cases["unknown request key"] = unknown
        missing = request_document()
        del missing["authority"]
        cases["missing authority"] = missing
        bad_scope = request_document()
        bad_scope["authority"] = {**AUTHORITY, "organization_id": "foreign"}
        cases["bad scope"] = bad_scope
        wrong_subject = request_document()
        wrong_subject["authority"] = {**AUTHORITY, "subject_id": "12345678901"}
        cases["short account"] = wrong_subject
        expired = request_document()
        expired["authority"] = {
            **AUTHORITY,
            "credential_expires_at": AUTHORITY["observed_at"],
        }
        cases["expired credential"] = expired
        for name, value in cases.items():
            with self.subTest(name=name), self.assertRaises(protocol.ProtocolError):
                protocol.read_request(io.BytesIO(frame(value)), protocol.MODE_CARTOGRAPHY)

        leading_zero = request_document()
        leading_zero["authority"] = {**leading_zero["authority"], "subject_id": "012345678901"}
        leading_zero["source"] = {**leading_zero["source"], "account_id": "012345678901"}
        leading_zero["authority"]["source_digest"] = hashlib.sha256(
            protocol._canonical(leading_zero["source"])
        ).hexdigest()
        parsed = protocol.read_request(
            io.BytesIO(frame(leading_zero)), protocol.MODE_CARTOGRAPHY
        )
        self.assertEqual(parsed["authority"]["subject_id"], "012345678901")

    def test_mode_exactly_controls_credential_authority(self) -> None:
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_request(
                io.BytesIO(frame(request_document(credential=True))),
                protocol.MODE_CARTOGRAPHY,
            )
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_request(
                io.BytesIO(frame(request_document())), protocol.MODE_PROWLER
            )

    @staticmethod
    def _raw_frame(body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + body


if __name__ == "__main__":
    unittest.main()
