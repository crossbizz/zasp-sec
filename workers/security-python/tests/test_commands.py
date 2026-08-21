from __future__ import annotations

import base64
import io
import json
import struct
import unittest
from unittest import mock

from security_worker import __main__ as command


def authority(phase: str) -> dict[str, object]:
    return {
        "attempt": 1,
        "cartography_version": "0.139.1",
        "connection_id": "pid_00000003-0000-4000-8000-000000000003",
        "credential_expires_at": "2026-08-20T00:15:00Z",
        "cursor_lineage": 3,
        "environment_id": "pid_00000004-0000-4000-8000-000000000004",
        "integration_id": "pid_00000005-0000-4000-8000-000000000005",
        "job_id": "pid_00000006-0000-4000-8000-000000000006",
        "observed_at": "2026-08-20T00:00:00Z",
        "organization_id": "pid_00000001-0000-4000-8000-000000000001",
        "phase": phase,
        "prowler_version": "5.39.1",
        "remaining_bytes": 1024,
        "remaining_entities": 10,
        "remaining_relationships": 20,
        "source_digest": "c" * 64,
        "subject_id": "123456789012",
        "subject_kind": "aws_account",
        "workspace_id": "pid_00000002-0000-4000-8000-000000000002",
    }


def frame(document: dict[str, object]) -> bytes:
    body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    return struct.pack(">I", len(body)) + body


def decode_frame(payload: bytes) -> dict[str, object]:
    length = struct.unpack(">I", payload[:4])[0]
    assert length == len(payload) - 4
    return json.loads(payload[4:])


class SecurityWorkerCommandTests(unittest.TestCase):
    def test_cartography_command_reads_and_writes_one_exact_frame(self) -> None:
        request = {
            "authority": authority("iam"),
            "protocol_version": 1,
            "source": {"account_id": "123456789012", "roles": []},
        }
        output = io.BytesIO()
        with mock.patch.object(
            command.cartography_aws,
            "transform",
            return_value={"roles": [], "version": "0.139.1"},
        ) as transform:
            status = command.run_binary(
                ["cartography-aws-v1"], io.BytesIO(frame(request)), output
            )

        self.assertEqual(status, 0)
        transform.assert_called_once_with(
            {
                "authority": {
                    "phase": "iam",
                    "source_digest": "c" * 64,
                    "subject_id": "123456789012",
                },
                "source": request["source"],
            }
        )
        self.assertEqual(
            decode_frame(output.getvalue()),
            {
                "authority": request["authority"],
                "protocol_version": 1,
                "result": {"roles": [], "version": "0.139.1"},
                "source_digest": "c" * 64,
            },
        )

    def test_prowler_command_passes_only_scoped_credential_request(self) -> None:
        credential = base64.urlsafe_b64encode(b"credential-material").rstrip(b"=").decode()
        request = {
            "authority": authority("posture"),
            "credential": credential,
            "protocol_version": 1,
            "source": {"account_id": "123456789012", "instances": [], "roles": []},
        }
        output = io.BytesIO()
        with mock.patch.object(
            command.prowler_aws,
            "scan",
            return_value={"findings": [], "version": "5.39.1"},
        ) as scan:
            status = command.run_binary(
                ["prowler-aws-v1"], io.BytesIO(frame(request)), output
            )

        self.assertEqual(status, 0)
        scan.assert_called_once_with(
            {
                "authority": {
                    "credential_expires_at": "2026-08-20T00:15:00Z",
                    "phase": "posture",
                    "source_digest": "c" * 64,
                    "subject_id": "123456789012",
                },
                "credential": credential,
                "source": request["source"],
            }
        )
        self.assertEqual(
            decode_frame(output.getvalue())["result"],
            {"findings": [], "version": "5.39.1"},
        )

    def test_invalid_command_and_failure_emit_no_binary_output(self) -> None:
        for arguments in ([], ["health"], ["prowler-aws-v1", "extra"]):
            with self.subTest(arguments=arguments):
                output = io.BytesIO()
                self.assertEqual(
                    command.run_binary(arguments, io.BytesIO(), output), 2
                )
                self.assertEqual(output.getvalue(), b"")

        request = {
            "authority": authority("iam"),
            "protocol_version": 1,
            "source": {},
        }
        output = io.BytesIO()
        with mock.patch.object(
            command.cartography_aws,
            "transform",
            side_effect=ValueError("secret-bearing provider error"),
        ):
            self.assertEqual(
                command.main(
                    ["cartography-aws-v1"],
                    input_stream=io.BytesIO(frame(request)),
                    binary_output=output,
                ),
                1,
            )
        self.assertEqual(output.getvalue(), b"")

    def test_typed_failures_map_to_stable_process_statuses(self) -> None:
        request = {
            "authority": authority("posture"),
            "credential": base64.urlsafe_b64encode(b"credential-material")
            .rstrip(b"=")
            .decode(),
            "protocol_version": 1,
            "source": {"account_id": "123456789012", "instances": [], "roles": []},
        }
        for code, expected in (
            ("retryable", 10),
            ("rate_limited", 11),
            ("denied", 12),
            ("malformed", 13),
        ):
            with self.subTest(code=code), mock.patch.object(
                command.prowler_aws,
                "scan",
                side_effect=command.prowler_aws.CollectionError(code),
            ):
                output = io.BytesIO()
                self.assertEqual(
                    command.main(
                        ["prowler-aws-v1"],
                        input_stream=io.BytesIO(frame(request)),
                        binary_output=output,
                    ),
                    expected,
                )
                self.assertEqual(output.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
