from __future__ import annotations

import base64
import json
import unittest

from security_worker import prowler_aws


ACCOUNT_ID = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/admin"
INSTANCE_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:instance/i-0123456789abcdef0"
CHECKS = (
    "iam_role_administratoraccess_policy",
    "iam_role_cross_service_confused_deputy_prevention",
    "ec2_instance_imdsv2_enabled",
)


def encoded_credential() -> str:
    body = json.dumps(
        {
            "access_key_id": "ASIAABCDEFGHIJKLMNOP",
            "expires_at": "2026-08-20T00:15:00Z",
            "secret_access_key": "s" * 40,
            "session_token": "t" * 64,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(body).rstrip(b"=").decode()


def request_document() -> dict[str, object]:
    return {
        "authority": {
            "credential_expires_at": "2026-08-20T00:15:00Z",
            "phase": "posture",
            "source_digest": "b" * 64,
            "subject_id": ACCOUNT_ID,
        },
        "credential": encoded_credential(),
        "source": {
            "account_id": ACCOUNT_ID,
            "instances": [
                {
                    "Arn": INSTANCE_ARN,
                    "HttpEndpoint": "enabled",
                    "HttpTokens": "optional",
                    "InstanceId": "i-0123456789abcdef0",
                    "Region": "us-east-1",
                    "State": "running",
                }
            ],
            "roles": [
                {
                    "Arn": ROLE_ARN,
                    "AssumeRolePolicyDocument": {
                        "Statement": [],
                        "Version": "2012-10-17",
                    },
                    "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                    "IsServiceRole": False,
                    "RoleId": "AROA1234567890ABCDEF",
                    "RoleName": "admin",
                }
            ],
        },
    }


class FakeProwlerAPI:
    version = "5.39.1"

    def __init__(self) -> None:
        self.credential = None
        self.calls: list[str] = []

    def reattest(self, credential: object, account_id: str) -> None:
        self.credential = credential
        self.asserted_account_id = account_id

    def execute(self, check_id: str, source: dict[str, object]) -> list[dict[str, object]]:
        self.calls.append(check_id)
        if check_id == "iam_role_administratoraccess_policy":
            return [
                {
                    "resource_arn": ROLE_ARN,
                    "resource_id": "admin",
                    "region": "global",
                    "status": "FAIL",
                }
            ]
        if check_id == "iam_role_cross_service_confused_deputy_prevention":
            return []
        if check_id == "ec2_instance_imdsv2_enabled":
            return [
                {
                    "resource_arn": INSTANCE_ARN,
                    "resource_id": "i-0123456789abcdef0",
                    "region": "us-east-1",
                    "status": "FAIL",
                }
            ]
        raise AssertionError(f"unexpected check {check_id}")


class ProwlerScanTests(unittest.TestCase):
    def test_reattests_and_executes_only_fixed_checks_with_cleared_credential(self) -> None:
        api = FakeProwlerAPI()

        result = prowler_aws.scan(request_document(), api)

        self.assertEqual(api.asserted_account_id, ACCOUNT_ID)
        self.assertEqual(tuple(api.calls), CHECKS)
        self.assertEqual(
            result,
            {
                "findings": [
                    {
                        "check_id": "ec2_instance_imdsv2_enabled",
                        "resource_arn": INSTANCE_ARN,
                        "resource_id": "i-0123456789abcdef0",
                        "region": "us-east-1",
                        "severity": "high",
                        "status": "FAIL",
                    },
                    {
                        "check_id": "iam_role_administratoraccess_policy",
                        "resource_arn": ROLE_ARN,
                        "resource_id": "admin",
                        "region": "global",
                        "severity": "high",
                        "status": "FAIL",
                    },
                ],
                "version": "5.39.1",
            },
        )
        self.assertEqual(api.credential.access_key_id, bytearray())
        self.assertEqual(api.credential.secret_access_key, bytearray())
        self.assertEqual(api.credential.session_token, bytearray())

    def test_rejects_scope_input_and_runtime_drift_without_secret_echo(self) -> None:
        cases: dict[str, dict[str, object]] = {}
        wrong_account = request_document()
        wrong_account["source"] = {
            **wrong_account["source"],
            "account_id": "999999999999",
        }
        cases["wrong account"] = wrong_account
        secret_source = request_document()
        secret_source["source"] = {
            **secret_source["source"],
            "secret_access_key": "must-not-survive",
        }
        cases["secret source"] = secret_source
        duplicate = request_document()
        duplicate["source"] = {
            **duplicate["source"],
            "roles": [
                duplicate["source"]["roles"][0],
                duplicate["source"]["roles"][0],
            ],
        }
        cases["duplicate role"] = duplicate
        for name, request in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                prowler_aws.CollectionError, "^collection unavailable$"
            ):
                prowler_aws.scan(request, FakeProwlerAPI())

        class DriftedAPI(FakeProwlerAPI):
            version = "5.40.0"

        with self.assertRaisesRegex(
            prowler_aws.CollectionError, "^collection unavailable$"
        ):
            prowler_aws.scan(request_document(), DriftedAPI())

    def test_rejects_unknown_duplicate_and_foreign_check_output(self) -> None:
        class BadAPI(FakeProwlerAPI):
            def execute(
                self, check_id: str, source: dict[str, object]
            ) -> list[dict[str, object]]:
                if check_id == "iam_role_administratoraccess_policy":
                    return [
                        {
                            "resource_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/foreign",
                            "resource_id": "foreign",
                            "region": "global",
                            "status": "FAIL",
                        }
                    ]
                return []

        with self.assertRaisesRegex(
            prowler_aws.CollectionError, "^collection unavailable$"
        ):
            prowler_aws.scan(request_document(), BadAPI())

        class DuplicateAPI(FakeProwlerAPI):
            def execute(
                self, check_id: str, source: dict[str, object]
            ) -> list[dict[str, object]]:
                rows = super().execute(check_id, source)
                return rows + rows

        with self.assertRaisesRegex(
            prowler_aws.CollectionError, "^collection unavailable$"
        ):
            prowler_aws.scan(request_document(), DuplicateAPI())


if __name__ == "__main__":
    unittest.main()
