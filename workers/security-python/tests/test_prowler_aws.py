from __future__ import annotations

import base64
import json
import os
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest import mock

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
            "remaining_bytes": 1_048_576,
            "remaining_entities": 100,
            "remaining_relationships": 200,
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

    def test_rejects_result_beyond_item_or_byte_budget(self) -> None:
        for key in ("remaining_entities", "remaining_bytes"):
            with self.subTest(key=key):
                request = request_document()
                request["authority"] = {**request["authority"], key: 0}
                with self.assertRaises(prowler_aws.CollectionError):
                    prowler_aws.scan(request, FakeProwlerAPI())


class StsEndpointTests(unittest.TestCase):
    def test_production_and_unset_environments_use_the_regional_aws_endpoint(self) -> None:
        for environ in (
            {},
            {"ZASP_ENVIRONMENT": "production"},
            {"ZASP_ENVIRONMENT": "development"},
            {"ZASP_ENVIRONMENT": "production", "ZASP_LOCAL_CLOUD_ENDPOINT": ""},
        ):
            with self.subTest(environ=environ):
                self.assertEqual(
                    prowler_aws.sts_endpoint(environ),
                    "https://sts.us-east-1.amazonaws.com",
                )

    def test_local_endpoint_is_refused_outside_development_and_test(self) -> None:
        for environment in ("production", "staging", "", "Development", "prod"):
            with self.subTest(environment=environment):
                environ = {"ZASP_LOCAL_CLOUD_ENDPOINT": "http://127.0.0.1:4566"}
                if environment:
                    environ["ZASP_ENVIRONMENT"] = environment
                with self.assertRaises(prowler_aws.CollectionError) as raised:
                    prowler_aws.sts_endpoint(environ)
                self.assertEqual(raised.exception.code, "denied")

    def test_local_endpoint_must_be_plaintext_loopback_or_private_with_port(self) -> None:
        for environment in ("development", "test"):
            for endpoint in ("http://127.0.0.1:4566", "http://10.1.2.3:4566", "http://[::1]:4566"):
                with self.subTest(environment=environment, endpoint=endpoint):
                    self.assertEqual(
                        prowler_aws.sts_endpoint(
                            {"ZASP_ENVIRONMENT": environment, "ZASP_LOCAL_CLOUD_ENDPOINT": endpoint}
                        ),
                        endpoint,
                    )
        for endpoint in (
            "https://127.0.0.1:4566",
            "http://127.0.0.1",
            "http://localhost:4566",
            "http://8.8.8.8:4566",
            "http://sts.us-east-1.amazonaws.com:80",
            "http://user@127.0.0.1:4566",
            "http://127.0.0.1:4566/",
            "http://127.0.0.1:4566?x=1",
            "http://127.0.0.1:4566#x",
            "http://127.0.0.1:port",
            "127.0.0.1:4566",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(prowler_aws.CollectionError) as raised:
                    prowler_aws.sts_endpoint(
                        {"ZASP_ENVIRONMENT": "development", "ZASP_LOCAL_CLOUD_ENDPOINT": endpoint}
                    )
                self.assertEqual(raised.exception.code, "denied")


class ReattestEndpointTests(unittest.TestCase):
    def reattest(self, environ: dict[str, str]) -> dict[str, object]:
        seen: dict[str, object] = {}

        class Session:
            def __init__(self, **_: object) -> None:
                pass

            def client(self, service: str, **options: object) -> object:
                seen.update(options, service=service)
                return SimpleNamespace(get_caller_identity=lambda: {"Account": ACCOUNT_ID})

        boto3 = ModuleType("boto3")
        boto3.session = SimpleNamespace(Session=Session)
        botocore = ModuleType("botocore")
        config = ModuleType("botocore.config")
        config.Config = lambda **options: options
        credential = prowler_aws._decode_credential(encoded_credential(), "2026-08-20T00:15:00Z")
        modules = {"boto3": boto3, "botocore": botocore, "botocore.config": config}
        with mock.patch.dict(sys.modules, modules), mock.patch.dict(os.environ, environ, clear=True):
            prowler_aws.RuntimeProwlerAPI().reattest(credential, ACCOUNT_ID)
        return seen

    def test_production_reattests_against_aws_over_tls(self) -> None:
        for environ in ({}, {"ZASP_ENVIRONMENT": "production"}):
            with self.subTest(environ=environ):
                seen = self.reattest(environ)
                self.assertEqual(seen["service"], "sts")
                self.assertEqual(seen["endpoint_url"], "https://sts.us-east-1.amazonaws.com")
                self.assertIs(seen["use_ssl"], True)
                self.assertIs(seen["verify"], True)

    def test_production_refuses_a_local_endpoint_before_any_call(self) -> None:
        with self.assertRaises(prowler_aws.CollectionError) as raised:
            self.reattest(
                {"ZASP_ENVIRONMENT": "production", "ZASP_LOCAL_CLOUD_ENDPOINT": "http://127.0.0.1:4566"}
            )
        self.assertEqual(raised.exception.code, "denied")

    def test_development_reattests_against_the_local_emulator(self) -> None:
        seen = self.reattest(
            {"ZASP_ENVIRONMENT": "development", "ZASP_LOCAL_CLOUD_ENDPOINT": "http://127.0.0.1:4566"}
        )
        self.assertEqual(seen["endpoint_url"], "http://127.0.0.1:4566")
        self.assertIs(seen["use_ssl"], False)


class RuntimeRoleTests(unittest.TestCase):
    def test_role_is_reported_by_name_like_the_prowler_role_model(self) -> None:
        role = prowler_aws.RuntimeRole(
            arn=ROLE_ARN,
            name="admin",
            region="global",
            tags=(),
            attached_policies=(),
            is_service_role=False,
            assume_role_policy={},
        )
        # Prowler's AWS report takes the resource id, then its name.
        self.assertEqual(getattr(role, "id", None) or getattr(role, "name", None), "admin")

    def test_real_prowler_checks_report_ids_the_worker_accepts(self) -> None:
        try:
            api = prowler_aws.load_runtime_api()
        except prowler_aws.CollectionError:
            self.skipTest("Prowler is not installed in this environment")
        source = request_document()["source"]
        reported = 0
        for check_id in CHECKS:
            for report in api.execute(check_id, source):
                finding = prowler_aws._finding(check_id, report, source)
                self.assertEqual(finding["check_id"], check_id)
                reported += 1
        self.assertGreater(reported, 0)


if __name__ == "__main__":
    unittest.main()
