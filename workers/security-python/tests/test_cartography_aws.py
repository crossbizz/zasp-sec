from __future__ import annotations

import unittest
from types import SimpleNamespace

from security_worker import cartography_aws


ACCOUNT_ID = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/reader"
PEER_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/writer"
POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def request_document() -> dict[str, object]:
    return {
        "authority": {
            "phase": "iam",
            "remaining_bytes": 1_048_576,
            "remaining_entities": 100,
            "remaining_relationships": 200,
            "source_digest": "a" * 64,
            "subject_id": ACCOUNT_ID,
        },
        "source": {
            "account_id": ACCOUNT_ID,
            "managed_policies": {
                ROLE_ARN: {
                    POLICY_ARN: [
                        {
                            "Action": ["ec2:DescribeInstances"],
                            "Effect": "Allow",
                            "Resource": "*",
                        }
                    ]
                }
            },
            "roles": [
                {
                    "Arn": ROLE_ARN,
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": [
                                        PEER_ROLE_ARN,
                                        "arn:aws:iam::999999999999:role/external",
                                    ]
                                },
                            }
                        ],
                        "Version": "2012-10-17",
                    },
                    "CreateDate": "2026-08-20T00:00:00Z",
                    "Path": "/",
                    "RoleId": "AROA1234567890ABCDEF",
                    "RoleName": "reader",
                },
                {
                    "Arn": PEER_ROLE_ARN,
                    "AssumeRolePolicyDocument": {
                        "Statement": [],
                        "Version": "2012-10-17",
                    },
                    "CreateDate": "2026-08-20T00:00:00Z",
                    "Path": "/",
                    "RoleId": "AROA1234567890ABCDEG",
                    "RoleName": "writer",
                },
            ],
        },
    }


class FakeCartographyAPI:
    version = "0.139.1"

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def transform_role_trust_policies(
        self, roles: list[dict[str, object]], account_id: str
    ) -> object:
        self.calls.append(("roles", roles, account_id))
        return SimpleNamespace(
            role_data=[
                {
                    "arn": ROLE_ARN,
                    "name": "reader",
                    "trusted_aws_principals": [
                        "arn:aws:iam::999999999999:role/external",
                        PEER_ROLE_ARN,
                    ],
                },
                {
                    "arn": PEER_ROLE_ARN,
                    "name": "writer",
                    "trusted_aws_principals": [],
                },
            ],
            federated_principals=[],
            service_principals=[],
            external_aws_accounts=[{"id": "999999999999"}],
        )

    def transform_policy_data(
        self, policies: dict[str, object], policy_type: str
    ) -> object:
        self.calls.append(("policies", policies, policy_type))
        return SimpleNamespace(
            managed_policies=[
                {
                    "arn": POLICY_ARN,
                    "id": POLICY_ARN,
                    "name": "ReadOnlyAccess",
                    "principal_arns": [ROLE_ARN],
                    "type": "managed",
                }
            ],
            inline_policies=[],
            statements_by_policy_id={POLICY_ARN: []},
        )

    def __getattr__(self, name: str) -> object:
        if name in ("sync", "load", "cleanup", "neo4j", "socket"):
            raise AssertionError(f"forbidden Cartography path: {name}")
        raise AttributeError(name)


class CartographyTransformTests(unittest.TestCase):
    def test_accepts_a_complete_empty_iam_snapshot(self) -> None:
        request = request_document()
        request["source"] = {
            "account_id": ACCOUNT_ID,
            "managed_policies": {},
            "roles": [],
        }

        class EmptyAPI(FakeCartographyAPI):
            def transform_role_trust_policies(
                self, roles: list[dict[str, object]], account_id: str
            ) -> object:
                self.calls.append(("roles", roles, account_id))
                return SimpleNamespace(
                    role_data=[],
                    federated_principals=[],
                    service_principals=[],
                    external_aws_accounts=[],
                )

            def transform_policy_data(
                self, policies: dict[str, object], policy_type: str
            ) -> object:
                self.calls.append(("policies", policies, policy_type))
                return SimpleNamespace(
                    managed_policies=[],
                    inline_policies=[],
                    statements_by_policy_id={},
                )

        self.assertEqual(
            cartography_aws.transform(request, EmptyAPI()),
            {"policies": [], "roles": [], "version": "0.139.1"},
        )

    def test_transforms_exact_native_snapshot_without_external_graph_nodes(self) -> None:
        api = FakeCartographyAPI()

        result = cartography_aws.transform(request_document(), api)

        self.assertEqual(
            result,
            {
                "policies": [
                    {
                        "arn": POLICY_ARN,
                        "name": "ReadOnlyAccess",
                        "principal_arns": [ROLE_ARN],
                    }
                ],
                "roles": [
                    {
                        "arn": ROLE_ARN,
                        "name": "reader",
                        "trusted_role_arns": [PEER_ROLE_ARN],
                    },
                    {
                        "arn": PEER_ROLE_ARN,
                        "name": "writer",
                        "trusted_role_arns": [],
                    },
                ],
                "version": "0.139.1",
            },
        )
        self.assertEqual([call[0] for call in api.calls], ["roles", "policies"])

    def test_rejects_scope_duplicates_and_transform_drift(self) -> None:
        cases: dict[str, dict[str, object]] = {}
        wrong_account = request_document()
        wrong_account["source"] = {
            **wrong_account["source"],
            "account_id": "999999999999",
        }
        cases["wrong account"] = wrong_account
        duplicate = request_document()
        duplicate["source"] = {
            **duplicate["source"],
            "roles": [
                duplicate["source"]["roles"][0],
                duplicate["source"]["roles"][0],
            ],
        }
        cases["duplicate role"] = duplicate
        secret = request_document()
        secret["source"] = {**secret["source"], "secret_access_key": "secret"}
        cases["secret field"] = secret
        for name, request in cases.items():
            with self.subTest(name=name), self.assertRaises(
                cartography_aws.CollectionError
            ):
                cartography_aws.transform(request, FakeCartographyAPI())

        class DriftedAPI(FakeCartographyAPI):
            version = "0.140.0"

        with self.assertRaises(cartography_aws.CollectionError):
            cartography_aws.transform(request_document(), DriftedAPI())

    def test_rejects_result_beyond_item_relationship_or_byte_budget(self) -> None:
        for key in ("remaining_entities", "remaining_relationships", "remaining_bytes"):
            with self.subTest(key=key):
                request = request_document()
                request["authority"] = {**request["authority"], key: 0}
                with self.assertRaises(cartography_aws.CollectionError):
                    cartography_aws.transform(request, FakeCartographyAPI())


if __name__ == "__main__":
    unittest.main()
