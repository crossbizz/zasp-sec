from __future__ import annotations

import importlib
import importlib.metadata
import re
from dataclasses import dataclass
from typing import Callable

from . import protocol


EXPECTED_VERSION = "0.139.1"
_ROLE_ARN = re.compile(
    r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]{1,512})\Z"
)
_POLICY_ARN = re.compile(
    r"arn:aws:iam::(?:aws|[0-9]{12}):policy/[A-Za-z0-9+=,.@_/-]{1,512}\Z"
)
_ROLE_ID = re.compile(r"AROA[A-Z0-9]{16,32}\Z")
_ROLE_NAME = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}\Z")


class CollectionError(ValueError):
    def __init__(self, code: str = "malformed") -> None:
        super().__init__("collection unavailable")
        self.code = code if code in ("malformed", "retryable") else "malformed"


@dataclass(frozen=True)
class CartographyAPI:
    version: str
    transform_role_trust_policies: Callable[[list[dict[str, object]], str], object]
    transform_policy_data: Callable[[dict[str, object], str], object]


def load_runtime_api() -> CartographyAPI:
    try:
        version = importlib.metadata.version("cartography")
        module = importlib.import_module("cartography.intel.aws.iam")
        role_transform = getattr(module, "transform_role_trust_policies")
        policy_transform = getattr(module, "transform_policy_data")
        if (
            version != EXPECTED_VERSION
            or not callable(role_transform)
            or not callable(policy_transform)
        ):
            raise CollectionError("retryable")
        return CartographyAPI(version, role_transform, policy_transform)
    except Exception as exc:
        if isinstance(exc, CollectionError):
            raise
        raise CollectionError("retryable") from exc


def transform(request: dict[str, object], api: object | None = None) -> dict[str, object]:
    try:
        authority, source, roles, policies = _validate_request(request)
        selected_api = load_runtime_api() if api is None else api
        if getattr(selected_api, "version", None) != EXPECTED_VERSION:
            raise CollectionError("collection unavailable")
        transformed_roles = selected_api.transform_role_trust_policies(
            roles, authority["subject_id"]
        )
        transformed_policies = selected_api.transform_policy_data(policies, "managed")
        return _normalize_transforms(
            source, roles, policies, transformed_roles, transformed_policies
        )
    except CollectionError:
        raise
    except Exception as exc:
        raise CollectionError("collection unavailable") from exc


def _validate_request(
    request: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
    dict[str, object],
]:
    if type(request) is not dict or frozenset(request) != frozenset(
        ("authority", "source")
    ):
        raise CollectionError("collection unavailable")
    authority = request["authority"]
    source = request["source"]
    if (
        type(authority) is not dict
        or frozenset(authority) != frozenset(("phase", "source_digest", "subject_id"))
        or authority["phase"] != "iam"
        or type(authority["source_digest"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", authority["source_digest"]) is None
        or type(authority["subject_id"]) is not str
        or re.fullmatch(r"[0-9]{12}", authority["subject_id"]) is None
        or type(source) is not dict
        or frozenset(source)
        != frozenset(("account_id", "managed_policies", "roles"))
        or source["account_id"] != authority["subject_id"]
        or type(source["roles"]) is not list
        or len(source["roles"]) > 1_000
        or type(source["managed_policies"]) is not dict
    ):
        raise CollectionError("collection unavailable")
    protocol._bounded_json(source, 1)
    roles = source["roles"]
    seen_roles: set[str] = set()
    for role in roles:
        if type(role) is not dict or frozenset(role) != frozenset(
            (
                "Arn",
                "AssumeRolePolicyDocument",
                "CreateDate",
                "Path",
                "RoleId",
                "RoleName",
            )
        ):
            raise CollectionError("collection unavailable")
        match = _ROLE_ARN.fullmatch(role["Arn"]) if type(role["Arn"]) is str else None
        if (
            match is None
            or match[1] != authority["subject_id"]
            or role["Arn"] in seen_roles
            or type(role["AssumeRolePolicyDocument"]) is not dict
            or type(role["CreateDate"]) is not str
            or type(role["Path"]) is not str
            or not role["Path"].startswith("/")
            or type(role["RoleId"]) is not str
            or _ROLE_ID.fullmatch(role["RoleId"]) is None
        ):
            raise CollectionError("collection unavailable")
        if (
            type(role["RoleName"]) is not str
            or _ROLE_NAME.fullmatch(role["RoleName"]) is None
            or match[2].split("/")[-1] != role["RoleName"]
        ):
            raise CollectionError("collection unavailable")
        seen_roles.add(role["Arn"])
    policies = source["managed_policies"]
    for principal_arn, attached in policies.items():
        if principal_arn not in seen_roles or type(attached) is not dict:
            raise CollectionError("collection unavailable")
        for policy_arn, statements in attached.items():
            if (
                type(policy_arn) is not str
                or _POLICY_ARN.fullmatch(policy_arn) is None
                or type(statements) is not list
                or len(statements) > 1_000
            ):
                raise CollectionError("collection unavailable")
    return authority, source, roles, policies


def _normalize_transforms(
    source: dict[str, object],
    roles: list[dict[str, object]],
    policies: dict[str, object],
    transformed_roles: object,
    transformed_policies: object,
) -> dict[str, object]:
    role_arns = {role["Arn"] for role in roles}
    role_names = {role["Arn"]: role["RoleName"] for role in roles}
    raw_roles = getattr(transformed_roles, "role_data", None)
    if type(raw_roles) is not list or len(raw_roles) != len(role_arns):
        raise CollectionError("collection unavailable")
    normalized_roles: list[dict[str, object]] = []
    observed_roles: set[str] = set()
    for role in raw_roles:
        if (
            type(role) is not dict
            or type(role.get("arn")) is not str
            or role["arn"] not in role_arns
            or role["arn"] in observed_roles
            or type(role.get("name")) is not str
            or _ROLE_NAME.fullmatch(role["name"]) is None
            or role["name"] != role_names[role["arn"]]
            or type(role.get("trusted_aws_principals")) is not list
        ):
            raise CollectionError("collection unavailable")
        trusted = sorted(
            {
                value
                for value in role["trusted_aws_principals"]
                if type(value) is str and value in role_arns
            }
        )
        observed_roles.add(role["arn"])
        normalized_roles.append(
            {
                "arn": role["arn"],
                "name": role["name"],
                "trusted_role_arns": trusted,
            }
        )
    if observed_roles != role_arns:
        raise CollectionError("collection unavailable")

    expected_policies = {
        policy_arn
        for attached in policies.values()
        for policy_arn in attached
    }
    raw_policies = getattr(transformed_policies, "managed_policies", None)
    if type(raw_policies) is not list or len(raw_policies) != len(expected_policies):
        raise CollectionError("collection unavailable")
    normalized_policies: list[dict[str, object]] = []
    observed_policies: set[str] = set()
    for policy in raw_policies:
        if (
            type(policy) is not dict
            or type(policy.get("arn")) is not str
            or policy["arn"] not in expected_policies
            or policy["arn"] in observed_policies
            or type(policy.get("name")) is not str
            or _ROLE_NAME.fullmatch(policy["name"]) is None
            or policy["name"] != policy["arn"].split("/")[-1]
            or type(policy.get("principal_arns")) is not list
        ):
            raise CollectionError("collection unavailable")
        principals = sorted(policy["principal_arns"])
        expected_principals = sorted(
            principal
            for principal, attached in policies.items()
            if policy["arn"] in attached
        )
        if principals != expected_principals:
            raise CollectionError("collection unavailable")
        observed_policies.add(policy["arn"])
        normalized_policies.append(
            {
                "arn": policy["arn"],
                "name": policy["name"],
                "principal_arns": principals,
            }
        )
    if observed_policies != expected_policies:
        raise CollectionError("collection unavailable")
    normalized_roles.sort(key=lambda item: item["arn"])
    normalized_policies.sort(key=lambda item: item["arn"])
    return {
        "policies": normalized_policies,
        "roles": normalized_roles,
        "version": EXPECTED_VERSION,
    }
