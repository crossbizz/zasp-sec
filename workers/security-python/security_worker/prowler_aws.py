from __future__ import annotations

import base64
import importlib
import importlib.metadata
import json
import re
import sys
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace

from . import protocol


EXPECTED_VERSION = "5.39.1"
CHECKS = (
    "iam_role_administratoraccess_policy",
    "iam_role_cross_service_confused_deputy_prevention",
    "ec2_instance_imdsv2_enabled",
)
_CHECK_MODULES = {
    check_id: f"prowler.providers.aws.services.{service}.{check_id}.{check_id}"
    for service, check_id in (
        ("iam", CHECKS[0]),
        ("iam", CHECKS[1]),
        ("ec2", CHECKS[2]),
    )
}
_CLIENT_MODULES = {
    CHECKS[0]: "prowler.providers.aws.services.iam.iam_client",
    CHECKS[1]: "prowler.providers.aws.services.iam.iam_client",
    CHECKS[2]: "prowler.providers.aws.services.ec2.ec2_client",
}
_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_ROLE_ARN = re.compile(
    r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]{1,512})\Z"
)
_INSTANCE_ARN = re.compile(
    r"arn:aws:ec2:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):instance/(i-[0-9a-f]{17})\Z"
)
_ROLE_ID = re.compile(r"AROA[A-Z0-9]{16,32}\Z")
_ROLE_NAME = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}\Z")
_ACCESS_KEY = re.compile(r"(?:ASIA|AKIA)[A-Z0-9]{16}\Z")
_SECRET_KEY = re.compile(r"[A-Za-z0-9/+=]{40}\Z")
_SESSION_TOKEN = re.compile(r"[A-Za-z0-9/+=_-]{32,4096}\Z")


class CollectionError(ValueError):
    def __init__(self, code: str = "malformed") -> None:
        super().__init__("collection unavailable")
        self.code = (
            code
            if code in ("denied", "malformed", "rate_limited", "retryable")
            else "malformed"
        )


@dataclass
class Credential:
    access_key_id: bytearray
    secret_access_key: bytearray
    session_token: bytearray
    expires_at: str

    def clear(self) -> None:
        self.access_key_id.clear()
        self.secret_access_key.clear()
        self.session_token.clear()


@dataclass(frozen=True)
class RuntimeRole:
    id: str
    arn: str
    name: str
    region: str
    tags: tuple[object, ...]
    attached_policies: tuple[dict[str, str], ...]
    is_service_role: bool
    assume_role_policy: dict[str, object]


@dataclass(frozen=True)
class RuntimeInstance:
    id: str
    arn: str
    region: str
    state: str
    http_endpoint: str
    http_tokens: str
    tags: tuple[object, ...]


class RuntimeProwlerAPI:
    version = EXPECTED_VERSION

    def reattest(self, credential: Credential, account_id: str) -> None:
        try:
            boto3 = importlib.import_module("boto3")
            config_type = getattr(importlib.import_module("botocore.config"), "Config")
            session = boto3.session.Session(
                aws_access_key_id=bytes(credential.access_key_id).decode("ascii"),
                aws_secret_access_key=bytes(credential.secret_access_key).decode("ascii"),
                aws_session_token=bytes(credential.session_token).decode("ascii"),
                region_name="us-east-1",
            )
            sts = session.client(
                "sts",
                endpoint_url="https://sts.us-east-1.amazonaws.com",
                use_ssl=True,
                verify=True,
                config=config_type(
                    connect_timeout=5,
                    read_timeout=5,
                    retries={"max_attempts": 1, "mode": "standard"},
                ),
            )
            identity = sts.get_caller_identity()
            if type(identity) is not dict or identity.get("Account") != account_id:
                raise CollectionError("denied")
        except CollectionError:
            raise
        except Exception as exc:
            response = getattr(exc, "response", None)
            error = response.get("Error", {}) if type(response) is dict else {}
            error_code = error.get("Code", "") if type(error) is dict else ""
            if error_code in (
                "AccessDenied",
                "AccessDeniedException",
                "ExpiredToken",
                "InvalidClientTokenId",
                "SignatureDoesNotMatch",
            ):
                raise CollectionError("denied") from exc
            if error_code in (
                "RequestLimitExceeded",
                "SlowDown",
                "ThrottledException",
                "Throttling",
                "ThrottlingException",
                "TooManyRequestsException",
            ):
                raise CollectionError("rate_limited") from exc
            raise CollectionError("retryable") from exc

    def execute(
        self, check_id: str, source: dict[str, object]
    ) -> list[dict[str, object]]:
        if check_id not in CHECKS:
            raise CollectionError()
        client_module = _CLIENT_MODULES[check_id]
        guarded = ModuleType(client_module)
        if check_id.startswith("iam_"):
            roles = tuple(
                RuntimeRole(
                    id=role["RoleId"],
                    arn=role["Arn"],
                    name=role["RoleName"],
                    region="global",
                    tags=(),
                    attached_policies=tuple(role["AttachedPolicies"]),
                    is_service_role=role["IsServiceRole"],
                    assume_role_policy=role["AssumeRolePolicyDocument"],
                )
                for role in source["roles"]
            )
            guarded.iam_client = SimpleNamespace(
                audited_account=source["account_id"], region="global", roles=roles
            )
        else:
            instances = tuple(
                RuntimeInstance(
                    id=instance["InstanceId"],
                    arn=instance["Arn"],
                    region=instance["Region"],
                    state=instance["State"],
                    http_endpoint=instance["HttpEndpoint"],
                    http_tokens=instance["HttpTokens"],
                    tags=(),
                )
                for instance in source["instances"]
            )
            guarded.ec2_client = SimpleNamespace(instances=instances)
        module_name = _CHECK_MODULES[check_id]
        previous_client = sys.modules.get(client_module)
        previous_check = sys.modules.pop(module_name, None)
        sys.modules[client_module] = guarded
        try:
            module = importlib.import_module(module_name)
            check_type = getattr(module, check_id)
            reports = check_type().execute()
            if type(reports) is not list:
                raise CollectionError()
            return [
                {
                    "region": report.region,
                    "resource_arn": report.resource_arn,
                    "resource_id": report.resource_id,
                    "status": report.status,
                }
                for report in reports
            ]
        finally:
            sys.modules.pop(module_name, None)
            if previous_check is not None:
                sys.modules[module_name] = previous_check
            if previous_client is None:
                sys.modules.pop(client_module, None)
            else:
                sys.modules[client_module] = previous_client


def load_runtime_api() -> RuntimeProwlerAPI:
    try:
        if importlib.metadata.version("prowler") != EXPECTED_VERSION:
            raise CollectionError("collection unavailable")
        return RuntimeProwlerAPI()
    except Exception as exc:
        raise CollectionError("retryable") from exc


def scan(request: dict[str, object], api: object | None = None) -> dict[str, object]:
    credential: Credential | None = None
    try:
        authority, source = _validate_request(request)
        credential = _decode_credential(
            request["credential"], authority["credential_expires_at"]
        )
        selected_api = load_runtime_api() if api is None else api
        if getattr(selected_api, "version", None) != EXPECTED_VERSION:
            raise CollectionError("retryable")
        selected_api.reattest(credential, authority["subject_id"])
        findings: list[dict[str, object]] = []
        observed: set[tuple[str, str]] = set()
        for check_id in CHECKS:
            reports = selected_api.execute(check_id, source)
            if type(reports) is not list:
                raise CollectionError("collection unavailable")
            for report in reports:
                finding = _finding(check_id, report, source)
                identity = (check_id, finding["resource_arn"])
                if identity in observed:
                    raise CollectionError()
                observed.add(identity)
                findings.append(finding)
        findings.sort(key=lambda item: (item["check_id"], item["resource_arn"]))
        result = {"findings": findings, "version": EXPECTED_VERSION}
        if (
            len(findings) > authority["remaining_entities"]
            or len(protocol._canonical(result)) > authority["remaining_bytes"]
        ):
            raise CollectionError("collection unavailable")
        return result
    except CollectionError:
        raise
    except Exception as exc:
        raise CollectionError() from exc
    finally:
        if credential is not None:
            credential.clear()


def _validate_request(
    request: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    if type(request) is not dict or frozenset(request) != frozenset(
        ("authority", "credential", "source")
    ):
        raise CollectionError("collection unavailable")
    authority = request["authority"]
    source = request["source"]
    if (
        type(authority) is not dict
        or frozenset(authority)
        != frozenset(
            (
                "credential_expires_at",
                "phase",
                "remaining_bytes",
                "remaining_entities",
                "remaining_relationships",
                "source_digest",
                "subject_id",
            )
        )
        or authority["phase"] != "posture"
        or type(authority["source_digest"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", authority["source_digest"]) is None
        or type(authority["subject_id"]) is not str
        or _ACCOUNT_ID.fullmatch(authority["subject_id"]) is None
        or type(authority["credential_expires_at"]) is not str
        or type(request["credential"]) is not str
        or type(authority["remaining_bytes"]) is not int
        or not 0 <= authority["remaining_bytes"] <= 64 * 1024 * 1024
        or type(authority["remaining_entities"]) is not int
        or not 0 <= authority["remaining_entities"] <= 1_000
        or type(authority["remaining_relationships"]) is not int
        or not 0 <= authority["remaining_relationships"] <= 2_000
        or type(source) is not dict
        or frozenset(source) != frozenset(("account_id", "instances", "roles"))
        or source["account_id"] != authority["subject_id"]
        or type(source["roles"]) is not list
        or type(source["instances"]) is not list
        or len(source["roles"]) > 1_000
        or len(source["instances"]) > 1_000
    ):
        raise CollectionError("collection unavailable")
    protocol._bounded_json(source, 1)
    _validate_roles(source["roles"], authority["subject_id"])
    _validate_instances(source["instances"], authority["subject_id"])
    return authority, source


def _validate_roles(roles: list[dict[str, object]], account_id: str) -> None:
    observed: set[str] = set()
    for role in roles:
        if type(role) is not dict or frozenset(role) != frozenset(
            (
                "Arn",
                "AssumeRolePolicyDocument",
                "AttachedPolicies",
                "IsServiceRole",
                "RoleId",
                "RoleName",
            )
        ):
            raise CollectionError("collection unavailable")
        match = _ROLE_ARN.fullmatch(role["Arn"]) if type(role["Arn"]) is str else None
        if (
            match is None
            or match[1] != account_id
            or role["Arn"] in observed
            or type(role["RoleId"]) is not str
            or _ROLE_ID.fullmatch(role["RoleId"]) is None
            or type(role["RoleName"]) is not str
            or _ROLE_NAME.fullmatch(role["RoleName"]) is None
            or match[2].split("/")[-1] != role["RoleName"]
            or type(role["IsServiceRole"]) is not bool
            or type(role["AssumeRolePolicyDocument"]) is not dict
            or type(role["AttachedPolicies"]) is not list
            or len(role["AttachedPolicies"]) > 1_000
        ):
            raise CollectionError("collection unavailable")
        policy_names: set[str] = set()
        for policy in role["AttachedPolicies"]:
            if (
                type(policy) is not dict
                or frozenset(policy) != frozenset(("PolicyName",))
                or type(policy["PolicyName"]) is not str
                or _ROLE_NAME.fullmatch(policy["PolicyName"]) is None
                or policy["PolicyName"] in policy_names
            ):
                raise CollectionError("collection unavailable")
            policy_names.add(policy["PolicyName"])
        observed.add(role["Arn"])


def _validate_instances(instances: list[dict[str, object]], account_id: str) -> None:
    observed: set[str] = set()
    for instance in instances:
        if type(instance) is not dict or frozenset(instance) != frozenset(
            ("Arn", "HttpEndpoint", "HttpTokens", "InstanceId", "Region", "State")
        ):
            raise CollectionError("collection unavailable")
        match = (
            _INSTANCE_ARN.fullmatch(instance["Arn"])
            if type(instance["Arn"]) is str
            else None
        )
        if (
            match is None
            or match[2] != account_id
            or match[3] != instance["InstanceId"]
            or match[1] != instance["Region"]
            or instance["Arn"] in observed
            or instance["HttpEndpoint"] not in ("enabled", "disabled")
            or instance["HttpTokens"] not in ("optional", "required")
            or instance["State"]
            not in ("pending", "running", "shutting-down", "terminated", "stopping", "stopped")
        ):
            raise CollectionError("collection unavailable")
        observed.add(instance["Arn"])


def _decode_credential(value: str, expected_expiry: str) -> Credential:
    raw = bytearray()
    try:
        raw.extend(
            base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
            )
        )
        if len(raw) > protocol.MAX_STRING_BYTES:
            raise CollectionError("collection unavailable")
        document = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            type(document) is not dict
            or frozenset(document)
            != frozenset(
                ("access_key_id", "expires_at", "secret_access_key", "session_token")
            )
            or json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
            != bytes(raw)
            or type(document["access_key_id"]) is not str
            or _ACCESS_KEY.fullmatch(document["access_key_id"]) is None
            or type(document["secret_access_key"]) is not str
            or _SECRET_KEY.fullmatch(document["secret_access_key"]) is None
            or type(document["session_token"]) is not str
            or _SESSION_TOKEN.fullmatch(document["session_token"]) is None
            or document["expires_at"] != expected_expiry
        ):
            raise CollectionError("collection unavailable")
        return Credential(
            bytearray(document["access_key_id"], "ascii"),
            bytearray(document["secret_access_key"], "ascii"),
            bytearray(document["session_token"], "ascii"),
            document["expires_at"],
        )
    except CollectionError:
        raise
    except Exception as exc:
        raise CollectionError("collection unavailable") from exc
    finally:
        raw.clear()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("collection unavailable")
        result[key] = value
    return result


def _finding(
    check_id: str, report: object, source: dict[str, object]
) -> dict[str, object]:
    if type(report) is not dict or frozenset(report) != frozenset(
        ("region", "resource_arn", "resource_id", "status")
    ):
        raise CollectionError("collection unavailable")
    resource_arn = report["resource_arn"]
    if check_id.startswith("iam_"):
        resources = {
            role["Arn"]: (role["RoleName"], "global")
            for role in source["roles"]
            if (
                check_id == CHECKS[0]
                and not role["IsServiceRole"]
                or check_id == CHECKS[1]
                and role["IsServiceRole"]
                and "/aws-service-role/" not in role["Arn"]
            )
        }
    else:
        resources = {
            instance["Arn"]: (instance["InstanceId"], instance["Region"])
            for instance in source["instances"]
            if instance["State"] != "terminated"
        }
    if (
        type(resource_arn) is not str
        or resource_arn not in resources
        or report["resource_id"] != resources[resource_arn][0]
        or report["region"] != resources[resource_arn][1]
        or report["status"] not in ("PASS", "FAIL")
    ):
        raise CollectionError("collection unavailable")
    return {
        "check_id": check_id,
        "resource_arn": resource_arn,
        "resource_id": report["resource_id"],
        "region": report["region"],
        "severity": "high",
        "status": report["status"],
    }
