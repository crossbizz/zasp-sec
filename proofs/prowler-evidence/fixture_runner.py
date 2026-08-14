from __future__ import annotations

import contextlib
import hashlib
import importlib
import importlib.metadata
import inspect
import io
import json
import logging
import os
import platform
import re
import signal
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from types import ModuleType, SimpleNamespace
from typing import Callable, Mapping, TextIO


MAX_FIXTURE_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_CAPTURE_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_STRING_BYTES = 16 * 1024
MAX_COLLECTION_SIZE = 32
OPERATION_TIMEOUT_SECONDS = 30.0
FIXTURE_PATH = "/proof/fixture.json"
OUTPUT_PATH = "/proof/output/prowler.ocsf.json"
SUCCESS_LINE = "Prowler fixture bridge produced one FAIL finding.\n"
FAILURE_LINE = "Prowler fixture bridge failed.\n"
EXPECTED_PROWLER_VERSION = "5.39.0"
EXPECTED_OCSF_MODELS_VERSION = "0.10.0"
EXPECTED_PYTHON_VERSION = "3.12.13"
EXPECTED_INTERPRETER = "/home/prowler/.venv/bin/python"
FIXED_OBSERVATION = datetime(2026, 8, 14, 0, 0, 0, tzinfo=timezone.utc)
BASE_ENVIRONMENT = {
    "PATH": "/home/prowler/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "GPG_KEY": "7169605F62C75135" + "6D054A26A821E680E5FA6305",
    "PYTHON_VERSION": "3.12.13",
    "PYTHON_SHA256": "c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
    "POWERSHELL_VERSION": "7.5.9",
    "POWERSHELL_TELEMETRY_OPTOUT": "1",
    "TRIVY_VERSION": "0.72.0",
    "ZIZMOR_VERSION": "1.24.1",
    "HOME": "/tmp",
    "PYTHONUNBUFFERED": "1",
}

_ACCOUNT_ID = "000000000000"
_REGION = "us-east-1"
_PARTITION = "aws"
_ROLE_NAME = "shared-fixture-role"
_ROLE_ARN = "arn:aws:iam::000000000000:role/shared-fixture-role"
_CHECK_ID = "iam_role_cross_service_confused_deputy_prevention"
_CHECK_MODULE = (
    "prowler.providers.aws.services.iam."
    "iam_role_cross_service_confused_deputy_prevention."
    "iam_role_cross_service_confused_deputy_prevention"
)
_IAM_CLIENT_MODULE = "prowler.providers.aws.services.iam.iam_client"
_CHECK_SOURCE = (
    "/home/prowler/prowler/providers/aws/services/iam/"
    "iam_role_cross_service_confused_deputy_prevention/"
    "iam_role_cross_service_confused_deputy_prevention.py"
)
_OCSF_SOURCE = "/home/prowler/prowler/lib/outputs/ocsf/ocsf.py"
_PROWLER_SOURCE_ROOT = "/home/prowler/prowler"
_OCSF_MODELS_SOURCE_ROOT = "/home/prowler/.venv/lib/python3.12/site-packages/py_ocsf_models"
_HOSTNAME_PATTERN = re.compile(r"zasp-m0-11-[0-9a-f]{16}-prowler\Z")
_UUID7_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)

_ROOT_KEYS = (
    "message",
    "metadata",
    "severity_id",
    "severity",
    "status",
    "status_code",
    "status_detail",
    "status_id",
    "unmapped",
    "activity_name",
    "activity_id",
    "finding_info",
    "resources",
    "category_name",
    "category_uid",
    "class_name",
    "class_uid",
    "cloud",
    "time",
    "time_dt",
    "remediation",
    "risk_details",
    "type_uid",
    "type_name",
)


@dataclass(frozen=True)
class Fixture:
    account_id: str
    region: str
    partition: str
    role: dict[str, object]


@dataclass
class RuntimeAPI:
    version: str
    role_type: type
    client: object
    check_type: type
    report_type: type
    finding_type: type
    ocsf_type: type
    detection_type: type
    set_output_timestamp: Callable[[datetime], object]


@dataclass(frozen=True)
class RuntimeIdentity:
    executable: str
    python_version: str
    distribution_version: str
    ocsf_distribution_version: str
    config_version: str
    check_source: str
    ocsf_source: str


@dataclass(frozen=True)
class SymbolRule:
    label: str
    module: str
    export: str
    source: str
    source_root: str
    sha256: str


SYMBOL_RULES = (
    SymbolRule(
        "Role",
        "prowler.providers.aws.services.iam.iam_service",
        "Role",
        "/home/prowler/prowler/providers/aws/services/iam/iam_service.py",
        _PROWLER_SOURCE_ROOT,
        "d5e87ac4e0e3f17df5ebb5e610451b2a538fe00b6ca4f19c19ebd87fe2eb849d",
    ),
    SymbolRule(
        "Check_Report_AWS",
        "prowler.lib.check.models",
        "Check_Report_AWS",
        "/home/prowler/prowler/lib/check/models.py",
        _PROWLER_SOURCE_ROOT,
        "422db283f9b16025c584593bb74c9bef2cc6c3570385ec15334184f2985c2e9d",
    ),
    SymbolRule(
        "Finding",
        "prowler.lib.outputs.finding",
        "Finding",
        "/home/prowler/prowler/lib/outputs/finding.py",
        _PROWLER_SOURCE_ROOT,
        "00ed79bee5e32239d3cce4943c70df33dbfe3f85056deb750ad11f2073613cce",
    ),
    SymbolRule(
        "OCSF",
        "prowler.lib.outputs.ocsf.ocsf",
        "OCSF",
        _OCSF_SOURCE,
        _PROWLER_SOURCE_ROOT,
        "e6f1136285057bd2d9635b0e190e86dfec61ba1a4ebbf7cdfd2139032dac5379",
    ),
    SymbolRule(
        "DetectionFinding",
        "py_ocsf_models.events.findings.detection_finding",
        "DetectionFinding",
        _OCSF_MODELS_SOURCE_ROOT + "/events/findings/detection_finding.py",
        _OCSF_MODELS_SOURCE_ROOT,
        "72a26d986f71b5e533e7e530531a466f3db8738cfda0db0ae21a84aeb4d25fd4",
    ),
    SymbolRule(
        "is_policy_public",
        "prowler.providers.aws.services.iam.lib.policy",
        "is_policy_public",
        "/home/prowler/prowler/providers/aws/services/iam/lib/policy.py",
        _PROWLER_SOURCE_ROOT,
        "30929177646fcf5c08908fe847d6223272edd28d5db69c61e88eb18a66ee028b",
    ),
    SymbolRule(
        _CHECK_ID,
        _CHECK_MODULE,
        _CHECK_ID,
        _CHECK_SOURCE,
        _PROWLER_SOURCE_ROOT,
        "d9b106165878e8221d7faee82b908dd13bcbdf317d5180012fa27d63bfce7187",
    ),
)


class _GuardedIamClient:
    __slots__ = ("roles", "region", "audited_account")

    def __init__(self) -> None:
        self.roles: list[object] = []
        self.region = _REGION
        self.audited_account = _ACCOUNT_ID


def parse_fixture(raw: bytes) -> Fixture:
    value = _parse_bounded_json(raw, MAX_FIXTURE_BYTES)
    root = _expect_object(
        value,
        ("schema_version", "account_id", "region", "partition", "role"),
        "fixture",
    )
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != 1
        or root["account_id"] != _ACCOUNT_ID
        or root["region"] != _REGION
        or root["partition"] != _PARTITION
    ):
        raise ValueError("invalid fixture")

    role = _expect_object(
        root["role"],
        (
            "name",
            "arn",
            "assume_role_policy",
            "is_service_role",
            "attached_policies",
            "inline_policies",
            "permissions_boundary",
            "tags",
        ),
        "role",
    )
    policy = _expect_object(
        role["assume_role_policy"], ("Version", "Statement"), "trust policy"
    )
    statements = _expect_list(policy["Statement"], 1, "trust statements")
    statement = _expect_object(
        statements[0], ("Effect", "Principal", "Action"), "trust statement"
    )
    principal = _expect_object(statement["Principal"], ("Service",), "principal")
    for key in ("attached_policies", "inline_policies", "tags"):
        _expect_list(role[key], 0, key)
    if (
        role["name"] != _ROLE_NAME
        or role["arn"] != _ROLE_ARN
        or role["is_service_role"] is not True
        or role["permissions_boundary"] is not None
        or policy["Version"] != "2012-10-17"
        or statement["Effect"] != "Allow"
        or statement["Action"] != "sts:AssumeRole"
        or principal["Service"] != "lambda.amazonaws.com"
    ):
        raise ValueError("invalid fixture")
    return Fixture(_ACCOUNT_ID, _REGION, _PARTITION, role)


def parse_official_artifact(raw: bytes) -> list[dict[str, object]]:
    value = _parse_bounded_json(raw, MAX_ARTIFACT_BYTES)
    findings = _expect_list(value, 1, "OCSF findings")
    finding = _expect_object(findings[0], _ROOT_KEYS, "OCSF finding")

    metadata = _expect_object(
        finding["metadata"],
        ("event_code", "product", "version", "profiles", "tenant_uid"),
        "metadata",
    )
    product = _expect_object(
        metadata["product"], ("name", "uid", "vendor_name", "version"), "product"
    )
    if (
        metadata["event_code"] != _CHECK_ID
        or metadata["version"] != "1.5.0"
        or metadata["profiles"] != ["cloud", "datetime"]
        or metadata["tenant_uid"] != ""
        or product
        != {
            "name": "Prowler",
            "uid": "prowler",
            "vendor_name": "Prowler",
            "version": EXPECTED_PROWLER_VERSION,
        }
    ):
        raise ValueError("invalid OCSF metadata")
    if (
        type(finding["status_id"]) is not int
        or type(finding["activity_id"]) is not int
        or finding["severity_id"] != 4
        or finding["severity"] != "High"
        or finding["status"] != "New"
        or finding["status_code"] != "FAIL"
        or finding["status_id"] != 1
        or finding["activity_name"] != "Create"
        or finding["activity_id"] != 1
        or finding["category_name"] != "Findings"
        or finding["category_uid"] != 2
        or finding["class_name"] != "Detection Finding"
        or finding["class_uid"] != 2004
        or finding["type_uid"] != 200401
        or finding["type_name"] != "Detection Finding: Create"
    ):
        raise ValueError("invalid OCSF classification")

    info = _expect_object(
        finding["finding_info"],
        (
            "analytic",
            "created_time",
            "created_time_dt",
            "desc",
            "title",
            "uid",
            "types",
        ),
        "finding info",
    )
    analytic = _expect_object(
        info["analytic"], ("name", "uid", "type_id", "type", "category"), "analytic"
    )
    if (
        analytic["uid"] != _CHECK_ID
        or type(analytic["type_id"]) is not int
        or analytic["type_id"] != 1
        or analytic["type"] != "Rule"
        or analytic["category"] != "iam"
        or info["types"]
        != [
            "Software and Configuration Checks/AWS Security Best Practices",
            "TTPs/Privilege Escalation",
        ]
    ):
        raise ValueError("invalid OCSF finding info")
    _validate_timestamp_pair(info["created_time"], info["created_time_dt"])

    resources = _expect_list(finding["resources"], 1, "resources")
    resource = _expect_object(
        resources[0],
        ("cloud_partition", "region", "data", "group", "labels", "name", "type", "uid"),
        "resource",
    )
    data = _expect_object(resource["data"], ("details", "metadata"), "resource data")
    group = _expect_object(resource["group"], ("name",), "resource group")
    fixture_role = parse_fixture(
        json.dumps(
            {
                "schema_version": 1,
                "account_id": _ACCOUNT_ID,
                "region": _REGION,
                "partition": _PARTITION,
                "role": data["metadata"],
            },
            separators=(",", ":"),
        ).encode("utf-8")
    ).role
    if (
        resource["cloud_partition"] != _PARTITION
        or resource["region"] != _REGION
        or resource["name"] != _ROLE_NAME
        or resource["uid"] != _ROLE_ARN
        or resource["type"] != "AwsIamRole"
        or resource["labels"] != []
        or group["name"] != "iam"
        or data["details"] != ""
        or fixture_role != data["metadata"]
    ):
        raise ValueError("invalid OCSF resource")

    cloud = _expect_object(finding["cloud"], ("account", "org", "provider", "region"), "cloud")
    account = _expect_object(
        cloud["account"], ("name", "type", "type_id", "uid", "labels"), "account"
    )
    organization = _expect_object(cloud["org"], ("name", "uid"), "organization")
    if (
        cloud["provider"] != "aws"
        or cloud["region"] != _REGION
        or account
        != {
            "name": "",
            "type": "AWS Account",
            "type_id": 10,
            "uid": _ACCOUNT_ID,
            "labels": [],
        }
        or organization != {"name": "", "uid": ""}
    ):
        raise ValueError("invalid OCSF cloud")

    unmapped = _expect_object(
        finding["unmapped"],
        (
            "related_url",
            "categories",
            "depends_on",
            "related_to",
            "additional_urls",
            "notes",
            "compliance",
            "scan_id",
            "provider_uid",
            "provider",
        ),
        "unmapped",
    )
    if (
        unmapped["provider"] != "aws"
        or unmapped["provider_uid"] != _ACCOUNT_ID
        or type(unmapped["scan_id"]) is not str
        or _UUID7_PATTERN.fullmatch(unmapped["scan_id"]) is None
    ):
        raise ValueError("invalid OCSF provider")
    _expect_object(unmapped["compliance"], (), "compliance")
    for key in ("categories", "depends_on", "related_to", "additional_urls"):
        _expect_string_list(unmapped[key], key)
    remediation = _expect_object(
        finding["remediation"], ("desc", "references"), "remediation"
    )
    _expect_string_list(remediation["references"], "remediation references")
    for key in ("message", "status_detail", "risk_details", "time_dt"):
        _expect_string(finding[key], key)
    for value_to_check in (
        info["desc"],
        info["title"],
        info["uid"],
        analytic["name"],
        remediation["desc"],
        unmapped["related_url"],
        unmapped["notes"],
    ):
        _expect_string(value_to_check, "OCSF text")
    _validate_timestamp_pair(finding["time"], finding["time_dt"])
    return findings


def validate_runtime_identity(identity: RuntimeIdentity) -> None:
    if (
        identity.executable != EXPECTED_INTERPRETER
        or identity.python_version != EXPECTED_PYTHON_VERSION
        or identity.distribution_version != EXPECTED_PROWLER_VERSION
        or identity.ocsf_distribution_version != EXPECTED_OCSF_MODELS_VERSION
        or identity.config_version != EXPECTED_PROWLER_VERSION
        or identity.check_source != _CHECK_SOURCE
        or identity.ocsf_source != _OCSF_SOURCE
    ):
        raise ValueError("invalid Prowler runtime")


def validate_symbol_binding(
    value: object,
    rule: SymbolRule,
    *,
    modules: Mapping[str, object] | None = None,
    source_file: Callable[[object], str | None] | None = None,
    realpath: Callable[[str], str] | None = None,
    lstat: Callable[[str], os.stat_result] | None = None,
    source_digest: Callable[[str], str] | None = None,
) -> None:
    modules = sys.modules if modules is None else modules
    source_file = inspect.getsourcefile if source_file is None else source_file
    realpath = os.path.realpath if realpath is None else realpath
    lstat = os.lstat if lstat is None else lstat
    source_digest = _source_digest if source_digest is None else source_digest

    module = modules.get(rule.module)
    source = source_file(value)
    if (
        type(rule.module) is not str
        or type(rule.export) is not str
        or type(source) is not str
        or getattr(value, "__module__", None) != rule.module
        or module is None
        or getattr(module, rule.export, None) is not value
        or source != rule.source
        or realpath(source) != rule.source
        or os.path.commonpath((rule.source_root, rule.source)) != rule.source_root
    ):
        raise ValueError(f"invalid {rule.label} runtime binding")
    metadata = lstat(source)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"invalid {rule.label} runtime source")
    if source_digest(source) != rule.sha256:
        raise ValueError(f"invalid {rule.label} runtime source")


def execute_fixture(fixture: Fixture, runtime: RuntimeAPI) -> bytes:
    if type(runtime.version) is not str or runtime.version != EXPECTED_PROWLER_VERSION:
        raise ValueError("invalid Prowler version")
    role = runtime.role_type(**fixture.role)
    runtime.client.roles = [role]
    runtime.client.region = fixture.region
    runtime.client.audited_account = fixture.account_id
    runtime.set_output_timestamp(FIXED_OBSERVATION)

    reports = runtime.check_type().execute()
    if type(reports) is not list or len(reports) != 1:
        raise ValueError("invalid check result cardinality")
    report = reports[0]
    if not isinstance(report, runtime.report_type):
        raise TypeError("invalid check report type")
    if (
        report.status != "FAIL"
        or report.check_metadata.CheckID != _CHECK_ID
        or report.check_metadata.Severity != "high"
        or report.resource_id != _ROLE_NAME
        or report.resource_arn != _ROLE_ARN
        or report.region != _REGION
    ):
        raise ValueError("invalid check result")
    report.compliance = {}

    provider = _fixture_provider()
    options = SimpleNamespace(unix_timestamp=False, bulk_checks_metadata={})
    finding = runtime.finding_type.generate_output(provider, report, options)
    if finding.status != "FAIL" or finding.prowler_version != EXPECTED_PROWLER_VERSION:
        raise ValueError("invalid official finding")
    output = runtime.ocsf_type([finding])
    if type(output.data) is not list or len(output.data) != 1:
        raise ValueError("invalid OCSF cardinality")
    detection = output.data[0]
    if not isinstance(detection, runtime.detection_type):
        raise TypeError("invalid OCSF model")
    serialized = detection.model_dump_json(exclude_none=True)
    if type(serialized) is not str:
        raise TypeError("invalid OCSF serialization")
    artifact = ("[" + serialized + "]").encode("utf-8", errors="strict")
    parse_official_artifact(artifact)
    return artifact


def validate_boundary(argv: list[str], environ: Mapping[str, str]) -> None:
    if (
        type(argv) is not list
        or argv
        != [
            "/proof/fixture_runner.py",
            "--fixture",
            FIXTURE_PATH,
            "--output",
            OUTPUT_PATH,
        ]
    ):
        raise ValueError("invalid arguments")
    hostname = environ.get("HOSTNAME")
    if type(hostname) is not str or _HOSTNAME_PATTERN.fullmatch(hostname) is None:
        raise ValueError("invalid hostname")
    if dict(environ) != {**BASE_ENVIRONMENT, "HOSTNAME": hostname}:
        raise ValueError("invalid environment")


class _CaptureBudget:
    __slots__ = ("maximum", "used", "overflowed")

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.used = 0
        self.overflowed = False

    def consume(self, size: int) -> None:
        if type(size) is not int or size < 0:
            raise TypeError("invalid capture size")
        if self.used + size > self.maximum:
            self.overflowed = True
            raise OverflowError("captured process output exceeded limit")
        self.used += size


class _BoundedBinarySink(io.RawIOBase):
    __slots__ = ("_budget",)

    def __init__(self, budget: _CaptureBudget) -> None:
        self._budget = budget

    def writable(self) -> bool:
        return True

    def write(self, value: bytes | bytearray) -> int:
        if type(value) not in (bytes, bytearray):
            raise TypeError("captured binary output must be bytes")
        self._budget.consume(len(value))
        return len(value)


class _BoundedTextSink(io.TextIOBase):
    __slots__ = ("_budget", "_binary")

    def __init__(self, budget: _CaptureBudget) -> None:
        self._budget = budget
        self._binary = _BoundedBinarySink(budget)

    @property
    def buffer(self) -> _BoundedBinarySink:
        return self._binary

    @property
    def encoding(self) -> str:
        return "utf-8"

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def write(self, value: str) -> int:
        if type(value) is not str:
            raise TypeError("captured text output must be a string")
        self._budget.consume(len(value.encode("utf-8", errors="strict")))
        return len(value)

    def flush(self) -> None:
        return None


def _stream_handlers() -> tuple[logging.StreamHandler, ...]:
    handlers: list[logging.StreamHandler] = []
    seen: set[int] = set()
    loggers: list[logging.Logger] = [logging.getLogger()]
    loggers.extend(
        value
        for value in logging.Logger.manager.loggerDict.values()
        if isinstance(value, logging.Logger)
    )
    for logger in loggers:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and id(handler) not in seen:
                handlers.append(handler)
                seen.add(id(handler))
    return tuple(handlers)


@contextlib.contextmanager
def _capture_logger_output(
    original_stdout: TextIO,
    original_stderr: TextIO,
    captured_stdout: _BoundedTextSink,
    captured_stderr: _BoundedTextSink,
):
    starting_handlers = _stream_handlers()
    for handler in starting_handlers:
        if handler.stream is original_stdout:
            handler.stream = captured_stdout
        elif handler.stream is original_stderr:
            handler.stream = captured_stderr
    try:
        yield
    finally:
        handlers = {id(handler): handler for handler in starting_handlers}
        handlers.update({id(handler): handler for handler in _stream_handlers()})
        for handler in handlers.values():
            if handler.stream is captured_stdout:
                handler.stream = original_stdout
            elif handler.stream is captured_stderr:
                handler.stream = original_stderr


@contextlib.contextmanager
def _capture_process_output(maximum: int):
    if type(maximum) is not int or maximum <= 0:
        raise ValueError("invalid capture limit")
    budget = _CaptureBudget(maximum)
    captured_stdout = _BoundedTextSink(budget)
    captured_stderr = _BoundedTextSink(budget)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    try:
        with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(
            captured_stderr
        ), _capture_logger_output(
            original_stdout,
            original_stderr,
            captured_stdout,
            captured_stderr,
        ):
            yield
    finally:
        if budget.overflowed and sys.exc_info()[0] is None:
            raise OverflowError("captured process output exceeded limit")


def run_main(argv: list[str], environ: Mapping[str, str], stdout: TextIO) -> int:
    try:
        validate_boundary(argv, environ)
        with _absolute_deadline(OPERATION_TIMEOUT_SECONDS):
            with _capture_process_output(MAX_CAPTURE_BYTES):
                fixture = parse_fixture(_read_fixture(FIXTURE_PATH))
                artifact = execute_fixture(fixture, _load_runtime())
                _write_artifact(artifact)
    except BaseException:
        _remove_output()
        try:
            _write_exact(stdout, FAILURE_LINE)
        except BaseException:
            pass
        return 1
    try:
        _write_exact(stdout, SUCCESS_LINE)
    except BaseException:
        _remove_output()
        return 1
    return 3


def _load_runtime() -> RuntimeAPI:
    from prowler.config import config
    from prowler.lib.check.models import Check_Report_AWS
    from prowler.lib.outputs.finding import Finding
    from prowler.lib.outputs.ocsf import ocsf as ocsf_module
    from prowler.lib.outputs.ocsf.ocsf import OCSF
    from prowler.providers.aws.services.iam.lib.policy import is_policy_public
    from prowler.providers.aws.services.iam.iam_service import Role
    from py_ocsf_models.events.findings.detection_finding import DetectionFinding

    client = _GuardedIamClient()
    stub = ModuleType(_IAM_CLIENT_MODULE)
    stub.iam_client = client
    if _CHECK_MODULE in sys.modules or _IAM_CLIENT_MODULE in sys.modules:
        raise ValueError("Prowler runtime was preloaded")
    sys.modules[_IAM_CLIENT_MODULE] = stub
    check_module = importlib.import_module(_CHECK_MODULE)

    identity = RuntimeIdentity(
        executable=sys.executable,
        python_version=platform.python_version(),
        distribution_version=importlib.metadata.version("prowler"),
        ocsf_distribution_version=importlib.metadata.version("py-ocsf-models"),
        config_version=config.prowler_version,
        check_source=os.path.realpath(check_module.__file__),
        ocsf_source=os.path.realpath(ocsf_module.__file__),
    )
    validate_runtime_identity(identity)
    check_type = getattr(check_module, _CHECK_ID)
    critical_symbols = (
        Role,
        Check_Report_AWS,
        Finding,
        OCSF,
        DetectionFinding,
        is_policy_public,
        check_type,
    )
    for value, rule in zip(critical_symbols, SYMBOL_RULES, strict=True):
        validate_symbol_binding(value, rule)
    if (
        getattr(check_module, "Check_Report_AWS", None) is not Check_Report_AWS
        or getattr(check_module, "is_policy_public", None) is not is_policy_public
        or getattr(ocsf_module, "DetectionFinding", None) is not DetectionFinding
        or getattr(ocsf_module, "Finding", None) is not Finding
    ):
        raise ValueError("invalid Prowler dependency binding")
    return RuntimeAPI(
        version=config.prowler_version,
        role_type=Role,
        client=client,
        check_type=check_type,
        report_type=Check_Report_AWS,
        finding_type=Finding,
        ocsf_type=OCSF,
        detection_type=DetectionFinding,
        set_output_timestamp=config.set_output_timestamp,
    )


def _fixture_provider() -> SimpleNamespace:
    return SimpleNamespace(
        type="aws",
        identity=SimpleNamespace(account=_ACCOUNT_ID, partition=_PARTITION, profile=""),
        organizations_metadata=SimpleNamespace(
            account_name="",
            account_email="",
            organization_arn="",
            organization_id="",
            account_tags={},
            account_ou_id=None,
            account_ou_name=None,
        ),
    )


def _source_digest(path: str) -> str:
    if type(path) is not str:
        raise TypeError("invalid source path")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_SOURCE_BYTES:
            raise ValueError("invalid runtime source")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError("truncated runtime source")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("runtime source changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_fixture(path: str) -> bytes:
    if path != FIXTURE_PATH:
        raise ValueError("invalid fixture path")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FIXTURE_BYTES:
            raise ValueError("invalid fixture file")
        raw = os.read(descriptor, MAX_FIXTURE_BYTES + 1)
        if len(raw) > MAX_FIXTURE_BYTES or os.read(descriptor, 1):
            raise ValueError("invalid fixture file")
        return raw
    finally:
        os.close(descriptor)


def _write_artifact(artifact: bytes) -> None:
    if type(artifact) is not bytes or not 0 < len(artifact) <= MAX_ARTIFACT_BYTES:
        raise ValueError("invalid artifact")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(OUTPUT_PATH, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("invalid output file")
        offset = 0
        while offset < len(artifact):
            written = os.write(descriptor, artifact[offset:])
            if written <= 0:
                raise OSError("output write failed")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            _remove_output()
        raise
    os.close(descriptor)


def _remove_output() -> None:
    try:
        metadata = os.lstat(OUTPUT_PATH)
        if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            os.unlink(OUTPUT_PATH)
    except FileNotFoundError:
        return
    except OSError:
        return


def _parse_bounded_json(raw: bytes, maximum_bytes: int) -> object:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum_bytes:
        raise ValueError("invalid JSON bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        _preflight_json_depth(text)
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(value, 0)
        return value
    except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid JSON") from exc


def _preflight_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting is too deep")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("invalid JSON nesting")
    if depth != 0 or in_string:
        raise ValueError("invalid JSON nesting")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len(pairs) > MAX_COLLECTION_SIZE:
        raise ValueError("JSON object is too large")
    value: dict[str, object] = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = entry
    return value


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_json_shape(value: object, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep")
    if type(value) is str:
        if len(value.encode("utf-8", errors="strict")) > MAX_STRING_BYTES:
            raise ValueError("JSON string is too large")
    elif type(value) is list:
        if len(value) > MAX_COLLECTION_SIZE:
            raise ValueError("JSON array is too large")
        for entry in value:
            _validate_json_shape(entry, depth + 1)
    elif type(value) is dict:
        if len(value) > MAX_COLLECTION_SIZE:
            raise ValueError("JSON object is too large")
        for key, entry in value.items():
            _validate_json_shape(key, depth + 1)
            _validate_json_shape(entry, depth + 1)
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError("invalid JSON value")
    elif type(value) is float and not (float("-inf") < value < float("inf")):
        raise ValueError("invalid JSON number")


def _expect_object(value: object, keys: tuple[str, ...], context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(keys) or len(value) != len(keys):
        raise ValueError(f"invalid {context}")
    return value


def _expect_list(value: object, length: int, context: str) -> list[object]:
    if type(value) is not list or len(value) != length:
        raise ValueError(f"invalid {context}")
    return value


def _expect_string(value: object, context: str) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise ValueError(f"invalid {context}")
    return value


def _expect_string_list(value: object, context: str) -> None:
    if type(value) is not list or len(value) > MAX_COLLECTION_SIZE:
        raise ValueError(f"invalid {context}")
    for entry in value:
        _expect_string(entry, context)


def _validate_timestamp_pair(seconds: object, instant: object) -> None:
    if type(seconds) is not int or seconds < 0 or type(instant) is not str:
        raise ValueError("invalid OCSF timestamp")
    normalized = instant[:-1] + "+00:00" if instant.endswith("Z") else instant
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("invalid OCSF timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("invalid OCSF timestamp")
    if int(parsed.timestamp()) != seconds:
        raise ValueError("invalid OCSF timestamp")


@contextlib.contextmanager
def _absolute_deadline(seconds: float):
    if type(seconds) not in (int, float) or seconds <= 0:
        raise ValueError("invalid deadline")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, float(seconds))

    def expire(signum, frame):
        del signum, frame
        raise TimeoutError("operation deadline exceeded")

    signal.signal(signal.SIGALRM, expire)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def _write_exact(stream: TextIO, value: str) -> None:
    written = stream.write(value)
    if written is not None and written != len(value):
        raise OSError("short output write")
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(run_main(sys.argv, os.environ, sys.stdout))
