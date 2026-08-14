from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import fixture_runner


FIXTURE_PATH = "/proof/fixture.json"
OUTPUT_PATH = "/proof/output/prowler.ocsf.json"
HOSTNAME = "zasp-m0-11-0123456789abcdef-prowler"
ARGV = [
    "/proof/fixture_runner.py",
    "--fixture",
    FIXTURE_PATH,
    "--output",
    OUTPUT_PATH,
]
ENVIRON = {
    **fixture_runner.BASE_ENVIRONMENT,
    "HOSTNAME": HOSTNAME,
}
ROLE_ARN = "arn:aws:iam::000000000000:role/shared-fixture-role"
PROWLER_IMAGE = "prowlercloud/prowler:5.39.0@sha256:58c8a0eb0c947517bd89b6214cde0cc1d5f59df4eebbb99a87475ab741914959"
FIXTURE_DOCUMENT = {
    "schema_version": 1,
    "account_id": "000000000000",
    "region": "us-east-1",
    "partition": "aws",
    "role": {
        "name": "shared-fixture-role",
        "arn": ROLE_ARN,
        "assume_role_policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "is_service_role": True,
        "attached_policies": [],
        "inline_policies": [],
        "permissions_boundary": None,
        "tags": [],
    },
}
FIXTURE_BYTES = json.dumps(FIXTURE_DOCUMENT, separators=(",", ":")).encode()


def official_document():
    return [
        {
            "message": "IAM Service Role shared-fixture-role does not prevent against a cross-service confused deputy attack.",
            "metadata": {
                "event_code": "iam_role_cross_service_confused_deputy_prevention",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.39.0",
                },
                "version": "1.5.0",
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
            },
            "severity_id": 4,
            "severity": "High",
            "status": "New",
            "status_code": "FAIL",
            "status_detail": "IAM Service Role shared-fixture-role does not prevent against a cross-service confused deputy attack.",
            "status_id": 1,
            "unmapped": {
                "related_url": "",
                "categories": ["identity-access", "trust-boundaries"],
                "depends_on": [],
                "related_to": [],
                "additional_urls": ["https://example.invalid/reference"],
                "notes": "",
                "compliance": {},
                "scan_id": "0198a2c3-4d5e-7abc-8def-0123456789ab",
                "provider_uid": "000000000000",
                "provider": "aws",
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "analytic": {
                    "name": "IAM service role prevents cross-service confused deputy attack",
                    "uid": "iam_role_cross_service_confused_deputy_prevention",
                    "type_id": 1,
                    "type": "Rule",
                    "category": "iam",
                },
                "created_time": 1_786_665_600,
                "created_time_dt": "2026-08-14T00:00:00Z",
                "desc": "official description",
                "title": "IAM service role prevents cross-service confused deputy attack",
                "uid": "prowler-aws-iam_role_cross_service_confused_deputy_prevention-000000000000-us-east-1-shared-fixture-role",
                "types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "TTPs/Privilege Escalation",
                ],
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-east-1",
                    "data": {
                        "details": "",
                        "metadata": FIXTURE_DOCUMENT["role"],
                    },
                    "group": {"name": "iam"},
                    "labels": [],
                    "name": "shared-fixture-role",
                    "type": "AwsIamRole",
                    "uid": ROLE_ARN,
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": "",
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": "000000000000",
                    "labels": [],
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-east-1",
            },
            "time": 1_786_665_600,
            "time_dt": "2026-08-14T00:00:00Z",
            "remediation": {"desc": "official remediation", "references": []},
            "risk_details": "official risk",
            "type_uid": 200401,
            "type_name": "Detection Finding: Create",
        }
    ]


def official_bytes(document=None):
    return json.dumps(
        official_document() if document is None else document,
        separators=(",", ":"),
    ).encode()


class FakeRole:
    def __init__(self, **values):
        self.__dict__.update(values)

    def dict(self):
        return dict(self.__dict__)


class FakeReport:
    def __init__(self, role, status="FAIL"):
        self.status = status
        self.status_extended = "official check result"
        self.resource_id = role.name
        self.resource_arn = role.arn
        self.region = "us-east-1"
        self.resource = role.dict()
        self.check_metadata = SimpleNamespace(
            CheckID="iam_role_cross_service_confused_deputy_prevention",
            Severity="high",
            Provider="aws",
            ResourceType="AwsIamRole",
        )


class GuardedClient:
    def __init__(self):
        self.roles = []
        self.region = ""
        self.audited_account = ""

    def __getattr__(self, name):
        raise AssertionError(f"unexpected client call: {name}")


class FakeCheck:
    client = None
    status = "FAIL"
    finding_count = 1
    error = None

    def execute(self):
        if self.error is not None:
            raise self.error
        return [FakeReport(self.client.roles[0], self.status)] * self.finding_count


class FakeFinding:
    calls = []

    @classmethod
    def generate_output(cls, provider, report, options):
        cls.calls.append((provider, report, options))
        return SimpleNamespace(status=report.status, prowler_version="5.39.0")


class FakeDetectionFinding:
    document = official_document()[0]

    def model_dump_json(self, *, exclude_none):
        if not exclude_none:
            raise AssertionError("official output must exclude absent fields")
        return json.dumps(self.document, separators=(",", ":"))


class FakeOCSF:
    calls = []

    def __init__(self, findings):
        self.calls.append(findings)
        self.data = [FakeDetectionFinding()]


def fake_runtime():
    client = GuardedClient()
    check_type = type("BoundFakeCheck", (FakeCheck,), {"client": client})
    return fixture_runner.RuntimeAPI(
        version="5.39.0",
        role_type=FakeRole,
        client=client,
        check_type=check_type,
        report_type=FakeReport,
        finding_type=FakeFinding,
        ocsf_type=FakeOCSF,
        detection_type=FakeDetectionFinding,
        set_output_timestamp=lambda instant: None,
    )


class FixtureParsingTests(unittest.TestCase):
    def test_parses_only_the_exact_unscoped_synthetic_role(self):
        fixture = fixture_runner.parse_fixture(FIXTURE_BYTES)

        self.assertEqual(fixture.account_id, "000000000000")
        self.assertEqual(fixture.region, "us-east-1")
        self.assertEqual(fixture.partition, "aws")
        self.assertEqual(fixture.role["arn"], ROLE_ARN)
        self.assertEqual(
            fixture.role["assume_role_policy"]["Statement"][0],
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        )

    def test_rejects_malformed_duplicate_trailing_deep_long_and_oversized_json(self):
        duplicate = FIXTURE_BYTES.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
            1,
        )
        deep = json.dumps({"x": [[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]}).encode()
        long_string = json.dumps({"x": "x" * 4097}).encode()
        for raw in (
            b"{",
            b"\xff",
            FIXTURE_BYTES + b" true",
            duplicate,
            deep,
            long_string,
            b" " * (fixture_runner.MAX_FIXTURE_BYTES + 1),
        ):
            with self.subTest(raw=raw[:48]):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_fixture(raw)

    def test_rejects_missing_extra_case_aliased_and_semantically_drifted_fixture(self):
        invalid = []
        missing = json.loads(FIXTURE_BYTES)
        del missing["region"]
        invalid.append(missing)
        extra = json.loads(FIXTURE_BYTES)
        extra["unexpected"] = True
        invalid.append(extra)
        alias = json.loads(FIXTURE_BYTES)
        alias["Region"] = alias["region"]
        invalid.append(alias)
        for path, changed in (
            (("account_id",), "111111111111"),
            (("region",), "us-west-2"),
            (("partition",), "aws-cn"),
            (("role", "name"), "other-role"),
            (("role", "arn"), "arn:aws:iam::000000000000:role/other-role"),
            (("role", "is_service_role"), False),
            (("role", "permissions_boundary"), {}),
        ):
            value = json.loads(FIXTURE_BYTES)
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = changed
            invalid.append(value)
        scoped = json.loads(FIXTURE_BYTES)
        scoped["role"]["assume_role_policy"]["Statement"][0]["Condition"] = {}
        invalid.append(scoped)

        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_fixture(json.dumps(value).encode())


class ArtifactBoundaryTests(unittest.TestCase):
    def test_accepts_one_exact_official_ocsf_detection_finding(self):
        parsed = fixture_runner.parse_official_artifact(official_bytes())

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["status_code"], "FAIL")
        self.assertNotIn("name", parsed[0]["finding_info"])

    def test_rejects_no_multiple_malformed_and_schema_drifted_findings(self):
        invalid = [[], official_document() * 2]
        for path, changed in (
            ((0, "metadata", "version"), "1.4.0"),
            ((0, "metadata", "product", "version"), "5.38.0"),
            ((0, "metadata", "event_code"), "other_check"),
            ((0, "status_code"), "PASS"),
            ((0, "status_id"), True),
            ((0, "activity_id"), True),
            ((0, "severity"), "Medium"),
            ((0, "class_uid"), 2005),
            ((0, "type_uid"), 200402),
            ((0, "cloud", "account", "uid"), "111111111111"),
            ((0, "cloud", "region"), "us-west-2"),
            ((0, "resources", 0, "uid"), "arn:aws:iam::000000000000:role/other"),
            ((0, "finding_info", "analytic", "type_id"), True),
        ):
            value = official_document()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = changed
            invalid.append(value)
        extra = official_document()
        extra[0]["unexpected"] = True
        invalid.append(extra)

        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_official_artifact(official_bytes(value))
        for raw in (b"{", b"\xff", official_bytes() + b" true"):
            with self.subTest(raw=raw[:32]):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_official_artifact(raw)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        FakeFinding.calls = []
        FakeOCSF.calls = []
        FakeDetectionFinding.document = official_document()[0]
        FakeCheck.status = "FAIL"
        FakeCheck.finding_count = 1
        FakeCheck.error = None

    def test_executes_one_official_check_and_official_ocsf_transform(self):
        runtime = fake_runtime()
        artifact = fixture_runner.execute_fixture(
            fixture_runner.parse_fixture(FIXTURE_BYTES), runtime
        )

        parsed = json.loads(artifact)
        self.assertEqual(parsed[0]["status_code"], "FAIL")
        self.assertEqual(len(runtime.client.roles), 1)
        self.assertEqual(runtime.client.roles[0].arn, ROLE_ARN)
        self.assertEqual(runtime.client.region, "us-east-1")
        self.assertEqual(runtime.client.audited_account, "000000000000")
        self.assertEqual(len(FakeFinding.calls), 1)
        self.assertEqual(len(FakeOCSF.calls), 1)

    def test_rejects_version_check_cardinality_status_and_output_model_drift(self):
        fixture = fixture_runner.parse_fixture(FIXTURE_BYTES)
        cases = []

        runtime = fake_runtime()
        runtime.version = "5.38.0"
        cases.append(runtime)

        runtime = fake_runtime()
        runtime.check_type.finding_count = 0
        cases.append(runtime)

        runtime = fake_runtime()
        runtime.check_type.finding_count = 2
        cases.append(runtime)

        runtime = fake_runtime()
        runtime.check_type.status = "PASS"
        cases.append(runtime)

        runtime = fake_runtime()
        runtime.ocsf_type = type(
            "NoOutputOCSF", (), {"__init__": lambda self, findings: setattr(self, "data", [])}
        )
        cases.append(runtime)

        for runtime in cases:
            with self.subTest(runtime=runtime):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.execute_fixture(fixture, runtime)

    def test_rejects_unexpected_client_access_panic_and_output_overflow(self):
        fixture = fixture_runner.parse_fixture(FIXTURE_BYTES)

        runtime = fake_runtime()
        runtime.check_type.execute = lambda self: self.client.list_roles()
        with self.assertRaises((AssertionError, TypeError, ValueError)):
            fixture_runner.execute_fixture(fixture, runtime)

        runtime = fake_runtime()
        runtime.check_type.execute = lambda self: (_ for _ in ()).throw(
            RuntimeError("sensitive panic")
        )
        with self.assertRaises(RuntimeError):
            fixture_runner.execute_fixture(fixture, runtime)

        runtime = fake_runtime()
        huge = official_document()[0]
        huge["message"] = "x" * fixture_runner.MAX_ARTIFACT_BYTES
        runtime.detection_type.document = huge
        with self.assertRaises((TypeError, ValueError)):
            fixture_runner.execute_fixture(fixture, runtime)

    def test_runtime_identity_rejects_interpreter_distribution_and_source_drift(self):
        valid = fixture_runner.RuntimeIdentity(
            executable="/home/prowler/.venv/bin/python",
            python_version="3.12.13",
            distribution_version="5.39.0",
            ocsf_distribution_version="0.10.0",
            config_version="5.39.0",
            check_source="/home/prowler/prowler/providers/aws/services/iam/iam_role_cross_service_confused_deputy_prevention/iam_role_cross_service_confused_deputy_prevention.py",
            ocsf_source="/home/prowler/prowler/lib/outputs/ocsf/ocsf.py",
        )
        fixture_runner.validate_runtime_identity(valid)

        for field, changed in (
            ("executable", "/usr/bin/python"),
            ("python_version", "3.12.12"),
            ("distribution_version", "5.38.0"),
            ("ocsf_distribution_version", "0.9.0"),
            ("config_version", "5.38.0"),
            ("check_source", "/tmp/check.py"),
            ("ocsf_source", "/tmp/ocsf.py"),
        ):
            values = vars(valid).copy()
            values[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture_runner.validate_runtime_identity(
                    fixture_runner.RuntimeIdentity(**values)
                )

    def test_every_critical_symbol_is_bound_to_its_exact_export_and_source(self):
        for rule in fixture_runner.SYMBOL_RULES:
            def official_symbol():
                return None

            official_symbol.__module__ = rule.module
            module = SimpleNamespace(**{rule.export: official_symbol})
            modules = {rule.module: module}
            fixture_runner.validate_symbol_binding(
                official_symbol,
                rule,
                modules=modules,
                source_file=lambda value, path=rule.source: path,
                realpath=lambda path: path,
                lstat=lambda path: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
                source_digest=lambda path, digest=rule.sha256: digest,
            )

            forged = SimpleNamespace()
            setattr(forged, rule.export, object())
            with self.subTest(symbol=rule.label), self.assertRaises(ValueError):
                fixture_runner.validate_symbol_binding(
                    official_symbol,
                    rule,
                    modules={rule.module: forged},
                    source_file=lambda value, path=rule.source: path,
                    realpath=lambda path: path,
                    lstat=lambda path: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
                    source_digest=lambda path, digest=rule.sha256: digest,
                )

    def test_symbol_binding_rejects_module_symlink_out_of_root_nonregular_and_digest_drift(self):
        rule = fixture_runner.SYMBOL_RULES[0]

        def symbol():
            return None

        symbol.__module__ = rule.module
        module = SimpleNamespace(**{rule.export: symbol})
        base = {
            "modules": {rule.module: module},
            "source_file": lambda value: rule.source,
            "realpath": lambda path: path,
            "lstat": lambda path: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
            "source_digest": lambda path: rule.sha256,
        }
        invalid = [
            {"source_file": lambda value: "/tmp/forged.py"},
            {"realpath": lambda path: "/tmp/forged.py"},
            {"lstat": lambda path: SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)},
            {"lstat": lambda path: SimpleNamespace(st_mode=stat.S_IFDIR | 0o555)},
            {"source_digest": lambda path: "0" * 64},
        ]
        for mutation in invalid:
            dependencies = {**base, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                fixture_runner.validate_symbol_binding(symbol, rule, **dependencies)

        symbol.__module__ = "forged.module"
        with self.assertRaises(ValueError):
            fixture_runner.validate_symbol_binding(symbol, rule, **base)


class FileBoundaryTests(unittest.TestCase):
    def test_reads_only_a_bounded_regular_non_symlink_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "fixture.json")
            path.write_bytes(FIXTURE_BYTES)
            with mock.patch.object(fixture_runner, "FIXTURE_PATH", str(path)):
                self.assertEqual(fixture_runner._read_fixture(str(path)), FIXTURE_BYTES)

            target = Path(directory, "target.json")
            target.write_bytes(FIXTURE_BYTES)
            path.unlink()
            path.symlink_to(target)
            with (
                mock.patch.object(fixture_runner, "FIXTURE_PATH", str(path)),
                self.assertRaises((OSError, ValueError)),
            ):
                fixture_runner._read_fixture(str(path))

    def test_rejects_fifo_without_blocking_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "fixture.json")
            os.mkfifo(path)
            before = time.monotonic()
            with (
                mock.patch.object(fixture_runner, "FIXTURE_PATH", str(path)),
                self.assertRaises((OSError, ValueError)),
            ):
                fixture_runner._read_fixture(str(path))
            self.assertLess(time.monotonic() - before, 0.25)

            path.unlink()
            path.write_bytes(b"x" * (fixture_runner.MAX_FIXTURE_BYTES + 1))
            with (
                mock.patch.object(fixture_runner, "FIXTURE_PATH", str(path)),
                self.assertRaises(ValueError),
            ):
                fixture_runner._read_fixture(str(path))

    def test_rejects_non_exact_fixture_path_before_open(self):
        with mock.patch.object(os, "open") as open_mock:
            for path in ("proof/fixture.json", "/tmp/fixture.json", "/proof/../fixture.json"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    fixture_runner._read_fixture(path)
            open_mock.assert_not_called()


class MainBoundaryTests(unittest.TestCase):
    @contextlib.contextmanager
    def fake_deadline(self, seconds):
        self.deadline = seconds
        yield

    def test_accepts_only_exact_argv_and_allowlisted_image_environment(self):
        self.assertEqual(fixture_runner.validate_boundary(ARGV, ENVIRON), None)
        invalid_argv = [
            ARGV[:-2],
            [*ARGV, "--extra"],
            [ARGV[0], "--fixture", "/tmp/fixture.json", "--output", OUTPUT_PATH],
            [ARGV[0], "--fixture", FIXTURE_PATH, "--output", "/tmp/out.json"],
        ]
        for argv in invalid_argv:
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                fixture_runner.validate_boundary(argv, ENVIRON)
        for key, value in (
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("HTTPS_PROXY", "http://proxy.invalid"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
            ("PATH", "/tmp"),
            ("HOSTNAME", "foreign"),
        ):
            environ = dict(ENVIRON, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture_runner.validate_boundary(ARGV, environ)

    def test_success_writes_one_bounded_artifact_fixed_line_and_exit_three(self):
        stdout = io.StringIO()
        writes = []
        with (
            mock.patch.object(fixture_runner, "_read_fixture", return_value=FIXTURE_BYTES),
            mock.patch.object(fixture_runner, "_load_runtime", return_value=fake_runtime()),
            mock.patch.object(fixture_runner, "_write_artifact", side_effect=writes.append),
            mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
        ):
            code = fixture_runner.run_main(ARGV, ENVIRON, stdout)

        self.assertEqual(code, 3)
        self.assertEqual(stdout.getvalue(), fixture_runner.SUCCESS_LINE)
        self.assertEqual(len(writes), 1)
        self.assertEqual(json.loads(writes[0])[0]["status_code"], "FAIL")
        self.assertEqual(self.deadline, fixture_runner.OPERATION_TIMEOUT_SECONDS)

    def test_noisy_check_and_logger_output_never_reaches_actual_process_streams(self):
        runtime = fake_runtime()
        ordinary_execute = runtime.check_type.execute

        def noisy_execute(check):
            print("sensitive check stdout")
            print("sensitive check stderr", file=sys.stderr)
            noisy_logger.warning("sensitive logger output")
            return ordinary_execute(check)

        runtime.check_type.execute = noisy_execute
        fixed = io.StringIO()
        actual_stdout = io.StringIO()
        actual_stderr = io.StringIO()
        noisy_logger = logging.getLogger("fixture-noise")
        noisy_logger.propagate = False
        noisy_logger.setLevel(logging.WARNING)
        bound_handler = logging.StreamHandler(actual_stderr)
        noisy_logger.addHandler(bound_handler)
        try:
            with (
                contextlib.redirect_stdout(actual_stdout),
                contextlib.redirect_stderr(actual_stderr),
                mock.patch.object(fixture_runner, "_read_fixture", return_value=FIXTURE_BYTES),
                mock.patch.object(fixture_runner, "_load_runtime", return_value=runtime),
                mock.patch.object(fixture_runner, "_write_artifact"),
                mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
            ):
                code = fixture_runner.run_main(ARGV, ENVIRON, fixed)
        finally:
            noisy_logger.removeHandler(bound_handler)
            bound_handler.close()

        self.assertEqual(code, 3)
        self.assertEqual(fixed.getvalue(), fixture_runner.SUCCESS_LINE)
        self.assertEqual(actual_stdout.getvalue(), "")
        self.assertEqual(actual_stderr.getvalue(), "")

    def test_noisy_import_raise_and_capture_overflow_emit_only_fixed_failure(self):
        def noisy_import():
            print("sensitive import stdout")
            print("sensitive import stderr", file=sys.stderr)
            logging.getLogger("fixture-import-noise").warning("sensitive import log")
            raise RuntimeError("sensitive import panic")

        for loader in (
            noisy_import,
            lambda: print("x" * (fixture_runner.MAX_CAPTURE_BYTES + 1)),
        ):
            fixed = io.StringIO()
            actual_stdout = io.StringIO()
            actual_stderr = io.StringIO()
            with (
                contextlib.redirect_stdout(actual_stdout),
                contextlib.redirect_stderr(actual_stderr),
                mock.patch.object(fixture_runner, "_read_fixture", return_value=FIXTURE_BYTES),
                mock.patch.object(fixture_runner, "_load_runtime", side_effect=loader),
                mock.patch.object(fixture_runner, "_remove_output"),
                mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
            ):
                code = fixture_runner.run_main(ARGV, ENVIRON, fixed)
            with self.subTest(loader=loader):
                self.assertEqual(code, 1)
                self.assertEqual(fixed.getvalue(), fixture_runner.FAILURE_LINE)
                self.assertEqual(actual_stdout.getvalue(), "")
                self.assertEqual(actual_stderr.getvalue(), "")

    def test_timeout_panic_client_call_and_write_failure_emit_only_fixed_failure(self):
        failures = [
            TimeoutError("secret timeout"),
            RuntimeError("secret panic"),
            AssertionError("secret client call"),
            OSError("secret output path"),
        ]
        for failure in failures:
            stdout = io.StringIO()
            with (
                mock.patch.object(fixture_runner, "_read_fixture", return_value=FIXTURE_BYTES),
                mock.patch.object(fixture_runner, "_load_runtime", side_effect=failure),
                mock.patch.object(fixture_runner, "_remove_output") as remove,
                mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
            ):
                code = fixture_runner.run_main(ARGV, ENVIRON, stdout)
            with self.subTest(failure=failure):
                self.assertEqual(code, 1)
                self.assertEqual(stdout.getvalue(), fixture_runner.FAILURE_LINE)
                self.assertNotIn("secret", stdout.getvalue())
                remove.assert_called_once_with()

    def test_real_deadline_interrupts_a_hung_operation(self):
        before = time.monotonic()
        with self.assertRaises(TimeoutError):
            with fixture_runner._absolute_deadline(0.05):
                time.sleep(2)
        self.assertLess(time.monotonic() - before, 0.5)


class PinnedImageCompatibilityTests(unittest.TestCase):
    def test_exact_image_imports_check_and_emits_official_ocsf_without_network(self):
        repository_directory = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory, "output")
            output_directory.mkdir(mode=0o777)
            output_directory.chmod(0o777)
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "768m",
                    "--cpus",
                    "1",
                    "--hostname",
                    HOSTNAME,
                    "--entrypoint",
                    fixture_runner.EXPECTED_INTERPRETER,
                    "--env",
                    "HOME=/tmp",
                    "--env",
                    "PYTHONUNBUFFERED=1",
                    "--volume",
                    f"{repository_directory / 'fixture_runner.py'}:/proof/fixture_runner.py:ro",
                    "--volume",
                    f"{repository_directory / 'fixture.json'}:{FIXTURE_PATH}:ro",
                    "--volume",
                    f"{output_directory}:/proof/output:rw",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=32m",
                    PROWLER_IMAGE,
                    "/proof/fixture_runner.py",
                    "--fixture",
                    FIXTURE_PATH,
                    "--output",
                    OUTPUT_PATH,
                ],
                capture_output=True,
                check=False,
                timeout=90,
                env={"PATH": os.environ["PATH"]},
            )

            self.assertEqual(result.returncode, 3, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout.decode(), fixture_runner.SUCCESS_LINE)
            self.assertEqual(result.stderr, b"")
            artifact = (output_directory / "prowler.ocsf.json").read_bytes()
            parsed = fixture_runner.parse_official_artifact(artifact)
            self.assertEqual(parsed[0]["status_code"], "FAIL")


if __name__ == "__main__":
    unittest.main()
