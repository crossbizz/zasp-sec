#!/usr/bin/env python3
"""Require exact Agent read component evidence; never native/provider acceptance."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

# Frozen source-derived roster: 76 named results, including every ancestor.
# New coverage requires a reviewed roster successor, not a relaxed count check.
EXPECTED = {'github.com/zasp-ai/zasp-sec/services/platform/apiserver': ['TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/normal',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/audit',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/wrong_purpose',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/wrong_parent',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/foreign_scope',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/collection',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/unknown_profile',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/legacy_SQL',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgent/invalid_bounds',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/normal',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/audit',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/wrong_purpose',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/wrong_parent',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/foreign_scope',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/collection',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/unknown_profile',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/legacy_SQL',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentCapabilities/invalid_bounds',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/normal',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/audit',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/wrong_purpose',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/wrong_parent',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/foreign_scope',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/collection',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/unknown_profile',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/legacy_SQL',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/getAgentRelationships/invalid_bounds',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/normal',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/audit',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/wrong_purpose',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/wrong_parent',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/foreign_scope',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/collection',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/unknown_profile',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/legacy_SQL',
                                                             'TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute/listAgentSessions/invalid_bounds',
                                                             'TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile',
                                                             'TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile/getAgent',
                                                             'TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile/getAgentCapabilities',
                                                             'TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile/getAgentRelationships',
                                                             'TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile/listAgentSessions',
                                                             'TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute',
                                                             'TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute/getAgent',
                                                             'TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute/getAgentCapabilities',
                                                             'TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute/getAgentRelationships',
                                                             'TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute/listAgentSessions'],
 'github.com/zasp-ai/zasp-sec/services/platform/agentsec-api': ['TestAgentCurrentReadRuntimeProfileIsExplicitAndFailClosed'],
 'github.com/zasp-ai/zasp-sec/services/platform/agentsec-migrate': ['TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-profile',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-profile/accepted',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-profile/catalog_refused',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-profile/uncertain_commit',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-profile/canceled',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-audit-profile',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-audit-profile/accepted',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-audit-profile/catalog_refused',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-audit-profile/uncertain_commit',
                                                                    'TestAgentCurrentReadMigrationRecipesAndBoundedConfirmation/up-agent-read-audit-profile/canceled'],
 'github.com/zasp-ai/zasp-sec/services/platform/migrations': ['TestAgentReadInstallerClosedAdmission',
                                                              'TestAgentReadInstallerClosedAdmission/normal-fresh',
                                                              'TestAgentReadInstallerClosedAdmission/audit-fresh',
                                                              'TestAgentReadInstallerClosedAdmission/normal-existing',
                                                              'TestAgentReadInstallerClosedAdmission/audit-existing',
                                                              'TestAgentReadInstallerClosedAdmission/parent-refused',
                                                              'TestAgentReadInstallerClosedAdmission/catalog-refused',
                                                              'TestAgentReadInstallerClosedAdmission/restore-refused',
                                                              'TestAgentReadInstallerClosedAdmission/normal-explicit-self-role',
                                                              'TestAgentReadInstallerClosedAdmission/audit-explicit-self-role',
                                                              'TestAgentReadCompilerIdentity',
                                                              'TestAgentReadCompilerIdentity/normal',
                                                              'TestAgentReadCompilerIdentity/audit']}

REQUIRED_SOURCE_PATHS = frozenset(['.github/workflows/agents-current-read-components.yml',
 'deploy/production/agent-read-profile.mjs',
 'deploy/production/agent-read-profile.test.mjs',
 'deploy/production/release-contract.mjs',
 'deploy/staging/product/templates/_agent-read.tpl',
 'deploy/staging/product/templates/workloads.yaml',
 'deploy/staging/product/values.yaml',
 'scripts/validate_agent_read_components.py',
 'scripts/validate_agent_read_components_test.py',
 'services/platform/agentsec-api/agent_read_runtime.go',
 'services/platform/agentsec-api/agent_read_runtime_test.go',
 'services/platform/agentsec-api/production_runtime.go',
 'services/platform/agentsec-api/runtime.go',
 'services/platform/agentsec-api/runtime_test.go',
 'services/platform/agentsec-migrate/agent_read_profile.go',
 'services/platform/agentsec-migrate/agent_read_profile_test.go',
 'services/platform/agentsec-migrate/forward_release_confirmation.go',
 'services/platform/agentsec-migrate/main.go',
 'services/platform/agentsec-migrate/main_test.go',
 'services/platform/agentsec-migrate/maintenance_confirmation_role_test.go',
 'services/platform/agentsec-migrate/release_readiness_test.go',
 'services/platform/agentsec-migrate/retention_profile.go',
 'services/platform/apiserver/agent_current_read.go',
 'services/platform/apiserver/agent_current_read_handler_test.go',
 'services/platform/apiserver/agent_current_read_test.go',
 'services/platform/apiserver/authorization_attestation_test.go',
 'services/platform/apiserver/authorization_statement.go',
 'services/platform/apiserver/authorization_transaction.go',
 'services/platform/apiserver/authorization_transaction_test.go',
 'services/platform/apiserver/inventory_repository.go',
 'services/platform/apiserver/inventory_repository_test.go',
 'services/platform/apiserver/middleware_test.go',
 'services/platform/apiserver/production.go',
 'services/platform/apiserver/repository.go',
 'services/platform/migrations/migrations_test.go',
 'services/platform/migrations/production_agent_read_compiler_test.go',
 'services/platform/migrations/production_agent_read_profile.go',
 'services/platform/migrations/production_agent_read_profile_test.go',
 'services/platform/migrations/sql/agent_read_profile.sql'])


MAXIMUM_JSONL_BYTES = 32 * 1024 * 1024
MAXIMUM_LINE_BYTES = 1024 * 1024


class EvidenceRejected(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceRejected("duplicate JSON member")
        result[key] = value
    return result


def reject_constant(_value):
    raise EvidenceRejected("non-finite JSON number")


def decode_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError) as error:
        raise EvidenceRejected("invalid JSON") from error


def load_events(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAXIMUM_JSONL_BYTES + 1)
    if not raw or len(raw) > MAXIMUM_JSONL_BYTES:
        raise EvidenceRejected("missing or oversized evidence")
    lines = raw.splitlines()
    if not lines or any(not line.strip() or len(line) > MAXIMUM_LINE_BYTES for line in lines):
        raise EvidenceRejected("invalid evidence line")
    return [decode_json(line) for line in lines]


def validate_events(events, go_exit_code, expected_roster=None):
    if type(go_exit_code) is not int or go_exit_code != 0:
        raise EvidenceRejected("Go execution did not succeed")
    roster = EXPECTED if expected_roster is None else expected_roster
    expected = {package: set(names) for package, names in roster.items()}
    state = {package: {"started": False, "passed": False, "tests": {}} for package in expected}
    if not events:
        raise EvidenceRejected("empty evidence")
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("Package"), str) or event["Package"] not in expected:
            raise EvidenceRejected("unexpected package or event")
        if set(event) - {"Time", "Action", "Package", "Test", "Elapsed", "Output", "FailedBuild"}:
            raise EvidenceRejected("unexpected event member")
        action, package = event.get("Action"), event["Package"]
        if not isinstance(action, str) or action not in {"start", "run", "output", "pause", "cont", "pass"}:
            raise EvidenceRejected("failed, skipped or unknown action")
        if event.get("FailedBuild"):
            raise EvidenceRejected("build failure")
        if "Time" in event and not isinstance(event["Time"], str):
            raise EvidenceRejected("invalid event time")
        if action == "output" and "Output" not in event:
            raise EvidenceRejected("missing output member")
        if "Output" in event and not isinstance(event["Output"], str):
            raise EvidenceRejected("invalid output member")
        if "Elapsed" in event and (type(event["Elapsed"]) not in (int, float) or event["Elapsed"] < 0 or event["Elapsed"] > 86400 or (type(event["Elapsed"]) is float and not math.isfinite(event["Elapsed"]))):
            raise EvidenceRejected("invalid elapsed time")
        current = state[package]
        if current["passed"]:
            raise EvidenceRejected("event after package pass")
        if "Test" not in event:
            if action == "start":
                if current["started"]:
                    raise EvidenceRejected("duplicate package start")
                current["started"] = True
            elif action == "output":
                if not current["started"]:
                    raise EvidenceRejected("output before package start")
            elif action == "pass":
                if not current["started"] or set(current["tests"]) != expected[package] or any(value != "passed" for value in current["tests"].values()):
                    raise EvidenceRejected("partial package result")
                current["passed"] = True
            else:
                raise EvidenceRejected("invalid package lifecycle")
            continue
        test = event["Test"]
        if not isinstance(test, str) or test not in expected[package] or not current["started"]:
            raise EvidenceRejected("unexpected or unstarted named test")
        tests = current["tests"]
        if action == "run":
            if test in tests:
                raise EvidenceRejected("duplicate test run")
            pieces = test.split("/")
            if any(tests.get("/".join(pieces[:index])) != "running" for index in range(1, len(pieces))):
                raise EvidenceRejected("child without running parent")
            tests[test] = "running"
        elif action == "pause":
            if tests.get(test) != "running":
                raise EvidenceRejected("invalid pause")
            tests[test] = "paused"
        elif action == "cont":
            if tests.get(test) != "paused":
                raise EvidenceRejected("invalid continuation")
            tests[test] = "running"
        elif action == "pass":
            descendants = (name for name in expected[package] if name.startswith(test + "/"))
            if tests.get(test) != "running" or any(tests.get(name) != "passed" for name in descendants):
                raise EvidenceRejected("duplicate, premature or unstarted test pass")
            tests[test] = "passed"
        elif action == "output":
            if test not in tests:
                raise EvidenceRejected("named output without run")
        else:
            raise EvidenceRejected("invalid named lifecycle")
    if not all(value["started"] and value["passed"] for value in state.values()):
        raise EvidenceRejected("missing package completion")
    return {"classification": "component-only", "packages": len(expected), "named_passes": sum(map(len, expected.values()))}


def check_sources(root, manifest, required_paths=None):
    root = Path(root).resolve()
    with Path(manifest).open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise EvidenceRejected("oversized source manifest")
    data = decode_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list) or not data["sources"]:
        raise EvidenceRejected("missing source manifest")
    seen = set()
    for item in data["sources"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise EvidenceRejected("invalid source entry")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != item["path"] or item["path"] in seen:
            raise EvidenceRejected("unsafe or duplicate source path")
        candidate = root / relative
        path = candidate.resolve()
        if path != candidate or not path.is_relative_to(root) or type(item.get("bytes")) is not int or item["bytes"] < 0:
            raise EvidenceRejected("invalid source boundary")
        if not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in item["sha256"]):
            raise EvidenceRejected("invalid source digest")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
        if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
            raise EvidenceRejected("source mismatch")
        seen.add(item["path"])
    if not (REQUIRED_SOURCE_PATHS if required_paths is None else required_paths).issubset(seen):
        raise EvidenceRejected("missing required source custody")
    return {"classification": "source-custody-only", "sources": len(seen)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?")
    parser.add_argument("--go-exit-code", type=int)
    parser.add_argument("--check-sources")
    args = parser.parse_args()
    try:
        if args.check_sources is not None:
            if args.evidence is not None or args.go_exit_code is not None:
                raise EvidenceRejected("mixed invocation")
            result = check_sources(Path.cwd(), args.check_sources)
        else:
            if args.evidence is None or args.go_exit_code is None:
                raise EvidenceRejected("missing actual execution status")
            result = validate_events(load_events(args.evidence), args.go_exit_code)
    except (EvidenceRejected, OSError, UnicodeError):
        print("Agent read component evidence rejected", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
