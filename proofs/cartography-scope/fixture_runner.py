from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import stat
import time
from dataclasses import dataclass
from typing import Callable, Mapping, TextIO


MAX_DOCUMENT_BYTES = 16 * 1024
CONNECTION_TIMEOUT_SECONDS = 10.0
OPERATION_TIMEOUT_SECONDS = 45.0
FAILURE_LINE = "Cartography fixture bridge failed.\n"
FIXTURE_PATH = "/proof/fixture.json"
BASE_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
}

_ACCOUNT_ID = "000000000000"
_ROLE_ARN = "arn:aws:iam::000000000000:role/shared-fixture-role"
_ORGANIZATION_URL = "https://api.github.test/orgs/shared-fixture"
_REPOSITORY_ID = "424242"
_CARTOGRAPHY_HOST = re.compile(
    r"zasp-m0-10-([0-9a-f]{16})-cartography-([ab])\Z"
)
_NEO4J_URI = re.compile(
    r"bolt://zasp-m0-10-([0-9a-f]{16})-neo4j-([ab]):7687\Z"
)

NODE_INSPECTION_QUERY = """
MATCH (n)
WHERE n:AWSAccount
   OR n:AWSRole
   OR n:GitHubOrganization
   OR n:GitHubRepository
WITH n ORDER BY elementId(n) LIMIT 5
RETURN collect({
  labels: [label IN labels(n) WHERE label IN [
    'AWSAccount', 'AWSRole', 'GitHubOrganization', 'GitHubRepository'
  ]],
  properties: CASE
    WHEN n:AWSAccount THEN {id: n.id}
    WHEN n:AWSRole THEN {arn: n.arn}
    WHEN n:GitHubOrganization THEN {url: n.id}
    WHEN n:GitHubRepository THEN {id: n.id}
  END
}) AS nodes
""".strip()

RELATIONSHIP_INSPECTION_QUERY = """
MATCH (source)-[relationship]->(target)
WHERE type(relationship) IN ['RESOURCE', 'OWNER']
  AND (source:AWSAccount OR source:AWSRole OR source:GitHubOrganization OR source:GitHubRepository)
  AND (target:AWSAccount OR target:AWSRole OR target:GitHubOrganization OR target:GitHubRepository)
WITH source, relationship, target
ORDER BY type(relationship), elementId(source), elementId(target)
LIMIT 3
RETURN collect({
  type: type(relationship),
  source: {
    label: head([label IN labels(source) WHERE label IN [
      'AWSAccount', 'AWSRole', 'GitHubOrganization', 'GitHubRepository'
    ]]),
    id: CASE
      WHEN source:AWSAccount THEN source.id
      WHEN source:AWSRole THEN source.arn
      WHEN source:GitHubOrganization THEN source.id
      WHEN source:GitHubRepository THEN source.id
    END
  },
  target: {
    label: head([label IN labels(target) WHERE label IN [
      'AWSAccount', 'AWSRole', 'GitHubOrganization', 'GitHubRepository'
    ]]),
    id: CASE
      WHEN target:AWSAccount THEN target.id
      WHEN target:AWSRole THEN target.arn
      WHEN target:GitHubOrganization THEN target.id
      WHEN target:GitHubRepository THEN target.id
    END
  }
}) AS relationships
""".strip()


@dataclass(frozen=True)
class Fixture:
    aws_account: dict[str, str]
    aws_role: dict[str, str]
    github_organization: dict[str, str]
    github_repository: dict[str, str]


@dataclass(frozen=True)
class CartographyAPI:
    load: Callable[..., None]
    AWSAccountSchema: Callable[[], object]
    AWSRoleSchema: Callable[[], object]
    GitHubOrganizationSchema: Callable[[], object]
    GitHubRepositorySchema: Callable[[], object]


def parse_fixture(raw: bytes) -> Fixture:
    if type(raw) is not bytes or len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("invalid fixture")
    try:
        text = raw.decode("utf-8", errors="strict")
        graph = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid fixture") from exc
    return _fixture_from_graph(graph)


def load_fixture(session: object, fixture: Fixture, api: CartographyAPI) -> None:
    api.load(
        session,
        api.AWSAccountSchema(),
        [fixture.aws_account],
        lastupdated=1,
        inscope=True,
    )
    api.load(
        session,
        api.AWSRoleSchema(),
        [fixture.aws_role],
        lastupdated=1,
        AWS_ID=fixture.aws_account["id"],
    )
    api.load(
        session,
        api.GitHubOrganizationSchema(),
        [fixture.github_organization],
        lastupdated=1,
    )
    api.load(
        session,
        api.GitHubRepositorySchema(),
        [fixture.github_repository],
        lastupdated=1,
    )


def inspect_graph(session: object, fixture: Fixture) -> dict[str, object]:
    node_record = _single_record(session.run(NODE_INSPECTION_QUERY), "nodes")
    relationship_record = _single_record(
        session.run(RELATIONSHIP_INSPECTION_QUERY), "relationships"
    )
    graph = {
        "schema_version": 1,
        "nodes": node_record["nodes"],
        "relationships": relationship_record["relationships"],
    }
    inspected_fixture = _fixture_from_graph(graph)
    if inspected_fixture != fixture:
        raise ValueError("graph differs from fixture")
    return _ordered_graph()


def run_main(argv: list[str], environ: Mapping[str, str], stdout: TextIO) -> int:
    try:
        fixture_path, neo4j_uri = _validate_boundary(argv, environ)
        fixture = parse_fixture(_read_fixture(fixture_path))
        with _absolute_deadline(OPERATION_TIMEOUT_SECONDS):
            neo4j, api = _load_runtime()
            with neo4j.GraphDatabase.driver(
                neo4j_uri,
                auth=None,
                connection_timeout=CONNECTION_TIMEOUT_SECONDS,
            ) as driver:
                with driver.session() as session:
                    load_fixture(session, fixture, api)
                    graph = inspect_graph(session, fixture)
            document = json.dumps(graph, ensure_ascii=True, separators=(",", ":"))
            if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                raise ValueError("output too large")
    except Exception:
        _write_failure(stdout)
        return 1

    try:
        _write_exact(stdout, document + "\n")
    except Exception:
        return 1
    return 0


def _fixture_from_graph(value: object) -> Fixture:
    graph = _expect_object(value, ("schema_version", "nodes", "relationships"))
    if type(graph["schema_version"]) is not int or graph["schema_version"] != 1:
        raise ValueError("invalid fixture")

    nodes = _expect_list(graph["nodes"], 4)
    by_label: dict[str, dict[str, str]] = {}
    property_by_label = {
        "AWSAccount": ("id", _ACCOUNT_ID),
        "AWSRole": ("arn", _ROLE_ARN),
        "GitHubOrganization": ("url", _ORGANIZATION_URL),
        "GitHubRepository": ("id", _REPOSITORY_ID),
    }
    for raw_node in nodes:
        node = _expect_object(raw_node, ("labels", "properties"))
        labels = _expect_list(node["labels"], 1)
        label = labels[0]
        if type(label) is not str or label not in property_by_label or label in by_label:
            raise ValueError("invalid fixture")
        property_name, expected_value = property_by_label[label]
        properties = _expect_object(node["properties"], (property_name,))
        if properties[property_name] != expected_value:
            raise ValueError("invalid fixture")
        by_label[label] = {property_name: expected_value}
    if set(by_label) != set(property_by_label):
        raise ValueError("invalid fixture")

    relationships = _expect_list(graph["relationships"], 2)
    expected_relationships = {
        (
            "RESOURCE",
            "AWSAccount",
            _ACCOUNT_ID,
            "AWSRole",
            _ROLE_ARN,
        ),
        (
            "OWNER",
            "GitHubRepository",
            _REPOSITORY_ID,
            "GitHubOrganization",
            _ORGANIZATION_URL,
        ),
    }
    actual_relationships = set()
    for raw_relationship in relationships:
        relationship = _expect_object(raw_relationship, ("type", "source", "target"))
        source = _expect_object(relationship["source"], ("label", "id"))
        target = _expect_object(relationship["target"], ("label", "id"))
        values = (
            relationship["type"],
            source["label"],
            source["id"],
            target["label"],
            target["id"],
        )
        if any(type(item) is not str for item in values):
            raise ValueError("invalid fixture")
        if values in actual_relationships:
            raise ValueError("invalid fixture")
        actual_relationships.add(values)
    if actual_relationships != expected_relationships:
        raise ValueError("invalid fixture")

    return Fixture(
        aws_account=by_label["AWSAccount"],
        aws_role=by_label["AWSRole"],
        github_organization=by_label["GitHubOrganization"],
        github_repository={
            **by_label["GitHubRepository"],
            "owner_org_id": _ORGANIZATION_URL,
        },
    )


def _ordered_graph() -> dict[str, object]:
    return {
        "schema_version": 1,
        "nodes": [
            {"labels": ["AWSAccount"], "properties": {"id": _ACCOUNT_ID}},
            {"labels": ["AWSRole"], "properties": {"arn": _ROLE_ARN}},
            {
                "labels": ["GitHubOrganization"],
                "properties": {"url": _ORGANIZATION_URL},
            },
            {"labels": ["GitHubRepository"], "properties": {"id": _REPOSITORY_ID}},
        ],
        "relationships": [
            {
                "type": "RESOURCE",
                "source": {"label": "AWSAccount", "id": _ACCOUNT_ID},
                "target": {"label": "AWSRole", "id": _ROLE_ARN},
            },
            {
                "type": "OWNER",
                "source": {"label": "GitHubRepository", "id": _REPOSITORY_ID},
                "target": {
                    "label": "GitHubOrganization",
                    "id": _ORGANIZATION_URL,
                },
            },
        ],
    }


def _single_record(result: object, expected_key: str) -> dict[str, object]:
    iterator = iter(result)
    try:
        first = next(iterator)
    except StopIteration as exc:
        raise ValueError("invalid graph response") from exc
    try:
        next(iterator)
    except StopIteration:
        pass
    else:
        raise ValueError("invalid graph response")
    try:
        record = dict(first)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid graph response") from exc
    return _expect_object(record, (expected_key,))


def _expect_object(value: object, keys: tuple[str, ...]) -> dict[str, object]:
    if type(value) is not dict or len(value) != len(keys) or set(value) != set(keys):
        raise ValueError("invalid structure")
    return value


def _expect_list(value: object, length: int) -> list[object]:
    if type(value) is not list or len(value) != length:
        raise ValueError("invalid structure")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("invalid JSON constant")


def _validate_boundary(
    argv: list[str], environ: Mapping[str, str]
) -> tuple[str, str]:
    if (
        type(argv) is not list
        or len(argv) != 4
        or argv[0] != "--fixture"
        or argv[1] != FIXTURE_PATH
        or argv[2] != "--neo4j-uri"
        or type(argv[3]) is not str
    ):
        raise ValueError("invalid arguments")

    environment = dict(environ)
    if set(environment) != {*BASE_ENVIRONMENT, "HOSTNAME"}:
        raise ValueError("invalid environment")
    if any(environment[key] != value for key, value in BASE_ENVIRONMENT.items()):
        raise ValueError("invalid environment")
    hostname = environment["HOSTNAME"]
    if type(hostname) is not str:
        raise ValueError("invalid environment")
    cartography_match = _CARTOGRAPHY_HOST.fullmatch(hostname)
    neo4j_match = _NEO4J_URI.fullmatch(argv[3])
    if (
        cartography_match is None
        or neo4j_match is None
        or cartography_match.groups() != neo4j_match.groups()
    ):
        raise ValueError("invalid owned runtime")
    return argv[1], argv[3]


def _read_fixture(path: str) -> bytes:
    if path != FIXTURE_PATH or not os.path.isabs(path):
        raise ValueError("invalid fixture path")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DOCUMENT_BYTES:
            raise ValueError("invalid fixture file")
        chunks = []
        size = 0
        while size <= MAX_DOCUMENT_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_DOCUMENT_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("invalid fixture file")
        return raw
    finally:
        os.close(descriptor)


def _load_runtime() -> tuple[object, CartographyAPI]:
    import neo4j
    from cartography.client.core.tx import load
    from cartography.models.aws.account import AWSAccountSchema
    from cartography.models.aws.iam.role import AWSRoleSchema
    from cartography.models.github.orgs import GitHubOrganizationSchema
    from cartography.models.github.repos import GitHubRepositorySchema

    return neo4j, CartographyAPI(
        load=load,
        AWSAccountSchema=AWSAccountSchema,
        AWSRoleSchema=AWSRoleSchema,
        GitHubOrganizationSchema=GitHubOrganizationSchema,
        GitHubRepositorySchema=GitHubRepositorySchema,
    )


@contextlib.contextmanager
def _absolute_deadline(seconds: float):
    if seconds <= 0 or signal.getsignal(signal.SIGALRM) is None:
        raise ValueError("invalid deadline")

    def expire(_signal_number: int, _frame: object) -> None:
        raise TimeoutError("operation deadline exceeded")

    started_at = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay > 0:
            elapsed = time.monotonic() - started_at
            signal.setitimer(
                signal.ITIMER_REAL,
                max(previous_delay - elapsed, 0.000001),
                previous_interval,
            )


def _write_failure(stdout: TextIO) -> None:
    try:
        _write_exact(stdout, FAILURE_LINE)
    except Exception:
        pass


def _write_exact(stdout: TextIO, value: str) -> None:
    written = stdout.write(value)
    if written != len(value):
        raise OSError("short stdout write")


def main() -> int:
    import sys

    return run_main(sys.argv[1:], os.environ, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
