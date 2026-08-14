import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fixture_runner


RUN_ID = "0123456789abcdef"
FIXTURE_PATH = "/proof/fixture.json"
NEO4J_URI = f"bolt://zasp-m0-10-{RUN_ID}-neo4j-a:7687"
ENVIRON = {
    "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "HOSTNAME": f"zasp-m0-10-{RUN_ID}-cartography-a",
}

RAW_GRAPH = {
    "schema_version": 1,
    "nodes": [
        {"labels": ["AWSAccount"], "properties": {"id": "000000000000"}},
        {
            "labels": ["AWSRole"],
            "properties": {
                "arn": "arn:aws:iam::000000000000:role/shared-fixture-role"
            },
        },
        {
            "labels": ["GitHubOrganization"],
            "properties": {"url": "https://api.github.test/orgs/shared-fixture"},
        },
        {"labels": ["GitHubRepository"], "properties": {"id": "424242"}},
    ],
    "relationships": [
        {
            "type": "RESOURCE",
            "source": {"label": "AWSAccount", "id": "000000000000"},
            "target": {
                "label": "AWSRole",
                "id": "arn:aws:iam::000000000000:role/shared-fixture-role",
            },
        },
        {
            "type": "OWNER",
            "source": {"label": "GitHubRepository", "id": "424242"},
            "target": {
                "label": "GitHubOrganization",
                "id": "https://api.github.test/orgs/shared-fixture",
            },
        },
    ],
}
RAW_BYTES = json.dumps(RAW_GRAPH, separators=(",", ":")).encode("utf-8")


class FakeAPI:
    AWSAccountSchema = staticmethod(lambda: "AWSAccountSchema")
    AWSRoleSchema = staticmethod(lambda: "AWSRoleSchema")
    GitHubOrganizationSchema = staticmethod(lambda: "GitHubOrganizationSchema")
    GitHubRepositorySchema = staticmethod(lambda: "GitHubRepositorySchema")

    def __init__(self):
        self.calls = []

    def load(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class FakeSession:
    def __init__(self, node_records=None, relationship_records=None):
        self.node_records = node_records or [{"nodes": RAW_GRAPH["nodes"]}]
        self.relationship_records = relationship_records or [
            {"relationships": RAW_GRAPH["relationships"]}
        ]
        self.calls = []

    def run(self, query):
        self.calls.append(query)
        if query == fixture_runner.NODE_INSPECTION_QUERY:
            return FakeResult(self.node_records)
        if query == fixture_runner.RELATIONSHIP_INSPECTION_QUERY:
            return FakeResult(self.relationship_records)
        raise AssertionError("unexpected query")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeGraphDatabase:
    driver_calls = []
    driver_result = None
    driver_error = None

    @classmethod
    def reset(cls, session):
        cls.driver_calls = []
        cls.driver_result = FakeDriver(session)
        cls.driver_error = None

    @classmethod
    def driver(cls, *args, **kwargs):
        cls.driver_calls.append((args, kwargs))
        if cls.driver_error is not None:
            raise cls.driver_error
        return cls.driver_result


class FakeNeo4j:
    GraphDatabase = FakeGraphDatabase


class FixtureParsingTests(unittest.TestCase):
    def test_parse_fixture_builds_exact_cartography_rows(self):
        fixture = fixture_runner.parse_fixture(RAW_BYTES)

        self.assertEqual(fixture.aws_account, {"id": "000000000000"})
        self.assertEqual(
            fixture.aws_role,
            {"arn": "arn:aws:iam::000000000000:role/shared-fixture-role"},
        )
        self.assertEqual(
            fixture.github_organization,
            {"url": "https://api.github.test/orgs/shared-fixture"},
        )
        self.assertEqual(
            fixture.github_repository,
            {
                "id": "424242",
                "owner_org_id": "https://api.github.test/orgs/shared-fixture",
            },
        )

    def test_parse_fixture_accepts_json_members_in_a_different_order(self):
        reordered = {
            "relationships": RAW_GRAPH["relationships"],
            "nodes": RAW_GRAPH["nodes"],
            "schema_version": 1,
        }

        fixture = fixture_runner.parse_fixture(
            json.dumps(reordered, separators=(",", ":")).encode("utf-8")
        )

        self.assertEqual(fixture.aws_account, {"id": "000000000000"})

    def test_parse_fixture_rejects_malformed_utf8_and_oversized_input(self):
        for raw in (b"{", b"\xff", b" " * 16_385):
            with self.subTest(raw=raw[:8]):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_fixture(raw)

    def test_parse_fixture_rejects_duplicate_and_unknown_json_keys(self):
        duplicate = RAW_BYTES.replace(
            b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
        )
        unknown = dict(RAW_GRAPH, extra=True)
        for raw in (
            duplicate,
            json.dumps(unknown, separators=(",", ":")).encode("utf-8"),
        ):
            with self.subTest(raw=raw[:80]):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_fixture(raw)

    def test_parse_fixture_rejects_wrong_cardinality_labels_properties_and_edges(self):
        invalid_graphs = []

        graph = json.loads(RAW_BYTES)
        graph["nodes"].pop()
        invalid_graphs.append(graph)

        graph = json.loads(RAW_BYTES)
        graph["nodes"][1]["labels"] = ["AWSRole", "AWSAccount"]
        invalid_graphs.append(graph)

        graph = json.loads(RAW_BYTES)
        graph["nodes"][0]["properties"]["name"] = "unexpected"
        invalid_graphs.append(graph)

        graph = json.loads(RAW_BYTES)
        graph["relationships"][0]["target"]["id"] = "missing"
        invalid_graphs.append(graph)

        graph = json.loads(RAW_BYTES)
        graph["relationships"].append(graph["relationships"][0])
        invalid_graphs.append(graph)

        for graph in invalid_graphs:
            with self.subTest(graph=graph):
                raw = json.dumps(graph, separators=(",", ":")).encode("utf-8")
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.parse_fixture(raw)


class CartographyLoadTests(unittest.TestCase):
    def test_load_fixture_invokes_only_the_four_exact_schema_loads(self):
        fixture = fixture_runner.parse_fixture(RAW_BYTES)
        api = FakeAPI()
        session = object()

        fixture_runner.load_fixture(session, fixture, api)

        self.assertEqual(
            api.calls,
            [
                (
                    (session, "AWSAccountSchema", [{"id": "000000000000"}]),
                    {"lastupdated": 1, "inscope": True},
                ),
                (
                    (
                        session,
                        "AWSRoleSchema",
                        [
                            {
                                "arn": "arn:aws:iam::000000000000:role/shared-fixture-role"
                            }
                        ],
                    ),
                    {"lastupdated": 1, "AWS_ID": "000000000000"},
                ),
                (
                    (
                        session,
                        "GitHubOrganizationSchema",
                        [{"url": "https://api.github.test/orgs/shared-fixture"}],
                    ),
                    {"lastupdated": 1},
                ),
                (
                    (
                        session,
                        "GitHubRepositorySchema",
                        [
                            {
                                "id": "424242",
                                "owner_org_id": "https://api.github.test/orgs/shared-fixture",
                            }
                        ],
                    ),
                    {"lastupdated": 1},
                ),
            ],
        )


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_runner.parse_fixture(RAW_BYTES)

    def test_inspect_graph_returns_exact_allowlisted_graph_from_two_bounded_queries(self):
        session = FakeSession(
            node_records=[{"nodes": list(reversed(RAW_GRAPH["nodes"]))}],
            relationship_records=[
                {"relationships": list(reversed(RAW_GRAPH["relationships"]))}
            ],
        )

        graph = fixture_runner.inspect_graph(session, self.fixture)

        self.assertEqual(graph, RAW_GRAPH)
        self.assertEqual(
            session.calls,
            [
                fixture_runner.NODE_INSPECTION_QUERY,
                fixture_runner.RELATIONSHIP_INSPECTION_QUERY,
            ],
        )
        self.assertIn("LIMIT 5", fixture_runner.NODE_INSPECTION_QUERY)
        self.assertIn("LIMIT 3", fixture_runner.RELATIONSHIP_INSPECTION_QUERY)

    def test_inspect_graph_rejects_cardinality_multiple_records_and_missing_endpoints(self):
        invalid_sessions = [
            FakeSession(node_records=[{"nodes": RAW_GRAPH["nodes"][:-1]}]),
            FakeSession(
                node_records=[{"nodes": RAW_GRAPH["nodes"]}, {"nodes": []}]
            ),
            FakeSession(relationship_records=[{"relationships": []}]),
        ]
        dangling = json.loads(json.dumps(RAW_GRAPH["relationships"]))
        dangling[0]["target"]["id"] = "missing"
        invalid_sessions.append(
            FakeSession(relationship_records=[{"relationships": dangling}])
        )

        for session in invalid_sessions:
            with self.subTest(session=session):
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.inspect_graph(session, self.fixture)

    def test_inspect_graph_rejects_duplicate_unknown_labels_and_unexpected_properties(self):
        invalid_nodes = []

        nodes = json.loads(json.dumps(RAW_GRAPH["nodes"]))
        nodes[1] = nodes[0]
        invalid_nodes.append(nodes)

        nodes = json.loads(json.dumps(RAW_GRAPH["nodes"]))
        nodes[1]["labels"] = ["Unknown"]
        invalid_nodes.append(nodes)

        nodes = json.loads(json.dumps(RAW_GRAPH["nodes"]))
        nodes[0]["properties"]["lastupdated"] = 1
        invalid_nodes.append(nodes)

        for nodes in invalid_nodes:
            with self.subTest(nodes=nodes):
                session = FakeSession(node_records=[{"nodes": nodes}])
                with self.assertRaises((TypeError, ValueError)):
                    fixture_runner.inspect_graph(session, self.fixture)


class FileBoundaryTests(unittest.TestCase):
    def test_read_fixture_reads_an_actual_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory, "fixture.json")
            fixture_path.write_bytes(RAW_BYTES)

            with mock.patch.object(
                fixture_runner, "FIXTURE_PATH", str(fixture_path)
            ):
                raw = fixture_runner._read_fixture(str(fixture_path))

        self.assertEqual(raw, RAW_BYTES)

    def test_read_fixture_rejects_an_actual_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory, "target.json")
            target_path.write_bytes(RAW_BYTES)
            fixture_path = Path(directory, "fixture.json")
            fixture_path.symlink_to(target_path)

            with (
                mock.patch.object(fixture_runner, "FIXTURE_PATH", str(fixture_path)),
                self.assertRaises((OSError, ValueError)),
            ):
                fixture_runner._read_fixture(str(fixture_path))

    def test_read_fixture_rejects_an_actual_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory, "fixture.json")
            os.mkfifo(fixture_path)

            try:
                with (
                    mock.patch.object(
                        fixture_runner, "FIXTURE_PATH", str(fixture_path)
                    ),
                    fixture_runner._absolute_deadline(0.25),
                ):
                    fixture_runner._read_fixture(str(fixture_path))
            except TimeoutError:
                self.fail("FIFO open blocked until the test deadline")
            except (OSError, ValueError):
                pass
            else:
                self.fail("FIFO fixture was accepted")

    def test_read_fixture_rejects_an_actual_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory, "fixture.json")
            fixture_path.write_bytes(b"x" * 16_385)

            with (
                mock.patch.object(fixture_runner, "FIXTURE_PATH", str(fixture_path)),
                self.assertRaises(ValueError),
            ):
                fixture_runner._read_fixture(str(fixture_path))

    def test_read_fixture_rejects_symlink_without_opening_its_target(self):
        with mock.patch.object(os, "open", side_effect=OSError("symlink")) as open_mock:
            with self.assertRaises((TypeError, ValueError, OSError)):
                fixture_runner._read_fixture(FIXTURE_PATH)

        flags = open_mock.call_args.args[1]
        self.assertEqual(open_mock.call_args.args[0], FIXTURE_PATH)
        self.assertTrue(flags & os.O_NOFOLLOW)

    def test_read_fixture_rejects_non_exact_proof_paths_before_open(self):
        for path in (
            "proof/fixture.json",
            "/proof/../tmp/fixture.json",
            "/proof/nested/fixture.json",
            "/tmp/fixture.json",
        ):
            with self.subTest(path=path), mock.patch.object(os, "open") as open_mock:
                with self.assertRaises((TypeError, ValueError, OSError)):
                    fixture_runner._read_fixture(path)
                open_mock.assert_not_called()


class MainBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.session = FakeSession()
        FakeGraphDatabase.reset(self.session)

    @contextlib.contextmanager
    def fake_deadline(self, seconds):
        self.deadline_seconds = seconds
        yield

    def run_main(self, *, argv=None, environ=None, stdout=None):
        argv = argv or ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI]
        environ = environ or ENVIRON
        stdout = stdout or io.StringIO()
        patches = (
            mock.patch.object(fixture_runner, "_read_fixture", return_value=RAW_BYTES),
            mock.patch.object(
                fixture_runner, "_load_runtime", return_value=(FakeNeo4j, self.api)
            ),
            mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
        )
        with patches[0], patches[1], patches[2]:
            code = fixture_runner.run_main(argv, environ, stdout)
        return code, stdout

    def test_run_main_uses_exact_driver_contract_and_emits_one_compact_document(self):
        code, stdout = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), json.dumps(RAW_GRAPH, separators=(",", ":")) + "\n")
        self.assertEqual(
            FakeGraphDatabase.driver_calls,
            [
                (
                    (NEO4J_URI,),
                    {"auth": None, "connection_timeout": 10.0},
                )
            ],
        )
        self.assertEqual(self.deadline_seconds, 45.0)

    def test_run_main_enters_deadline_before_fixture_file_access(self):
        events = []

        @contextlib.contextmanager
        def deadline(_seconds):
            events.append("deadline-entered")
            yield

        def read_fixture(_path):
            events.append("fixture-read")
            return RAW_BYTES

        with (
            mock.patch.object(fixture_runner, "_read_fixture", read_fixture),
            mock.patch.object(
                fixture_runner, "_load_runtime", return_value=(FakeNeo4j, self.api)
            ),
            mock.patch.object(fixture_runner, "_absolute_deadline", deadline),
        ):
            code = fixture_runner.run_main(
                ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI],
                ENVIRON,
                io.StringIO(),
            )

        self.assertEqual(code, 0)
        self.assertEqual(events[:2], ["deadline-entered", "fixture-read"])

    def test_inert_mountpoint_alone_cannot_run_the_bridge(self):
        placeholder = Path(__file__).with_name("fixture.json").read_bytes()
        self.assertEqual(placeholder, b"{}\n")
        with (
            mock.patch.object(fixture_runner, "_read_fixture", return_value=placeholder),
            mock.patch.object(
                fixture_runner,
                "_load_runtime",
                side_effect=AssertionError("runtime must not load"),
            ) as runtime,
            mock.patch.object(
                fixture_runner, "_absolute_deadline", self.fake_deadline
            ),
        ):
            stdout = io.StringIO()
            code = fixture_runner.run_main(
                ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI],
                ENVIRON,
                stdout,
            )

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "Cartography fixture bridge failed.\n")
        runtime.assert_not_called()

    def test_run_main_rejects_every_nonbaseline_environment_entry_and_wrong_value(self):
        invalid_environments = [
            dict(ENVIRON, AWS_SECRET_ACCESS_KEY="secret"),
            dict(ENVIRON, HTTPS_PROXY="http://proxy.test"),
            dict(ENVIRON, NEO4J_URI=NEO4J_URI),
            dict(ENVIRON, HOME="/root"),
            {key: value for key, value in ENVIRON.items() if key != "LANG"},
        ]
        for environ in invalid_environments:
            with self.subTest(environ=environ):
                code, stdout = self.run_main(environ=environ)
                self.assertEqual(code, 1)
                self.assertEqual(
                    stdout.getvalue(), "Cartography fixture bridge failed.\n"
                )

    def test_run_main_rejects_nonexact_arguments_and_neo4j_uris(self):
        invalid_argv = [
            ["--neo4j-uri", NEO4J_URI, "--fixture", FIXTURE_PATH],
            ["--fixture", FIXTURE_PATH],
            ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI, "extra"],
        ]
        invalid_uris = [
            f"http://zasp-m0-10-{RUN_ID}-neo4j-a:7687",
            f"bolt://user@zasp-m0-10-{RUN_ID}-neo4j-a:7687",
            f"bolt://zasp-m0-10-{RUN_ID}-neo4j-a:7688",
            "bolt://127.0.0.1:7687",
            f"bolt://zasp-m0-10-{RUN_ID.upper()}-neo4j-a:7687",
            f"bolt://zasp-m0-10-{RUN_ID}-neo4j-b:7687",
            f"bolt://zasp-m0-10-{RUN_ID}-neo4j-a:7687?x=1",
            f"bolt://zasp-m0-10-{RUN_ID}-neo4j-a:7687#fragment",
        ]
        invalid_argv.extend(
            ["--fixture", FIXTURE_PATH, "--neo4j-uri", uri]
            for uri in invalid_uris
        )

        for argv in invalid_argv:
            with self.subTest(argv=argv):
                code, stdout = self.run_main(argv=argv)
                self.assertEqual(code, 1)
                self.assertEqual(
                    stdout.getvalue(), "Cartography fixture bridge failed.\n"
                )

    def test_run_main_collapses_driver_timeout_and_output_failures(self):
        FakeGraphDatabase.driver_error = RuntimeError("provider-value")
        code, stdout = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "Cartography fixture bridge failed.\n")
        self.assertNotIn("provider-value", stdout.getvalue())

        @contextlib.contextmanager
        def timeout(_seconds):
            raise TimeoutError("deadline-value")
            yield

        with (
            mock.patch.object(fixture_runner, "_read_fixture", return_value=RAW_BYTES),
            mock.patch.object(fixture_runner, "_absolute_deadline", timeout),
        ):
            timeout_stdout = io.StringIO()
            code = fixture_runner.run_main(
                ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI],
                ENVIRON,
                timeout_stdout,
            )
        self.assertEqual(code, 1)
        self.assertEqual(
            timeout_stdout.getvalue(), "Cartography fixture bridge failed.\n"
        )

        class BrokenWriter:
            def write(self, _value):
                raise OSError("stdout-value")

        code, _stdout = self.run_main(stdout=BrokenWriter())
        self.assertEqual(code, 1)

    def test_run_main_rejects_output_larger_than_sixteen_kibibytes(self):
        with (
            mock.patch.object(fixture_runner, "_read_fixture", return_value=RAW_BYTES),
            mock.patch.object(
                fixture_runner, "_load_runtime", return_value=(FakeNeo4j, self.api)
            ),
            mock.patch.object(fixture_runner, "inspect_graph", return_value={"x": "a" * 16_385}),
            mock.patch.object(fixture_runner, "_absolute_deadline", self.fake_deadline),
        ):
            stdout = io.StringIO()
            code = fixture_runner.run_main(
                ["--fixture", FIXTURE_PATH, "--neo4j-uri", NEO4J_URI],
                ENVIRON,
                stdout,
            )

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "Cartography fixture bridge failed.\n")


if __name__ == "__main__":
    unittest.main()
