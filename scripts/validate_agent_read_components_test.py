"""Synthetic validator checks only: these never establish Go or native passes."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import validate_agent_read_components as guard


def synthetic_events(packages=None):
    """Construct a complete synthetic lifecycle without writing workflow artifacts."""
    events = []
    for package, names in guard.EXPECTED.items():
        if packages is not None and package not in packages:
            continue
        events.append({"Action": "start", "Package": package})
        def emit(name):
            events.append({"Action": "run", "Package": package, "Test": name})
            for child in names:
                if child.rpartition("/")[0] == name:
                    emit(child)
            events.append({"Action": "pass", "Package": package, "Test": name})
        for name in names:
            if "/" not in name:
                emit(name)
        events.append({"Action": "pass", "Package": package})
    return events


class AgentReadComponentValidatorTests(unittest.TestCase):
    def test_synthetic_complete_76_is_validator_acceptance_only(self):
        self.assertEqual([len(names) for names in guard.EXPECTED.values()], [51, 1, 11, 13])
        self.assertEqual(guard.validate_events(synthetic_events(), 0), {
            "classification": "component-only", "packages": 4, "named_passes": 76})

    def test_partial_failed_skipped_extra_and_malformed_lifecycles_reject(self):
        full = synthetic_events()
        migrations = next(package for package in guard.EXPECTED if package.endswith("/migrations"))
        target = next(event["Test"] for event in full if event.get("Test", "").endswith("/unknown_profile"))
        variants = {"empty": [], "only_migration_13": synthetic_events({migrations}),
                    "one_missing_case": [event for event in full if event.get("Test") != target]}
        for action in ["fail", "skip", "bench", "unknown"]:
            value = copy.deepcopy(full)
            value[2]["Action"] = action
            variants[action] = value
        value = copy.deepcopy(full); value.insert(3, dict(value[1])); variants["duplicate_run"] = value
        index = next(i for i, event in enumerate(full) if event.get("Test") == target and event["Action"] == "pass")
        value = copy.deepcopy(full); value.insert(index + 1, dict(value[index])); variants["duplicate_pass"] = value
        value = copy.deepcopy(full); value[1]["Test"] = "TestAgentCurrentReadProfilePostgres"; variants["native_or_unknown_case"] = value
        value = copy.deepcopy(full); value[0]["Package"] = "unexpected/package"; variants["unknown_package"] = value
        value = copy.deepcopy(full); value[0]["Package"] = []; variants["malformed_package"] = value
        value = copy.deepcopy(full); value[1]["Action"] = "pass"; variants["unstarted_parent_pass"] = value
        value = copy.deepcopy(full); value[2]["Action"] = "pass"; variants["premature_child_pass"] = value
        value = copy.deepcopy(full); value[-1]["Action"] = "output"; value[-1]["Output"] = "synthetic"; variants["missing_package_pass"] = value
        value = copy.deepcopy(full); value[2]["Elapsed"] = 10**1000; variants["oversized_elapsed"] = value
        value = copy.deepcopy(full); value[2]["Elapsed"] = True; variants["boolean_elapsed"] = value
        value = copy.deepcopy(full); value[1]["FailedBuild"] = "synthetic"; variants["build_failure"] = value
        for name, events in variants.items():
            with self.subTest(name=name), self.assertRaises(guard.EvidenceRejected):
                guard.validate_events(events, 0)
        for exit_code in [1, -1, None, True]:
            with self.subTest(exit_code=exit_code), self.assertRaises(guard.EvidenceRejected):
                guard.validate_events(full, exit_code)

    def test_json_lines_require_bounded_unique_well_formed_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.jsonl"
            path.write_text("\n".join(json.dumps(event) for event in synthetic_events()) + "\n")
            self.assertEqual(guard.validate_events(guard.load_events(path), 0)["named_passes"], 76)
            for raw in [b"", b"not-json\n", b'{}\n\n', b'{"Package":"a","Package":"b"}\n', b'{"Elapsed":NaN}\n', b"x"*(guard.MAXIMUM_LINE_BYTES + 1)]:
                with self.subTest(length=len(raw)), self.assertRaises(guard.EvidenceRejected):
                    path.write_bytes(raw)
                    guard.load_events(path)

    def test_complete_source_custody_rejects_missing_drift_duplicate_and_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = []
            for relative in sorted(guard.REQUIRED_SOURCE_PATHS):
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic source fixture")
                sources.append({"path": relative, "bytes": path.stat().st_size,
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            manifest = root / "source-manifest.json"
            def check(rows):
                manifest.write_text(json.dumps({"sources": rows}))
                return guard.check_sources(root, manifest)
            self.assertEqual(check(sources)["sources"], len(guard.REQUIRED_SOURCE_PATHS))
            bad = copy.deepcopy(sources); bad[0]["sha256"] = "0"*64
            for name, rows in {"missing_required": sources[1:], "duplicate": sources+[sources[0]],
                               "digest_drift": bad, "escape": [{"path": "../outside", "bytes": 0, "sha256": "0"*64}]}.items():
                with self.subTest(name=name), self.assertRaises(guard.EvidenceRejected):
                    check(rows)
            first = root / sources[0]["path"]
            first.unlink(); destination = root / "alias-target"; destination.write_bytes(b"synthetic source fixture")
            first.symlink_to(destination)
            with self.assertRaises(guard.EvidenceRejected):
                check(sources)


if __name__ == "__main__":
    unittest.main()
