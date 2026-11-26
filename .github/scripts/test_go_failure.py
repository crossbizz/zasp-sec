import json
import unittest

from go_failure import summarize


class GoFailureTest(unittest.TestCase):
    def test_reports_test_and_source_location_without_its_values(self):
        lines = [
            json.dumps({"Action": "output", "Output": "    config_test.go:19: secret-value"}),
            json.dumps({"Action": "fail", "Test": "TestConfiguration/case_1"}),
            json.dumps({"Action": "fail", "Test": "arbitrary data"}),
            "worker/client.go:7:2: compiler details",
        ]
        self.assertEqual(summarize(lines), "TestConfiguration/case_1, config_test.go:19, client.go:7:2")

    def test_ignores_unrecognized_output(self):
        self.assertEqual(summarize(["stdout from a test", json.dumps({"Action": "pass"})]), "")
