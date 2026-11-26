"""Render the exact upstream archives in CI; requires Helm and access to the mirror or GitHub."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from test_installer import ROOT, dep


@unittest.skipUnless(os.environ.get("ZASP_TEST_RUNTIME_HELM") == "1", "enable real pinned chart rendering with ZASP_TEST_RUNTIME_HELM=1")
class PinnedCharts(unittest.TestCase):
    def test_real_helm_resources_satisfy_database_network_and_image_contract(self):
        with tempfile.TemporaryDirectory() as name:
            temp = Path(name)
            deployments = set()
            for service, archive in dep.charts(temp).items():
                overrides = temp / (service + ".json")
                overrides.write_text(json.dumps(dep.values(ROOT, service)))
                result = subprocess.run(["helm", "template", service, str(archive), "--namespace", dep.RUNTIME,
                                         "-f", str(overrides), "--skip-tests"], capture_output=True, timeout=60, check=True)
                objects = [r for r in yaml.safe_load_all(result.stdout) if r]
                self.assertTrue(any(r["kind"] == "Service" for r in objects))
                for resource in objects:
                    kind = resource["kind"]
                    self.assertNotIn(kind, {"Ingress", "Gateway", "HTTPRoute"})
                    if kind == "Service":
                        self.assertEqual(resource["spec"].get("type", "ClusterIP"), "ClusterIP")
                        self.assertFalse(resource["spec"].get("externalIPs"))
                    if kind in {"Job", "Deployment", "StatefulSet"}:
                        pod = resource["spec"]["template"]
                        for key, value in dep.workload_labels(service).items():
                            self.assertEqual(pod["metadata"]["labels"][key], value)
                        for c in pod["spec"].get("initContainers", []) + pod["spec"]["containers"]:
                            self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
                    if kind == "Deployment":
                        deployments.add(resource["metadata"]["name"])
                if service == "temporal":
                    configs = "\n".join(str(x["data"]) for x in objects if x["kind"] == "ConfigMap" and x.get("data"))
                    for database in ["temporal-db", "temporal-visibility-db"]:
                        self.assertIn(dep.cluster_host(database), configs)
            self.assertEqual(deployments, set(dep.DEPLOYMENTS))
