"""Render the exact upstream archives in CI; requires Helm and access to the mirror or GitHub."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from test_installer import ROOT, dep


def workload_containers(spec):
    # The Temporal 1.7.0 chart's schema Job emits an empty YAML key when migrations run externally.
    initial = spec.get("initContainers")
    if initial is None:
        initial = []
    main = spec["containers"]
    if not isinstance(initial, list) or not isinstance(main, list) or not main:
        raise ValueError("invalid rendered container lists")
    return initial + main


class PodContract(unittest.TestCase):
    def test_absent_or_null_init_containers_still_check_each_main_image(self):
        for source in ["containers: [{name: done}]", "initContainers:\ncontainers: [{name: done}]"]:
            self.assertEqual(workload_containers(yaml.safe_load(source)), [{"name": "done"}])
        self.assertEqual(workload_containers({"initContainers": [{"name": "migrate"}], "containers": [{"name": "server"}]}),
                         [{"name": "migrate"}, {"name": "server"}])
        for spec in [{"containers": []}, {"containers": None}, {"initContainers": "", "containers": [{}]}]:
            with self.assertRaises(ValueError):
                workload_containers(spec)


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
                        for c in workload_containers(pod["spec"]):
                            self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")
                    if kind == "Deployment":
                        deployments.add(resource["metadata"]["name"])
                if service == "temporal":
                    configs = "\n".join(str(x["data"]) for x in objects if x["kind"] == "ConfigMap" and x.get("data"))
                    for database in ["temporal-db", "temporal-visibility-db"]:
                        self.assertIn(dep.cluster_host(database), configs)
            self.assertEqual(deployments, set(dep.DEPLOYMENTS))
