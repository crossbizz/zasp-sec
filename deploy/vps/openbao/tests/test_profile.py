"""Checks that apply to every deployable release of the OpenBao profile."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

import yaml

CHART = Path(__file__).resolve().parents[1]
IMAGE = "quay.io/openbao/openbao@sha256:" + "a" * 64


class OpenBaoConfiguration(unittest.TestCase):
    def test_image_schema_requires_digest(self):
        schema = json.loads((CHART / "values.schema.json").read_text())
        pattern = schema["properties"]["image"]["pattern"]
        self.assertRegex(IMAGE, pattern)
        for value in ["", "quay.io/openbao/openbao:latest", "bao@sha256:abcd"]:
            self.assertIsNone(re.fullmatch(pattern, value))

    def test_server_paths_and_tls(self):
        config = (CHART / "files/server.hcl").read_text()
        self.assertIn('storage "raft"', config)
        self.assertIn('path = "/openbao/data"', config)
        self.assertIn('tls_key_file = "/openbao/tls/tls.key"', config)
        self.assertIn('tls_cert_file = "/openbao/tls/tls.crt"', config)
        self.assertIn('tls_min_version = "tls12"', config)
        self.assertNotIn("tls_disable", config)
        self.assertNotIn('seal "', config)

    def test_snapshot_policy_has_only_read(self):
        policy = (CHART / "files/snapshot-reader.hcl").read_text()
        self.assertEqual(re.findall(r'path "([^"]+)"', policy), ["sys/storage/raft/snapshot"])
        self.assertEqual(re.findall(r'capabilities = \[(.*?)\]', policy), ['"read"'])


@unittest.skipUnless(shutil.which("helm"), "helm is required for render tests")
class OpenBaoRender(unittest.TestCase):
    def render(self, *values):
        return subprocess.run(
            ["helm", "template", "independent", str(CHART), "-n", "pilot-bao", *values],
            capture_output=True, text=True,
        )

    def test_no_unpinned_image_or_empty_client_selector(self):
        for values in ([], ["--set-string", "image=bao:latest"],
                       ["--set-string", "image=" + IMAGE, "--set-json", "clientPodLabels=null"]):
            self.assertNotEqual(self.render(*values).returncode, 0)

    def test_isolated_persistent_single_node(self):
        result = self.render("--set-string", "image=" + IMAGE, "--set-string", "storageClass=encrypted")
        self.assertEqual(result.returncode, 0, result.stderr)
        objects = {obj["kind"]: obj for obj in yaml.safe_load_all(result.stdout)}
        self.assertEqual(set(objects), {"ConfigMap", "Service", "NetworkPolicy", "StatefulSet"})
        self.assertEqual(objects["ConfigMap"]["data"]["server.hcl"].strip(),
                         (CHART / "files/server.hcl").read_text().strip())
        stateful = objects["StatefulSet"]["spec"]
        pod = stateful["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(stateful["replicas"], 1)
        self.assertEqual(container["image"], IMAGE)
        self.assertEqual(container["command"], ["/usr/bin/bao", "server", "-config=/openbao/config/server.hcl"])
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["readinessProbe"]["exec"]["command"], ["/usr/bin/bao", "status"])
        self.assertEqual(stateful["volumeClaimTemplates"][0]["spec"]["storageClassName"], "encrypted")
        env = {entry["name"]: entry["value"] for entry in container["env"]}
        self.assertEqual(env["BAO_API_ADDR"], "https://openbao.pilot-bao.svc:8200")
        self.assertEqual(env["BAO_CACERT"], "/openbao/tls/ca.crt")
        self.assertNotIn("BAO_TOKEN", env)
        self.assertEqual(objects["Service"]["spec"]["clusterIP"], "None")
        policy = objects["NetworkPolicy"]["spec"]
        self.assertEqual(policy["egress"], [])
        self.assertEqual(policy["ingress"], [{
            "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "zasp"}},
                      "podSelector": {"matchLabels": {"zasp.io/openbao-client": "true"}}}],
            "ports": [{"protocol": "TCP", "port": 8200}],
        }])


if __name__ == "__main__":
    unittest.main()
