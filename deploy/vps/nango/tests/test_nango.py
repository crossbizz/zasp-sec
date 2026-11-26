"""Check database transport requirements, external network boundaries and Helm compatibility."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

CHART = Path(__file__).resolve().parents[1]
PRODUCT = CHART.parents[1] / "staging/product"
IMAGE = "registry.example/nginx-unprivileged@sha256:" + "1" * 64
SETTINGS = {
    "publicOrigin": "https://zasp.example.test", "tlsProxyImage": IMAGE,
    "databaseEgressCIDRs": ["192.0.2.10/32"], "providerEgressCIDRs": ["198.51.100.5/32"],
}


class DatabaseTransport(unittest.TestCase):
    def test_both_processes_use_validated_database_url(self):
        tpl = (CHART / "templates/workloads.yaml").read_text()
        self.assertEqual(tpl.count('include "nango.dbCheck"'), 2)
        self.assertEqual(tpl.count('include "nango.databaseEnv"'), 2)

    def test_db_url_guard_fails_closed_without_printing_credentials(self):
        helper = (CHART / "templates/_helpers.tpl").read_text()
        command = helper.split('{{- define "nango.dbCheck" -}}\n', 1)[1].split("\n", 1)[0]
        good = "postgresql://drill:fixture@database.private:5432/nango?sslmode=verify-full"
        for url, records_url, expected in [
            (good, good, 0), (good, good + "x", 64), ("invalid", "invalid", 64),
            *[(bad, bad, 64) for bad in [
                good.replace("verify-full", "require"), good.replace("@database.private:5432", "@database.private"),
                good.replace("drill:fixture@", ""), good + "&sslrootcert=system",
                good + "&sslmode=disable", good + "#extra", good.replace("postgresql:", "http:"),
            ]],
        ]:
            with self.subTest(url=url):
                result = subprocess.run(["sh", "-ec", command], capture_output=True,
                                        env={**os.environ, "NANGO_DATABASE_URL": url, "RECORDS_DATABASE_URL": records_url})
                self.assertEqual(result.returncode, expected)
                self.assertEqual(result.stdout + result.stderr, b"")


@unittest.skipUnless(shutil.which("helm"), "helm is required for render tests")
class NangoRender(unittest.TestCase):
    def render(self, chart, values, namespace):
        with tempfile.NamedTemporaryFile(mode="w") as f:
            json.dump(values, f)
            f.flush()
            return subprocess.run(["helm", "template", "test", str(chart), "-n", namespace, "-f", f.name],
                                  capture_output=True, text=True)

    def test_external_service_and_migration(self):
        result = self.render(CHART, SETTINGS, "connectors")
        self.assertEqual(result.returncode, 0, result.stderr)
        resources = {(o["kind"], o["metadata"]["name"]): o for o in yaml.safe_load_all(result.stdout)}
        svc = resources["Service", "nango"]["spec"]
        self.assertEqual(svc["ports"], [{"name": "https", "port": 8443, "targetPort": "https"}])
        deploy = resources["Deployment", "nango"]["spec"]["template"]["spec"]
        container, tls = deploy["containers"]
        self.assertEqual(tls["image"], IMAGE)
        env = {e["name"]: e for e in container["env"]}
        self.assertEqual(env["NANGO_PUBLIC_CONNECT_URL"]["value"], "https://nango.connectors.svc.cluster.local:8443/connect")
        self.assertEqual(env["NANGO_PUBLIC_SERVER_URL"]["value"], "https://zasp.example.test/api/v1/integrations")
        self.assertNotIn("NANGO_SECRET_KEY_PROD", env)
        storage = next(v["secret"] for v in deploy["volumes"] if v["name"] == "storage")
        self.assertEqual(storage["defaultMode"], 0o440)
        self.assertIn({"key": "service-key", "path": "service-key"}, storage["items"])
        job_volumes = resources["Job", "nango-migrate"]["spec"]["template"]["spec"]["volumes"]
        job_secrets = next(v["secret"] for v in job_volumes if v["name"] == "storage")
        self.assertNotIn("service-key", [item["key"] for item in job_secrets["items"]])
        self.assertFalse(deploy["automountServiceAccountToken"])
        private = resources["NetworkPolicy", "nango"]["spec"]
        self.assertEqual(private["ingress"][0]["ports"], [{"protocol": "TCP", "port": 8443}])
        self.assertEqual(private["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], "zasp")
        migrate = resources["NetworkPolicy", "nango-migrate"]["spec"]
        self.assertEqual(migrate["ingress"], [])
        self.assertNotIn({"protocol": "TCP", "port": 443}, [port for rule in migrate["egress"] for port in rule["ports"]])
        self.assertEqual(resources["Job", "nango-migrate"]["metadata"]["annotations"]["helm.sh/hook"], "pre-install,pre-upgrade")

    def test_rejects_broad_egress_or_insecure_origin(self):
        for changes in [{"databaseEgressCIDRs": ["0.0.0.0/0"]}, {"providerEgressCIDRs": []},
                        {"publicOrigin": "http://zasp.example.test"}, {"tlsProxyImage": "nginx:latest"},
                        {"clients": []}]:
            self.assertNotEqual(self.render(CHART, SETTINGS | changes, "connectors").returncode, 0)

    def test_external_product_profile_renders_only_scoped_egress(self):
        # Isolate the product's Nango templates from unrelated EKS dependencies.
        with tempfile.TemporaryDirectory() as d:
            chart = Path(d)
            shutil.copy(PRODUCT / "Chart.yaml", chart)
            (chart / "templates").mkdir()
            for name in ["nango.yaml", "nango-external.yaml"]:
                shutil.copy(PRODUCT / "templates" / name, chart / "templates")
            values = {"profile": "single_tenant", "nango": {"externalNamespace": "connectors"}, "discovery": {}}
            result = self.render(chart, values, "zasp")
            self.assertEqual(result.returncode, 0, result.stderr)
            resources = list(yaml.safe_load_all(result.stdout))
            self.assertEqual(len(resources), 1)
            pol = resources[0]["spec"]
            self.assertEqual(pol["podSelector"]["matchExpressions"][0]["values"], ["agentsec-api"])
            dest = pol["egress"][0]["to"][0]
            self.assertEqual(dest, {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "connectors"}},
                                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "nango"}}})
            self.assertNotEqual(self.render(chart, values, "connectors").returncode, 0)


if __name__ == "__main__":
    unittest.main()
