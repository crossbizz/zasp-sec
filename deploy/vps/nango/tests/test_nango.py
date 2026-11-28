"""Check database transport requirements, external network boundaries and Helm compatibility."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

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

    def test_pinned_nango_requires_uuid_v4_environment_key_and_independent_admin_key(self):
        startup = (CHART / "templates/workloads.yaml").read_text()
        check = startup.split("node --input-type=module <<'CHECK'\n", 1)[1].split("\n              CHECK", 1)[0]
        admin = "a" * 64
        key = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as scratch:
            mount = Path(scratch)
            (mount / "admin-key").write_text(admin)
            check = check.replace("/run/nango-storage", scratch)
            for service, expected in [(key, 0), (key.upper(), 0), ("b" * 64, 64),
                                      (key[:14] + "5" + key[15:], 64), (key + "\n", 64)]:
                with self.subTest(valid=expected == 0):
                    (mount / "service-key").write_text(service)
                    result = subprocess.run(["node", "--input-type=module", "-e", check], capture_output=True,
                                            env={**os.environ, "NANGO_SECRET_KEY_PROD": service.rstrip("\n"),
                                                 "NANGO_ADMIN_KEY": admin, "NANGO_ENCRYPTION_KEY": "fixture"})
                    self.assertEqual(result.returncode, expected)
                    self.assertEqual(result.stdout + result.stderr, b"")

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
        self.assertEqual(env["NANGO_SERVER_URL"]["value"], "https://zasp.example.test/api/v1/integrations")
        self.assertEqual(env["NANGO_PUBLIC_SERVER_URL"]["value"], "https://nango.connectors.svc.cluster.local:18443")
        self.assertEqual(env["FLAG_AUTH_ENABLED"]["value"], "true")
        self.assertEqual(env["AUTH_ALLOW_SIGNUP"]["value"], "false")
        proxy = resources["ConfigMap", "nango-tls-proxy"]["data"]["nginx.conf"]
        self.assertIn("listen 127.0.0.1:9443 ssl", proxy)
        self.assertIn("""sub_filter '"apiUrl": "https://zasp.example.test/api/v1/integrations"' '"apiUrl": "https://nango.connectors.svc.cluster.local:18443"'""", proxy)
        self.assertIn("X-Forwarded-Proto https", proxy)
        self.assertIn("location / { return 404; }", proxy)
        self.assertNotIn("NANGO_SECRET_KEY_PROD", env)
        storage = next(v["secret"] for v in deploy["volumes"] if v["name"] == "storage")
        self.assertEqual(storage["defaultMode"], 0o440)
        self.assertIn({"key": "service-key", "path": "service-key"}, storage["items"])
        job_volumes = resources["Job", "nango-migrate"]["spec"]["template"]["spec"]["volumes"]
        job_secrets = next(v["secret"] for v in job_volumes if v["name"] == "storage")
        self.assertEqual({item["key"] for item in job_secrets["items"]}, {"database-url", "encryption-key"})
        self.assertIn({"key": "admin-key", "path": "admin-key"}, storage["items"])
        self.assertFalse(deploy["automountServiceAccountToken"])
        private = resources["NetworkPolicy", "nango"]["spec"]
        self.assertEqual(private["ingress"][0]["ports"], [{"protocol": "TCP", "port": 8443}])
        self.assertEqual(private["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], "zasp")
        migrate = resources["NetworkPolicy", "nango-migrate"]["spec"]
        self.assertEqual(migrate["ingress"], [])
        self.assertNotIn({"protocol": "TCP", "port": 443}, [port for rule in migrate["egress"] for port in rule["ports"]])
        self.assertEqual(resources["Job", "nango-migrate"]["metadata"]["annotations"]["helm.sh/hook"], "pre-install,pre-upgrade")

    def test_private_gateway_is_opt_in_and_restricted_to_its_workload(self):
        config = {"hostname": "admin.private.example", "allowSignup": True,
                  "emailSecret": "nango-mail", "smtpEgressCIDRs": ["192.0.2.50/32"],
                  "clients": [{"namespace": "network", "workloads": ["private-admin-gateway"]}]}
        result = self.render(CHART, SETTINGS | {"dashboard": config}, "connectors")
        self.assertEqual(result.returncode, 0, result.stderr)
        resources = {o["kind"]: o for o in yaml.safe_load_all(result.stdout) if o["metadata"]["name"] in ("nango", "nango-tls-proxy")}
        self.assertEqual(resources["Service"]["spec"]["type"], "ClusterIP")
        self.assertEqual(resources["Service"]["spec"]["ports"][-1], {"name": "dashboard", "port": 18443, "targetPort": "dashboard"})
        policy = resources["NetworkPolicy"]["spec"]["ingress"][1]
        self.assertEqual(policy["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], "network")
        self.assertEqual(policy["from"][0]["podSelector"]["matchExpressions"][0]["values"], ["private-admin-gateway"])
        self.assertEqual(policy["ports"], [{"protocol": "TCP", "port": 9443}])
        self.assertIn("listen 9443 ssl", resources["ConfigMap"]["data"]["nginx.conf"])
        server = resources["Deployment"]["spec"]["template"]["spec"]["containers"][0]
        env = {x["name"]: x.get("value") for x in server["env"]}
        self.assertEqual(env["NANGO_PUBLIC_SERVER_URL"], "https://admin.private.example:18443")
        self.assertEqual(env["AUTH_ALLOW_SIGNUP"], "true")
        smtp = next(item for item in server["env"] if item["name"] == "SMTP_URL")
        self.assertEqual(smtp["valueFrom"]["secretKeyRef"], {"name": "nango-mail", "key": "smtp-url"})
        mail_policy = resources["NetworkPolicy"]["spec"]["egress"][-1]
        self.assertEqual(mail_policy, {"to": [{"ipBlock": {"cidr": "192.0.2.50/32"}}],
                                       "ports": [{"protocol": "TCP", "port": 465}]})

    def test_rejects_broad_egress_or_insecure_origin(self):
        for changes in [{"databaseEgressCIDRs": ["0.0.0.0/0"]}, {"providerEgressCIDRs": []},
                        {"publicOrigin": "http://zasp.example.test"}, {"tlsProxyImage": "nginx:latest"},
                        {"clients": []}, {"dashboard": {"emailSecret": "mail"}}]:
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
