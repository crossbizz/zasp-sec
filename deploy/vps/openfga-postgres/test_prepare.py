import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TEST_IMAGE = "registry.example.test/cloudnative-pg/postgresql:18-fixture@sha256:" + "7" * 64


class OpenFGAPostgresTest(unittest.TestCase):
    def test_generated_credentials_and_catalog_match_the_workload(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "secret material"
            args = [sys.executable, HERE / "prepare.py", "--image", TEST_IMAGE, "--output", directory]
            result = subprocess.run(args, check=True, capture_output=True)
            self.assertEqual(result.stdout + result.stderr, b"")
            password = (directory / "password").read_text()
            uri = urlsplit((directory / "uri").read_text())
            self.assertEqual(uri.password, password)
            self.assertGreaterEqual(len(password), 48)
            self.assertEqual(uri.username, (directory / "username").read_text())
            self.assertEqual(uri.hostname, "openfga-db-rw.zasp-data.svc.cluster.local")
            self.assertEqual((uri.port, uri.path), (5432, "/openfga"))
            self.assertEqual(parse_qs(uri.query), {"sslmode": ["verify-full"], "sslrootcert": ["/etc/database-ca/ca.crt"]})
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(f.stat().st_mode & 0o777 == 0o600 for f in directory.iterdir()))
            catalog = json.loads((directory / "catalog.json").read_text())
            self.assertEqual(catalog["spec"]["images"], [{"major": 18, "image": TEST_IMAGE}])
            cluster, _ = yaml.safe_load_all((HERE / "cluster.yaml").read_text())
            self.assertEqual(catalog["metadata"]["name"], cluster["spec"]["imageCatalogRef"]["name"])
            self.assertEqual(catalog["metadata"]["namespace"], cluster["metadata"]["namespace"])
            rerun = subprocess.run(args, capture_output=True)
            self.assertNotEqual(rerun.returncode, 0)
            self.assertEqual((directory / "password").read_text(), password)

    def test_unpinned_image_cannot_create_credentials(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "new"
            result = subprocess.run([sys.executable, HERE / "prepare.py", "--image", "registry.example.test/postgres:18",
                                     "--output", directory], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(directory.exists())

    def test_database_admission_and_existing_openfga_chart_agree(self):
        cluster, network = yaml.safe_load_all((HERE / "cluster.yaml").read_text())
        spec = cluster["spec"]
        self.assertFalse(spec["enableSuperuserAccess"])
        self.assertEqual(spec["instances"], 1)
        self.assertEqual(spec["bootstrap"]["initdb"]["owner"], "openfga")
        self.assertTrue(spec["bootstrap"]["initdb"]["dataChecksums"])
        self.assertEqual(spec["postgresql"]["pg_hba"], ["hostssl openfga openfga all scram-sha-256", "host all all all reject"])
        self.assertEqual(spec["certificates"], {"serverTLSSecret": "openfga-db-tls", "serverCASecret": "openfga-db-public-ca"})
        self.assertEqual(network["spec"]["podSelector"]["matchLabels"]["cnpg.io/cluster"], cluster["metadata"]["name"])
        database, controller = network["spec"]["ingress"]
        self.assertEqual(database["ports"][0]["port"], 5432)
        self.assertEqual(database["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"], "zasp-runtime")
        self.assertEqual(database["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"], "openfga")
        self.assertEqual(controller["ports"][0]["port"], 8000)
        chart = yaml.safe_load((ROOT / "deploy/staging/openfga.values.yaml").read_text())
        self.assertEqual(chart["datastore"]["existingSecret"], "openfga-datastore")
        self.assertEqual(chart["datastore"]["secretKeys"]["uriKey"], "uri")
        for mounts in [chart["extraVolumeMounts"], chart["migrate"]["extraVolumeMounts"]]:
            self.assertIn({"name": "database-ca", "mountPath": "/etc/database-ca", "readOnly": True}, mounts)


if __name__ == "__main__":
    unittest.main()
