import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_installer import dep, make_installer
from prepare_inputs import prepare


class OperatorInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.tls = cls.directory / "certificates"
        cls.tls.mkdir(mode=0o700)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.tls, capture_output=True, timeout=15, check=True)
        for group in ["database", "runtime"]:
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                    "-keyout", group + "-ca.key", "-out", group + "-ca.crt", "-days", "1", "-subj", "/CN=" + group + "-root")
        for name in [*dep.DBS, "openfga", "temporal-frontend", "temporal-internode"]:
            db = name in dep.DBS
            group = "database" if db else "runtime"
            host = dep.cluster_host(name) if db else name + ".zasp-runtime.svc.cluster.local"
            openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                    "-keyout", name + ".key", "-out", "request.pem", "-subj", "/CN=" + name)
            (cls.tls / "ext").write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth,clientAuth\n")
            openssl("x509", "-req", "-in", "request.pem", "-CA", group + "-ca.crt", "-CAkey", group + "-ca.key",
                    "-CAcreateserial", "-days", "1", "-extfile", "ext", "-out", name + ".crt")
        cls.output = cls.directory / "credentials.json"
        prepare(cls.tls, cls.output)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_private_manifest_roundtrip_and_no_replacement(self):
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        previous = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            prepare(self.tls, self.output)
        self.assertEqual(self.output.read_bytes(), previous)
        items = json.loads(previous)["items"]
        index = {(v["metadata"]["namespace"], v["metadata"]["name"]): v for v in items}
        unit = make_installer()
        def secret(ns, kind, name):
            self.assertEqual(kind, "secret")
            return index[(ns, name)]
        with patch.object(unit, "get", side_effect=secret):
            unit.secrets()
            index[dep.RUNTIME, "temporal-persistence"]["data"]["password"] = index[dep.DATA, "openfga-db-owner"]["data"]["password"]
            with self.assertRaisesRegex(dep.Rejected, "password mismatch"):
                unit.secrets()

    def test_wrong_server_certificate_and_insecure_key_mode_leave_no_output(self):
        other = self.directory / "bad.json"
        cert = self.tls / "openfga.crt"
        good = cert.read_bytes()
        try:
            cert.write_bytes((self.tls / "temporal-frontend.crt").read_bytes())
            with self.assertRaisesRegex(ValueError, "TLS certificate validation failed"):
                prepare(self.tls, other)
            self.assertFalse(other.exists())
        finally:
            cert.write_bytes(good)
        key = self.tls / "openfga.key"
        try:
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private keys"):
                prepare(self.tls, other)
            self.assertFalse(other.exists())
        finally:
            key.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
