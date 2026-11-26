"""Exercise the public CLI with real OpenSSL/tar and a filesystem-backed s3api stand-in."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from lib.backup import new_output


ROOT = Path(__file__).resolve().parents[2]


class BackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyring = tempfile.TemporaryDirectory()
        base = Path(cls.keyring.name)
        cls.cert, cls.key = base / "cert.pem", base / "key.pem"
        subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", cls.key, "-out", cls.cert, "-subj", "/CN=backup-test"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.keyring.cleanup()

    def setUp(self):
        box = tempfile.TemporaryDirectory()
        self.addCleanup(box.cleanup)
        self.box = Path(box.name)
        self.source = self.box / "input"
        self.source.write_bytes(b"private backup marker" + os.urandom(8192))
        self.receipt = self.box / "backup.receipt"
        self.dest = self.box / "restore"
        self.credentials = self.box / "credentials"
        self.credentials.write_text("[default]\naws_access_key_id = fixture\naws_secret_access_key = secret-fixture\n")
        self.credentials.chmod(0o600)
        self.env = {"PATH": str(self.box) + ":" + os.environ["PATH"], "HOME": str(self.box),
                    "ZASP_BACKUP_PROVIDER": "r2", "ZASP_BACKUP_R2_ACCOUNT_ID": "c" * 32,
                    "ZASP_BACKUP_EXPECTED_BUCKET_OWNER": "123456789012", "ZASP_BACKUP_BUCKET": "backup-test", "ZASP_BACKUP_REGION": "us-east-1",
                    "ZASP_BACKUP_CREDENTIALS_FILE": str(self.credentials), "ZASP_BACKUP_IDENTITY_FILE": str(self.key),
                    "ZASP_BACKUP_RECIPIENT_FILE": str(self.cert), "AWS_ENDPOINT_URL": "http://bad.invalid",
                    "AWS_ACCESS_KEY_ID": "customer-key", "AWS_PROFILE": "customer", "AWS_CA_BUNDLE": "bad"}
        aws = self.box / "aws"
        aws.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
base=Path(__file__).parent
a=sys.argv[1:]
assert set(os.environ).isdisjoint({'AWS_ACCESS_KEY_ID','AWS_PROFILE','AWS_ENDPOINT_URL','AWS_CA_BUNDLE'})
assert '--no-verify-ssl' not in a
assert '--endpoint-url' not in a or a[a.index('--endpoint-url')+1].startswith('https://')
assert 'secret-fixture' in Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).read_text()
assert Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).stat().st_mode & 0o777 == 0o600
with (base/'calls').open('a') as f: f.write(json.dumps(a)+'\\n')
def value(name): return a[a.index(name)+1]
obj=base/('object-'+value('--key').split('/')[-1])
mode=(base/'mode').read_text() if (base/'mode').exists() else ''
if 'put-object' in a:
    assert value('--if-none-match') == '*'
    if mode == 'down': sys.exit(2)
    with obj.open('xb') as f: f.write(Path(value('--body')).read_bytes())
    if mode == 'ambiguous': sys.exit(1)
elif 'get-object' in a:
    if mode == 'down': sys.exit(2)
    data = obj.read_bytes()
    end = int(value('--range').split('-')[1])+1
    Path(a[-1]).write_bytes((data if mode != 'wrong' else b'corrupt')[:end])
else: sys.exit(3)
""")
        aws.chmod(0o700)

    def cli(self, *args, ok=True, **extra):
        result = subprocess.run(["bash", ROOT / "zasp", "--config", self.box / "zasp.env", *args],
                                cwd=self.box, env={**self.env, **extra}, capture_output=True, text=True)
        self.assertNotIn("secret-fixture", result.stdout + result.stderr)
        self.assertNotIn("customer-key", result.stdout + result.stderr)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def upload(self, **options):
        return self.cli("backup", "upload", self.source, self.receipt, **options)

    def download(self, **options):
        return self.cli("backup", "download", self.receipt, self.dest, **options)

    def test_r2_roundtrip_and_ambiguous_publish(self):
        (self.box / "mode").write_text("ambiguous")
        self.upload()
        self.download()
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.dest.stat().st_mode & 0o777, 0o600)
        raw = next(self.box.glob("object-*")).read_bytes()
        self.assertNotIn(b"private backup marker", raw)
        self.assertEqual(json.loads(self.receipt.read_text())["size"], len(raw))
        for args in map(json.loads, (self.box / "calls").read_text().splitlines()):
            self.assertIn("https://" + "c" * 32 + ".r2.cloudflarestorage.com", args)
            self.assertIn("auto", args)
        self.assertIn("exists", self.download(ok=False))

    def test_backup_profile_through_s3_and_restore(self):
        self.env["ZASP_BACKUP_PROVIDER"] = "s3"
        self.env["ZASP_STATE_DIR"] = str(self.box / "state")
        stack = self.box / "stack"
        self.env["ZASP_LOCAL_STACK_SCRIPT"] = str(stack)
        stack.write_text('#!/bin/sh\ncase "$1" in dump) printf db > "$2/postgres.sql" ;; load) test "$(cat "$2/postgres.sql")" = db ;; stop|verify) : ;; *) exit 8 ;; esac\n')
        stack.chmod(0o700)
        state = Path(self.env["ZASP_STATE_DIR"])
        (state / "secrets").mkdir(parents=True)
        (state / "up.done").touch()
        secret = state / "secrets" / "original"
        secret.write_text("credential for the fixture")
        self.cli("backup", self.receipt)
        self.assertEqual(json.loads(self.receipt.read_text())["kind"], "profile")
        self.assertIn("--yes", self.cli("restore", self.receipt, ok=False))
        secret.unlink()
        self.cli("restore", self.receipt, "--yes")
        self.assertEqual(secret.read_text(), "credential for the fixture")
        self.assertNotIn("--endpoint-url", (self.box / "calls").read_text())
        self.assertIn("us-east-1", (self.box / "calls").read_text())
        self.assertIn("--expected-bucket-owner", (self.box / "calls").read_text())

    def test_wrong_scope_corruption_and_restore_rejection(self):
        self.upload()
        self.assertIn("destination", self.download(ok=False, ZASP_BACKUP_BUCKET="other-bucket"))
        self.assertIn("this profile", self.cli("restore", self.receipt, "--yes", ok=False))
        self.assertIn("not automated", self.cli("--profile", "aws", "restore", self.receipt, "--yes", ok=False))
        self.assertIn("PostgreSQL replay", self.cli("--profile", "kubernetes", "restore", self.receipt, "--yes", ok=False))
        obj = next(self.box.glob("object-*"))
        original = obj.read_bytes()
        obj.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        self.assertIn("SHA-256", self.download(ok=False))
        obj.write_bytes(original + b"x")
        self.assertIn("SHA-256", self.download(ok=False))
        self.assertFalse(self.dest.exists())
        self.receipt.write_text('{"sha256":1}')
        self.assertIn("invalid receipt", self.download(ok=False))

    def test_local_encryption_authentication_and_permissions(self):
        self.env["ZASP_BACKUP_PROVIDER"] = "local"
        self.upload()
        self.download()
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())
        self.dest.unlink()
        data = bytearray(self.receipt.read_bytes())
        data[len(data) // 2] ^= 1
        self.receipt.write_bytes(data)
        self.assertIn("authentication", self.download(ok=False))
        self.assertFalse(self.dest.exists())
        self.assertFalse((self.box / "calls").exists())

    def test_remote_failure_produces_no_receipt(self):
        for mode in ["down", "wrong"]:
            with self.subTest(mode=mode):
                (self.box / "mode").write_text(mode)
                self.upload(ok=False)
                self.assertFalse(self.receipt.exists())
        self.credentials.chmod(0o644)
        self.assertIn("0600", self.upload(ok=False))
        self.assertIn("invalid ZASP_BACKUP_R2_ACCOUNT_ID", self.upload(ok=False, ZASP_BACKUP_R2_ACCOUNT_ID="invalid/url"))

    def test_credential_source_and_key_fail_closed(self):
        self.credentials.write_text("[default]\ncredential_process = other-tool\n")
        self.assertIn("one [default] section", self.upload(ok=False))
        self.credentials.write_text("bad credentials")
        self.assertIn("invalid backup credentials file", self.upload(ok=False))
        self.env["ZASP_BACKUP_PROVIDER"] = "local"
        self.upload()
        wrong = self.box / "wrong-key"
        wrong.write_text("not a private key")
        wrong.chmod(0o600)
        self.assertIn("authentication", self.download(ok=False, ZASP_BACKUP_IDENTITY_FILE=str(wrong)))
        self.assertFalse(self.dest.exists())

    def test_encrypted_recovery_key_and_passphrase_file(self):
        self.env["ZASP_BACKUP_PROVIDER"] = "local"
        password, protected_key = self.box / "password", self.box / "protected.pem"
        password.write_text("fixture-passphrase\n")
        password.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-aes-256-cbc", "-passout",
                        "file:" + str(password), "-out", protected_key], check=True)
        protected_key.chmod(0o600)
        self.upload()
        self.download(ZASP_BACKUP_IDENTITY_FILE=str(protected_key), ZASP_BACKUP_PASSPHRASE_FILE=str(password))
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())

    def test_missing_inputs_bad_configuration_and_oversized_receipt(self):
        self.assertIn("does not exist", self.download(ok=False))
        self.assertIn("usage", self.cli("backup", "download", self.receipt, ok=False))
        self.assertIn("usage", self.cli("restore", ok=False))
        self.assertIn("set ZASP_BACKUP_BUCKET", self.upload(ok=False, ZASP_BACKUP_BUCKET=""))
        self.assertIn("invalid ZASP_BACKUP_BUCKET", self.upload(ok=False, ZASP_BACKUP_BUCKET="invalid/name"))
        self.assertIn("invalid ZASP_BACKUP_REGION", self.upload(ok=False, ZASP_BACKUP_PROVIDER="s3", ZASP_BACKUP_REGION="*"))
        self.assertIn("invalid ZASP_BACKUP_EXPECTED_BUCKET_OWNER", self.upload(
            ok=False, ZASP_BACKUP_PROVIDER="s3", ZASP_BACKUP_EXPECTED_BUCKET_OWNER="unknown"))
        self.assertIn("local backup failed", self.cli("backup", self.receipt, ok=False))
        self.receipt.write_bytes(b"x" * 4097)
        self.assertIn("receipt size", self.download(ok=False))
        self.assertFalse(self.dest.exists())

    def test_competing_publication_and_oversize_before_encryption(self):
        with self.assertRaises(FileExistsError):
            with new_output(self.dest) as pending:
                pending.write_bytes(b"contender")
                self.dest.write_bytes(b"original")
        self.assertEqual(self.dest.read_bytes(), b"original")
        with self.source.open("wb") as stream:
            stream.truncate(5_000_000_001)
        self.assertIn("5 GB", self.upload(ok=False))
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.box / "calls").exists())

    def test_dry_run_legacy_default_and_protected_destinations(self):
        self.cli("--dry-run", "backup", "upload", self.source, self.receipt)
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.box / "calls").exists())
        self.receipt.symlink_to(self.dest)
        self.assertIn("exists", self.upload(ok=False))
        self.assertFalse(self.dest.exists())
        self.assertIn("must be local", self.upload(ok=False, ZASP_BACKUP_PROVIDER=""))
        self.assertIn("nothing is installed", self.cli("backup", self.dest, ok=False,
                       ZASP_BACKUP_PROVIDER="local", ZASP_BACKUP_RECIPIENT_FILE="", ZASP_BACKUP_IDENTITY_FILE=""))


class LiveBackupTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("ZASP_TEST_R2_BACKUP") == "1", "opt-in live R2 test")
    def test_r2(self):
        self.roundtrip("r2", {"ZASP_BACKUP_R2_ACCOUNT_ID": os.environ["ZASP_TEST_R2_BACKUP_ACCOUNT_ID"]})

    @unittest.skipUnless(os.environ.get("ZASP_TEST_S3_BACKUP") == "1", "opt-in live S3 test")
    def test_s3(self):
        self.roundtrip("s3", {"ZASP_BACKUP_EXPECTED_BUCKET_OWNER": os.environ["ZASP_TEST_S3_BACKUP_EXPECTED_BUCKET_OWNER"],
                              "ZASP_BACKUP_REGION": os.environ["ZASP_TEST_S3_BACKUP_REGION"]})

    def roundtrip(self, provider, destination):
        setting_prefix = "ZASP_TEST_" + provider.upper() + "_BACKUP_"
        bucket = os.environ[setting_prefix + "BUCKET"]
        self.assertTrue(bucket.startswith("zasp-contract-"), "use a dedicated zasp-contract-* bucket")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, receipt, output = root / "source", root / "receipt", root / "output"
            key, cert = root / "key", root / "certificate"
            source.write_bytes(os.urandom(8192))
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=ephemeral-backup-contract", "-keyout", key, "-out", cert],
                           check=True, capture_output=True)
            key.chmod(0o600)
            env = {**destination, "PATH": os.environ["PATH"], "HOME": directory, "ZASP_BACKUP_PROVIDER": provider,
                   "ZASP_BACKUP_BUCKET": bucket, "ZASP_BACKUP_CREDENTIALS_FILE": os.environ[setting_prefix + "CREDENTIALS_FILE"],
                   "ZASP_BACKUP_RECIPIENT_FILE": str(cert), "ZASP_BACKUP_IDENTITY_FILE": str(key)}
            cli = ["bash", ROOT / "zasp", "--config", root / "unused.env", "backup"]
            subprocess.run([*cli, "upload", source, receipt], check=True, env=env)
            subprocess.run([*cli, "download", receipt, output], check=True, env=env)
            self.assertEqual(source.read_bytes(), output.read_bytes())


if __name__ == "__main__":
    unittest.main()
