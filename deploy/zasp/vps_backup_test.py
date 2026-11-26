"""VPS CLI recovery tests; no customer data, kubeconfig or cloud access."""
import hashlib
import http.server
import shutil
import socket
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tarfile
import tempfile
import threading
import unittest
import unittest.mock

import offsite_backup_test as existing


def snapshot(complete=True):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name in (["state.bin", "SHA256SUMS.sealed"] if complete else ["state.bin"]):
            info = tarfile.TarInfo(name)
            info.size = 3
            bundle.addfile(info, io.BytesIO(b"foo"))
    return buffer.getvalue()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/v1/sys/storage/raft/snapshot" or self.headers.get("X-Vault-Token") != "snapshot-reader":
            self.send_error(403)
            return
        self.send_response(self.server.code)
        data = self.server.snapshot
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class VPSBackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        existing.BackupTests.setUpClass()
        cls.location = tempfile.TemporaryDirectory()
        base = Path(cls.location.name)
        cls.ca, key = base / "ca.pem", base / "key.pem"
        subprocess.run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", key, "-out", cls.ca], check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cls.ca, key)
        cls.server.socket = tls.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.location.cleanup()
        existing.BackupTests.tearDownClass()

    def setUp(self):
        self.base = existing.BackupTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.box, self.env = self.base.box, self.base.env
        self.specfile = self.box / "capture.json"
        self.receipts = self.box / "ledger"
        self.receipts.mkdir(mode=0o700)
        self.recovery = self.box / "restored"
        self.env.update(ZASP_PROFILE="vps", ZASP_VPS_INSTALLATION_ID="pilot-west", ZASP_VPS_BACKUP_SPEC_FILE=str(self.specfile),
                        ZASP_VPS_BACKUP_RECEIPT_DIR=str(self.receipts), ZASP_VPS_RESTORE_DIRECTORY=str(self.recovery))
        self.server.code, self.server.snapshot = 200, snapshot()
        self.config = self.box / "release.json"
        secret = self.box / "nango-key"
        readtoken = self.box / "token"
        password = self.box / "password"
        for path, value in [(self.config,'{"release":"sha256-pinned"}'),(secret,"original-key"),(readtoken,"snapshot-reader"),(password,"test:password")]:
            path.write_text(value)
            path.chmod(0o600)
        self.spec = json.loads((existing.ROOT / "deploy/vps/backup/sources.example.json").read_text())
        self.spec["sources"]["release-config"]["path"] = str(self.config)
        self.spec["sources"]["nango-encryption-key"]["path"] = str(secret)
        for name in ("nango-postgres","openfga-postgres"):
            self.spec["sources"][name].update(password_file=str(password), ca_file=str(self.ca))
        self.spec["sources"]["openbao-raft"].update(address=f"https://localhost:{self.server.server_port}",
                                                     ca_file=str(self.ca), token_file=str(readtoken))
        self.write_spec()
        self.command("pg_dump", """import os, sys
from pathlib import Path
assert os.environ['PGSSLMODE'] == 'verify-full'
assert os.environ['PGAPPNAME'] == 'zasp-backup'
assert 'PGPASSWORD' not in os.environ
assert 'AWS_ACCESS_KEY_ID' not in os.environ
assert Path(os.environ['PGPASSFILE']).stat().st_mode & 0o777 == 0o600
assert 'test\\\\:password' in Path(os.environ['PGPASSFILE']).read_text()
assert 'password' not in ' '.join(sys.argv).replace('--no-password','')
Path(sys.argv[-1]).write_bytes(b'PGDMP:'+os.environ['PGDATABASE'].encode())
""")
        self.command("pg_restore","import sys\nfrom pathlib import Path\nassert sys.argv[1]=='--list' and Path(sys.argv[-1]).read_bytes().startswith(b'PGDMP:')")
        aws = self.box / "aws"
        aws.write_text(aws.read_text().replace("else: sys.exit(3)", "elif 'delete-object' in a: obj.unlink(missing_ok=True)\nelse: sys.exit(3)"))

    def command(self, name, source):
        f = self.box / name
        f.write_text("#!/usr/bin/env python3\n"+source+"\n")
        f.chmod(0o700)

    def write_spec(self):
        self.specfile.write_text(json.dumps(self.spec))
        self.specfile.chmod(0o600)

    def cli(self,*args,**kw):
        result = self.base.cli(*args, **kw)
        for secret in ("test:password", "snapshot-reader", "original-key"):
            self.assertNotIn(secret, result)
        return result

    def test_public_backup_and_fresh_recovery(self):
        receipt = self.box / "backup.json"
        self.cli("backup", receipt)
        self.assertEqual(json.loads(receipt.read_text())["profile"],"vps")
        self.assertIn("--yes",self.cli("restore",receipt,ok=False))
        self.cli("restore",receipt,"--yes")
        self.assertEqual((self.recovery/"nango-encryption-key").read_bytes(), b"original-key")
        self.assertEqual((self.recovery/"openbao-raft").read_bytes(), self.server.snapshot)
        self.assertEqual((self.recovery/"openfga-postgres").read_bytes(), b"PGDMP:openfga")
        manifest = json.loads((self.recovery/"manifest.json").read_text())
        self.assertEqual(manifest["sources"]["nango-postgres"]["sha256"],hashlib.sha256(b"PGDMP:nango").hexdigest())
        self.assertEqual(manifest["sources"]["s3-evidence"]["type"],"external")
        self.assertNotIn("password",json.dumps(manifest))
        self.assertTrue(all(x.stat().st_mode & 0o777 == 0o600 for x in self.recovery.iterdir()))
        self.assertIn("new destination",self.cli("restore",receipt,"--yes",ok=False))

    def test_installation_identity_blocks_mixed_bundles_and_inventories(self):
        self.assertIn("different VPS installation", self.cli("backup","scheduled",ok=False,ZASP_VPS_INSTALLATION_ID="other"))
        self.cli("backup","scheduled")
        receipt=next(self.receipts.glob("*.json"))
        self.assertEqual(json.loads(receipt.read_text())["installation"],"pilot-west")
        self.assertIn("different VPS installation",self.cli("restore",receipt,"--yes",ok=False,ZASP_VPS_INSTALLATION_ID="other"))
        self.assertIn("different VPS installation",self.cli("backup","prune","--yes",ok=False,ZASP_VPS_INSTALLATION_ID="other"))
        self.assertFalse(self.recovery.exists())

    def test_refuses_sealed_redirect_incomplete_and_wrong_tls_host(self):
        for code, snap in [(503,snapshot()),(302,snapshot()),(200,snapshot(False))]:
            self.server.code,self.server.snapshot=code,snap
            self.cli("backup","scheduled",ok=False)
            self.assertFalse(list(self.receipts.glob("*.json")))
        self.spec["sources"]["openbao-raft"]["address"]=f"https://127.0.0.1:{self.server.server_port}"
        self.write_spec()
        self.cli("backup","scheduled",ok=False)
        self.assertFalse(list(self.box.glob("object-*")))

    def test_manifest_mismatch_never_publishes_plaintext(self):
        import lib.vps_backup as vps
        archive=self.box/"archive.tar"
        with unittest.mock.patch.dict(os.environ,self.env):
            vps.capture(archive)
            rewritten=self.box/"tampered"
            with tarfile.open(archive) as original, tarfile.open(rewritten,"w") as out:
                for member in original:
                    data=original.extractfile(member).read()
                    if member.name=="nango-encryption-key":
                        data=b"x"*len(data)
                    out.addfile(member,io.BytesIO(data))
            with self.assertRaisesRegex(vps.RecoveryError,"does not match"):
                vps.recover(rewritten)
        self.assertFalse(self.recovery.exists())

    def test_explicit_retention_preserves_drilled_and_recent_backups(self):
        self.env["ZASP_VPS_BACKUP_KEEP"]="2"
        # Generate immutable receipt names independently of seconds resolution,
        # then put them in known chronological order under the scheduler schema.
        for i in range(4):
            self.cli("backup","scheduled")
            generated = next(p for p in self.receipts.glob("*.json") if not p.name.startswith("vps-202501"))
            generated.rename(self.receipts/f"vps-2025010{i+1}T000000Z-{'a'*32}.receipt.json")
        names=sorted(self.receipts.glob("*.json"))
        protected=self.box/"independently-restored.receipt"
        protected.write_bytes(names[0].read_bytes())
        protected.chmod(0o600)
        self.env["ZASP_VPS_BACKUP_VERIFIED_RECEIPT"]=str(protected)
        self.cli("backup","prune",ok=False)
        self.assertEqual(len(list(self.box.glob("object-*"))),4)
        (self.box/"mode").write_text("down")
        self.cli("backup","prune","--yes",ok=False)
        self.assertEqual(len(list(self.receipts.glob("*.json"))),4)
        (self.box/"mode").unlink()
        self.cli("backup","prune","--yes")
        self.assertEqual(len(list(self.box.glob("object-*"))),3)
        self.assertEqual(list((self.receipts/"pruned").glob("*.json")),[self.receipts/"pruned"/names[1].name])
        self.cli("restore",protected,"--yes")

    def test_known_unlock_material_cannot_be_included_as_configuration(self):
        key_alias = self.box / "key-alias"
        os.link(self.env["ZASP_BACKUP_IDENTITY_FILE"], key_alias)
        self.spec["sources"]["release-config"]["path"] = str(key_alias)
        self.write_spec()
        self.assertIn("unlock", self.cli("backup", "scheduled", ok=False))
        self.assertFalse(list(self.box.glob("object-*")))

    def test_spec_checks_coverage_modes_and_dry_run(self):
        self.cli("--dry-run","backup","scheduled")
        self.assertFalse(any(self.receipts.iterdir()))
        self.spec["sources"]["nango-encryption-key"]={"type":"absent","reference":"unknown"}
        self.write_spec()
        self.cli("backup","scheduled",ok=False)
        self.spec["sources"].pop("neo4j")
        self.write_spec()
        self.cli("backup","scheduled",ok=False)
        self.specfile.chmod(0o644)
        self.assertIn("permissions", self.cli("backup","scheduled",ok=False))


@unittest.skipUnless(os.environ.get("ZASP_TEST_VPS_POSTGRES") == "1", "opt-in disposable PostgreSQL restore")
class PostgresRestoreTest(unittest.TestCase):
    def test_verified_dump_restores_to_fresh_database(self):
        from lib.vps_backup import postgres
        for program in ("initdb", "pg_ctl", "pg_dump", "pg_restore", "psql"):
            self.assertIsNotNone(shutil.which(program), program + " must be on PATH")
        with tempfile.TemporaryDirectory() as temporary:
            work=Path(temporary)
            data, password = work / "data", work / "password"
            password.write_text("ephemeral-database-password")
            password.chmod(0o600)
            key, cert = work / "key", work / "ca"
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost",
                            "-addext","subjectAltName=DNS:localhost","-keyout",key,"-out",cert],check=True,capture_output=True)
            key.chmod(0o600)
            with socket.socket() as free:
                free.bind(("127.0.0.1",0))
                port = free.getsockname()[1]
            subprocess.run(["initdb","-D",data,"-U","fixture","--auth-local=trust","--auth-host=scram-sha-256",
                            "--pwfile",password],check=True,capture_output=True)
            with (data/"postgresql.conf").open("a") as config:
                config.write(f"\nlisten_addresses='127.0.0.1'\nport={port}\nunix_socket_directories='{work}'\n"
                             f"ssl=on\nssl_cert_file='{cert}'\nssl_key_file='{key}'\n")
            subprocess.run(["pg_ctl","-D",data,"-l",work/"pg.log","-w","start"],check=True,capture_output=True)
            try:
                conn={"PATH":os.environ["PATH"],"PGHOST":str(work),"PGPORT":str(port),"PGUSER":"fixture","PGDATABASE":"postgres"}
                def sql(statement, database="postgres"):
                    return subprocess.run(["psql","-XAt","-v","ON_ERROR_STOP=1","-c",statement],env={**conn,"PGDATABASE":database},
                                          check=True,capture_output=True,text=True).stdout.strip()
                sql("CREATE TABLE restore_fixture(id integer PRIMARY KEY, evidence text)")
                sql("INSERT INTO restore_fixture VALUES(1, 'retained evidence')")
                dump=work/"database.dump"
                postgres({"host":"localhost","port":port,"database":"postgres","user":"fixture",
                          "ca_file":str(cert),"password_file":str(password)},dump,work)
                sql("CREATE DATABASE fresh")
                subprocess.run(["pg_restore","--exit-on-error","--single-transaction","--dbname","fresh",dump],
                               env=conn,check=True,capture_output=True)
                self.assertEqual(sql("SELECT id, evidence FROM restore_fixture","fresh"),"1|retained evidence")
            finally:
                subprocess.run(["pg_ctl","-D",data,"-m","immediate","-w","stop"],check=True,capture_output=True)


if __name__ == "__main__":
    unittest.main()
