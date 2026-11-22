#!/usr/bin/env python3
"""Exercise the actual TLS scanner and encrypted retention processes on Linux.

Run `python3 scripts/smoke-private-addon-retention.py` from any directory with
Go, Node.js and OpenSSL on PATH. Optional --scanner and --retention accept
prebuilt binaries. All keys, scopes and archives are unique synthetic fixtures.
"""

import argparse
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
from contextlib import ExitStack
from tempfile import TemporaryDirectory
import time
from uuid import uuid4
import zipfile

REPOSITORY = Path(__file__).resolve().parents[1]
PREFIX = "ZASP_PRIVATE_ADDON_"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pid():
    return "pid_" + str(uuid4())


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=180, check=True, **kwargs).stdout


def binary(override, module, package, output):
    if override:
        return Path(override).resolve(strict=True)
    command(["go", "-C", str(REPOSITORY / module), "build", "-o", output, package])
    return output


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def wait_until(proc, ready):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"{Path(proc.args[0]).name} exited during startup")
        try:
            if ready():
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"{Path(proc.args[0]).name} did not become ready")


def run(args):
    if sys.platform != "linux":
        raise RuntimeError("the retention service requires Linux")
    with TemporaryDirectory(prefix="zasp-retain-") as location, ExitStack() as tasks:
        root = Path(location).resolve()
        for subdir in ("sockets", "journal", "objects", "markers"):
            (root / subdir).mkdir(mode=0o700)
        scanner = binary(args.scanner, "cmd/zaspctl", "./cmd/private-addon-worker", root / "scanner")
        retention = binary(args.retention, "services/platform", "./agentsec-private-retention", root / "retention")
        key, cert, tls_key = (root / n for n in ("grant.pem", "public.crt", "tls.pem"))
        command(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key])
        der = command(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"])
        check(len(der) == 44 and der[:12] == bytes.fromhex("302a300506032b6570032100"), "unexpected signer public key encoding")
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", tls_key, "-out", cert])
        aes_key = root / "retention.key"
        aes_key.write_text(b64url(secrets.token_bytes(32)))
        aes_key.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"https://127.0.0.1:{port}"
        scope = "/".join(pid() for _ in range(3))
        foreign = scope.rsplit("/", 1)[0] + "/" + pid()
        env = {k: v for k,v in os.environ.items() if not k.startswith((PREFIX, "AWS_"))}
        env.update({"ZASP_ENVIRONMENT":"test", PREFIX+"WORKER_SCOPE":scope, PREFIX+"WORKER_ORIGIN":origin, PREFIX+"VERIFY_KEY":b64url(der[-32:])})
        sockets = root / "sockets"
        store_env = env | {PREFIX+"RETENTION_BACKEND":"local_encrypted", PREFIX+"RETENTION_SOCKET_DIR":str(sockets), PREFIX+"RETENTION_JOURNAL_DIR":str(root/"journal"), PREFIX+"RETENTION_LOCAL_DIR":str(root/"objects"), PREFIX+"RETENTION_LOCAL_KEY_FILE":str(aes_key)}
        worker_env = env | {PREFIX+"TLS_CERT":str(cert), PREFIX+"TLS_KEY":str(tls_key), PREFIX+"MARKER_DIR":str(root/"markers"), PREFIX+"RETENTION_UPLOAD_SOCKET":str(sockets/"uploads.sock"), PREFIX+"LISTEN_ADDRESS":f"127.0.0.1:{port}"}

        def service(binary_path, argv, service_env):
            proc = subprocess.Popen([binary_path,*argv], env=service_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tasks.callback(stop, proc)
            return proc

        def start_store():
            proc = service(retention, ["serve"], store_env)
            wait_until(proc, lambda: (sockets/"uploads.sock").is_socket() and (sockets/"admin.sock").is_socket())
            return proc

        store = start_store()
        worker = service(scanner, [], worker_env)
        trust = ssl.create_default_context(cafile=cert)
        def ready():
            with socket.create_connection(("127.0.0.1",port),timeout=1) as raw, trust.wrap_socket(raw,server_hostname="127.0.0.1"):
                return True
        wait_until(worker, ready)
        marker = b"synthetic-retention-" + secrets.token_hex(16).encode()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("SKILL.md", b"# Local fixture\n<!-- " + marker + b" -->\n")
        body = archive.getvalue()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        def upload(grant, destination_scope, retained):
            expires = int(time.time())+240
            cap = {"version":"private-addon-upload-retained.v1" if retained else "private-addon-upload.v1", "id":grant,"audience":origin,"scope":destination_scope,"actor":pid(),"sha256":digest,"size":len(body),"expires":expires}
            if retained:
                cap["retain_until"] = expires + 86_100
            raw = json.dumps(cap,separators=(",",":"),ensure_ascii=True).encode()
            message = root/"signed-grant.bin"
            message.write_bytes(b"zasp-private-addon-upload.v1\0"+raw)
            sig = command(["openssl","pkeyutl","-sign","-rawin","-inkey",key,"-in",message]); message.unlink()
            conn = http.client.HTTPSConnection("127.0.0.1",port,context=trust,timeout=10)
            try:
                conn.request("PUT","/v1/uploads/"+grant,body=body,headers={"Content-Type":"application/zip","Authorization":"Bearer "+b64url(raw)+"."+b64url(sig)})
                response = conn.getresponse(); status = response.status; data = response.read(8193)
            finally:
                conn.close()
            check(len(data)<=8192,"oversized worker reply")
            return status, json.loads(data) if status==200 else {}, cap.get("retain_until")

        def operator(action, grant, requested_scope=scope, denied=False):
            proc = subprocess.run([retention,action,"--scope",requested_scope,"--grant",grant],env={PREFIX+"RETENTION_SOCKET_DIR":str(sockets)},capture_output=True,timeout=10)
            if denied:
                check(proc.returncode!=0 and b'"storage_version"' not in proc.stdout,"operator crossed the scope boundary")
                return {}
            check(proc.returncode==0,"operator request failed")
            return json.loads(proc.stdout)

        def objects():
            return [f for f in (root/"objects").rglob("*") if f.is_file()]

        check(upload(pid(),foreign,True)[0]==403,"foreign signed scope accepted")
        code,reply,_ = upload(pid(),scope,False)
        check(code==200 and "retention" not in reply and not objects(),"memory-only scan created storage")
        keep, remove = pid(),pid()
        for grant in (keep,remove):
            code,reply,deadline = upload(grant,scope,True)
            check(code==200 and reply.get("retention",{}).get("state")=="retained" and reply["retention"].get("grant_id")==grant,"missing verified retention receipt")
            check(reply["result"]["status"]=="complete" and reply["result"]["rule_counts"].get("instruction.hidden_text")==1,"missing independent static finding")
            state = operator("status",grant)
            check(state["scope"]==scope and state["archive_digest"]==digest and state["retain_until"]==deadline,"stored record differs from grant")
        files=objects()
        check(len(files)==2,"expected two independently scoped retained objects")
        target=next(f for f in files if remove in f.parts)
        ciphertext=target.read_bytes()
        check(len(ciphertext)==len(body)+28 and marker not in ciphertext and not ciphertext.startswith(b"PK\x03\x04"),"private source stored in the clear")
        check(hashlib.sha256(ciphertext).hexdigest()==operator("status",remove)["storage_version"],"ciphertext version differs from receipt")
        decrypt = """const fs=require('node:fs'),c=require('node:crypto');const [file,aad,key]=process.argv.slice(1), b=fs.readFileSync(file);const d=c.createDecipheriv('aes-256-gcm',Buffer.from(fs.readFileSync(key,'utf8'),'base64url'),b.subarray(0,12));d.setAAD(Buffer.from(aad));d.setAuthTag(b.subarray(-16));process.stdout.write(Buffer.concat([d.update(b.subarray(12,-16)),d.final()]));"""
        check(command(["node","-e",decrypt,str(target),target.relative_to(root/"objects").as_posix(),str(aes_key)])==body,"independent scoped AES-GCM readback differs from the ZIP")
        stop(store); start_store()
        operator("status",remove,foreign,denied=True);operator("delete",remove,foreign,denied=True)
        check(target.read_bytes()==ciphertext and operator("status",remove)["state"]=="retained","foreign deletion changed the target")
        for _ in range(2):
            result=operator("delete",remove)
            check(result["state"]=="deleted" and result.get("deleted_at"),"absent durable deletion receipt")
        check(not target.exists() and len(objects())==1 and operator("status",keep)["state"]=="retained","delete was not exact")
        check(operator("delete",keep)["state"]=="deleted" and not objects(),"final retained object still present")
        print("PASS: TLS worker, memory-only default, AES-256-GCM readback, restart, foreign scope rejection, idempotent exact deletion and unaffected second grant")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner",help="prebuilt private-addon-worker binary")
    parser.add_argument("--retention",help="prebuilt agentsec-private-retention binary")
    run(parser.parse_args())
