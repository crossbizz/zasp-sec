"""Rehearse OpenBao Raft recovery on two disposable TLS-only Docker instances."""

import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
from contextlib import contextmanager
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import uuid

CHART = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("OPENBAO_TEST_IMAGE", "quay.io/openbao/openbao:2.7.3")


class Client:
    def __init__(self, url, ca):
        self.url = url
        self.http = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))

    def request(self, path, data=None, token="", method=None, binary=False):
        headers = {}
        if token:
            headers["X-Vault-Token"] = token
        if data is not None:
            if isinstance(data, bytes):
                headers["Content-Type"] = "application/octet-stream"
            else:
                headers["Content-Type"] = "application/json"
                data = json.dumps(data).encode()
        req = Request(self.url + "/v1/" + path, data=data, headers=headers, method=method)
        with self.http.open(req, timeout=20) as response:
            body = response.read()
        return body if binary else (json.loads(body) if body else None)

    def wait_for(self, condition, expect, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = condition()
                if expect(value):
                    return value
            except (URLError, ConnectionError, TimeoutError):
                pass
            time.sleep(0.5)
        raise RuntimeError("OpenBao did not reach the expected state within the deadline")

    def initialize(self):
        self.wait_for(lambda: self.request("sys/init"), lambda r: not r["initialized"])
        init = self.request("sys/init", {"secret_shares": 1, "secret_threshold": 1}, method="PUT")
        share = init["keys_base64"][0]
        self.unseal(share)
        return init["root_token"], share

    def unseal(self, share):
        self.request("sys/unseal", {"key": share}, method="PUT")
        self.wait_for(lambda: self.request("sys/health"), lambda h: not h["sealed"])

    def policy_token(self, root, name, filename):
        self.request("sys/policies/acl/" + name, {"policy": (CHART / "files" / filename).read_text()}, root)
        response = self.request("auth/token/create", {"policies": [name], "no_default_policy": True, "ttl": "10m"}, root)
        return response["auth"]["client_token"]


@contextmanager
def server(directory):
    uid, gid = os.getuid(), os.getgid()
    # This directory contains disposable test data and TLS material only.
    container = subprocess.check_output([
        "docker", "run", "--detach", "--publish", "127.0.0.1::8200", "--read-only",
        "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", f"/openbao/data:rw,uid={uid},gid={gid},mode=0700", "--tmpfs", "/tmp",
        "--mount", f"type=bind,src={CHART}/files,dst=/openbao/config,readonly",
        "--mount", f"type=bind,src={directory},dst=/openbao/tls,readonly",
        "--env", "TMPDIR=/openbao/data", "--env", "BAO_API_ADDR=https://127.0.0.1:8200", "--env", "BAO_CLUSTER_ADDR=https://127.0.0.1:8201",
        "--entrypoint", "/usr/bin/bao", IMAGE, "server", "-config=/openbao/config/server.hcl",
    ], text=True).strip()
    try:
        address = subprocess.check_output(["docker", "port", container, "8200/tcp"], text=True).strip()
        if not address.startswith("127.0.0.1:") or not address.split(":")[1].isdecimal():
            raise RuntimeError("drill expected a loopback-only disposable server")
        yield Client("https://" + address, directory / "tls.crt")
    finally:
        subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, check=True)


def must_deny(request, expected_status):
    try:
        request()
    except HTTPError as error:
        if error.code == expected_status:
            return
        raise
    raise AssertionError("operation unexpectedly succeeded")


def test_workload(client, root, tls_dir, name, policy, package, test_name, config):
    client.request("sys/policies/acl/" + name, {"policy": policy}, root)
    token = client.request("auth/token/create", {"policies": [name], "ttl": "20m", "no_default_policy": True}, root)
    # Workload credentials live outside the TLS directory mounted into the server.
    with tempfile.TemporaryDirectory(prefix="openbao-workload-") as d:
        credential = Path(d) / "token"
        with open(credential, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as f:
            f.write(token["auth"]["client_token"])
        env = {**os.environ, **config, "ZASP_OPENBAO_ADDR": client.url,
               "ZASP_OPENBAO_TOKEN_FILE": str(credential), "ZASP_OPENBAO_CA_FILE": str(tls_dir / "tls.crt")}
        result = subprocess.run(["go", "test", "-json", package, "-run", "^" + test_name + "$", "-count=1"],
                                cwd=CHART.parents[2] / "services/platform", env=env, check=False,
                                stdout=subprocess.PIPE, text=True)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        if result.returncode or not any(e.get("Test") == test_name and e["Action"] == "pass" for e in events):
            for event in events:
                if event.get("Output"):
                    print(event["Output"], end="")
            raise RuntimeError("live workload test failed or skipped: " + test_name)


def exercise_go_clients(client, root, tls_dir, key):
    if os.environ.get("ZASP_TEST_OPENBAO_TRANSIT") == "1":
        policy = "\n".join(f'path "{path}/{key}{suffix}" {{ capabilities = ["{capability}"] }}'
                           for path, suffix, capability in [
                               ("transit/keys", "", "read"), ("transit/sign", "/sha2-256", "update"),
                               ("transit/verify", "/sha2-256", "update")])
        test_workload(client, root, tls_dir, "drill-transit", policy, "./recovery/transit",
                      "TestLiveTransitRecovery", {"ZASP_OPENBAO_TRANSIT_KEY": key})
    if os.environ.get("ZASP_TEST_OPENBAO_KV") == "1":
        policy = ('path "zasp-kv/config" { capabilities = ["read"] }\n'
                  'path "zasp-kv/data/zasp/pilot/oauth/*" { capabilities = ["read", "create", "update"] }')
        test_workload(client, root, tls_dir, "drill-kv", policy, "./openbaokv", "TestLiveConnectorKV",
                      {"ZASP_CONNECTOR_SECRETS_PROVIDER": "openbao", "ZASP_OPENBAO_KV_MOUNT": "zasp-kv"})


def run():
    with tempfile.TemporaryDirectory(prefix="openbao-drill-") as temporary:
        directory = Path(temporary)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=OpenBao fixture", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(directory / "tls.key"), "-out", str(directory / "tls.crt"),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        marker = secrets.token_hex(24)
        key = str(uuid.uuid4())
        message = base64.b64encode(b"pre-backup recovery fixture").decode()
        with server(directory) as source:
            original, share = source.initialize()
            source.request("sys/mounts/zasp-kv", {"type": "kv", "options": {"version": "2"}}, original)
            source.request("zasp-kv/config", {"max_versions": 1}, original)
            source.request("zasp-kv/data/drill", {"data": {"value": marker}}, original)
            source.request("sys/mounts/transit", {"type": "transit"}, original)
            source.request("transit/keys/" + key, {"type": "ecdsa-p256"}, original)
            sign = "transit/sign/" + key + "/sha2-256"
            exercise_go_clients(source, original, directory, key)
            signatures = [source.request(sign, {"input": message}, original)["data"]["signature"]]
            source.request("transit/keys/" + key + "/rotate", {}, original)
            signatures.append(source.request(sign, {"input": message}, original)["data"]["signature"])
            reader = source.policy_token(original, "drill-snapshot", "snapshot-reader.hcl")
            must_deny(lambda: source.request("zasp-kv/data/drill", token=reader), 403)
            snapshot = source.request("sys/storage/raft/snapshot", token=reader, binary=True)
            must_deny(lambda: source.request("sys/storage/raft/snapshot-force", snapshot, reader), 403)
            if not snapshot or signatures[0].split(":")[1] == signatures[1].split(":")[1]:
                raise AssertionError("snapshot or version rotation failed")
            source.request("zasp-kv/data/after-snapshot", {"data": {"value": "newer"}}, original)
        # The original server and all its storage are gone.
        with server(directory) as target:
            transient, _ = target.initialize()
            operator = target.policy_token(transient, "drill-restore", "restore-operator.hcl")
            target.request("sys/storage/raft/snapshot-force", snapshot, operator)
            target.wait_for(lambda: target.request("sys/seal-status"), lambda status: status["sealed"])
            target.unseal(share)
            value = target.request("zasp-kv/data/drill", token=original)["data"]["data"]["value"]
            if value != marker:
                raise AssertionError("restored credential differs from the source")
            must_deny(lambda: target.request("zasp-kv/data/after-snapshot", token=original), 404)
            must_deny(lambda: target.request("zasp-kv/data/drill", token=operator), 403)
            for signature in signatures:
                verify = "transit/verify/" + key + "/sha2-256"
                if not target.request(verify, {"input": message, "signature": signature}, original)["data"]["valid"]:
                    raise AssertionError("historical recovery signature failed after restore")
        print("Restored a credential and verified both Transit key versions on a replacement TLS server.")


if __name__ == "__main__":
    run()
