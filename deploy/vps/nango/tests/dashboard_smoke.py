"""Install the independent Helm release in a disposable kind cluster and exercise private TLS."""
import base64
import contextlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parents[1]
NAMESPACE = "connectors"
HOST = "nango.connectors.svc.cluster.local"
DASH = "https://" + HOST + ":18443"
ORIGIN = "https://zasp.example.test"
POSTGRES = "public.ecr.aws/docker/library/postgres:18.3@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db"
PROXY = "nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03"


# Only controlled phase names, HTTP methods/statuses and Kubernetes state names
# go into the Actions job label. Response bodies and verification URLs stay private.
phase = "runtime prerequisites"


def checking(label):
    global phase
    phase = label
    print(label, flush=True)


class ProbeFailure(RuntimeError):
    """A bounded diagnostic safe for CI output."""


def job_failure(detail):
    output = os.getenv("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf8") as stream:
            stream.write(f"failure={detail[:180]}\n")


def command(*args, data=None, timeout=360):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        # Kubernetes input and app output can contain credentials.
        raise ProbeFailure(f"{Path(args[0]).name} exit {result.returncode}")
    return result.stdout


def issue_certificate(folder, name, host):
    key, cert = folder / (name + ".key"), folder / (name + ".crt")
    request, ext = folder / (name + ".csr"), folder / (name + ".ext")
    ext.write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
    command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", request, "-subj", "/CN=" + host)
    command("openssl", "x509", "-req", "-in", request, "-CA", folder/"ca.crt", "-CAkey", folder/"ca.key",
            "-CAcreateserial", "-out", cert, "-days", "1", "-extfile", ext)
    return cert, key


@contextlib.contextmanager
def forward(kube, target, local, remote):
    with subprocess.Popen([*kube, "port-forward", "--address=127.0.0.1", target, f"{local}:{remote}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        try:
            for _ in range(75):
                if process.poll() is not None:
                    raise ProbeFailure("kubectl port-forward exited early")
                try:
                    with socket.create_connection(("127.0.0.1", local), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise ProbeFailure("kubectl port-forward timed out")
            yield
        finally:
            process.terminate()


def request(context, port, method, path, expected, headers=None, body=None):
    # Verify the production DNS SAN over the workstation loopback tunnel.
    conn = http.client.HTTPSConnection(HOST, port, context=context, timeout=10)
    try:
        conn.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname=HOST)
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json", "Accept": "application/json", **(headers or {})})
        response = conn.getresponse()
        data = response.read()
        expected_codes = (expected,) if isinstance(expected, int) else expected
        if response.status not in expected_codes:
            # The only path with a sensitive value carries it in the query.
            raise ProbeFailure(f"{method} {path.split('?')[0]} HTTP {response.status}")
        return response.headers, data
    finally:
        conn.close()


def exercise(kube, ca, bearer):
    ctx = ssl.create_default_context(cafile=ca)
    checking("opening dashboard and service tunnels")
    with forward(kube, "deployment/nango", 18443, 9443), forward(kube, "service/nango", 18444, 8443):
        def dashboard(method, path, headers=None, body=None):
            return request(ctx, 18443, method, path, 200, {"Origin": DASH, **(headers or {})}, body)

        def api(method, path, status=200, body=None):
            return request(ctx, 18444, method, path, status, {"Authorization": "Bearer " + bearer}, body)

        checking("dashboard TLS and anonymous access")
        try:
            request(ssl.create_default_context(), 18443, "GET", "/ready", 200)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("client accepted an untrusted dashboard TLS chain")
        request(ctx, 18443, "GET", "/api/v1/environments/current?env=prod", (401, 403))
        checking("dashboard origin and assets")
        _, html = dashboard("GET", "/")
        assert b"/env.js" in html
        _, script = dashboard("GET", "/env.js")
        config = json.loads(script.decode().split("=", 1)[1].strip().removesuffix(";"))
        assert config["apiUrl"] == config["publicUrl"] == DASH and config["features"]["auth"]
        credentials = {"email": "operator@example.test", "password": "Ci1!" + secrets.token_hex(12)}
        checking("first operator signup")
        _, signup = dashboard("POST", "/api/v1/account/signup", body={"name": "Release Operator", **credentials})
        assert json.loads(signup)["data"]["verified"] is False
        checking("private verification email")
        logs = command(*kube, "logs", "deployment/nango", "-c", "nango", "--tail=200").decode()
        token = re.search(re.escape(DASH) + r"/signup/verification/([A-Za-z0-9_-]+)", logs)
        assert token, "verification link needs the private TLS dashboard origin"
        checking("email verification")
        dashboard("POST", "/api/v1/account/verify/code", body={"token": token[1]})
        checking("operator login and secure session")
        headers, _ = dashboard("POST", "/api/v1/account/signin", body=credentials)
        cookie = headers.get("Set-Cookie", "")
        assert "nango_session=" in cookie and "secure" in cookie.lower() and "httponly" in cookie.lower()
        dashboard("GET", "/api/v1/environments/current?env=prod", {"Cookie": cookie.split(";")[0]})
        checking("private route isolation")
        request(ctx, 18444, "GET", "/api/v1/environments?env=prod", 404)
        checking("anonymous integration list")
        request(ctx, 18444, "GET", "/integrations", (401, 403))
        checking("authenticated integration list")
        _, empty = api("GET", "/integrations")
        assert json.loads(empty)["data"] == []
        checking("creating the provider configuration")
        api("POST", "/integrations", body={"provider": "slack", "unique_key": "slack", "credentials": {
            "type": "OAUTH2", "client_id": "smoke", "client_secret": secrets.token_hex(16), "scopes": "team:read"}})
        _, integrations = api("GET", "/integrations")
        assert [row["unique_key"] for row in json.loads(integrations)["data"]] == ["slack"]
        checking("broker connect-session creation")
        _, session = api("POST", "/connect/sessions", 201, {
            "end_user": {"id": "smoke-user"}, "organization": {"id": "smoke-organization"}, "allowed_integrations": ["slack"]})
        checking("public OAuth redirect verification")
        location, _ = api("GET", "/oauth/connect/slack?connect_session_token=" + json.loads(session)["data"]["token"], 302)
        redirect = urlsplit(location["Location"])
        assert redirect.scheme == "https" and redirect.hostname == "slack.com"
        assert parse_qs(redirect.query)["redirect_uri"] == [ORIGIN + "/api/v1/integrations/oauth/callback"]
        return credentials


def main():
    missing = [tool for tool in ("kind", "helm", "kubectl", "docker", "openssl") if not shutil.which(tool)]
    if missing:
        raise SystemExit("Independent Nango runtime smoke requires " + ", ".join(missing))
    with tempfile.TemporaryDirectory(prefix="zasp-private-nango-") as scratch:
        folder = Path(scratch)
        cluster = "zasp-vps-nango-" + secrets.token_hex(4)
        config = folder / "kubeconfig"
        kube = ["kubectl", "--kubeconfig", config, "--context", "kind-" + cluster, "-n", NAMESPACE]
        try:
            checking("creating the disposable Kubernetes cluster")
            command("kind", "create", "cluster", "--name", cluster, "--kubeconfig", config, "--wait", "120s")
            checking("provisioning fixture namespace and TLS certificates")
            command(*kube, "create", "namespace", NAMESPACE)
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=smoke",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", folder/"ca.key", "-out", folder/"ca.crt")
            pg_host = "postgres.connectors.svc.cluster.local"
            for name, host in [("postgres", pg_host), ("nango-server", HOST)]:
                cert, key = issue_certificate(folder, name, host)
                command(*kube, "create", "secret", "tls", name + "-tls", "--cert=" + str(cert), "--key=" + str(key))
            command(*kube, "create", "configmap", "nango-database-ca", "--from-file=ca.crt=" + str(folder/"ca.crt"))
            password, bearer = secrets.token_hex(32), str(uuid4())
            # Generated data is passed through stdin and never printed or passed in command arguments.
            def apply(obj):
                command(*kube, "apply", "-f", "-", data=json.dumps(obj).encode())
            apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "nango-storage"}, "stringData": {
                "database-url": "postgresql://nango:" + password + "@" + pg_host + ":5432/nango?sslmode=verify-full",
                "service-key": bearer, "admin-key": secrets.token_hex(32), "encryption-key": base64.b64encode(secrets.token_bytes(32)).decode()}})
            apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db-login"}, "stringData": {"password": password}})
            apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "postgres"}, "spec": {
                "selector": {"app": "postgres"}, "ports": [{"port": 5432}]}})
            apply({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "postgres", "labels": {"app": "postgres"}}, "spec": {
                "securityContext": {"fsGroup": 999}, "volumes": [{"name": "cert", "secret": {"secretName": "postgres-tls", "defaultMode": 0o440}}],
                "containers": [{"name": "postgres", "image": POSTGRES, "args": ["postgres", "-c", "ssl=on", "-c",
                    "ssl_cert_file=/cert/tls.crt", "-c", "ssl_key_file=/cert/tls.key"],
                    "env": [{"name": "POSTGRES_USER", "value": "nango"}, {"name": "POSTGRES_PASSWORD", "valueFrom": {
                        "secretKeyRef": {"name": "db-login", "key": "password"}}}], "volumeMounts": [{"name": "cert", "mountPath": "/cert"}],
                    "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "nango"]}}}]}})
            checking("TLS PostgreSQL readiness")
            command(*kube, "wait", "--for=condition=Ready", "pod/postgres", "--timeout=180s")
            ip = command(*kube, "get", "pod", "postgres", "-o", "jsonpath={.status.podIP}").decode()
            values = {"publicOrigin": ORIGIN, "tlsProxyImage": PROXY, "dashboard": {"allowSignup": True},
                      "databaseEgressCIDRs": [ip + "/32"], "providerEgressCIDRs": ["192.0.2.1/32"]}
            checking("independent Helm install and migration")
            command("helm", "--kubeconfig", config, "--kube-context", "kind-" + cluster, "-n", NAMESPACE, "install",
                    "nango", HERE, "--wait", "--timeout=5m", "-f", "-", data=json.dumps(values).encode())
            credentials = exercise(kube, folder/"ca.crt", bearer)
            checking("Helm upgrade with signup closed")
            values["dashboard"]["allowSignup"] = False
            command("helm", "--kubeconfig", config, "--kube-context", "kind-" + cluster, "-n", NAMESPACE, "upgrade",
                    "nango", HERE, "--wait", "--timeout=5m", "-f", "-", data=json.dumps(values).encode())
            checking("existing account and provider after upgrade")
            ctx = ssl.create_default_context(cafile=folder/"ca.crt")
            with forward(kube, "deployment/nango", 18443, 9443), forward(kube, "service/nango", 18444, 8443):
                request(ctx, 18443, "POST", "/api/v1/account/signin", 200, {"Origin": DASH}, credentials)
                request(ctx, 18443, "POST", "/api/v1/account/signup", 403, {"Origin": DASH},
                        {**credentials, "name": "Another Operator", "email": "second@example.test"})
                _, inventory = request(ctx, 18444, "GET", "/integrations", 200, {"Authorization": "Bearer " + bearer})
                assert [row["unique_key"] for row in json.loads(inventory)["data"]] == ["slack"]
            print("Verified independent Nango TLS login, session, environment inventory and Zasp OAuth redirect.")
        except Exception as error:
            detail = str(error) if isinstance(error, ProbeFailure) else type(error).__name__
            # A waiting reason such as ImagePullBackOff or CreateContainerConfigError
            # helps distinguish startup failures without reading container logs.
            if phase in ("independent Helm install and migration", "TLS PostgreSQL readiness", "Helm upgrade with signup closed"):
                try:
                    pods = json.loads(command(*kube, "get", "pods", "-o", "json", timeout=8))["items"]
                    problems = []
                    for pod in pods:
                        for status in pod.get("status", {}).get("containerStatuses", []):
                            state = status.get("state", {})
                            reason = (state.get("waiting") or state.get("terminated") or {}).get("reason", "")
                            if reason in {"ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError", "OOMKilled", "Error"}:
                                problems.append(status["name"] + " " + reason)
                    if problems:
                        detail += " " + ", ".join(sorted(set(problems)))
                except (OSError, RuntimeError, KeyError, ValueError, subprocess.TimeoutExpired):
                    pass
            job_failure(phase + " - " + detail)
            raise
        finally:
            command("kind", "delete", "cluster", "--name", cluster, "--kubeconfig", config, timeout=90)


if __name__ == "__main__":
    main()
