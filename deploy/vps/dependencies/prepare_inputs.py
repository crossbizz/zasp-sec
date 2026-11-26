"""Create the private Secret manifest for the VPS dependency unit on an operator machine."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
from urllib.parse import quote

DBS = {"openfga-db": "openfga", "temporal-db": "temporal", "temporal-visibility-db": "temporal_visibility"}
SERVICES = {"openfga": "openfga", "temporal-frontend": "temporal-frontend", "temporal-internode": "temporal-internode"}


def private(path, directory=False):
    info = path.lstat()
    mode = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not mode or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("use an operator-owned 0700 directory and regular 0600 private keys")


def openssl(*args):
    result = subprocess.run(["openssl", *map(str, args)], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError("TLS certificate validation failed; check issuer, purpose, expiry, hostname and key")
    return result.stdout


def certificate(directory, name, host, ca, mutual=False):
    cert, key = directory / (name + ".crt"), directory / (name + ".key")
    private(key)
    openssl("verify", "-purpose", "sslserver", "-verify_hostname", host, "-CAfile", ca, cert)
    if mutual:
        openssl("verify", "-purpose", "sslclient", "-CAfile", ca, cert)
    if openssl("x509", "-in", cert, "-pubkey", "-noout") != openssl("pkey", "-in", key, "-pubout"):
        raise ValueError("TLS certificate and private key do not match")
    return {"tls.crt": cert.read_bytes(), "tls.key": key.read_bytes()}


def prepare(directory, output):
    private(directory, directory=True)
    private(output.parent, directory=True)
    items = []

    def add(namespace, name, data, secret_type="Opaque"):
        fields = {key: base64.b64encode(value).decode() for key, value in data.items()}
        items.append({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": namespace},
                      "type": secret_type, "data": fields})

    data, runtime = "zasp-data", "zasp-runtime"
    db_ca, service_ca = directory / "database-ca.crt", directory / "runtime-ca.crt"
    for namespace, name in [(data, "openfga-db-public-ca"), (runtime, "runtime-database-ca")]:
        add(namespace, name, {"ca.crt": db_ca.read_bytes()})
    for name, role in DBS.items():
        host = name + "-rw.zasp-data.svc.cluster.local"
        pair = certificate(directory, name, host, db_ca)
        add(data, name + "-tls", pair, "kubernetes.io/tls")
        password = secrets.token_urlsafe(48)
        add(data, name + "-owner", {"username": role.encode(), "password": password.encode()}, "kubernetes.io/basic-auth")
        if role == "openfga":
            uri = (f"postgresql://openfga:{quote(password, safe='')}@{host}:5432/openfga"
                   "?sslmode=verify-full&sslrootcert=/etc/database-ca/ca.crt")
            add(runtime, "openfga-datastore", {"uri": uri.encode()})
        else:
            name = "temporal-persistence" if role == "temporal" else "temporal-visibility"
            add(runtime, name, {"password": password.encode()})
    for name, service in SERVICES.items():
        pair = certificate(directory, name, service + ".zasp-runtime.svc.cluster.local", service_ca,
                           mutual=name.startswith("temporal-"))
        add(runtime, name + "-tls", {**pair, "ca.crt": service_ca.read_bytes()}, "kubernetes.io/tls")
    add(runtime, "openfga-auth", {"keys": secrets.token_urlsafe(48).encode()})
    # The caller's original file must survive retries unchanged. Link only the completed copy.
    import tempfile
    with tempfile.NamedTemporaryFile(dir=output.parent) as temp:
        temp.write(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}).encode())
        temp.flush()
        os.fsync(temp.fileno())
        os.link(temp.name, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tls-dir", type=Path, required=True, help="private directory of operator-issued certificates and keys")
    parser.add_argument("--output", type=Path, required=True, help="new Secret manifest inside a private directory")
    args = parser.parse_args()
    try:
        prepare(args.tls_dir, args.output)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, str(exc) + "\n")
