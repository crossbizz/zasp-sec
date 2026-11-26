"""Exercise the operator initialization code against a disposable TLS Raft server."""
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
from unittest import mock
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import vps_services as ops


def check_operator_flow(base_url, certificate):
    address = urlsplit(base_url)
    if address.scheme != "https" or address.hostname != "127.0.0.1" or not address.port:
        raise AssertionError("fixture requires a disposable loopback origin")
    api = ops.API(address.hostname, address.port, (address.hostname, address.port),
                  ssl.create_default_context(cafile=str(certificate)))
    with tempfile.TemporaryDirectory(prefix="zasp-disposable-custody-") as d:
        directory = Path(d)
        gnupg = directory / "gnupg"
        gnupg.mkdir(mode=0o700)
        public = directory / "public"
        public.mkdir(mode=0o700)
        handoff = directory / "handoff"
        gpg = ["gpg", "--homedir", str(gnupg), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        try:
            for name in ["custodian-" + str(i) for i in range(1, 6)] + ["root"]:
                uid = name + "@drill.invalid"
                subprocess.run(gpg + ["--quick-generate-key", uid, "rsa2048", "encr", "1d"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                key = subprocess.check_output(gpg + ["--export", uid], stderr=subprocess.DEVNULL)
                (public / (name + ".gpg")).write_bytes(key)
            env = {"ZASP_VPS_OPENBAO_PGP_KEYS_DIR": str(public), "ZASP_VPS_OPENBAO_HANDOFF_FILE": str(handoff),
                   "ZASP_VPS_INSTALLATION_ID": "disposable", "ZASP_VPS_CLUSTER_UID": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}
            with mock.patch.dict(os.environ, env):
                component = ops.Service("openbao")
                if not component.inspect(api).startswith("uninitialized"):
                    raise AssertionError("expected a fresh uninitialized server")
                ops.initialize(component, api)
                original = handoff.read_bytes()
                ops.initialize(component, api)
                if original != handoff.read_bytes() or not component.inspect(api).startswith("sealed"):
                    raise AssertionError("initialization did not resume safely")
                record = json.loads(original)
                def decrypt(value):
                    return subprocess.check_output(gpg + ["--decrypt"], input=base64.b64decode(value),
                                                   stderr=subprocess.DEVNULL).decode()
                for packet in record["custodian_packets"][:3]:
                    # Supply one simulated interactive custodian per call. No cleartext is written to disk.
                    with mock.patch.object(ops, "prompt_share", return_value=decrypt(packet)):
                        ops.unseal(api)
                if not component.inspect(api).startswith("unauthenticated"):
                    raise AssertionError("unsealed server must still require scoped authentication")
                root = decrypt(record["bootstrap_packet"])
                code, result = api.request("POST", "/v1/auth/token/create", {"policies": ["default"], "ttl": "5m"},
                                           {"X-Vault-Token": root})
                if code != 200:
                    raise AssertionError("fixture could not create scoped status identity")
                status_token = directory / "status-token"
                with open(status_token, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
                    f.write(result["auth"]["client_token"])
                with mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_STATUS_TOKEN_FILE": str(status_token)}):
                    if component.inspect(api) != "healthy":
                        raise AssertionError("scoped status authentication failed")
                print("Verified 3-of-5 encrypted initialization, original-share unseal and scoped status over real TLS.")
        finally:
            subprocess.run(["gpgconf", "--homedir", str(gnupg), "--kill", "gpg-agent"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
