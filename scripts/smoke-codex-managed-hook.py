#!/usr/bin/env python3
"""Exercise the installed Linux Codex CLI, managed hook, signed endpoint policy and target.

Requires Linux user namespaces, bubblewrap, OpenSSL, Python 3 and a locally built
Linux endpoint binary. Run from a checkout, with both binaries already installed:

  go build -C services/endpoint-agent -o /tmp/zasp-endpoint-smoke .
  python3 scripts/smoke-codex-managed-hook.py --codex /opt/codex/bin/codex --endpoint /tmp/zasp-endpoint-smoke

The Linux daemon intentionally identifies its adapter as linux_claude_pretool_v2_test.
"""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


STAGE = Path("/fixture")
ENDPOINT = "/usr/local/libexec/zasp-endpoint"
CODEX = "/opt/codex/bin/codex"
SOCKET = "/Library/Application Support/Zasp/run/endpoint.sock"
ADAPTER = "linux_claude_pretool_v2_test"
FIXTURE_BYTES = b"synthetic endpoint fixture\n"


def run(args, **options):
    result = subprocess.run(args, capture_output=True, timeout=45, **options)
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()[-600:]
        raise RuntimeError(f"{Path(args[0]).name} exited {result.returncode}. {detail}")
    return result.stdout


def encode(data):
    return base64.b64encode(data).decode("ascii")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def isolate(codex, endpoint):
    repo = Path(__file__).resolve().parents[1]
    require(sys.platform == "linux", "Linux with user and network namespaces is required")
    require(all(shutil.which(cmd) for cmd in ["unshare", "bwrap", "openssl"]), "Missing test tools")
    with tempfile.TemporaryDirectory(prefix="zasp-codex-hook-") as tmp:
        stage = Path(tmp)
        for name in ["work", "home", "codex", "run", "state", "xdg"]:
            (stage / name).mkdir(mode=0o700)
        (stage / "passwd").write_text("root:x:0:0:fixture:/fixture/home:/bin/sh\n")
        args = [
            "unshare", "-Ur", "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--tmpfs", "/", "--ro-bind", "/usr", "/usr", "--tmpfs", "/usr/local",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--dir", "/usr/local/libexec", "--ro-bind", str(endpoint), ENDPOINT,
            "--dir", "/etc", "--ro-bind", str(stage / "passwd"), "/etc/passwd",
            "--dir", "/etc/codex", "--ro-bind", str(repo / "deploy/endpoint/codex/hooks.fragment.json"), "/etc/codex/hooks.json",
            "--dir", "/opt", "--dir", "/opt/codex", "--dir", "/opt/codex/bin", "--ro-bind", str(codex), CODEX,
            "--dir", "/Library", "--dir", "/Library/Application Support", "--dir", "/Library/Application Support/Zasp",
            "--bind", str(stage / "run"), str(Path(SOCKET).parent), "--tmpfs", "/tmp",
            "--proc", "/proc", "--dev", "/dev", "--bind", tmp, str(STAGE),
            "--ro-bind", str(Path(__file__).resolve()), "/fixture/check.py",
        ]
        for companion in ["codex-exec-server", "codex-code-mode-host"]:
            path = codex.with_name(companion)
            if path.is_file():
                args.extend(["--ro-bind", str(path), str(Path(CODEX).with_name(companion))])
        args.extend([
            "--chdir", "/fixture/work", "--clearenv", "--setenv", "HOME", "/fixture/home",
            "--setenv", "CODEX_HOME", "/fixture/codex", "--setenv", "PATH", "/opt/codex/bin:/usr/bin:/bin",
            "--setenv", "LANG", "C.UTF-8", "--setenv", "XDG_RUNTIME_DIR", "/fixture/xdg",
            "/usr/bin/python3", "/fixture/check.py", "--isolated-child",
        ])
        subprocess.run(args, env={"PATH": os.defpath + ":/usr/sbin:/sbin"}, check=True, timeout=135)


def provision():
    binding = dict(organization_id="fixture-org", workspace_id="fixture-space",
                   environment_id="fixture-env", device_id="fixture-device", credential_generation=1)
    signing = STAGE / "policy-signing.key"
    run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", signing])
    public_der = run(["openssl", "pkey", "-in", signing, "-pubout", "-outform", "DER"])
    public_prefix = bytes.fromhex("302a300506032b6570032100")
    require(public_der[:-32] == public_prefix, "Unexpected policy public key format")
    now = datetime.now(timezone.utc)
    policy = dict(audience="zasp.endpoint-policy.v2", binding=binding, revision=1,
                  issued_at=(now - timedelta(seconds=2)).isoformat(), expires_at=(now + timedelta(minutes=15)).isoformat(),
                  mode="enforce", failure_mode="closed", rules=[dict(id="fixture-files", type="file_path_policy", values=["dotenv"])])
    payload = STAGE / "policy-payload.json"
    write_json(payload, policy)
    signature = run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", signing, "-in", payload])
    signed = STAGE / "policy.json"
    write_json(signed, dict(payload=encode(payload.read_bytes()), signature=encode(signature)))

    seed = os.urandom(32)
    seed_file = STAGE / "device-seed"
    seed_file.write_text(encode(seed))
    seed_file.chmod(0o600)
    # RFC 8410 Ed25519 private seed representation, used only to verify the
    # daemon's receipt signature independently of its own export implementation.
    device_key = STAGE / "device.der"
    device_key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
    device_public = STAGE / "device.pub"
    run(["openssl", "pkey", "-inform", "DER", "-in", device_key, "-pubout", "-out", device_public])
    config = STAGE / "endpoint.json"
    write_json(config, dict(adapter=ADAPTER, binding=binding, allowed_uid=0, policy_public_key=encode(public_der[-32:]),
                            policy_file=str(signed), state_dir="/fixture/state", socket=SOCKET, seed_file=str(seed_file)))
    return config, device_public, binding


@contextmanager
def daemon(config):
    child = subprocess.Popen([ENDPOINT, "serve", "--config", config])
    try:
        for _ in range(100):
            if Path(SOCKET).is_socket():
                break
            require(child.poll() is None, "Endpoint exited before opening its managed socket")
            time.sleep(0.05)
        require(Path(SOCKET).is_socket(), "Endpoint did not become ready")
        yield
    finally:
        child.terminate()
        child.wait(timeout=4)


class ModelFixture(BaseHTTPRequestHandler):
    """Two static Responses frames. No model, tool selection or external I/O."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", 0))
        if self.path != "/v1/responses" or not 0 < size < 2_000_000 or self.server.turn >= 2:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(size))
        self.server.turn += 1
        if self.server.turn == 1:
            tools = request.get("tools", [])
            candidates = [(None, t) for t in tools] + [(t["name"], n) for t in tools if t["type"] == "namespace" for n in t.get("tools", [])]
            found = [(ns, t) for ns, t in candidates if t.get("name") == "apply_patch" and t.get("type") == "custom"]
            if len(found) != 1:
                self.send_error(422, "Native apply_patch missing from catalog")
                return
            patch = f"*** Begin Patch\n*** Add File: {self.server.target}\n+{FIXTURE_BYTES.decode().rstrip()}\n*** End Patch"
            item = dict(type="custom_tool_call", id="ct_fixture", call_id="call_fixture", name="apply_patch", input=patch, status="completed")
            if found[0][0]:
                item["namespace"] = found[0][0]
        else:
            item = dict(type="message", role="assistant", id="msg_fixture",
                        content=[dict(type="output_text", text="Fixture complete.", annotations=[])])
        rid = "resp_" + str(self.server.turn)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for kind, body in [
            ("response.created", dict(response=dict(id=rid, status="in_progress", output=[]))),
            ("response.output_item.added", dict(output_index=0, item=item)),
            ("response.output_item.done", dict(output_index=0, item=item)),
            ("response.completed", dict(response=dict(id=rid, status="completed", output=[item], usage=dict(input_tokens=1, output_tokens=1, total_tokens=2)))),
        ]:
            self.wfile.write(f"event: {kind}\ndata: {json.dumps(dict(type=kind, **body))}\n\n".encode())
        self.close_connection = True


def exercise(target, model):
    with ThreadingHTTPServer(("127.0.0.1", 0), ModelFixture) as server:
        server.target, server.turn = target, 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        (STAGE / "codex/config.toml").write_text(f'''model = {json.dumps(model)}
model_provider = "fixture"
sandbox_mode = "workspace-write"
approval_policy = "never"
[analytics]
enabled = false
[features]
hooks = true
[model_providers.fixture]
name = "Local static Responses fixture"
base_url = "http://127.0.0.1:{server.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
[projects."/fixture/work"]
trust_level = "trusted"
''')
        try:
            run([CODEX, "--no-daemon", "exec", "--ephemeral", "--skip-git-repo-check", "--json", "-C", "/fixture/work",
                 "Run the harmless scratch-file verification requested by the local fixture."], stdin=subprocess.DEVNULL)
            require(server.turn == 2, "Codex did not complete the two-frame fixture")
        finally:
            server.shutdown()
            thread.join()


def verify_receipts(device_public, binding):
    signed = json.loads(run([ENDPOINT, "export"]))["receipts"]
    require(len(signed) == 2, "Expected two durable signed observations")
    pairs = set()
    for receipt in signed:
        payload = STAGE / "received.json"
        sig = STAGE / "received.sig"
        payload.write_bytes(base64.b64decode(receipt["payload"], validate=True))
        sig.write_bytes(base64.b64decode(receipt["signature"], validate=True))
        run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", device_public, "-in", payload, "-sigfile", sig])
        obs = json.loads(payload.read_bytes())
        require(obs["binding"] == binding and obs["adapter"] == ADAPTER and obs["policy_revision"] == 1
                and obs["tool"] == "file" and obs["target_effect"] == "unknown", "Unexpected device receipt scope or evidence")
        pairs.add((obs["verdict"], obs["reason_code"], obs.get("rule_id")))
    require(pairs == {("deny", "dotenv", "fixture-files"), ("continue", "within_scope", None)}, "Missing expected policy decisions")


def child():
    require(Path(__file__).resolve() == STAGE / "check.py" and Path.cwd() == STAGE / "work"
            and os.environ.get("CODEX_HOME") == "/fixture/codex", "Use the outer smoke command")
    require(os.geteuid() == 0 and {name for _, name in socket.if_nameindex()} == {"lo"}, "Isolated root and loopback required")
    version = run([CODEX, "--version"]).decode().strip()
    catalog = json.loads(run([CODEX, "debug", "models", "--bundled"]))["models"]
    available = [m["slug"] for m in catalog if m.get("apply_patch_tool_type") == "freeform"]
    require(available, "Codex requires a bundled freeform apply_patch tool definition")
    model = "gpt-5.5" if "gpt-5.5" in available else available[0]
    config, pub, binding = provision()
    with daemon(config):
        for target in [".env", "guide.txt"]:
            exercise(target, model)
        require(not (STAGE / "work/.env").exists(), "Protected synthetic file was created")
        require((STAGE / "work/guide.txt").read_bytes() == FIXTURE_BYTES, "Allowed synthetic write missing")
        verify_receipts(pub, binding)
    digest = hashlib.sha256(Path(ENDPOINT).read_bytes()).hexdigest()
    print(f"{version}; endpoint sha256 {digest}\nManaged Codex apply_patch denied .env and wrote guide.txt. Both signed Linux test receipts verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--endpoint", type=Path)
    parser.add_argument("--isolated-child", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.isolated_child:
        child()
    elif options.codex and options.endpoint:
        isolate(options.codex.resolve(strict=True), options.endpoint.resolve(strict=True))
    else:
        parser.error("Supply existing --codex and --endpoint executables")
