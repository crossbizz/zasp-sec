import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

spec = importlib.util.spec_from_file_location("vps_services", Path(__file__).parent / "lib/vps_services.py")
services = importlib.util.module_from_spec(spec)
spec.loader.exec_module(services)
UID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


class Runtime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"ZASP_VPS_KUBE_CONTEXT": "named-target", "ZASP_VPS_CLUSTER_UID": UID,
                                                "ZASP_VPS_INSTALLATION_ID": "pilot"}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_cluster_identity_and_namespace_protect_mutations(self):
        for results in ([b"unexpected-cluster"], [UID.encode(), b'{"metadata":{"labels":{}}}']):
            with self.subTest(results=results), mock.patch.object(services, "command", side_effect=results) as calls:
                with self.assertRaises(services.ServiceError):
                    services.run("stop", "openbao")
                self.assertTrue(all(call.args[0][:3] == ["kubectl", "--context", "named-target"] for call in calls.call_args_list))
                self.assertFalse(any("scale" in call.args[0] for call in calls.call_args_list))

    def test_dry_runs_and_external_ownership(self):
        with mock.patch.dict(os.environ, {"ZASP_DRY_RUN": "1", "ZASP_VPS_OPENBAO_STATUS_TOKEN_FILE": "sensitivepath"}), \
                mock.patch.object(services, "command") as call, contextlib.redirect_stdout(io.StringIO()) as log:
            for action in ["install", "init", "unseal", "stop", "start"]:
                services.run(action, "openbao")
            call.assert_not_called()
            self.assertNotIn("sensitivepath", log.getvalue())
        with mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_MODE": "existing"}), mock.patch.object(services, "command") as call:
            for action in ["init", "unseal", "stop", "upgrade"]:
                with self.assertRaises(services.ServiceError):
                    services.run(action, "openbao")
            call.assert_not_called()
        with mock.patch.dict(os.environ, {"ZASP_VPS_NANGO_URL": "https://arbitrary.invalid:8443"}):
            with self.assertRaises(services.ServiceError):
                services.run("install", "nango")

    def test_installed_release_and_upgrade_never_rerun_migrations(self):
        s = services.Service("nango")
        with mock.patch.object(services, "command") as call, contextlib.redirect_stdout(io.StringIO()):
            services.install(s, "deployed")
            call.assert_not_called()
            with self.assertRaises(services.ServiceError):
                services.install(s, "failed")
        with mock.patch.object(services.Service, "namespace", return_value=True), \
                mock.patch.object(services.Service, "release", return_value="deployed"), \
                mock.patch.object(services, "command") as call, self.assertRaisesRegex(services.ServiceError, "checkpoint"):
            services.run("upgrade", "nango")
        call.assert_not_called()

    def test_scale_uses_resource_version_and_current_replicas(self):
        obj = {"metadata": {"resourceVersion": "19", "labels": {"app.kubernetes.io/managed-by": "Helm"},
                            "annotations": {"meta.helm.sh/release-name": "openbao", "meta.helm.sh/release-namespace": "openbao-system"}},
               "spec": {"replicas": 1}}
        with mock.patch.object(services.Service, "namespace", return_value=True), \
                mock.patch.object(services.Service, "release", return_value="deployed"), \
                mock.patch.object(services, "command", side_effect=[json.dumps(obj).encode(), b""]) as cmd, \
                contextlib.redirect_stdout(io.StringIO()):
            services.run("stop", "openbao")
            args = cmd.call_args_list[-1].args[0]
            self.assertTrue({"--resource-version=19", "--current-replicas=1", "--replicas=0"}.issubset(args))
        obj["metadata"]["annotations"]["meta.helm.sh/release-name"] = "unrelated"
        with mock.patch.object(services, "command", return_value=json.dumps(obj).encode()), self.assertRaises(services.ServiceError):
            services.owned_workload(services.Service("openbao"))

    def test_service_status_distinguishes_states_and_credentials(self):
        token = self.dir / "token"
        token.write_text("fixture-secret")
        token.chmod(0o600)
        with mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_STATUS_TOKEN_FILE": str(token),
                                         "ZASP_VPS_NANGO_SERVICE_KEY_FILE": str(token)}):
            up = (200, {"initialized": True, "sealed": False})
            for rows, status in [
                ([(501, {"initialized": False})], "uninitialized"), ([(503, {"sealed": True})], "sealed"),
                ([up, (403, {})], "unauthenticated"), ([up, (200, {"data": {"policies": ["status"]}})], "healthy"),
            ]:
                api = mock.Mock()
                api.request.side_effect = rows
                self.assertTrue(services.Service("openbao").inspect(api).startswith(status))
            api = mock.Mock()
            api.request.side_effect = [up, (200, {"data": {"policies": ["root"]}})]
            with self.assertRaisesRegex(services.ServiceError, "non-root"):
                services.Service("openbao").inspect(api)
            api.request.side_effect = [(200, {"result": "ok"}), (200, {"data": []})]
            self.assertIn("no provider integrations", services.Service("nango").inspect(api))
            self.assertEqual(api.request.call_args.kwargs["headers"]["Authorization"], "Bearer fixture-secret")
            token.chmod(0o644)
            with self.assertRaises(services.ServiceError):
                services.read_file(str(token), private=True)

    def test_create_only_encrypted_handoff_and_idempotent_resume(self):
        packet = base64.b64encode(b"\xc1" + os.urandom(64)).decode()
        result = {"keys_base64": [packet] * 5, "root_token": packet, "unused-clear-field": "sensitive"}
        path = self.dir / "handoff"
        api = mock.Mock()
        api.request.side_effect = [(200, {"initialized": False}), (200, result)]
        with mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_HANDOFF_FILE": str(path)}), \
                mock.patch.object(services, "pgp_recipients", return_value=["public"] * 6), \
                contextlib.redirect_stdout(io.StringIO()) as log:
            service = services.Service("openbao")
            services.initialize(service, api)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            expected = path.read_bytes()
            self.assertEqual(json.loads(expected)["cluster_uid"], UID)
            self.assertNotIn("sensitive", expected.decode())
            self.assertNotIn(packet, log.getvalue())
            self.assertEqual(api.request.call_args.args[2]["secret_threshold"], 3)
            api.request.side_effect = [(200, {"initialized": True})]
            services.initialize(service, api)
            self.assertEqual(expected, path.read_bytes())
            api.request.side_effect = [(200, {"initialized": False})]
            with self.assertRaisesRegex(services.ServiceError, "preserved"):
                services.initialize(service, api)
            self.assertEqual(expected, path.read_bytes())
        result["root_token"] = "hvs.cleartext"
        with self.assertRaises(services.ServiceError):
            services.encrypted_init_fields(result)

    def test_pgp_key_failure_and_duplicate_fingerprint_do_not_initialize(self):
        for name in ["custodian-" + str(i) for i in range(1, 6)] + ["root"]:
            (self.dir / (name + ".gpg")).write_bytes(b"invalid-public-packet")
        svc = services.Service("openbao")
        env = {"ZASP_VPS_OPENBAO_PGP_KEYS_DIR": str(self.dir), "ZASP_VPS_OPENBAO_HANDOFF_FILE": str(self.dir / "handoff")}
        api = mock.Mock()
        api.request.return_value = (200, {"initialized": False})
        with mock.patch.dict(os.environ, env):
            # Exercise an actual gpg parser failure without a private key or local gpg-agent.
            with self.assertRaisesRegex(services.ServiceError, "verify a binary OpenPGP"):
                services.initialize(svc, api)
            self.assertEqual(api.request.call_count, 1)
            listing = b"pub:-:2048:1:0000000000000001:1:2000000000::-:::ecEC:\nfpr:::::::::0000000000000000000000000000000000000001:"
            with mock.patch.object(services, "command", return_value=listing), self.assertRaisesRegex(services.ServiceError, "six distinct"):
                services.pgp_recipients(svc)
        self.assertFalse((self.dir / "handoff").exists())

    def test_first_install_checks_chart_inputs_and_conflicts_before_helm(self):
        service = services.Service("openbao")
        value = self.dir / "public-values"
        value.write_text("image: registry.example/openbao@sha256:" + "1" * 64)
        template = b"kind: StatefulSet\nspec:\n  template:\n    spec:\n      volumes:\n        - name: tls\n          secret: {secretName: openbao-server-tls}\n"
        with mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_VALUES_FILE": str(value)}), \
                mock.patch.object(service, "namespace") as namespace, contextlib.redirect_stdout(io.StringIO()):
            for responses, expected in [([template, b"tls.crt\nca.crt\n"], "credential"),
                                        ([template, b"tls.crt\ntls.key\nca.crt\n", b"statefulset/openbao"], "pre-existing")]:
                with mock.patch.object(services, "command", side_effect=responses) as call:
                    with self.assertRaisesRegex(services.ServiceError, expected):
                        services.install(service, None)
                    self.assertTrue(all("install" not in c.args[0] for c in call.call_args_list))
            with mock.patch.object(services, "command", side_effect=[template, b"tls.crt\ntls.key\nca.crt\n", b"", b""]) as call:
                services.install(service, None)
                namespace.assert_called_with(create=True)
                args = call.call_args_list[-1].args[0]
                self.assertIn("install", args)
                self.assertNotIn("--wait", args)
                self.assertEqual(args[1:3], ["--kube-context", "named-target"])

    def test_nango_rejects_callback_mismatch_before_namespace_creation(self):
        service = services.Service("nango")
        values = self.dir / "nango-values"
        values.write_text("publicOrigin: https://wrong.example")
        with mock.patch.dict(os.environ, {"ZASP_VPS_NANGO_VALUES_FILE": str(values), "ZASP_ORIGIN": "https://approved.example"}), \
                mock.patch.object(service, "namespace") as ns, self.assertRaisesRegex(services.ServiceError, "publicOrigin"):
            services.install(service, None)
        ns.assert_not_called()

    def test_no_unseal_through_piped_input(self):
        api = mock.Mock()
        api.request.return_value = (200, {"sealed": True, "initialized": True, "type": "shamir"})
        with mock.patch("sys.stdin.isatty", return_value=False), self.assertRaisesRegex(services.ServiceError, "interactive"):
            services.unseal(api)
        self.assertEqual(api.request.call_count, 1)

    @contextlib.contextmanager
    def tls_server(self, handler):
        crt, key = self.dir / "tls.crt", self.dir / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture",
                        "-addext", "subjectAltName=DNS:fixture", "-keyout", str(key), "-out", str(crt)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        with HTTPServer(("127.0.0.1", 0), handler) as server:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield server.server_address, ssl.create_default_context(cafile=str(crt))
            finally:
                server.shutdown()
                thread.join()

    def test_tls_health_read_against_isolated_loopback_service(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(307 if self.path == "/redirect" else 200)
                self.end_headers()
                self.wfile.write(b'{"result":"ok"}')

            def log_message(self, *args):
                pass

        with self.tls_server(Handler) as (address, trusted):
            api = services.API("fixture", 443, address, trusted)
            self.assertEqual(api.request("GET", "/ready"), (200, {"result": "ok"}))
            with self.assertRaisesRegex(services.ServiceError, "redirect"):
                api.request("GET", "/redirect")
            with self.assertRaisesRegex(services.ServiceError, "TLS"):
                services.API("wrong-host", 443, address, trusted).request("GET", "/ready")

    def test_slow_single_init_over_tls_preserves_the_encrypted_handoff(self):
        packet = base64.b64encode(b"\xc1" + os.urandom(64)).decode()
        path = self.dir / "handoff"
        calls, reservations = [], []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"initialized": bool(calls)}).encode())

            def do_PUT(self):
                calls.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                reservations.append(path.read_bytes())
                # Cross the ordinary socket timeout after the server has committed the write.
                time.sleep(services.COMPONENT_IO_TIMEOUT + 0.3)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"keys_base64": [packet] * 5, "root_token": packet}).encode())

            def log_message(self, *args):
                pass

        with self.tls_server(Handler) as (address, trusted), \
                mock.patch.object(services, "pgp_recipients", return_value=["public"] * 6), \
                mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_HANDOFF_FILE": str(path)}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            api = services.API("fixture", 443, address, trusted)
            service = services.Service("openbao")
            services.initialize(service, api)
            handoff = path.read_bytes()
            services.initialize(service, api)
            self.assertEqual(path.read_bytes(), handoff)
            self.assertEqual(json.loads(handoff)["bootstrap_packet"], packet)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(packet, output.getvalue())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "/v1/sys/init")
        self.assertEqual(calls[0][1]["secret_threshold"], 3)
        self.assertTrue(reservations[0].startswith(b"pending:"))

    def test_init_acknowledgement_lost_after_commit_preserves_pending_handoff(self):
        commits = []
        path = self.dir / "handoff"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"initialized": bool(commits)}).encode())

            def do_PUT(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                commits.append(self.path)
                self.close_connection = True

            def log_message(self, *args):
                pass

        with self.tls_server(Handler) as (address, trusted), \
                mock.patch.object(services, "pgp_recipients", return_value=["public"] * 6), \
                mock.patch.dict(os.environ, {"ZASP_VPS_OPENBAO_HANDOFF_FILE": str(path)}):
            api = services.API("fixture", 443, address, trusted)
            service = services.Service("openbao")
            with self.assertRaisesRegex(services.ServiceError, "preserve the pending handoff"):
                services.initialize(service, api)
            pending = path.read_bytes()
            self.assertTrue(pending.startswith(b"pending:"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(services.ServiceError, "server is initialized but the handoff is pending"):
                services.initialize(service, api)
            self.assertEqual(path.read_bytes(), pending)
        self.assertEqual(commits, ["/v1/sys/init"])


if __name__ == "__main__":
    unittest.main()
