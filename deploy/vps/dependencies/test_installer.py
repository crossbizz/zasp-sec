import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "deploy/zasp/lib"))
import vps_dependencies as dep

UID = "296fb297-9538-44c7-af54-383498aa4190"
IMAGE = "registry.example/operand@sha256:" + "a" * 64


def make_installer():
    return dep.Installer(ROOT, "pilot", UID, "zasp-pilot")


def uri(password):
    from urllib.parse import quote
    return ("postgresql://openfga:" + quote(password, safe="") + "@" + dep.cluster_host("openfga-db") +
            ":5432/openfga?sslmode=verify-full&sslrootcert=/etc/database-ca/ca.crt").encode()


class Contract(unittest.TestCase):
    def test_clusters_attach_dedicated_storage_authentication_and_tls(self):
        objects = dep.resources(ROOT, IMAGE, "retained")
        catalog = objects[0]
        self.assertEqual(catalog["spec"]["images"], [{"major": 18, "image": IMAGE}])
        clusters = [o for o in objects if o["kind"] == "Cluster"]
        self.assertEqual({x["metadata"]["name"] for x in clusters}, set(dep.DBS))
        for db in clusters:
            name = db["metadata"]["name"]
            spec = db["spec"]
            role = dep.DBS[name]
            self.assertEqual(spec["storage"], {"size": "10Gi", "storageClass": "retained"})
            self.assertTrue(spec["bootstrap"]["initdb"]["dataChecksums"])
            self.assertFalse(spec["enableSuperuserAccess"])
            self.assertEqual(spec["bootstrap"]["initdb"]["owner"], role)
            self.assertEqual(spec["postgresql"]["pg_hba"], [f"hostssl {role} {role} all scram-sha-256", "host all all all reject"])
            self.assertEqual(spec["certificates"]["serverTLSSecret"], name + "-tls")
            policy = next(o for o in objects if o["metadata"]["name"] == name + "-ingress")
            db_ports, operator = policy["spec"]["ingress"]
            self.assertEqual(db_ports["ports"][0]["port"], 5432)
            self.assertEqual(db_ports["from"][0]["namespaceSelector"], dep.namespace_selector(dep.RUNTIME))
            self.assertEqual(operator["ports"][0]["port"], 8000)

    def test_runtime_ingress_limits_selected_namespace_and_clients_per_port(self):
        for namespace, objects in [("zasp", dep.resources(ROOT, IMAGE, "retained")),
                                   ("agentsec", dep.resources(ROOT, IMAGE, "retained", "agentsec"))]:
            policies = {o["metadata"]["name"]: o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["namespace"] == dep.RUNTIME}
            self.assertEqual(set(policies), {"openfga-vps-ingress", "temporal-vps-ingress"})
            for name, port in [("openfga", 8080), ("temporal", 7233)]:
                rules = policies[name + "-vps-ingress"]["spec"]["ingress"]
                expected = ["agentsec-api", "agentsec-discovery-worker", "agentsec-discovery-scheduler"]
                if name == "openfga":
                    expected.append("zasp-authorization-projector")
                self.assertEqual(rules[0], {
                    "from": [{"namespaceSelector": dep.namespace_selector(namespace), "podSelector": {"matchExpressions": [{
                        "key": "app.kubernetes.io/name", "operator": "In", "values": expected,
                    }]}}],
                    "ports": [{"port": port, "protocol": "TCP"}],
                })
                self.assertEqual(rules[1:], [{"from": [{"podSelector": {"matchLabels": dep.workload_labels("temporal")}}]}] if name == "temporal" else [])
        with self.assertRaises(dep.Rejected):
            dep.resources(ROOT, IMAGE, "retained", "*")

    def test_reconcile_only_known_previous_runtime_policies_using_resource_version(self):
        unit = make_installer()
        for old, new in zip(dep.runtime_policy("agentsec", include_authorization_projector=False), dep.runtime_policy("zasp"), strict=True):
            live = copy.deepcopy(old)
            live["metadata"].update(labels={dep.LABEL: unit.owner}, resourceVersion="102", annotations={dep.SPEC: dep.fingerprint(old)})
            with patch.object(unit, "existing", return_value=live), patch.object(unit, "kubectl") as run:
                self.assertFalse(unit.owned(new))
                run.assert_not_called()
                unit.create(new)
                command = run.call_args.args
                self.assertEqual(command[:-1], ("-n", dep.RUNTIME, "patch", "networkpolicy", new["metadata"]["name"], "--type=json", "-p"))
                self.assertEqual(json.loads(command[-1]), [
                    {"op": "test", "path": "/metadata/resourceVersion", "value": "102"},
                    {"op": "replace", "path": "/spec", "value": new["spec"]},
                    {"op": "replace", "path": "/metadata/annotations/zasp.io~1installer-spec-sha256", "value": dep.fingerprint(new)},
                ])
                live["spec"] = new["spec"]
                live["metadata"]["annotations"][dep.SPEC] = dep.fingerprint(new)
                unit.create(new)
                run.assert_called_once()
            for change in ["owner", "spec", "annotation", "version"]:
                with self.subTest(change=change):
                    broken = copy.deepcopy(old)
                    broken["metadata"].update(labels={dep.LABEL: unit.owner}, resourceVersion="123", annotations={dep.SPEC: dep.fingerprint(old)})
                    if change == "owner":
                        broken["metadata"]["labels"][dep.LABEL] = "foreign"
                    if change == "annotation":
                        broken["metadata"]["annotations"].clear()
                    if change == "version":
                        del broken["metadata"]["resourceVersion"]
                    if change == "spec":
                        broken["spec"]["ingress"].append({"from": [{}]})
                    with patch.object(unit, "existing", return_value=broken), patch.object(unit, "kubectl") as run:
                        with self.assertRaises(dep.Rejected):
                            unit.create(new)
                        run.assert_not_called()

    def test_temporal_migration_and_actual_values_use_verified_tls(self):
        job = dep.migration(ROOT)
        self.assertNotIn("ttlSecondsAfterFinished", job["spec"])
        pod = job["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        values = dep.values(ROOT, "temporal")["server"]
        self.assertTrue(values["tls"]["frontend"]["requireClientAuth"])
        self.assertTrue(values["tls"]["internode"]["requireClientAuth"])
        for key, step in zip(("default", "visibility"), pod["initContainers"] + pod["containers"]):
            env = {e["name"]: e for e in step["env"]}
            sql = values["config"]["persistence"]["datastores"][key]["sql"]
            self.assertRegex(step["image"], r"@sha256:[0-9a-f]{64}$")
            self.assertEqual(env["SQL_TLS"]["value"], "true")
            self.assertTrue(sql["tls"]["enableHostVerification"])
            self.assertEqual(sql["connectAddr"], env["SQL_HOST"]["value"] + ":5432")
            self.assertEqual(sql["tls"]["serverName"], env["SQL_TLS_SERVER_NAME"]["value"])
            self.assertEqual(sql["existingSecret"], env["SQL_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"])
        fga = dep.values(ROOT, "openfga")
        self.assertTrue(fga["http"]["tls"]["enabled"] and fga["grpc"]["tls"]["enabled"])
        self.assertTrue(fga["datastore"]["applyMigrations"])
        self.assertEqual(fga["authn"]["method"], "preshared")

    def test_dsn_rejects_bypasses(self):
        password = "a p&ssword/with%reserved+chars"
        good = uri(password)
        dep.verify_uri(good, password.encode())
        for bad in [good + b"&sslmode=", good + b"&sslmode=disable", good + b"&passfile=x",
                    good.replace(b"verify-full", b"require"), good.replace(b"svc.cluster.local", b"example.test"),
                    good.replace(b"/openfga?", b"/postgres?"), good.replace(b"/etc/database-ca", b"/tmp"), good + b"#x", b"\xff"]:
            with self.subTest(bad=bad), self.assertRaises(dep.Rejected):
                dep.verify_uri(bad, password.encode())
        with self.assertRaises(dep.Rejected):
            dep.verify_uri(good, b"different")

    def test_target_and_ownership(self):
        unit = make_installer()
        ns = {"metadata": {"uid": UID, "labels": {dep.LABEL: unit.owner}}}
        with patch.object(unit, "get", return_value=ns):
            unit.target()
        for other in [{"metadata": {"uid": "foreign"}}, {"metadata": {"uid": UID, "labels": {dep.LABEL: "foreign"}}}]:
            with patch.object(unit, "get", return_value=other), self.assertRaises(dep.Rejected):
                unit.target()
        obj = dep.migration(ROOT)
        existing = copy.deepcopy(obj)
        existing["metadata"].update(labels={dep.LABEL: unit.owner}, annotations={dep.SPEC: dep.fingerprint(obj)})
        existing["spec"]["suspend"] = False
        with patch.object(unit, "existing", return_value=existing), patch.object(unit, "kubectl") as run:
            unit.create(obj)
            run.assert_not_called()
            existing["spec"]["template"]["spec"]["containers"][0]["image"] = "unexpected:latest"
            with self.assertRaises(dep.Rejected):
                unit.create(obj)
            run.assert_not_called()
        with patch.object(unit, "existing", return_value={}), patch.object(unit, "kubectl") as run:
            unit.create(obj)
            self.assertEqual(run.call_args.args, ("create", "-f", "-"))
            doc = json.loads(run.call_args.kwargs["data"])
            self.assertEqual(doc["metadata"]["annotations"][dep.SPEC], dep.fingerprint(obj))

    def test_chart_digest_and_damaged_archive(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as target:
            name, version, data = "temporal", "1.7.0", b"test archive"
            src = Path(source) / f"{name}-{version}.tgz"
            src.write_bytes(data)
            with patch.dict(os.environ, {"ZASP_VPS_RUNTIME_CHART_DIR": source}), patch.dict(dep.PINS, {name: ("temporalio", version, hashlib.sha256(data).hexdigest())}, clear=True):
                self.assertEqual(dep.charts(Path(target))[name].read_bytes(), data)
                src.write_bytes(data + b"bad")
                with self.assertRaises(dep.Rejected):
                    dep.charts(Path(target))

    def test_release_ownership_and_retry(self):
        unit = make_installer()
        hit = [{"name": "temporal", "chart": "temporal-1.7.0", "status": "deployed"}]
        for selected, expected in [([], False), (hit, True)]:
            with patch.object(unit, "helm", side_effect=[json.dumps(hit), json.dumps(selected), json.dumps(dep.values(ROOT, "temporal"))]) as helm:
                if expected:
                    self.assertEqual(unit.release("temporal"), "deployed")
                else:
                    with self.assertRaises(dep.Rejected):
                        unit.release("temporal")
                self.assertIn(dep.LABEL + "=" + unit.owner, helm.call_args_list[1].args)
        for status, command in [(None, "install"), ("failed", "upgrade"), ("deployed", None), ("pending-install", "error")]:
            with patch.object(unit, "release", return_value=status), patch.object(unit, "helm") as helm:
                if command == "error":
                    with self.assertRaises(dep.Rejected):
                        unit.install_release("temporal", "archive", "values")
                else:
                    unit.install_release("temporal", "archive", "values")
                if command in {"error", None}:
                    helm.assert_not_called()
                else:
                    self.assertEqual(helm.call_args.args[0], command)
                    self.assertIn("--wait-for-jobs", helm.call_args.args)


    def test_network_rejects_additive_grants_and_allows_dedicated_owned_rules(self):
        unit = make_installer()
        policy = {"metadata": {"name": "openfga-db-ingress", "labels": {dep.LABEL: unit.owner}}, "spec": {"ingress": [{"from": [{}]}]}}
        empty = json.dumps({"items": []})
        with patch.object(unit, "kubectl", side_effect=[json.dumps({"items": [policy]}), empty]):
            unit.network()
        policy["metadata"]["name"] = "someone-else"
        with patch.object(unit, "kubectl", return_value=json.dumps({"items": [policy]})), self.assertRaisesRegex(dep.Rejected, "additive ingress grant"):
            unit.network()
        policy["spec"]["ingress"] = []
        with patch.object(unit, "kubectl", return_value=json.dumps({"items": [policy]})):
            unit.network()

    def test_release_rejects_values_drift(self):
        unit = make_installer()
        hits = json.dumps([{"name": "openfga", "chart": "openfga-0.3.15", "status": "deployed"}])
        with patch.object(unit, "helm", side_effect=[hits, hits, '{"authn":{"method":"none"}}']), self.assertRaisesRegex(dep.Rejected, "configuration drift"):
            unit.release("openfga")


class Operations(unittest.TestCase):
    def test_doctor_does_not_write_and_install_orders_dependencies(self):
        for action in ["doctor", "install"]:
            unit = make_installer()
            events = []
            with contextlib.ExitStack() as ctx:
                ctx.enter_context(patch.dict(os.environ, {"ZASP_VPS_POSTGRES_IMAGE": IMAGE}))
                ctx.enter_context(patch.object(dep, "charts", return_value={"temporal": "chart.tgz", "openfga": "chart.tgz"}))
                for method in ["target", "network", "get", "secrets", "owned", "release", "helm", "create", "wait", "install_release", "status"]:
                    ctx.enter_context(patch.object(unit, method, side_effect=lambda *a, m=method: events.append((m, a))))
                with contextlib.redirect_stdout(io.StringIO()):
                    unit.perform(action, False)
            actions = [x[0] for x in events]
            self.assertEqual(actions[0], "target")
            self.assertEqual(actions.count("helm"), 2)
            if action == "doctor":
                self.assertFalse(set(actions) & {"create", "wait", "install_release"})
                continue
            created = [e[1][0]["kind"] for e in events if e[0] == "create"]
            self.assertLess(max(i for i, k in enumerate(created) if k == "NetworkPolicy"), created.index("Cluster"))
            self.assertEqual(created[-1], "Job")
            self.assertTrue(all(c[1][1] == "cluster.postgresql.cnpg.io" for c in events if c[0] == "wait" and c[1][-1] != "complete"))
            self.assertLess(max(i for i, v in enumerate(actions) if v == "wait"), actions.index("install_release"))
            self.assertEqual(actions[-1], "status")

    def test_healthy_private_status_rejects_unbound_pvc_public_service_stale_rollout(self):
        unit = make_installer()

        def check_status(phase="Bound", service="ClusterIP", observed=1):
            def objects(ns, kind, name):
                if kind == "cluster.postgresql.cnpg.io":
                    return {"metadata": {"labels": {dep.LABEL: unit.owner}}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
                if kind == "deployment":
                    return {"metadata": {"generation": 1}, "spec": {"replicas": 1}, "status": {"readyReplicas": 1, "updatedReplicas": 1, "observedGeneration": observed}}
                return {"spec": {"type": service}}
            with patch.object(unit, "get", side_effect=objects), patch.object(unit, "kubectl", return_value=json.dumps({"items": [{"status": {"phase": phase}}]})), patch.object(unit, "release", return_value="deployed"), contextlib.redirect_stdout(io.StringIO()):
                unit.status()
        check_status()
        for wrong in [dict(phase="Pending"), dict(service="NodePort"), dict(observed=0)]:
            with self.assertRaises(dep.Rejected):
                check_status(**wrong)

    def test_dry_run_offline_and_raw_error_redaction(self):
        with patch.dict(os.environ, {"ZASP_VPS_INSTALLATION_ID": "pilot", "ZASP_DRY_RUN": "1", "ZASP_VPS_POSTGRES_IMAGE": IMAGE}), patch.object(dep, "run") as run, contextlib.redirect_stdout(io.StringIO()):
            dep.main(["x", str(ROOT), "pilot", UID, "install"])
            run.assert_not_called()
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(["helm"], 1, b"private", b"private")):
            with self.assertRaisesRegex(dep.Rejected, "helm operation failed") as error:
                dep.run(["helm", "template"])
            self.assertNotIn("private", str(error.exception))

    def test_frozen_authority_is_private_and_ephemeral(self):
        with patch.dict(os.environ, {"ZASP_VPS_INSTALLATION_ID": "pilot", "ZASP_DRY_RUN": "0"}), patch.object(dep, "run", return_value=b"fake sensitive kubeconfig") as call:
            paths = []
            def validate(action, dry):
                path = Path(os.environ["KUBECONFIG"])
                paths.append(path)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.read_bytes(), b"fake sensitive kubeconfig")
            with patch.object(dep.Installer, "perform", side_effect=validate):
                dep.main(["x", str(ROOT), "pilot", UID, "install"])
            self.assertFalse(paths[0].exists())
            self.assertIn("--flatten", call.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
