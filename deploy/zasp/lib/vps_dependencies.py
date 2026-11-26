"""Install the isolated Postgres, OpenFGA and Temporal prerequisites on one selected k3s cluster."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import parse_qs, unquote, urlsplit

DATA = "zasp-data"
RUNTIME = "zasp-runtime"
LABEL = "zasp.io/installation"
SPEC = "zasp.io/installer-spec-sha256"
DBS = {"openfga-db": "openfga", "temporal-db": "temporal", "temporal-visibility-db": "temporal_visibility"}
PINS = {
    "temporal": ("temporalio", "1.7.0", "f7b443f637b71fcbddd12900e5be9fe4c18cf741495d7b2cb247670681bf57d4"),
    "openfga": ("openfga", "0.3.15", "bde4e1fa8962314f403c8f52a49294fd583597e920465be21a78ba165bcc0894"),
}
DEPLOYMENTS = ["temporal-frontend", "temporal-history", "temporal-matching", "temporal-worker", "openfga"]


class Rejected(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Rejected(message)


def run(args, *, data=None, timeout=50):
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Rejected(f"{Path(args[0]).name} unavailable or timed out") from None
    # A rejected provider operation may include Secret data or rendered manifests.
    check(result.returncode == 0, f"{Path(args[0]).name} operation failed; inspect the named component on the selected cluster")
    return result.stdout


def document(raw):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise Rejected("invalid cluster response") from None


def read_yaml(path):
    import yaml
    return list(yaml.safe_load_all(path.read_text()))


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def cluster_host(name):
    return f"{name}-rw.{DATA}.svc.cluster.local"


def workload_labels(name):
    return {"app.kubernetes.io/name": name, "app.kubernetes.io/instance": name}


def namespace_selector(namespace):
    return {"matchLabels": {"kubernetes.io/metadata.name": namespace}}


def runtime_policy(app_namespace):
    internal = {"podSelector": {"matchLabels": workload_labels("temporal")}}
    apps = {"namespaceSelector": namespace_selector(app_namespace), "podSelector": {"matchExpressions": [{
        "key": "app.kubernetes.io/name", "operator": "In",
        "values": ["agentsec-api", "agentsec-discovery-worker", "agentsec-discovery-scheduler"],
    }]}}
    result = []
    for service, port in [("openfga", 8080), ("temporal", 7233)]:
        rules = [{"from": [apps], "ports": [{"port": port, "protocol": "TCP"}]}]
        if service == "temporal":
            # Member services and the authenticated namespace job communicate privately.
            rules.append({"from": [internal]})
        result.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                       "metadata": {"name": service + "-vps-ingress", "namespace": RUNTIME},
                       "spec": {"podSelector": {"matchLabels": workload_labels(service)},
                                "policyTypes": ["Ingress"], "ingress": rules}})
    return result


def resources(root, image, storage_class):
    deploy = root / "deploy"
    catalog = {"apiVersion": "postgresql.cnpg.io/v1", "kind": "ImageCatalog",
               "metadata": {"name": "pilot-database-images", "namespace": DATA},
               "spec": {"images": [{"major": 18, "image": image}]}}
    result = [catalog]
    for db, role in DBS.items():
        cluster, policy = read_yaml(deploy / "vps/openfga-postgres/cluster.yaml")
        cluster["metadata"]["name"] = db
        spec = cluster["spec"]
        spec["storage"]["storageClass"] = storage_class
        spec["certificates"]["serverTLSSecret"] = db + "-tls"
        spec["certificates"]["serverCASecret"] = "openfga-db-public-ca"
        bootstrap = spec["bootstrap"]["initdb"]
        bootstrap.update(database=role, owner=role, secret={"name": db + "-owner"})
        spec["postgresql"]["pg_hba"] = [f"hostssl {role} {role} all scram-sha-256", "host all all all reject"]
        policy["metadata"]["name"] = db + "-ingress"
        policy["spec"]["podSelector"]["matchLabels"]["cnpg.io/cluster"] = db
        service = "openfga" if db == "openfga-db" else "temporal"
        policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"] = workload_labels(service)
        result.extend([policy, cluster])
    result.extend(runtime_policy("agentsec"))
    return result


def migration(root):
    source = root / "deploy/staging/temporal-migrate.yaml"
    job, = read_yaml(source)
    job["metadata"] = {"name": "zasp-vps-temporal-schema-1320", "namespace": RUNTIME}
    # A durable receipt prevents setup-schema from being replayed after restart.
    job["spec"].pop("ttlSecondsAfterFinished", None)
    pod = job["spec"]["template"]
    pod["metadata"]["labels"].update(workload_labels("temporal"))
    pod["spec"]["automountServiceAccountToken"] = False
    steps = pod["spec"]["initContainers"] + pod["spec"]["containers"]
    for step, db in zip(steps, ("temporal-db", "temporal-visibility-db"), strict=True):
        step["env"].append({"name": "SQL_TLS_SERVER_NAME", "value": cluster_host(db)})
        for env in step["env"]:
            if env["name"] == "SQL_HOST":
                env["value"] = cluster_host(db)
    return job


def values(root, chart):
    result, = read_yaml(root / f"deploy/staging/{chart}.values.yaml")
    if chart == "temporal":
        result["server"]["replicaCount"] = 1
        datastores = result["server"]["config"]["persistence"]["datastores"]
        for key, db in (("default", "temporal-db"), ("visibility", "temporal-visibility-db")):
            datastores[key]["sql"]["connectAddr"] = cluster_host(db) + ":5432"
            datastores[key]["sql"]["tls"]["serverName"] = cluster_host(db)
    else:
        result["replicaCount"] = 1
    return result


def charts(temp):
    supplied = os.environ.get("ZASP_VPS_RUNTIME_CHART_DIR")
    paths = {}
    for name, (owner, version, digest) in PINS.items():
        filename = f"{name}-{version}.tgz"
        target = temp / filename
        if supplied:
            shutil.copyfile(Path(supplied) / filename, target)
        else:
            url = f"https://github.com/{owner}/helm-charts/releases/download/{name}-{version}/{filename}"
            run(["curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
                 "--location", "--max-filesize", "33554432", "--max-time", "75", "--output", str(target), url], timeout=85)
        check(target.stat().st_size <= 32 << 20 and hashlib.sha256(target.read_bytes()).hexdigest() == digest,
              f"official {name} chart archive does not match pinned SHA-256")
        paths[name] = target
    return paths


def decode(secret, field):
    try:
        return base64.b64decode(secret.get("data", {})[field], validate=True)
    except (ValueError, KeyError, TypeError):
        raise Rejected("required Secret field missing or malformed") from None


def verify_uri(uri, password):
    try:
        parsed = urlsplit(uri.decode("utf-8"))
        correct = (parsed.scheme in {"postgresql", "postgres"} and parsed.hostname == cluster_host("openfga-db")
                   and parsed.port == 5432 and parsed.username == "openfga" and unquote(parsed.password or "").encode() == password
                   and parsed.path == "/openfga" and parsed.fragment == "" and parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True) ==
                   {"sslmode": ["verify-full"], "sslrootcert": ["/etc/database-ca/ca.crt"]})
    except (ValueError, UnicodeError):
        correct = False
    check(correct, "OpenFGA datastore URI must bind the dedicated owner, database, verified TLS and CA path")


def matches(live, expected):
    # Admission may default fields. Drift in any configured security or storage setting must fail.
    if isinstance(expected, dict):
        return isinstance(live, dict) and all(k in live and matches(live[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(live, list) and len(live) == len(expected) and all(matches(a, b) for a, b in zip(live, expected))
    return live == expected


class Installer:
    def __init__(self, root, context, uid, owner):
        self.root = root
        check(context and not context.startswith("-") and len(context) <= 256 and context.isprintable(), "invalid Kubernetes context")
        check(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", uid), "invalid expected kube-system UID")
        check(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", owner), "invalid installation ID")
        self.context, self.uid, self.owner = context, uid, owner

    def kubectl(self, *args, data=None, timeout=50):
        return run(["kubectl", "--context", self.context, *args], data=data, timeout=timeout)

    def helm(self, *args, timeout=50):
        return run(["helm", "--kube-context", self.context, "--namespace", RUNTIME, *args], timeout=timeout)

    def get(self, ns, kind, name, *, optional=False):
        flags = ["--ignore-not-found"] if optional else []
        base = ["-n", ns] if ns else []
        raw = self.kubectl(*base, "get", kind, name, *flags, "-o", "json")
        return document(raw) if raw.strip() else {}

    def target(self):
        system = self.get("", "namespace", "kube-system")
        check(system.get("metadata", {}).get("uid") == self.uid, "selected cluster UID mismatch")
        for ns in [DATA, RUNTIME]:
            labels = self.get("", "namespace", ns).get("metadata", {}).get("labels", {})
            check(labels.get(LABEL) == self.owner, f"{ns} must be a dedicated namespace labeled for this installation")

    def secrets(self):
        # Validate sensitive input in memory. No subprocess argument or error contains its contents.
        def secret(ns, name):
            return self.get(ns, "secret", name)
        ca = decode(secret(DATA, "openfga-db-public-ca"), "ca.crt")
        runtime_ca = decode(secret(RUNTIME, "runtime-database-ca"), "ca.crt")
        check(ca.strip() and ca.strip() in runtime_ca, "runtime CA bundle must include the database CA")
        passwords = set()
        for db, role in DBS.items():
            db_owner = secret(DATA, db + "-owner")
            pwd = decode(db_owner, "password")
            check(len(pwd) >= 16 and decode(db_owner, "username") == role.encode(), f"invalid dedicated owner for {db}")
            check(pwd not in passwords, "each dependency database requires a distinct password")
            passwords.add(pwd)
            tls = secret(DATA, db + "-tls")
            check(decode(tls, "tls.crt") and decode(tls, "tls.key"), f"{db} TLS input missing")
            if db == "openfga-db":
                verify_uri(decode(secret(RUNTIME, "openfga-datastore"), "uri"), pwd)
            else:
                name = "temporal-persistence" if role == "temporal" else "temporal-visibility"
                check(decode(secret(RUNTIME, name), "password") == pwd, f"{name} database password mismatch")
        for name in ["openfga-tls", "temporal-frontend-tls", "temporal-internode-tls"]:
            tls = secret(RUNTIME, name)
            check(all(decode(tls, key) for key in ["tls.crt", "tls.key", "ca.crt"]), f"{name} TLS input missing")
        token = decode(secret(RUNTIME, "openfga-auth"), "keys").strip()
        check(len(token) >= 16 and token not in passwords, "OpenFGA needs a separate preshared credential")

    def existing(self, resource):
        meta = resource["metadata"]
        kind = {"Cluster": "cluster.postgresql.cnpg.io", "ImageCatalog": "imagecatalog.postgresql.cnpg.io"}.get(resource["kind"], resource["kind"])
        return self.get(meta["namespace"], kind, meta["name"], optional=True)

    def owned(self, resource):
        existing = self.existing(resource)
        if not existing:
            return False
        meta = existing.get("metadata", {})
        check(meta.get("labels", {}).get(LABEL) == self.owner and meta.get("annotations", {}).get(SPEC) == fingerprint(resource)
              and matches(existing.get("spec", {}), resource["spec"]),
              f"refusing to adopt or overwrite {resource['kind']}/{resource['metadata']['name']}")
        return True

    def create(self, resource):
        if self.owned(resource):
            return
        # create (not apply) refuses to overwrite an object created concurrently.
        stamp = fingerprint(resource)
        meta = {**resource["metadata"], "labels": {LABEL: self.owner}, "annotations": {SPEC: stamp}}
        self.kubectl("create", "-f", "-", data=json.dumps({**resource, "metadata": meta}).encode())

    def release(self, name):
        def listed(extra):
            return document(self.helm("list", "--all", "--filter", "^" + name + "$", *extra, "-o", "json"))
        hits = listed([])
        if not hits:
            return None
        owned = listed(["--selector", LABEL + "=" + self.owner])
        check(len(hits) == 1 and len(owned) == 1 and owned[0]["name"] == name and hits[0]["chart"] == f"{name}-{PINS[name][1]}",
              f"refusing foreign release or unexpected chart for {name}")
        status = hits[0]["status"]
        if status == "deployed":
            actual = document(self.helm("get", "values", name, "-o", "json"))
            check(actual == values(self.root, name), f"unexpected {name} release values; inspect configuration drift")
        return status

    def wait(self, ns, kind, name, condition):
        self.kubectl("-n", ns, "wait", f"--for=condition={condition}", "--timeout=10m", f"{kind}/{name}", timeout=620)

    def install_release(self, name, archive, overrides):
        status = self.release(name)
        if status == "deployed":
            return
        check(status in (None, "failed"), f"{name} release needs operator inspection before retry")
        self.helm("install" if status is None else "upgrade", name, str(archive), "-f", str(overrides),
                  "--labels", LABEL + "=" + self.owner, "--wait", "--wait-for-jobs", "--timeout", "10m", timeout=650)

    def network(self):
        allowed = {DATA: {db + "-ingress" for db in DBS}, RUNTIME: {"openfga-vps-ingress", "temporal-vps-ingress"}}
        for ns, names in allowed.items():
            result = document(self.kubectl("-n", ns, "get", "networkpolicies", "-o", "json"))
            for item in result["items"]:
                if item.get("spec", {}).get("ingress"):
                    meta = item["metadata"]
                    check(meta["name"] in names and meta.get("labels", {}).get(LABEL) == self.owner,
                          f"unexpected additive ingress grant in dedicated namespace {ns}")

    def status(self):
        for db in DBS:
            cluster = self.get(DATA, "cluster.postgresql.cnpg.io", db)
            check(cluster.get("metadata", {}).get("labels", {}).get(LABEL) == self.owner, f"unexpected owner for {db}")
            check(any(c.get("type") == "Ready" and c.get("status") == "True" for c in cluster.get("status", {}).get("conditions", [])), f"{db} is not ready")
            claims = document(self.kubectl("-n", DATA, "get", "pvc", "-l", "cnpg.io/cluster=" + db, "-o", "json")).get("items", [])
            check(claims and all(x.get("status", {}).get("phase") == "Bound" for x in claims), f"{db} lacks bound persistent storage")
        for name in PINS:
            check(self.release(name) == "deployed", f"{name} release is not ready")
        for name in DEPLOYMENTS:
            dep = self.get(RUNTIME, "deployment", name)
            st = dep.get("status", {})
            desired = dep.get("spec", {}).get("replicas", 1)
            check(dep.get("metadata", {}).get("generation", 0) > 0 and desired > 0 and st.get("readyReplicas", 0) >= desired and st.get("updatedReplicas", 0) >= desired
                  and st.get("observedGeneration") == dep["metadata"].get("generation"), f"{name} rollout is not ready")
        for ns, name in [(DATA, db + "-rw") for db in DBS] + [(RUNTIME, "temporal-frontend"), (RUNTIME, "openfga")]:
            service = self.get(ns, "service", name)["spec"]
            check(service.get("type", "ClusterIP") == "ClusterIP" and not service.get("externalIPs"), f"{name} service must remain private")
        print("PostgreSQL claims are bound; OpenFGA and Temporal workloads are ready with private services.")

    def perform(self, action, dry):
        check(action in {"doctor", "install", "status"}, "unknown dependencies action")
        image = os.environ.get("ZASP_VPS_POSTGRES_IMAGE", "")
        if action != "status":
            check(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}", image), "set a digest-pinned ZASP_VPS_POSTGRES_IMAGE")
        if dry:
            print(f"Dry-run {action}: verify selected cluster, namespace ownership, dedicated databases, TLS credentials and pinned charts.")
            if action == "install":
                print("Create private network policies, three PVC-backed PostgreSQL clusters, Temporal schema job, and Temporal/OpenFGA releases.")
            return
        self.target()
        self.network()
        if action == "status":
            self.status()
            return
        self.get("", "crd", "clusters.postgresql.cnpg.io")
        self.get("", "crd", "imagecatalogs.postgresql.cnpg.io")
        self.secrets()
        storage_class = os.environ.get("ZASP_VPS_STORAGE_CLASS") or "local-path"
        check(re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", storage_class), "invalid VPS storage class")
        self.get("", "storageclass", storage_class)
        plan = resources(self.root, image, storage_class)
        job = migration(self.root)
        for obj in [*plan, job]:
            self.owned(obj)
        with tempfile.TemporaryDirectory(prefix="zasp-pinned-runtime-") as directory:
            temp = Path(directory)
            files = charts(temp)
            for name, archive in files.items():
                self.release(name)
                override = temp / (name + ".json")
                override.write_text(json.dumps(values(self.root, name)))
                self.helm("template", name, str(archive), "-f", str(override), "--skip-tests")
            if action == "doctor":
                print("Dependency prerequisites and pinned Helm renders passed.")
                return
            # Install all network filters before creating any database or runtime pods.
            for obj in sorted(plan, key=lambda x: x["kind"] == "Cluster"):
                self.create(obj)
            for db in DBS:
                self.wait(DATA, "cluster.postgresql.cnpg.io", db, "Ready")
            self.create(job)
            self.wait(RUNTIME, "job", job["metadata"]["name"], "complete")
            for name, archive in files.items():
                self.install_release(name, archive, temp / (name + ".json"))
            self.status()


def main(argv):
    check(len(argv) == 5, "expected repository, context, cluster UID, and action")
    root, context, uid, action = argv[1:]
    installer = Installer(Path(root), context, uid, os.environ.get("ZASP_VPS_INSTALLATION_ID", ""))
    dry = os.environ.get("ZASP_DRY_RUN") == "1"
    if dry:
        installer.perform(action, True)
        return
    # Freeze the selected authority before reading or mutating resources. Named contexts
    # in the caller's kubeconfig may change while databases and controllers start.
    with tempfile.TemporaryDirectory(prefix="zasp-vps-kube-") as directory:
        config = Path(directory) / "kubeconfig"
        raw = run(["kubectl", "--context", context, "config", "view", "--minify", "--flatten", "--raw"])
        check(raw, "empty kubeconfig for the selected context")
        with config.open("xb") as output:
            os.chmod(config, 0o600)
            output.write(raw)
        os.environ["KUBECONFIG"] = str(config)
        installer.perform(action, False)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (Rejected, OSError, ImportError) as error:
        print(f"zasp dependencies: {error}" if isinstance(error, Rejected) else "zasp dependencies: required tool, chart file, or PyYAML unavailable", file=sys.stderr)
        sys.exit(1)
