"""Initialize the production namespaces and report the application release status."""
import json
import os
import sys
from pathlib import Path
from vps_dependencies import Installer, LABEL, Rejected, check, document, read_yaml, run

ROOT = Path(__file__).resolve().parents[3]
APP_NAMESPACE = "zasp"
NAMESPACES = (APP_NAMESPACE, "staging", "connectors", "opensearch")


def verify_cluster(target):
    current = target.get("", "namespace", "kube-system").get("metadata", {}).get("uid")
    check(current == target.uid, "selected cluster UID mismatch")


def namespace_exists(target, name):
    ns = target.get("", "namespace", name, optional=True)
    if not ns:
        return False
    check(ns.get("metadata", {}).get("labels", {}).get(LABEL) == target.owner,
          f"{name} is missing this installation's ownership label")
    return True


def prepare_namespaces(target):
    docs = read_yaml(ROOT / "deploy/vps/production/namespaces.yaml")
    check([d["metadata"]["name"] for d in docs] == list(NAMESPACES)
          and all(d.get("kind") == "Namespace" for d in docs), "unexpected production namespace manifest")
    verify_cluster(target)
    # Check the ownership of all existing namespaces before creating the first.
    missing = []
    evaluation_namespace_version = None
    for namespace in docs:
        name = namespace["metadata"]["name"]
        current = target.get("", "namespace", name, optional=True)
        if not current:
            missing.append(namespace)
            continue
        metadata = current["metadata"]
        owner = metadata.get("labels", {}).get(LABEL)
        if owner == target.owner:
            continue
        check(name == APP_NAMESPACE and owner is None, f"{name} belongs to another or unidentified installation")
        # Existing evaluation charts created this namespace without an owner
        # label. Bind only that verified namespace, never its workloads or PVC.
        sts = target.get(name, "statefulset", "zasp", optional=True).get("metadata", {})
        annotations = sts.get("annotations", {})
        check(sts.get("labels", {}).get("app.kubernetes.io/managed-by") == "Helm"
              and annotations.get("meta.helm.sh/release-name") == "zasp"
              and annotations.get("meta.helm.sh/release-namespace") == name,
              "existing application namespace has no matching evaluation release or installation label")
        evaluation_namespace_version = metadata.get("resourceVersion")
        check(bool(evaluation_namespace_version), "missing namespace resource version")
    if evaluation_namespace_version:
        target.kubectl("label", "namespace", APP_NAMESPACE, LABEL + "=" + target.owner,
                       "--resource-version=" + evaluation_namespace_version)
    for obj in missing:
        obj["metadata"]["labels"] = {LABEL: target.owner}
        target.kubectl("create", "-f", "-", data=json.dumps(obj).encode())
    print("Production namespaces ready: " + ", ".join(NAMESPACES))


def release_status(target):
    verify_cluster(target)
    check(namespace_exists(target, APP_NAMESPACE), "application namespace is missing")
    result = document(run(["helm", "--kube-context", target.context, "--namespace", APP_NAMESPACE,
                           "list", "--all", "--filter", "^agentsec$", "-o", "json"]))
    if not result:
        raise Rejected("application release is missing; install the signed production candidate")
    release = result[0]
    check(len(result) == 1 and release.get("name") == "agentsec" and release.get("namespace") == APP_NAMESPACE
          and release.get("chart", "").startswith("zasp-product-"), "unexpected application release")
    print("application:", release.get("status", "unknown"), "revision", release.get("revision", "unknown"))
    check(release.get("status") == "deployed", "application release is not deployed")


if __name__ == "__main__":
    try:
        target = Installer(ROOT, *(os.environ.get("ZASP_VPS_" + key, "") for key in
                                    ("KUBE_CONTEXT", "CLUSTER_UID", "INSTALLATION_ID")))
        if sys.argv[1:] == ["namespaces"]:
            prepare_namespaces(target)
        elif sys.argv[1:] == ["status"]:
            release_status(target)
        else:
            raise Rejected("expected namespaces or status")
    except (Rejected, OSError, ValueError) as exc:
        sys.exit(str(exc))
