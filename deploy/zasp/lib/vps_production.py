"""Initialize the production namespaces and report the application release status."""
import json
import os
import sys
from pathlib import Path
from vps_dependencies import Installer, LABEL, Rejected, check, document, read_yaml, run

ROOT = Path(__file__).resolve().parents[3]
NAMESPACES = ("agentsec", "staging", "connectors", "opensearch")


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
    missing = [d for d in docs if not namespace_exists(target, d["metadata"]["name"])]
    for obj in missing:
        obj["metadata"]["labels"] = {LABEL: target.owner}
        target.kubectl("create", "-f", "-", data=json.dumps(obj).encode())
    print("Production namespaces ready: " + ", ".join(NAMESPACES))


def release_status(target):
    verify_cluster(target)
    check(namespace_exists(target, "agentsec"), "application namespace is missing")
    result = document(run(["helm", "--kube-context", target.context, "--namespace", "agentsec",
                           "list", "--all", "--filter", "^agentsec$", "-o", "json"]))
    if not result:
        raise Rejected("application release is missing; install the signed production candidate")
    release = result[0]
    check(len(result) == 1 and release.get("name") == "agentsec" and release.get("namespace") == "agentsec"
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
