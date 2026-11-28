"""Render a k3s STS identity preflight or a narrowly scoped IAM trust statement."""

import argparse
import json
import os
import re
from pathlib import Path

DEFAULT_NAMESPACE = "zasp"
AUDIENCE = "sts.amazonaws.com"
MOUNT = "/var/run/secrets/eks.amazonaws.com/serviceaccount"
WORKLOADS = ("discovery-worker", "recovery-backup", "recovery-restore")


def render(kind, workload, cluster, account, issuer, region=None, image=None, namespace=DEFAULT_NAMESPACE):
    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", namespace):
        raise ValueError("namespace must be a Kubernetes DNS label")
    if kind not in ("trust", "preflight") or workload not in WORKLOADS:
        raise ValueError("choose a supported workload and output format")
    if not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", cluster) or len(cluster + "-" + workload) > 64:
        raise ValueError("cluster must yield a valid AWS workload role name")
    if not re.fullmatch(r"[0-9]{12}", account) or account == "000000000000":
        raise ValueError("account must be a 12-digit AWS account ID")
    # A canonical DNS HTTPS origin with an optional simple OIDC path. The same
    # authority produces the IAM provider ARN, claim keys, and STS expectation.
    dns_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if not re.fullmatch(rf"https://(?:{dns_label}\.)+[a-z]{{2,63}}(?:/[a-zA-Z0-9_-]+)*", issuer) or len(issuer) > 255:
        raise ValueError("issuer must be a canonical HTTPS DNS URL with no query, port or fragment")
    authority = issuer.removeprefix("https://")
    provider = f"arn:aws:iam::{account}:oidc-provider/{authority}"
    name = "zasp-" + workload
    subject = f"system:serviceaccount:{namespace}:{name}"
    if kind == "trust":
        return {
            "Effect": "Allow", "Principal": {"Federated": provider},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{authority}:sub": subject, f"{authority}:aud": AUDIENCE}},
        }
    if not region or not re.fullmatch(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[0-9]", region):
        raise ValueError("preflight requires a commercial AWS region")
    if not image or not re.fullmatch(r"public\.ecr\.aws/aws-cli/aws-cli@sha256:[0-9a-f]{64}", image):
        raise ValueError("preflight requires the official AWS CLI image pinned by SHA-256 digest")
    role = cluster + "-" + workload
    session = name if workload == "discovery-worker" else "zasp-recovery-worker"
    env = {
        "AWS_REGION": region,
        "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_CLI_AUTO_PROMPT": "off",
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true", "AWS_MAX_ATTEMPTS": "1",
        "PROJECTED_TOKEN": MOUNT + "/token",
        "ROLE_ARN": f"arn:aws:iam::{account}:role/{role}", "SESSION_NAME": session,
        "EXPECTED_ARN": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
        "EXPECTED_SUBJECT": subject, "EXPECTED_ISSUER": issuer, "EXPECTED_PROVIDER_ARN": provider,
    }
    service_account = {"apiVersion": "v1", "kind": "ServiceAccount",
                       "metadata": {"name": name, "namespace": namespace}, "automountServiceAccountToken": False}
    container = {
        "name": "identity-check", "image": image, "command": ["/bin/sh", "-ec"],
        "args": [Path(__file__).with_name("preflight.sh").read_text()],
        "env": [{"name": key, "value": value} for key, value in env.items()],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "workload-identity", "mountPath": MOUNT, "readOnly": True}],
        "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
    }
    pod = {
        "serviceAccountName": name, "automountServiceAccountToken": False,
        "enableServiceLinks": False, "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                            "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": [{"name": "workload-identity", "projected": {
            "defaultMode": 0o440, "sources": [{"serviceAccountToken": {"audience": AUDIENCE, "expirationSeconds": 3600, "path": "token"}}]}}],
    }
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name + "-identity-check", "namespace": namespace},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 3600,
                    "template": {"spec": pod}}}
    return {"apiVersion": "v1", "kind": "List", "items": [service_account, job]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["trust", "preflight"])
    parser.add_argument("--workload", choices=WORKLOADS, required=True)
    for field in ("cluster", "account", "issuer"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--namespace", default=os.environ.get("ZASP_VPS_APP_NAMESPACE", DEFAULT_NAMESPACE),
                        help="application namespace for the IAM subject and workload preflight")
    parser.add_argument("--region")
    parser.add_argument("--image")
    args = parser.parse_args()
    try:
        value = render(**vars(args))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(value, indent=2))


if __name__ == "__main__":
    main()
