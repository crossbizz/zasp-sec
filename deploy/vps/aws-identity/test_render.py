import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from render import AUDIENCE, MOUNT, WORKLOADS, render

HERE = Path(__file__).resolve().parent
ACCOUNT = "123456789012"
ISSUER = "https://identity.example.org/k3s-pilot"
IMAGE = "public.ecr.aws/aws-cli/aws-cli@sha256:" + "a" * 64


def build(kind="preflight", **changes):
    return render(**({"kind": kind, "workload": "discovery-worker", "cluster": "zasp-pilot",
                      "account": ACCOUNT, "issuer": ISSUER, "region": "us-east-1", "image": IMAGE} | changes))


class IdentityContract(unittest.TestCase):
    def test_roles_do_not_share_subjects_or_workload_tokens(self):
        for workload in WORKLOADS:
            with self.subTest(workload=workload):
                sa, job = build(workload=workload)["items"]
                pod = job["spec"]["template"]["spec"]
                container, = pod["containers"]
                name = "zasp-" + workload
                sub = "system:serviceaccount:agentsec:" + name
                self.assertEqual(sa["metadata"], {"namespace": "agentsec", "name": name})
                self.assertEqual(pod["serviceAccountName"], name)
                self.assertFalse(sa["automountServiceAccountToken"])
                self.assertFalse(pod["automountServiceAccountToken"])
                self.assertEqual(pod["volumes"][0]["projected"], {"defaultMode": 0o440, "sources": [{
                    "serviceAccountToken": {"audience": AUDIENCE, "expirationSeconds": 3600, "path": "token"}}]})
                self.assertEqual(container["volumeMounts"], [{"name": "workload-identity", "mountPath": MOUNT, "readOnly": True}])
                self.assertEqual(container["image"], IMAGE)
                self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
                env = {item["name"]: item["value"] for item in container["env"]}
                self.assertEqual(env["PROJECTED_TOKEN"], MOUNT + "/token")
                self.assertEqual(env["ROLE_ARN"], f"arn:aws:iam::{ACCOUNT}:role/zasp-pilot-{workload}")
                self.assertEqual(env["EXPECTED_SUBJECT"], sub)
                self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")
                self.assertFalse({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL"} & set(env))
                authority = ISSUER.removeprefix("https://")
                self.assertEqual(build("trust", workload=workload), {
                    "Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/{authority}"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {authority + ":sub": sub, authority + ":aud": AUDIENCE}},
                })

    def test_invalid_inputs_rejected(self):
        for field, invalid in {
            "issuer": ["http://issuer.example", "https://user@issuer.example", "https://127.0.0.1",
                       "https://issuer.example/path?debug", "https://issuer.example:8443", "https://issuer.example/../x"],
            "workload": ["other", "discovery-*"], "cluster": ["x"*65, "cluster/role"],
            "image": ["public.ecr.aws/aws-cli/aws-cli:latest", "other.example/cli@sha256:" + "a"*64],
            "region": ["us-gov-west-1", "us-east-1.evil.example"], "account": ["000000000000", "*"],
        }.items():
            for value in invalid:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    build(**{field: value})

    def test_preflight_compares_sts_response_and_only_emits_status(self):
        pod = build()["items"][1]["spec"]["template"]["spec"]
        container, = pod["containers"]
        env = {item["name"]: item["value"] for item in container["env"]}
        result = [env["EXPECTED_ARN"], env["EXPECTED_SUBJECT"], AUDIENCE, ISSUER]
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "aws"
            fake.write_text("""#!/bin/sh
printf '%s\\n' "$@" > "$CAPTURE"
printf '%s\\n' "$REPLY"
printf '%s\\n' 'private-provider-detail' >&2
exit "$STATUS"
""")
            fake.chmod(0o700)
            captured = Path(tmp) / "args"
            variants = [("expected", result, "0", True),
                        ("provider-arn", result[:3] + [env["EXPECTED_PROVIDER_ARN"]], "0", True),
                        ("unavailable", result, "1", False)]
            for index in range(4):
                changed = list(result)
                changed[index] = "other"
                variants.append((str(index), changed, "0", False))
            for name, fields, status, allowed in variants:
                with self.subTest(name=name):
                    run = subprocess.run(container["command"] + container["args"], capture_output=True, text=True,
                                         env={**env, "PATH": tmp + os.pathsep + os.defpath, "STATUS": status,
                                              "CAPTURE": str(captured), "REPLY": "\t".join(fields)})
                    self.assertEqual(run.returncode == 0, allowed)
                    for secret in ("private-provider-detail", ACCOUNT, ISSUER):
                        self.assertNotIn(secret, run.stdout + run.stderr)
                    args = captured.read_text().splitlines()
                    self.assertIn("--no-sign-request", args)
                    self.assertEqual(args[args.index("--web-identity-token") + 1], "file://" + MOUNT + "/token")
                    self.assertEqual(args[args.index("--endpoint-url") + 1], "https://sts.us-east-1.amazonaws.com")
                    self.assertEqual(args[args.index("--duration-seconds") + 1], "900")
                    self.assertIn('"Effect":"Deny","Action":"*"', args[args.index("--policy") + 1])
                    self.assertEqual(args[args.index("--query") + 1], "[AssumedRoleUser.Arn,SubjectFromWebIdentityToken,Audience,Provider]")


if __name__ == "__main__":
    unittest.main()
