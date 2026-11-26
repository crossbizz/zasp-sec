import contextlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vps_doctor as d

OWNER = "123456789012"
REGION = "us-east-1"
KEY = f"arn:aws:kms:{REGION}:{OWNER}:key/01234567-1234-4789-8910-123456789abc"
UID = "01234567-1234-4789-8910-123456789abc"


class Doctor(unittest.TestCase):
    def test_s3_checks_encryption_ownership_and_versioning_without_writes(self):
        good = {"get-bucket-location": {"LocationConstraint": None},
                "get-bucket-encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
                "get-bucket-versioning": {"Status": "Enabled"},
                "get-bucket-ownership-controls": {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}}
        def call(service, op, *flags):
            self.assertEqual(service, "s3api")
            self.assertEqual(flags, ("--bucket", "acme-evidence", "--expected-bucket-owner", OWNER))
            return responses[op]
        with mock.patch.dict(d.env, {"ZASP_EVIDENCE_BUCKET": "acme-evidence", "ZASP_EVIDENCE_ENCRYPTION": "provider-managed",
                                     "ZASP_EVIDENCE_KMS_KEY_ARN": KEY}, clear=True):
            responses = dict(good)
            d.s3(call, REGION, OWNER)
            for op, bad in [("get-bucket-location", {"LocationConstraint": "us-west-1"}),
                            ("get-bucket-versioning", {"Status": "Suspended"}),
                            ("get-bucket-ownership-controls", {"OwnershipControls": {"Rules": []}}),
                            ("get-bucket-encryption", {"ServerSideEncryptionConfiguration": {"Rules": []}})]:
                responses = dict(good, **{op: bad})
                with self.subTest(op=op), self.assertRaises(d.Refused):
                    d.s3(call, REGION, OWNER)
            responses = dict(good)
            d.env["ZASP_EVIDENCE_ENCRYPTION"] = "aws-kms"
            with self.assertRaises(d.Refused):
                d.s3(call, REGION, OWNER)
            responses["get-bucket-encryption"] = {"ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": KEY}}]}}
            d.s3(call, REGION, OWNER)

    def test_work_dlq_correspondence_retention_and_protection(self):
        name = "agentsec-audit-exports"
        arn = f"arn:aws:sqs:{REGION}:{OWNER}:{name}"
        url = f"https://sqs.{REGION}.amazonaws.com/{OWNER}/{name}"
        defaults = [{"QueueArn": arn, "SqsManagedSseEnabled": "true", "MessageRetentionPeriod": "345600",
                     "RedrivePolicy": json.dumps({"maxReceiveCount": "20", "deadLetterTargetArn": arn + "-dlq"})},
                    {"QueueArn": arn + "-dlq", "SqsManagedSseEnabled": "true", "MessageRetentionPeriod": "1209600",
                     "RedriveAllowPolicy": json.dumps({"redrivePermission": "byQueue", "sourceQueueArns": [arn]})}]
        def call(service, operation, flag, target, *args):
            self.assertEqual((service, operation, flag), ("sqs", "get-queue-attributes", "--queue-url"))
            self.assertIn(target, [url, url + "-dlq"])
            return {"Attributes": records[int(target != url)]}
        records = [dict(r) for r in defaults]
        d.sqs(call, REGION, OWNER, name, url, "provider-managed", 20)
        mutations = [(0, "MessageRetentionPeriod", "86400"), (1, "MessageRetentionPeriod", "86400"),
                     (0, "RedrivePolicy", '{"deadLetterTargetArn":"wrong","maxReceiveCount":20}'),
                     (1, "RedriveAllowPolicy", '{"redrivePermission":"allowAll"}'),
                     (0, "KmsMasterKeyId", KEY), (1, "SqsManagedSseEnabled", "false"), (1, "QueueArn", arn)]
        for index, field, value in mutations:
            with self.subTest(field=field), self.assertRaises(d.Refused):
                records = [dict(r) for r in defaults]
                records[index][field] = value
                d.sqs(call, REGION, OWNER, name, url, "provider-managed", 20)
        with self.assertRaises(d.Refused):
            d.sqs(call, REGION, OWNER, name, url.replace(OWNER, "999999999999"), "provider-managed", 20)
        records = [{k:v for k,v in r.items() if k != "SqsManagedSseEnabled"} | {"KmsMasterKeyId": KEY} for r in defaults]
        d.sqs(call, REGION, OWNER, name, url, "aws-kms", 20)

    def test_operator_sts_is_explicit_and_scoped(self):
        secret = "opaque-token-not-for-logs"
        role = f"arn:aws:iam::{OWNER}:role/zasp-vps-doctor"
        identity = f"arn:aws:sts::{OWNER}:assumed-role/zasp-vps-doctor/zasp-vps-doctor"
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "jwt"
            token.write_text(secret)
            token.chmod(0o600)
            config = {"ZASP_AWS_REGION": REGION, "ZASP_EVIDENCE_BUCKET_OWNER": OWNER, "ZASP_VPS_AWS_DOCTOR_ROLE_ARN": role,
                      "ZASP_VPS_AWS_DOCTOR_TOKEN_FILE": str(token), "AWS_ACCESS_KEY_ID": "customer-key",
                      "AWS_ENDPOINT_URL": "http://sink.local", "AWS_PROFILE": "customer"}
            sub = "system:serviceaccount:agentsec:zasp-vps-doctor"
            def fake(args, clean, fds=()):
                self.assertNotIn(secret, repr(args))
                self.assertNotIn("customer-key", repr(clean))
                self.assertNotIn("AWS_ENDPOINT_URL", clean)
                self.assertNotIn("AWS_PROFILE", clean)
                if "assume-role-with-web-identity" in args:
                    self.assertEqual(os.read(fds[0], 1000).decode(), secret)
                    perms = json.loads(args[args.index("--policy")+1])["Statement"][0]["Action"]
                    self.assertNotIn("sqs:ReceiveMessage", perms)
                    self.assertNotIn("s3:GetObject", perms)
                    return json.dumps({"AssumedRoleUser":{"Arn":identity}, "Audience":"sts.amazonaws.com", "SubjectFromWebIdentityToken":subject,
                                       "Credentials":{"AccessKeyId":"tmp-id","SecretAccessKey":"tmp-key","SessionToken":"tmp-token"}}).encode()
                self.assertEqual(clean["AWS_SESSION_TOKEN"], "tmp-token")
                return json.dumps({"Account": OWNER, "Arn":identity}).encode()
            with mock.patch.dict(d.env, config, clear=True), mock.patch.object(d, "run", side_effect=fake):
                subject = sub
                d.aws_identity()
                subject = "system:serviceaccount:other:zasp-vps-doctor"
                with self.assertRaises(d.Refused):
                    d.aws_identity()
                token.chmod(stat.S_IRUSR | stat.S_IROTH)
                with self.assertRaises(d.Refused):
                    d.aws_identity()

    def test_wrong_cluster_and_unready_k3s(self):
        config = {"ZASP_VPS_KUBE_CONTEXT":"target", "ZASP_VPS_CLUSTER_UID":UID, "ZASP_VPS_INSTALLATION_ID":"pilot"}
        with mock.patch.dict(d.env, config, clear=True), mock.patch.object(d, "run", return_value=b'{"metadata":{"uid":"wrong"}}') as cmd:
            with self.assertRaises(d.Refused):
                d.destination()
            self.assertEqual(cmd.call_count, 1)
            self.assertIn("target", cmd.call_args.args[0])
        with self.assertRaises(d.Refused):
            d.cluster_node(lambda *_: {"items":[]})

    def test_public_origin_and_registry_inputs_cannot_redirect_or_leak(self):
        with mock.patch.object(d.socket, "getaddrinfo", return_value=[(0,0,0,"",("127.0.0.1",443))]):
            for value in ["https://public.example.org", "https://token@public.example.org", "http://private", "https://public.example.org/data"]:
                with self.subTest(value=value), self.assertRaises(d.Refused):
                    d.public_tls(value)
        image = "registry.example.org/acme/api@sha256:" + "a"*64
        with mock.patch.dict(d.env, {}, clear=True), mock.patch.object(d, "run", return_value=json.dumps({"Os":"linux","Architecture":"amd64","Digest": image.split("@")[1]}).encode()):
            d.registry(image)
            with self.assertRaises(d.Refused):
                d.registry("registry.example.org/acme/api:latest")

    def test_discovery_workload_keeps_infrastructure_identity_separate(self):
        directory = "/var/run/secrets/eks.amazonaws.com/serviceaccount"
        worker = {"name": "discovery-worker", "env": [
            {"name": "ZASP_DISCOVERY_ROLE_ARN", "value": f"arn:aws:iam::{OWNER}:role/pilot-discovery-worker"},
            {"name": "ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE", "value": directory + "/token"}],
            "volumeMounts": [{"name":"sts", "mountPath":directory, "readOnly":True}]}
        token = {"serviceAccountToken":{"audience":"sts.amazonaws.com","path":"token","expirationSeconds":3600}}
        pod = {"serviceAccountName":"zasp-discovery-worker","automountServiceAccountToken":False,"containers":[worker],
               "volumes":[{"name":"sts","projected":{"sources":[token]}}]}
        def read(*args):
            self.assertEqual(args, ("deployment", "agentsec-discovery-worker", "-n", "agentsec"))
            return {"spec":{"template":{"spec":pod}}}
        with mock.patch.dict(d.env, {"ZASP_EVIDENCE_BUCKET_OWNER":OWNER}, clear=True):
            d.discovery_projection(read)
            token["serviceAccountToken"]["audience"] = "kubernetes"
            with self.assertRaises(d.Refused):
                d.discovery_projection(read)
            token["serviceAccountToken"]["audience"] = "sts.amazonaws.com"
            worker["env"].append({"name":"AWS_ENDPOINT_URL_STS", "value":"https://wrong.example"})
            with self.assertRaises(d.Refused):
                d.discovery_projection(read)

    def test_public_recipient_must_support_the_real_backup_envelope(self):
        import backup
        with tempfile.TemporaryDirectory() as directory:
            for algorithm in ("rsa:2048", "ec"):
                with self.subTest(algorithm=algorithm):
                    cert = Path(directory) / (algorithm + ".crt")
                    key = Path(directory) / (algorithm + ".key")
                    spec = ["-newkey", algorithm]
                    if algorithm == "ec":
                        spec += ["-pkeyopt", "ec_paramgen_curve:P-256"]
                    subprocess.run(["openssl", "req", "-new", "-x509", *spec, "-nodes", "-days", "1",
                                    "-subj", "/CN=Disposable doctor probe", "-keyout", key, "-out", cert],
                                   stdin=subprocess.DEVNULL, capture_output=True, check=True)
                    key.unlink()
                    with mock.patch.dict(d.env, {"ZASP_BACKUP_RECIPIENT_FILE": str(cert)}, clear=False), \
                         mock.patch.object(backup, "Remote", side_effect=AssertionError("recipient probe contacted storage")):
                        if algorithm == "ec":
                            with self.assertRaises(backup.BackupError):
                                d.backup_recipient()
                        else:
                            d.backup_recipient()

    def test_component_health_emits_only_allowlisted_state(self):
        bad = b"openbao: sealed (private-provider-detail)"
        result = d.subprocess.CompletedProcess([], 1, stdout=bad)
        with mock.patch.object(d.subprocess, "run", return_value=result), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(d.Refused):
                d.service_status("openbao")
        self.assertIn("sealed", out.getvalue())
        self.assertNotIn("private-provider-detail", out.getvalue())

    def test_unsupported_remote_selections_never_probe_substitute_aws_providers(self):
        with mock.patch.dict(d.env, {"ZASP_EVIDENCE_PROVIDER":"r2", "ZASP_QUEUE_PROVIDER":"cloudflare"}, clear=True), \
             mock.patch.object(d, "run", side_effect=d.Refused()), mock.patch.object(d, "aws_identity") as auth, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(d.main(False), 1)
            auth.assert_not_called()
        self.assertIn("S3 probes skipped", out.getvalue())
        self.assertIn("SQS probes skipped", out.getvalue())

    def test_successful_component_evidence_is_distinct_from_full_runtime_readiness(self):
        with tempfile.TemporaryDirectory() as disk:
            ctx = {"ZASP_VPS_STORAGE_PATH":disk, "ZASP_VPS_STORAGE_CLASS":"local-path", "ZASP_AWS_REGION":REGION,
                   "ZASP_EVIDENCE_BUCKET_OWNER":OWNER, "ZASP_PROFILE":"vps", "ZASP_BACKUP_PROVIDER":"r2",
                   "ZASP_RECOVERY_OPERATION_KIND":"restore", "ZASP_RECOVERY_QUEUE_URL":"restore-url",
                   "ZASP_IMAGE_API":"reg/app@sha256:"+"a"*64, "ZASP_IMAGE_WORKER":"reg/worker@sha256:"+"b"*64,
                   "ZASP_IMAGE_WEB":"reg/web@sha256:"+"c"*64}
            def read(*args):
                if args == ("nodes",):
                    return {"items":[{"status":{"nodeInfo":{"architecture":"amd64","operatingSystem":"linux","kubeletVersion":"v1.33.4+k3s1"},
                                           "conditions":[{"type":"Ready","status":"True"}]}}]}
                if args == ("storageclass", "local-path"):
                    return {"metadata":{"name":"local-path"}}
                self.fail("unexpected Kubernetes read")
            with contextlib.ExitStack() as mocks:
                mocks.enter_context(mock.patch.dict(d.env,ctx,clear=True))
                for helper in ("production_settings","public_tls","registry","discovery_projection","backup_probe","s3","run"):
                    mocks.enter_context(mock.patch.object(d,helper))
                mocks.enter_context(mock.patch.object(d,"destination",return_value=read))
                mocks.enter_context(mock.patch.object(d,"aws_identity",return_value=mock.Mock()))
                sqs = mocks.enter_context(mock.patch.object(d,"sqs"))
                health = mocks.enter_context(mock.patch.object(d,"service_status"))
                out = mocks.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(d.main(False),1)
                self.assertEqual(health.call_args_list,[mock.call("openbao"),mock.call("nango")])
                self.assertEqual([c.args[3] for c in sqs.call_args_list],
                                 ["agentsec-discovery-jobs","agentsec-audit-exports","agentsec-recovery-restore-jobs"])
                self.assertIn("OK configured persistent StorageClass",out.getvalue())
                self.assertIn("OK nango authenticated readiness",out.getvalue())
                self.assertIn("BLOCKED full customer-pilot",out.getvalue())

    def test_dry_run_is_nonmutating_and_redacts_failures(self):
        poison = "PRIVATE-UNTRUSTED-SETTING"
        for dry in [True, False]:
            buf = io.StringIO()
            with mock.patch.dict(d.env, {"ZASP_VPS_KUBE_CONTEXT":poison, "ZASP_IMAGE_API":poison}, clear=True), \
                 mock.patch.object(d, "run", side_effect=RuntimeError(poison)) as run, \
                 mock.patch.object(d.socket, "getaddrinfo", side_effect=OSError(poison)) as dns, \
                 contextlib.redirect_stdout(buf):
                self.assertEqual(d.main(dry), 1)
                if dry:
                    run.assert_not_called()
                    dns.assert_not_called()
            self.assertNotIn(poison, buf.getvalue())
            self.assertIn("BLOCKED full customer-pilot", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
