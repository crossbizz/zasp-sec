"""Read-only VPS preflight. Provider errors and untrusted configuration never reach stdout."""
import argparse
import contextlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

LIB = Path(__file__).resolve().parent
ROOT = LIB.parents[2]
env = os.environ
DNS = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
REGION = r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-\d"
KMS_ID = r"(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|mrk-[0-9a-f]{32})"
LABEL = re.compile(r"[a-z][a-z0-9-]{0,62}")
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]{0,246}@sha256:[0-9a-f]{64}")
UID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")


class Refused(Exception):
    pass


def checked(condition):
    if not condition:
        raise Refused()


def run(args, *, clean=None, fds=(), timeout=12):
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           env=clean, pass_fds=fds, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        raise Refused() from None
    checked(p.returncode == 0 and len(p.stdout) <= 16 << 20)
    return p.stdout


@contextlib.contextmanager
def protected(path):
    checked(path and Path(path).is_absolute())
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        s = os.fstat(f.fileno())
        checked(stat.S_ISREG(s.st_mode) and s.st_uid in (0, os.geteuid()) and not s.st_mode & 0o077 and s.st_size > 0)
        yield f


def public_tls(origin):
    p = urlsplit(origin)
    host = p.hostname or ""
    checked(p.scheme == "https" and re.fullmatch(rf"(?:{DNS}\.)+[a-z]{{2,63}}", host)
            and origin == f"https://{host}" and not host.endswith((".local", ".test", ".localhost")))
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    checked(records and all(ipaddress.ip_address(r[4][0]).is_global for r in records))
    # Connect to the address just checked and verify the certificate against the original hostname.
    ctx = ssl.create_default_context()
    for family, kind, proto, _, address in records[:4]:
        try:
            with socket.socket(family, kind, proto) as connection:
                connection.settimeout(3)
                connection.connect(address)
                with ctx.wrap_socket(connection, server_hostname=host):
                    return
        except OSError:
            continue
    raise Refused()


def aws_identity():
    region, owner = env.get("ZASP_AWS_REGION", ""), env.get("ZASP_EVIDENCE_BUCKET_OWNER", "")
    checked(re.fullmatch(REGION, region) and re.fullmatch(r"\d{12}", owner))
    role = env.get("ZASP_VPS_AWS_DOCTOR_ROLE_ARN", "")
    matched = re.fullmatch(rf"arn:aws:iam::{owner}:role/(?:[A-Za-z0-9_+=,.@-]+/)*([A-Za-z0-9_+=,.@-]{{1,64}})", role)
    checked(matched)
    role_name = matched[1]
    # Do not use a customer integration profile, IMDS, inherited static keys, credential_process or endpoint overrides.
    base = {"PATH": os.defpath if "PATH" not in env else env["PATH"], "HOME": "/nonexistent",
            "AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": os.devnull, "AWS_PAGER": "",
            "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true", "AWS_EC2_METADATA_DISABLED": "true", "AWS_MAX_ATTEMPTS": "1"}
    args = ["aws", "--region", region, "--no-cli-pager", "--output", "json", "--cli-connect-timeout", "3", "--cli-read-timeout", "6"]
    # This session cannot acquire data-plane permissions even if the host role is misconfigured.
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*",
              "Action": ["sts:GetCallerIdentity", "s3:GetBucketLocation", "s3:GetBucketVersioning",
                         "s3:GetBucketOwnershipControls", "s3:GetEncryptionConfiguration", "sqs:GetQueueAttributes"]}]}
    with protected(env.get("ZASP_VPS_AWS_DOCTOR_TOKEN_FILE")) as token:
        checked(os.fstat(token.fileno()).st_size <= 16384)
        data = json.loads(run([*args, "--no-sign-request", "sts", "assume-role-with-web-identity", "--role-arn", role,
                               "--role-session-name", "zasp-vps-doctor", "--duration-seconds", "900", "--policy",
                               json.dumps(policy, separators=(",", ":")), "--web-identity-token",
                               f"file:///proc/self/fd/{token.fileno()}"], clean=base, fds=(token.fileno(),)))
    arn = f"arn:aws:sts::{owner}:assumed-role/{role_name}/zasp-vps-doctor"
    checked(data["AssumedRoleUser"]["Arn"] == arn and data["Audience"] == "sts.amazonaws.com"
            and data["SubjectFromWebIdentityToken"] == "system:serviceaccount:agentsec:zasp-vps-doctor")
    creds = data["Credentials"]
    for name, field in (("AWS_ACCESS_KEY_ID", "AccessKeyId"), ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"), ("AWS_SESSION_TOKEN", "SessionToken")):
        checked(isinstance(creds[field], str) and creds[field])
        base[name] = creds[field]

    def call(*argv):
        return json.loads(run([*args, *argv], clean=base))
    caller = call("sts", "get-caller-identity")
    checked(caller["Arn"] == arn and caller["Account"] == owner)
    return call


def s3(call, region, owner):
    bucket = env.get("ZASP_EVIDENCE_BUCKET", "")
    checked(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) and ".." not in bucket)
    def get(op):
        return call("s3api", op, "--bucket", bucket, "--expected-bucket-owner", owner)
    location = get("get-bucket-location")["LocationConstraint"]
    checked(({None: "us-east-1", "EU": "eu-west-1"}.get(location, location)) == region)
    checked(get("get-bucket-versioning").get("Status") == "Enabled")
    ownership = get("get-bucket-ownership-controls")["OwnershipControls"]["Rules"]
    checked(ownership == [{"ObjectOwnership": "BucketOwnerEnforced"}])
    rules = get("get-bucket-encryption")["ServerSideEncryptionConfiguration"]["Rules"]
    checked(len(rules) == 1)
    config = rules[0]["ApplyServerSideEncryptionByDefault"]
    mode = env.get("ZASP_EVIDENCE_ENCRYPTION", "aws-kms")
    if mode == "provider-managed":
        historical = env.get("ZASP_EVIDENCE_KMS_KEY_ARN", "")
        checked(config == {"SSEAlgorithm": "AES256"} and (not historical or re.fullmatch(rf"arn:aws:kms:{region}:{owner}:key/{KMS_ID}", historical)))
    else:
        key = env.get("ZASP_EVIDENCE_KMS_KEY_ARN", "")
        checked(mode == "aws-kms" and re.fullmatch(rf"arn:aws:kms:{region}:{owner}:key/{KMS_ID}", key)
                and config.get("SSEAlgorithm") == "aws:kms" and config.get("KMSMasterKeyID") == key)


def sqs(call, region, owner, name, url, mode, max_receive):
    arn = f"arn:aws:sqs:{region}:{owner}:{name}"
    checked(url == f"https://sqs.{region}.amazonaws.com/{owner}/{name}")
    source_retention = 0
    for suffix, policy_field in (("", "RedrivePolicy"), ("-dlq", "RedriveAllowPolicy")):
        attrs = call("sqs", "get-queue-attributes", "--queue-url", url + suffix, "--attribute-names", "QueueArn",
                     "KmsMasterKeyId", "SqsManagedSseEnabled", "MessageRetentionPeriod", policy_field)["Attributes"]
        checked(attrs["QueueArn"] == arn + suffix)
        if mode == "provider-managed":
            checked(attrs.get("SqsManagedSseEnabled") == "true" and "KmsMasterKeyId" not in attrs)
        else:
            checked(mode == "aws-kms" and attrs.get("SqsManagedSseEnabled", "false") == "false"
                    and re.fullmatch(rf"arn:aws:kms:{region}:{owner}:key/{KMS_ID}", attrs.get("KmsMasterKeyId", "")))
        policy = json.loads(attrs[policy_field])
        retention = int(attrs["MessageRetentionPeriod"])
        if suffix:
            checked(retention >= 1209600 and retention >= source_retention and policy.get("redrivePermission") == "byQueue"
                    and policy.get("sourceQueueArns") == [arn])
        else:
            checked(retention >= 345600 and policy.get("deadLetterTargetArn") == arn + "-dlq"
                    and str(policy.get("maxReceiveCount")) == str(max_receive))
            source_retention = retention


def registry(reference):
    checked(IMAGE.fullmatch(reference) and "/" in reference and ".." not in reference)
    # No secret values or paths from tool error output are printed.
    args = ["skopeo", "--override-os", "linux", "--override-arch", "amd64", "inspect", "--no-tags"]
    with contextlib.ExitStack() as stack:
        auth = env.get("ZASP_VPS_REGISTRY_AUTH_FILE")
        fds = ()
        if auth:
            fd = stack.enter_context(protected(auth)).fileno()
            args += ["--authfile", f"/proc/self/fd/{fd}"]
            fds = (fd,)
        result = json.loads(run([*args, "docker://" + reference], clean={"PATH": env.get("PATH", os.defpath),
                                "HOME": "/nonexistent"}, fds=fds, timeout=25))
    checked(result.get("Architecture") == "amd64" and result.get("Os") == "linux"
            and result.get("Digest") == reference.rsplit("@", 1)[1])


def host_capacity():
    path = Path(env.get("ZASP_VPS_STORAGE_PATH", ""))
    checked(path.is_absolute() and path.is_dir())
    cpu = len(os.sched_getaffinity(0))
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    space = shutil.disk_usage(path)
    print(f"INFO host resources: {cpu} schedulable CPUs, {memory // 2**30} GiB RAM, {space.total // 10**9} GB disk, {space.free // 10**9} GB free")
    if cpu < 8 or memory < 24 * 10**9 or space.total < 200 * 10**9:
        print("WARN below initial planning recommendation (8 CPUs, 24 GB RAM, 200 GB disk); capacity has not been benchmarked")


def production_settings():
    checked(env.get("ZASP_PROFILE", "vps") == "vps")
    allowed = {"ZASP_CONNECTOR_SECRETS_PROVIDER": ("aws-secrets-manager", "openbao"),
               "ZASP_RECOVERY_SIGNING_PROVIDER": ("aws-kms", "openbao"), "ZASP_EVIDENCE_PROVIDER": ("s3",),
               "ZASP_EVIDENCE_ENCRYPTION": ("aws-kms", "provider-managed"), "ZASP_QUEUE_PROVIDER": ("sqs",),
               "ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION": ("aws-kms", "provider-managed"), "ZASP_BACKUP_PROVIDER": ("s3", "r2", "local")}
    for key, values in allowed.items():
        checked(env.get(key, values[0]) in values)
    checked(env.get("ZASP_ENVIRONMENT", "production") == "production")
    checked(not any(v for k, v in env.items() if k.startswith("AWS_ENDPOINT_URL")
                    or k in ("ZASP_LOCAL_CLOUD_ENDPOINT", "ZASP_LOCAL_AWS_ENDPOINT", "ZASP_RUNTIME_DIR",
                             "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")))
    checked(not env.get("ZASP_QUEUE_ENCRYPTION") or env["ZASP_QUEUE_ENCRYPTION"] == "aws-kms")


def destination():
    context = env.get("ZASP_VPS_KUBE_CONTEXT", "")
    uid = env.get("ZASP_VPS_CLUSTER_UID", "")
    checked(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,252}", context)
            and UID.fullmatch(uid) and LABEL.fullmatch(env.get("ZASP_VPS_INSTALLATION_ID", "")))
    def read(*args):
        return json.loads(run(["kubectl", "--context", context, "--request-timeout=8s", "get", *args, "-o", "json"]))
    checked(read("namespace", "kube-system")["metadata"]["uid"] == uid)
    return read


def cluster_node(read):
    nodes = read("nodes")["items"]
    checked(len(nodes) == 1)
    info = nodes[0]["status"]["nodeInfo"]
    checked(info["architecture"] == "amd64" and info["operatingSystem"] == "linux" and "+k3s" in info["kubeletVersion"])
    checked(any(c["type"] == "Ready" and c["status"] == "True" for c in nodes[0]["status"]["conditions"]))


def discovery_projection(read):
    owner = env.get("ZASP_EVIDENCE_BUCKET_OWNER", "")
    checked(re.fullmatch(r"\d{12}", owner))
    deployment = read("deployment", "agentsec-discovery-worker", "-n", "agentsec")
    pod = deployment["spec"]["template"]["spec"]
    checked(pod.get("serviceAccountName") == "zasp-discovery-worker" and pod.get("automountServiceAccountToken") is False)
    worker, = [c for c in pod["containers"] if c["name"] == "discovery-worker"]
    checked(not worker.get("envFrom"))
    entries = worker.get("env", [])
    settings = {v["name"]: v.get("value") for v in entries}
    checked(len(settings) == len(entries))
    checked(not any(k.startswith("AWS_ENDPOINT_URL") or k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                    "ZASP_LOCAL_CLOUD_ENDPOINT") for k in settings))
    checked(re.fullmatch(rf"arn:aws:iam::{owner}:role/[A-Za-z0-9_+=,.@/-]+", settings.get("ZASP_DISCOVERY_ROLE_ARN") or ""))
    token_dir = "/var/run/secrets/eks.amazonaws.com/serviceaccount"
    checked(settings.get("ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE") == token_dir + "/token")
    mount, = [m for m in worker["volumeMounts"] if m["mountPath"] == token_dir]
    checked(mount.get("readOnly") is True and not mount.get("subPath") and not mount.get("subPathExpr"))
    volume, = [v for v in pod["volumes"] if v["name"] == mount["name"]]
    token, = volume["projected"]["sources"]
    spec = token["serviceAccountToken"]
    checked(set(token) == {"serviceAccountToken"} and spec["path"] == "token" and spec["audience"] == "sts.amazonaws.com"
            and 600 <= spec["expirationSeconds"] <= 3600)


def backup_recipient():
    import backup
    with backup.trusted_file("RECIPIENT_FILE", False) as cert:
        fd = cert.fileno()
        run(["openssl", "x509", "-in", f"/proc/self/fd/{fd}", "-noout", "-checkend", "0"], fds=(fd,))
    # Exercise the exact CMS envelope creation used for an archive. The operator host
    # needs only the public certificate; private recovery material stays offline.
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        source = directory / "probe"
        source.write_bytes(b"zasp-backup-recipient-check")
        backup.encrypt(source, directory / "probe.cms")


def backup_probe(provider):
    # The transfer helper isolates backup credentials from all other AWS clients.
    import backup
    checked(provider in ("r2", "s3"))
    backup_recipient()
    with tempfile.TemporaryDirectory() as work:
        remote = backup.Remote(provider, Path(work))
        run(["aws", *remote.options, "s3api", "head-bucket", "--bucket", remote.bucket, *remote.owner_flags],
            clean=remote.env, timeout=15)
        if env.get("ZASP_VPS_BACKUP_VERIFIED_RECEIPT"):
            import vps_backup_retention
            receipt = vps_backup_retention.read_receipt(Path(env["ZASP_VPS_BACKUP_VERIFIED_RECEIPT"]), remote)
            obj = json.loads(run(remote.command(remote.key(receipt), "head-object"), clean=remote.env, timeout=15))
            checked(obj["ContentLength"] == receipt["size"])
            print("INFO operator-designated recovery receipt matches the offsite object location and ciphertext size")



def service_status(component):
    # Map only known status tokens to public labels. Never relay arbitrary child output.
    args = [sys.executable, LIB / "vps_services.py", "status", component]
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=24)
    if p.returncode:
        line = p.stdout.decode("utf-8", "replace")
        for status in ("uninitialized", "sealed", "unauthenticated", "unavailable"):
            if re.search(r"\b" + status + r"\b", line):
                print("INFO " + component + ": " + status)
                break
        raise Refused()


def main(dry):
    failed = []

    def check(label, operation, *, live=False):
        if dry and live:
            print("PLAN " + label + " (read-only check skipped)")
            return None
        try:
            result = operation()
        except Exception:  # External tools and adapters may include secrets in errors. Emit only the check label.
            failed.append(label)
            print("CHECK REQUIRED " + label)
            return None
        print("OK " + label)
        return result

    check("Linux x86_64 host", lambda: checked(platform.system() == "Linux" and platform.machine() == "x86_64"))
    check("storage path and available host resources", host_capacity)
    for name in ("kubectl", "helm", "aws", "skopeo", "openssl"):
        check(name + " executable", lambda n=name: checked(shutil.which(n)))
    check("supported provider selections and production settings; remove static credentials and AWS endpoint overrides",
          production_settings)
    check("public origin DNS and verified client-facing HTTPS; check ZASP_ORIGIN", lambda: public_tls(env.get("ZASP_ORIGIN", "")), live=True)
    print("UNVERIFIED proxy-to-origin TLS mode, origin ACLs and administrative perimeter require separate inspection")
    for name in ("ZASP_IMAGE_API", "ZASP_IMAGE_WORKER", "ZASP_IMAGE_WEB"):
        ref = env.get(name, "")
        check(name + " immutable reference", lambda: checked(IMAGE.fullmatch(ref)))
        check(name + " Linux amd64 registry manifest", lambda: registry(ref), live=True)

    kube = check("explicit Kubernetes context, installation identifier and kube-system UID", destination, live=True)
    if kube:
        check("one Ready Linux amd64 k3s node", lambda: cluster_node(kube))
        check("installed discovery worker: scoped infrastructure role, projected STS token and no customer endpoint overrides", lambda: discovery_projection(kube))
        storage = env.get("ZASP_VPS_STORAGE_CLASS", "")
        check("configured persistent StorageClass", lambda: checked(LABEL.fullmatch(storage) and
              kube("storageclass", storage)["metadata"]["name"] == storage))
    if kube or dry:
        for component in ("openbao", "nango"):
            check(component + " preflight", lambda c=component: run([sys.executable, LIB / "vps_services.py", "doctor", c], timeout=35), live=True)
            check(component + " authenticated readiness", lambda c=component: service_status(c), live=True)
        args = [sys.executable, LIB / "vps_dependencies.py", ROOT, env.get("ZASP_VPS_KUBE_CONTEXT", ""), env.get("ZASP_VPS_CLUSTER_UID", "")]
        for action in ("doctor", "status"):
            check("PostgreSQL, Temporal and OpenFGA dependencies: " + action, lambda a=action: run([*args, a], timeout=100), live=True)
    else:
        print("UNVERIFIED cluster storage and dependency checks withheld until the target UID matches")
        for component in ("openbao", "nango"):
            if env.get("ZASP_VPS_" + component.upper() + "_MODE") == "existing":
                check(component + " external authenticated readiness", lambda c=component: service_status(c))
    print("UNVERIFIED full application PostgreSQL, self-hosted OpenSearch and Neo4j security and persistence")
    use_s3 = env.get("ZASP_EVIDENCE_PROVIDER", "s3") == "s3"
    use_sqs = env.get("ZASP_QUEUE_PROVIDER", "sqs") == "sqs"
    call = None
    if use_s3 or use_sqs:
        call = check("dedicated metadata-only AWS role, STS audience and doctor service-account subject", aws_identity, live=True)
    if not use_s3:
        print("BLOCKED selected evidence provider; S3 probes skipped")
    if not use_sqs:
        print("BLOCKED selected queue provider; SQS probes skipped")
    if call:
        region, owner = env["ZASP_AWS_REGION"], env["ZASP_EVIDENCE_BUCKET_OWNER"]
        if use_s3:
            check("S3 evidence region, owner, ownership controls, versioning and default encryption", lambda: s3(call, region, owner))
        queues = [] if not use_sqs else [("agentsec-discovery-jobs", "ZASP_DISCOVERY_QUEUE_URL", "aws-kms", 5),
                  ("agentsec-audit-exports", "ZASP_AUDIT_EXPORT_QUEUE_URL", env.get("ZASP_AUDIT_EXPORT_QUEUE_ENCRYPTION", "aws-kms"), 20)]
        if use_sqs and (env.get("ZASP_RECOVERY_QUEUE_URL") or env.get("ZASP_RECOVERY_OPERATION_KIND")):
            op = env.get("ZASP_RECOVERY_OPERATION_KIND")
            if op not in ("backup", "restore"):
                check("valid recovery queue operation kind", lambda: checked(False))
            else:
                queues.append(("agentsec-recovery-" + op + "-jobs", "ZASP_RECOVERY_QUEUE_URL", "aws-kms", 100))
        for name, key, mode, count in queues:
            check(key + " source and DLQ: owner, encryption, retention and redrive",
                  lambda: sqs(call, region, owner, name, env.get(key, ""), mode, count))
    else:
        print("UNVERIFIED evidence bucket and selected SQS work/dead-letter queues; no customer identity was used")
    print("UNVERIFIED worker-specific STS trust, customer role access and bucket retention/WORM; use the workload identity preflight")
    check("backup source inventory and custody references", lambda: run([sys.executable, LIB / "vps_backup.py", "check"]), live=True)
    provider = env.get("ZASP_BACKUP_PROVIDER", "")
    if provider in ("r2", "s3"):
        check("backup recipient certificate and offsite bucket metadata access", lambda: backup_probe(provider), live=True)
    else:
        print("UNVERIFIED offsite backup; an explicit local destination does not verify disaster recovery")
    print("UNVERIFIED independently held decryption keys, unseal shares and completed fresh-machine restore require a recorded recovery rehearsal")
    print("The signed application install verifies its candidate and rendered workloads. Check a deployed release with ./zasp --profile vps status application.")
    return int(bool(failed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    sys.exit(main(parser.parse_args().dry_run or env.get("ZASP_DRY_RUN") == "1"))
