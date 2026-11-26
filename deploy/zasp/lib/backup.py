"""Client-side backup encryption and conditional object transfer for the zasp CLI."""
import configparser
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


class BackupError(Exception):
    pass


def setting(name):
    value = os.environ.get("ZASP_BACKUP_" + name)
    if not value:
        raise BackupError("set ZASP_BACKUP_" + name)
    return value


@contextlib.contextmanager
def trusted_file(name, secret):
    path = Path(setting(name)).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & (0o077 if secret else 0o022)):
            raise BackupError(f"ZASP_BACKUP_{name} must be a trusted regular file; "
                              + ("use mode 0600 or 0400" if secret else "remove group/other write access"))
        # Retain the checked inode throughout use, including during atomic rotation.
        yield stream


def run(args, message, **kwargs):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, **kwargs)
    if result.returncode:
        raise BackupError(message)


def encrypt(source, dest):
    with trusted_file("RECIPIENT_FILE", False) as cert:
        fd = cert.fileno()
        run(["openssl", "cms", "-encrypt", "-binary", "-stream", "-outform", "DER",
             "-aes-256-gcm", "-recip", f"/dev/fd/{fd}", "-keyopt", "rsa_padding_mode:oaep",
             "-keyopt", "rsa_oaep_md:sha256", "-in", source, "-out", dest],
            "encryption failed; check the RSA recipient certificate and OpenSSL CMS support", pass_fds=(fd,))


def decrypt(source, dest):
    with contextlib.ExitStack() as stack:
        key = stack.enter_context(trusted_file("IDENTITY_FILE", True))
        fds = [key.fileno()]
        args = ["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-inkey", f"/dev/fd/{fds[0]}"]
        if os.environ.get("ZASP_BACKUP_PASSPHRASE_FILE"):
            password = stack.enter_context(trusted_file("PASSPHRASE_FILE", True))
            fds.append(password.fileno())
            args.extend(["-passin", f"fd:{password.fileno()}"])
        run([*args, "-in", source, "-out", dest], "decryption or authentication failed", pass_fds=fds)


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@contextlib.contextmanager
def new_output(path):
    # Stage on the destination filesystem. link() publishes only a completed file
    # and fails atomically if another writer (or a symlink) owns this name.
    if os.path.lexists(path):
        raise BackupError(f"output already exists: {path}")
    with tempfile.TemporaryDirectory(dir=path.parent) as directory:
        staged = Path(directory) / "new"
        yield staged
        staged.chmod(0o600)
        os.link(staged, path)


class Remote:
    # A single conditional PutObject on both services, without multipart state.
    max_size = 5_000_000_000

    def __init__(self, provider, scratch):
        self.provider = provider
        self.bucket = setting("BUCKET")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket) or ".." in self.bucket:
            raise BackupError("invalid ZASP_BACKUP_BUCKET")
        self.scope = setting("R2_ACCOUNT_ID" if provider == "r2" else "REGION")
        self.owner_flags = []
        self.options = ["--no-cli-pager", "--cli-connect-timeout", "10", "--cli-read-timeout", "120"]
        if provider == "r2":
            if not re.fullmatch(r"[a-f0-9]{32}", self.scope):
                raise BackupError("invalid ZASP_BACKUP_R2_ACCOUNT_ID")
            self.options += ["--endpoint-url", f"https://{self.scope}.r2.cloudflarestorage.com", "--region", "auto"]
        else:
            if not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", self.scope):
                raise BackupError("invalid ZASP_BACKUP_REGION")
            owner = setting("EXPECTED_BUCKET_OWNER")
            if not re.fullmatch(r"[0-9]{12}", owner):
                raise BackupError("invalid ZASP_BACKUP_EXPECTED_BUCKET_OWNER")
            self.options += ["--region", self.scope]
            self.owner_flags = ["--expected-bucket-owner", owner]
            self.scope = self.scope + "/" + owner
        # Snapshot one rotation and accept only a credential tuple. The AWS
        # CLI would otherwise also interpret role or credential_process options.
        parsed = configparser.RawConfigParser()
        try:
            with trusted_file("CREDENTIALS_FILE", True) as stream:
                parsed.read_string(stream.read().decode("utf-8"))
        except (UnicodeError, configparser.Error):
            raise BackupError("invalid backup credentials file")
        fields = {"aws_access_key_id", "aws_secret_access_key"}
        if (parsed.sections() != ["default"] or parsed.defaults() or not fields <= set(parsed["default"])
                or set(parsed["default"]) - (fields | {"aws_session_token"})
                or any(not v or any(ch.isspace() for ch in v) for v in parsed["default"].values())):
            raise BackupError("backup credentials must have one [default] section with access key, secret and optional session token")
        credentials = scratch / "credentials"
        with credentials.open("x") as stream:
            parsed.write(stream)
        # Never inherit customer discovery keys, endpoint overrides, AWS profiles,
        # config credential_process, web-identity/metadata credentials, or TLS overrides.
        self.env = {"PATH": os.environ["PATH"], "HOME": "/nonexistent",
                    "AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                    "AWS_EC2_METADATA_DISABLED": "true", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
                    "AWS_REQUEST_CHECKSUM_CALCULATION": "when_required",
                    "AWS_RESPONSE_CHECKSUM_VALIDATION": "when_required",
                    "AWS_MAX_ATTEMPTS": "3", "AWS_PAGER": ""}

    def command(self, key, action, *args):
        return ["aws", *self.options, "s3api", action, "--bucket", self.bucket, "--key", key, *self.owner_flags, *args]

    def reference(self, kind, profile, encrypted):
        return dict(format="zasp-backup-v1", provider=self.provider, scope=self.scope, bucket=self.bucket,
                    kind=kind, profile=profile, size=encrypted.stat().st_size, sha256=digest(encrypted))

    def key(self, receipt):
        if (not isinstance(receipt, dict) or receipt.get("format") != "zasp-backup-v1"
                or receipt.get("provider") != self.provider or receipt.get("scope") != self.scope
                or receipt.get("bucket") != self.bucket or receipt.get("kind") not in ("profile", "file")
                or receipt.get("profile") not in ("local", "kubernetes", "aws")
                or not isinstance(receipt.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", receipt["sha256"])
                or type(receipt.get("size")) is not int or not 0 < receipt["size"] <= self.max_size):
            raise BackupError("invalid receipt or backup destination; select the original provider, account/region and bucket")
        return f'zasp-backups/v1/{receipt["kind"]}/{receipt["profile"]}/{receipt["sha256"]}.cms'

    def get(self, receipt, dest):
        key = self.key(receipt)
        run(self.command(key, "get-object", "--range", f'bytes=0-{receipt["size"]}', dest),
            "backup read failed; check backup credentials, destination and connectivity", env=self.env)
        if dest.stat().st_size != receipt["size"] or digest(dest) != receipt["sha256"]:
            raise BackupError("backup ciphertext failed the trusted receipt's SHA-256 or length check")

    def put(self, receipt, source, scratch):
        key = self.key(receipt)
        # An interrupted response or a conditional conflict is ambiguous. Only
        # a full matching read-back can establish that this backup is available.
        subprocess.run(self.command(key, "put-object", "--if-none-match", "*", "--body", source),
                       env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.get(receipt, scratch / "readback")


def profile_command(root, config, profile, command, path):
    env = {**os.environ, "ZASP_BACKUP_PROVIDER": "local",
           "ZASP_BACKUP_RECIPIENT_FILE": "", "ZASP_BACKUP_IDENTITY_FILE": ""}
    args = ["bash", root / "zasp", "--profile", profile, "--config", config, command, path]
    if command == "restore":
        args.append("--yes")
    result = subprocess.run(args, env=env)
    if result.returncode:
        raise BackupError(f"{profile} {command} failed")


def parse(command, args, profile, remote):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default = f"zasp-backup-{profile}-{stamp}." + ("receipt.json" if remote else "cms")
    if command == "backup":
        if args[:1] in (["upload"], ["download"]):
            if len(args) == 3:
                return args[0], Path(args[1]), Path(args[2])
            raise BackupError(f"usage: zasp backup {args[0]} <input> <output>")
        if len(args) <= 1:
            return "backup", None, Path(args[0] if args else default)
    if command == "restore" and len(args) == 1:
        if os.environ.get("ZASP_YES") != "1":
            raise BackupError("restore replaces profile data; pass --yes to confirm")
        if profile == "aws":
            raise BackupError("production restore is not automated; use the provider snapshot procedure in docs/operations/backup-restore-rollback.md")
        if profile == "kubernetes":
            raise BackupError("use 'zasp backup download' for this archive; the evaluation Kubernetes restore cannot verify PostgreSQL replay")
        return "restore", Path(args[0]), None
    raise BackupError("usage: zasp backup [file] | restore <file> --yes")


def main():
    root, config, command, *args = sys.argv[1:]
    provider = os.environ.get("ZASP_BACKUP_PROVIDER", "local")
    profile = os.environ["ZASP_PROFILE"]
    operation, source, target = parse(command, args, profile, provider != "local")
    if os.environ.get("ZASP_DRY_RUN") == "1":
        print(f"would {operation} with {provider} backup storage")
        return
    if source is not None and not source.is_file():
        raise BackupError("input file does not exist")
    if target is not None and os.path.lexists(target):
        raise BackupError(f"output already exists: {target}")
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        remote = Remote(provider, work) if provider != "local" else None
        plain = work / "archive"
        cipher = work / "envelope"
        if operation in ("backup", "upload"):
            if operation == "backup":
                profile_command(Path(root), config, profile, "backup", plain)
                source = plain
            if remote and source.stat().st_size > remote.max_size:
                raise BackupError("archive exceeds the 5 GB single-write limit")
            with new_output(target) as out:
                encrypt(source, cipher if remote else out)
                if remote:
                    if cipher.stat().st_size > remote.max_size:
                        raise BackupError("encrypted backup exceeds the 5 GB single-write limit")
                    receipt = remote.reference("file" if operation == "upload" else "profile", profile, cipher)
                    remote.put(receipt, cipher, work)
                    out.write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"wrote {'verified backup receipt' if remote else 'encrypted backup'} {target}")
            return
        if remote:
            with source.open("rb") as stream:
                data = stream.read(4097)
            if len(data) > 4096:
                raise BackupError("invalid backup receipt size")
            receipt = json.loads(data)
            remote.key(receipt)
            if operation == "restore" and (receipt["kind"] != "profile" or receipt["profile"] != profile):
                raise BackupError("receipt does not describe a backup of this profile")
            remote.get(receipt, cipher)
            source = cipher
        if operation == "download":
            with new_output(target) as out:
                decrypt(source, out)
            print(f"wrote private decrypted file {target}")
        else:
            decrypt(source, plain)
            profile_command(Path(root), config, profile, "restore", plain)


if __name__ == "__main__":
    try:
        main()
    except (BackupError, OSError, ValueError) as error:
        sys.exit(f"zasp backup: {error}")
