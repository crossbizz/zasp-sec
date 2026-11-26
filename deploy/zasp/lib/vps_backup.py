"""Capture verified recovery bundles for the services declared in a VPS installation."""
import ctypes
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit


class RecoveryError(Exception):
    pass


DATABASES = {"postgres", "nango-postgres", "openfga-postgres", "temporal-postgres", "temporal-visibility"}
MEMBERS = DATABASES | {"openbao-raft", "nango-encryption-key", "release-config", "opensearch", "neo4j",
                       "s3-evidence", "sqs-outbox"}
CUSTODY = {"backup-identity", "backup-reader", "openbao-unseal"}
MAX_ARCHIVE = 5_000_000_000


def reject(message):
    raise RecoveryError(message)


def checked_file(path, private=True):
    if not isinstance(path, str) or not os.path.isabs(path):
        reject("source paths must be absolute")
    fd = os.open(Path(path).resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & (0o077 if private else 0o022)):
        stream.close()
        reject("unsafe backup source ownership or permissions")
    return stream


def read_small(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        reject("backup metadata or credential exceeds size limit")
    return data


def proctool(args, env=None, stdout=None, limit=1800):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=stdout or subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=env, timeout=limit)
    except subprocess.TimeoutExpired:
        reject(f"{args[0]} timed out")
    if result.returncode:
        reject(f"{args[0]} failed; check the source, TLS trust, credentials and service health")


def text_label(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+ -]{0,255}", value))


def installation():
    name = os.environ.get("ZASP_VPS_INSTALLATION_ID", "")
    if not re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
        reject("set ZASP_VPS_INSTALLATION_ID to the intended installation DNS label")
    return name


def read_spec():
    name = os.environ.get("ZASP_VPS_BACKUP_SPEC_FILE")
    with checked_file(name) as stream:
        spec = json.loads(read_small(stream, 65536))
    if (not isinstance(spec, dict) or set(spec) != {"installation", "sources", "custody"}
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", str(spec["installation"]))
            or not isinstance(spec["sources"], dict) or set(spec["sources"]) != MEMBERS
            or not isinstance(spec["custody"], dict) or set(spec["custody"]) != CUSTODY
            or not all(text_label(v) for v in spec["custody"].values())):
        reject("invalid VPS backup spec: account for every source and each independent recovery reference")
    if spec["installation"] != installation():
        reject("capture inventory belongs to a different VPS installation")
    exclusions = set()
    for key in ("ZASP_BACKUP_IDENTITY_FILE", "ZASP_BACKUP_PASSPHRASE_FILE", "ZASP_BACKUP_CREDENTIALS_FILE"):
        configured = os.environ.get(key)
        if configured and os.path.isfile(configured):
            info = os.stat(configured)
            exclusions.add((info.st_dev, info.st_ino))
    if not isinstance(spec["sources"]["release-config"], dict) or spec["sources"]["release-config"].get("type") != "file":
        reject("release-config must name an explicitly reviewed configuration file")
    for name, source in spec["sources"].items():
        if not isinstance(source, dict):
            reject("invalid backup source")
        how = source.get("type")
        if how in ("external", "absent"):
            if set(source) != {"type", "reference"} or not text_label(source["reference"]):
                reject("external or absent source requires a non-secret recovery reference or reason")
        elif name in DATABASES and how == "postgres":
            fields = {"type", "host", "port", "database", "user", "password_file", "ca_file"}
            if (set(source) != fields or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", str(source["host"]))
                    or type(source["port"]) is not int or not 0 < source["port"] < 65536
                    or not all(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}", str(source[k])) for k in ("database", "user"))):
                reject("invalid PostgreSQL source coordinates")
            for field in ("password_file", "ca_file"):
                with checked_file(source[field], field != "ca_file"):
                    pass
        elif name == "openbao-raft" and how == "openbao":
            if set(source) != {"type", "address", "ca_file", "token_file"}:
                reject("invalid OpenBao snapshot source")
            addr = urlsplit(source["address"])
            if (addr.scheme != "https" or not addr.hostname or addr.username is not None
                    or addr.password is not None or addr.path not in ("", "/") or addr.query or addr.fragment):
                reject("OpenBao requires a verified HTTPS origin")
            for field in ("token_file", "ca_file"):
                with checked_file(source[field], field == "token_file"):
                    pass
        elif name in {"nango-encryption-key", "release-config", "opensearch", "neo4j"} and how == "file":
            if set(source) != {"type", "path"}:
                reject("file source requires a protected path")
            with checked_file(source["path"]) as stream:
                info = os.fstat(stream.fileno())
                if (info.st_dev, info.st_ino) in exclusions:
                    reject("backup source aliases independent unlock or provider-read material")
        else:
            reject(f"unsupported capture type for {name}")
    nango = spec["sources"]["nango-postgres"]["type"]
    if nango != "absent" and spec["sources"]["nango-encryption-key"]["type"] == "absent":
        reject("Nango recovery requires its encryption key or an independent recovery reference")
    return spec


def copy_bounded(src, dest, limit):
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = src.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            reject("recovery material exceeds the bundle size limit")
        dest.write(chunk)
        h.update(chunk)
    if total == 0:
        reject("empty backup source")
    return {"bytes": total, "sha256": h.hexdigest()}


def postgres(source, dest, temporary):
    # Only explicit coordinates are sent to libpq. No credential/DSN in argv.
    with tempfile.TemporaryDirectory(dir=temporary) as d:
        work = Path(d)
        with checked_file(source["password_file"]) as stream:
            password = read_small(stream, 4096).decode().rstrip("\r\n")
        if not password or any(ch in password for ch in "\n\r\0"):
            reject("invalid PostgreSQL backup password file")
        with checked_file(source["ca_file"], False) as src, (work / "ca").open("xb") as out:
            copy_bounded(src, out, 1024 * 1024)
        escaped = password.replace("\\", "\\\\").replace(":", "\\:")
        (work / "pass").write_text(":".join([source["host"], str(source["port"]), source["database"],
                                           source["user"], escaped]) + "\n")
        (work / "pass").chmod(0o600)
        env = dict(PATH=os.environ["PATH"], HOME=d, PGHOST=source["host"], PGPORT=str(source["port"]),
                   PGDATABASE=source["database"], PGUSER=source["user"], PGPASSFILE=str(work / "pass"),
                   PGSSLMODE="verify-full", PGSSLROOTCERT=str(work / "ca"), PGCONNECT_TIMEOUT="10",
                   PGAPPNAME="zasp-backup")
        proctool(["pg_dump", "--no-password", "--format=custom", "--lock-wait-timeout=30s", "--file", str(dest)], env)
        proctool(["pg_restore", "--list", str(dest)], env, limit=120)


def raft(source, target):
    addr = urlsplit(source["address"])
    with checked_file(source["ca_file"], False) as stream:
        trust = read_small(stream, 1024 * 1024).decode()
    ctx = ssl.create_default_context(cadata=trust)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with checked_file(source["token_file"]) as stream:
        token = read_small(stream, 8192).decode().strip()
    if not token or any(c.isspace() for c in token):
        reject("invalid OpenBao snapshot reader token file")
    conn = http.client.HTTPSConnection(addr.hostname, addr.port or 443, context=ctx, timeout=60)
    try:
        conn.request("GET", "/v1/sys/storage/raft/snapshot", headers={"X-Vault-Token": token})
        response = conn.getresponse()
        if response.status != 200:
            reject(f"OpenBao snapshot unavailable (HTTP {response.status}); check seal state and reader policy")
        with target.open("xb") as out:
            meta = copy_bounded(response, out, MAX_ARCHIVE)
            advertised = response.getheader("Content-Length")
            if advertised is not None and (not advertised.isdigit() or int(advertised) != meta["bytes"]):
                reject("incomplete OpenBao snapshot response")
        # Match the OpenBao CLI's end-of-snapshot completion check. A server
        # may have already sent HTTP 200 before its snapshot reader fails.
        with tarfile.open(target, "r|gz") as inner:
            if not any(m.name == "SHA256SUMS.sealed" and m.isfile() and m.size > 0
                       and inner.extractfile(m).read(1) for m in inner):
                reject("incomplete OpenBao snapshot: missing sealed checksum")
    finally:
        conn.close()


def file_digest(path):
    with path.open("rb") as src, open(os.devnull, "wb") as sink:
        return copy_bounded(src, sink, MAX_ARCHIVE)


def capture(target):
    spec = read_spec()
    sources = {}
    with tempfile.TemporaryDirectory(dir=target.parent) as d:
        work = Path(d)
        total = 0
        for name, source in sorted(spec["sources"].items()):
            how = source["type"]
            if how in ("absent", "external"):
                sources[name] = source
                continue
            dest = work / name
            if how == "postgres":
                postgres(source, dest, work)
            elif how == "openbao":
                raft(source, dest)
            else:
                with checked_file(source["path"]) as stream, dest.open("xb") as out:
                    copy_bounded(stream, out, MAX_ARCHIVE-total)
            meta = file_digest(dest)
            total += meta["bytes"]
            if total > MAX_ARCHIVE:
                reject("capture exceeds the single-object backup limit")
            sources[name] = {"type": how, **meta}
        manifest = {"format":"zasp-vps-recovery-v1", "installation":spec["installation"],
                    "created":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "sources":sources, "custody":spec["custody"]}
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with tarfile.open(target, "x") as out:
            for path in sorted(work.iterdir()):
                out.add(path, arcname=path.name, recursive=False)


def recover(archive):
    target_value = os.environ.get("ZASP_VPS_RESTORE_DIRECTORY")
    if not target_value or not Path(target_value).is_absolute():
        reject("set ZASP_VPS_RESTORE_DIRECTORY to a new absolute directory on the isolated recovery host")
    target = Path(target_value)
    if os.path.lexists(target):
        reject("VPS restore requires a new destination; existing state was left in place")
    with tarfile.open(archive, "r:") as bundle, tempfile.TemporaryDirectory(dir=target.parent) as tempdir:
        work = Path(tempdir)
        seen = {}
        total = 0
        for member in bundle:
            if (not member.isfile() or member.issparse() or member.name not in MEMBERS | {"manifest.json"}
                    or member.name in seen or member.size <= 0 or total + member.size > MAX_ARCHIVE + 65536
                    or (member.name == "manifest.json" and member.size > 65536)):
                reject("unexpected, duplicate or unsafe entry in VPS backup archive")
            with bundle.extractfile(member) as src, (work / member.name).open("xb") as out:
                seen[member.name] = copy_bounded(src, out, member.size)
            total += member.size
        if "manifest.json" not in seen:
            reject("VPS backup has no manifest")
        manifest = json.loads((work / "manifest.json").read_bytes())
        if (not isinstance(manifest, dict) or manifest.get("format") != "zasp-vps-recovery-v1"
                or not isinstance(manifest.get("sources"), dict) or set(manifest["sources"]) != MEMBERS
                or not text_label(manifest.get("installation")) or not isinstance(manifest.get("custody"), dict)
                or set(manifest["custody"]) != CUSTODY or not all(map(text_label,manifest["custody"].values()))):
            reject("invalid VPS recovery manifest")
        if manifest["installation"] != installation():
            reject("recovery manifest belongs to a different VPS installation")
        for name, entry in manifest["sources"].items():
            if not isinstance(entry, dict):
                reject("invalid VPS manifest source")
            if entry.get("type") in ("external","absent"):
                if name in seen or not text_label(entry.get("reference")):
                    reject("invalid external recovery source")
            elif (entry.get("type") not in ("openbao","postgres","file") or name not in seen
                  or type(entry.get("bytes")) is not int or entry["bytes"] != seen[name]["bytes"]
                  or entry.get("sha256") != seen[name]["sha256"]):
                reject("VPS archive component does not match its manifest")
        if manifest["sources"]["release-config"].get("type") != "file":
            reject("VPS release configuration absent from manifest")
        # VPS recovery runs on Linux. Publish the entire directory in one
        # no-replace rename so a crash cannot leave a partially accepted target.
        for path in work.iterdir():
            path.chmod(0o600)
        rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        if rename is None:
            reject("VPS restore requires Linux renameat2 support for atomic publication")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        if rename(-100, os.fsencode(work), -100, os.fsencode(target), 1) < 0:
            code = ctypes.get_errno()
            raise OSError(code, "cannot atomically publish recovery directory")
    print("verified VPS recovery material staged in a new directory; services have not been cut over")


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["check"]:
            reject("usage: vps_backup.py check")
        read_spec()
        print("VPS backup spec and source file permissions verified")
    except (OSError, ValueError, TypeError, RecoveryError) as exc:
        sys.exit(f"zasp: {exc}")
