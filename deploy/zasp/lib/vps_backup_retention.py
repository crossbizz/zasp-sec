"""Scheduled VPS receipt inventory and explicitly confirmed retention."""
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

if __package__:
    from .vps_backup import RecoveryError, checked_file, read_small
else:
    from vps_backup import RecoveryError, checked_file, read_small


PATTERN = re.compile(r"vps-\d{8}T\d{6}Z-[a-f0-9]{32}\.receipt\.json")


@contextlib.contextmanager
def inventory():
    path = os.environ.get("ZASP_VPS_BACKUP_RECEIPT_DIR", "")
    if not path or not Path(path).is_absolute():
        raise RecoveryError("set ZASP_VPS_BACKUP_RECEIPT_DIR to a private independently retained inventory directory")
    directory = Path(path)
    st = directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise RecoveryError("scheduled receipt directory must be owned by this operator with mode 0700")
    fd = os.open(directory / ".zasp-backup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,"rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RecoveryError("another scheduled backup or retention operation owns this inventory")
        yield directory


def next_receipt(directory):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return directory / f"vps-{now}-{uuid.uuid4().hex}.receipt.json"


def read_receipt(path, remote):
    with checked_file(str(path)) as stream:
        receipt = json.loads(read_small(stream, 4096))
    remote.key(receipt)
    if receipt.get("profile") != "vps" or receipt.get("kind") != "profile":
        raise RecoveryError("retention requires verified VPS profile receipts")
    return receipt


def prune(remote, directory, *, dry_run):
    try:
        keep = int(os.environ.get("ZASP_VPS_BACKUP_KEEP", "7"))
    except ValueError:
        raise RecoveryError("ZASP_VPS_BACKUP_KEEP must be an integer at least 2")
    if keep < 2:
        raise RecoveryError("ZASP_VPS_BACKUP_KEEP must be at least 2")
    names = sorted((p for p in directory.iterdir() if PATTERN.fullmatch(p.name)), reverse=True)
    receipts = [(p, read_receipt(p, remote)) for p in names]
    if len(receipts) <= keep:
        return 0
    protected = os.environ.get("ZASP_VPS_BACKUP_VERIFIED_RECEIPT")
    if not protected or not Path(protected).is_absolute():
        raise RecoveryError("set ZASP_VPS_BACKUP_VERIFIED_RECEIPT to an independent receipt that passed a restore drill")
    protected_receipt = read_receipt(Path(protected), remote)
    protected_set = {remote.key(v):v for _,v in receipts[:keep]}
    if len(protected_set) != keep:
        raise RecoveryError("duplicate generations in retained receipt set; refusing retention")
    protected_set[remote.key(protected_receipt)] = protected_receipt
    candidates = [(p,r) for p,r in receipts[keep:] if remote.key(r) not in protected_set]
    if not candidates or dry_run:
        return len(candidates)
    # Refuse any deletion when a retained generation or the independently
    # restore-tested backup fails full authenticated read-back.
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "verify"
        for receipt in protected_set.values():
            remote.get(receipt, target)
            target.unlink()
    tombstones = directory / "pruned"
    tombstones.mkdir(mode=0o700, exist_ok=True)
    if tombstones.is_symlink() or not tombstones.is_dir() or tombstones.stat().st_mode & 0o077:
        raise RecoveryError("unsafe retention audit directory")
    for path, receipt in candidates:
        # Preserve the receipt before removing the object or its active entry.
        retired = tombstones / path.name
        if os.path.lexists(retired):
            if retired.is_symlink() or read_receipt(retired, remote) != receipt:
                raise RecoveryError("conflict in retention audit inventory")
        else:
            os.link(path, retired)
        remote.delete(receipt)
        path.unlink()
    return len(candidates)
