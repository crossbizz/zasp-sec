"""Publish only fixed scalar observations; raw evidence stays in the artifact."""
import hashlib, json, os, re, stat, sys
from pathlib import Path

def bounded(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 33554432:
            raise ValueError("evidence bound")
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, 33554433 - len(raw)))
            if not part:
                break
            raw.extend(part)
            if len(raw) > 33554432:
                raise ValueError("evidence bound")
        fields = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        if fields(before) != fields(os.fstat(fd)) or fields(before) != fields(os.lstat(path)):
            raise ValueError("evidence changed")
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)

proof = Path(sys.argv[1])
summary = dict(complete=False, releaseAccepted=False)
outer = proof / "outer-join.json"
summary["outerExit"] = None
if outer.exists():
    value, _ = bounded(outer)
    code = value.get("normalShellWaitExit")
    if type(code) is not int or not 0 <= code <= 255:
        raise ValueError("outer exit grammar")
    summary["outerExit"] = code
paths = sorted(Path("/tmp").glob("official-public-lock-advisory-query-actual-*/result.json"))
if len(paths) > 1:
    raise ValueError("ambiguous result")
if paths:
    value, digest = bounded(paths[0])
    if value.get("format") != "root-owned-official-public-lock-query-observation-v1" or value.get("releaseAccepted") is not False:
        raise ValueError("result grammar")
    summary["resultSHA256"] = digest
    failure = value.get("failureClass")
    summary["failureClass"] = failure if failure is None or isinstance(failure, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,47}", failure) else "omitted"
    records = value.get("requests")
    if not isinstance(records, list) or len(records) > 256:
        raise ValueError("request bound")
    summary["recordedRequests"] = len(records)
    component = value.get("component")
    summary["complete"] = summary["outerExit"] == 0 and not os.path.lexists(paths[0].parent / "late-refusal.json") and value.get("completeIssuedQueries") is True and value.get("forced") is False and value.get("cancelled") is False and isinstance(component, dict) and component.get("allIssuedPublicLockQueriesTraversed") is True
    if isinstance(component, dict):
        for key in ("coverage", "upstreamMatchedObservations"):
            rows = component.get(key)
            if not isinstance(rows, list) or len(rows) > 100000:
                raise ValueError("component bound")
            summary[key + "Count"] = len(rows)
        observations = component["upstreamMatchedObservations"]
        summary["upstreamMatchedAdvisories"] = []
        summary["advisoryListTruncated"] = len(observations) > 64
        for row in observations[:64]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", row["id"]) or row.get("type") not in ("reviewed", "unreviewed", "malware"):
                raise ValueError("public advisory identity grammar")
            summary["upstreamMatchedAdvisories"].append(dict(id=row["id"], type=row["type"]))
        for key in ("requests", "wireBytes"):
            count = component.get(key)
            if type(count) is not int or not 0 <= count <= 134217728:
                raise ValueError("count grammar")
            summary[key] = count
print("::notice title=Official public npm query outcome::" + json.dumps(summary, separators=(",", ":"), sort_keys=True))
