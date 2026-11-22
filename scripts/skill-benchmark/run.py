"""Measure installed scanners against inert, labeled skill directories in a network namespace."""

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import time


def write_fixture(case, root):
    bundle = root / case["id"]
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        f'---\nname: {case["id"]}\ndescription: {case["description"]}\n---\n\n{case["body"]}\n',
        encoding="utf-8",
    )
    for name, content in case["files"].items():
        (bundle / name).write_text(content, encoding="utf-8")
    if case.get("link_fixture"):
        marker = root / "harmless-marker.txt"
        marker.write_text("synthetic", encoding="utf-8")
        (bundle / "linked.txt").symlink_to(marker)
    return bundle


def run_scan(engine, binary, bundle, scratch, case, legacy):
    home = scratch / "home"
    home.mkdir(exist_ok=True)
    report = scratch / "scan.sarif"
    report.unlink(missing_ok=True)
    if engine == "zasp":
        args = [binary, "addons", "scan", str(bundle), "--local", "--json"]
        if legacy:
            args += ["--ruleset", "zasp-static.v1"]
    else:
        args = [binary, "scan", str(bundle)]
        if engine == "nvidia":
            args.append("--no-llm")
        args += ["--format", "sarif", "--output", str(report)]
    cmd = [
        "bwrap", "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/",
        "--dev", "/dev", "--proc", "/proc", "--bind", str(scratch), str(scratch),
        "--clearenv", "--setenv", "HOME", str(home), "--setenv", "TMPDIR", str(scratch),
        "--setenv", "LANG", "C.UTF-8", "--setenv", "PATH", str(Path(binary).parent) + os.pathsep + os.defpath,
        "--chdir", str(scratch), "--", *args,
    ]
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    elapsed = int((time.monotonic() - start) * 1000)
    partial = bool(case.get("link_fixture")) and engine == "zasp"
    if result.returncode != (3 if partial else 0):
        raise RuntimeError(f"{engine} failed on {bundle.name} ({result.returncode}): {result.stderr[-600:]}")
    if engine == "zasp":
        data = json.loads(result.stdout)
        if data["status"] != ("partial" if partial else "complete"):
            raise ValueError("first-party scan completeness disagrees with fixture")
        if data["result"]["ruleset"] != ("zasp-static.v1" if legacy else "zasp-static.v2"):
            raise ValueError("unexpected scanner ruleset")
        if partial and data["result"].get("manifest_digest"):
            raise ValueError("escaped member acquired a reviewable digest")
        findings = [f["rule_id"] for f in data["result"]["findings"]]
        findings += ["skipped:" + entry["reason"] for entry in data["result"]["skipped"]]
    else:
        data = json.loads(report.read_text(encoding="utf-8"))
        runs = data["runs"]
        if data["version"] != "2.1.0" or not runs:
            raise ValueError("missing SARIF run")
        if any(i.get("executionSuccessful") is False for run in runs for i in run.get("invocations", [])):
            raise ValueError("scanner reported incomplete execution")
        findings = [item["ruleId"] for run in runs for item in run["results"]]
    return sorted(findings), elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for engine in ("zasp", "cisco", "nvidia"):
        parser.add_argument("--" + engine, help="Installed executable path")
    parser.add_argument("--repeats", type=int, default=3, choices=range(1, 11))
    parser.add_argument("--case", action="append", help="Run only this fixture (repeatable)")
    parser.add_argument("--legacy",action="store_true",help="Replay the historical v1 seven-case corpus")
    options = parser.parse_args()
    engines = {name: str(Path(getattr(options, name)).resolve()) for name in ("zasp", "cisco", "nvidia")
               if getattr(options, name)}
    if not engines or not shutil.which("bwrap"):
        parser.error("provide an installed scanner and Linux bwrap with network isolation")
    corpus = json.loads(Path(__file__).with_name("corpus-v1.json" if options.legacy else "corpus.json").read_text(encoding="utf-8"))
    if not options.legacy and (len(corpus) != 40 or len({c["id"] for c in corpus}) != 40 or
            sorted(c["label"] for c in corpus) != ["adverse"] * 20 + ["benign"] * 20):
        raise ValueError("expected exactly 20 adverse and 20 benign uniquely named cases")
    if options.case:
        if set(options.case) - {item["id"] for item in corpus}:
            parser.error("unknown fixture name")
        corpus = [item for item in corpus if item["id"] in options.case]
    output = []
    with tempfile.TemporaryDirectory(prefix="zasp-benchmark-") as tmp:
        root = Path(tmp)
        for case in corpus:
            bundle = write_fixture(case, root)
            for name, executable in engines.items():
                scratch = root / f'{name}-{case["id"]}'
                scratch.mkdir()
                readings = [run_scan(name, executable, bundle, scratch, case, options.legacy) for _ in range(options.repeats)]
                ids = readings[0][0]
                if any(other != ids for other, _ in readings):
                    raise ValueError(f"nonrepeatable findings for {name}/{bundle.name}")
                expected = case["expected_zasp"] + (["skipped:symlink"] if case.get("link_fixture") else [])
                if name == "zasp" and ids != sorted(expected):
                    raise ValueError(f"builtin capability-label regression for {bundle.name}: {ids}")
                output.append(dict(engine=name, fixture=case["id"], fact=case["fact"], rule_ids=ids,
                                   median_ms=statistics.median(ms for _, ms in readings)))
    if options.legacy or options.case or "zasp" not in engines:
        print(json.dumps(output, indent=2))
        return
    by_id = {row["fixture"]: row for row in output if row["engine"] == "zasp"}
    adverse_hits = sum(c["primary"] in by_id[c["id"]]["rule_ids"] for c in corpus if c["label"] == "adverse")
    false_positives = sum(bool(by_id[c["id"]]["rule_ids"]) for c in corpus if c["label"] == "benign")
    latency = statistics.median(row["median_ms"] for row in by_id.values())
    metrics = {"adverse_recall": adverse_hits / 20, "benign_false_positive_rate": false_positives / 20,
               "median_scan_ms": latency, "corpus_cases": len(corpus)}
    print(json.dumps({"summary": metrics, "cases": output}, indent=2))
    if adverse_hits < 18 or false_positives > 1 or by_id["comment-only"]["rule_ids"] or latency >= 150:
        raise SystemExit("v2 recall, false-positive or latency threshold failed")


if __name__ == "__main__":
    main()
