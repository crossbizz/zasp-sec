"""Report tracked test source locations from a failed CI log without copying test output."""
import re
import subprocess
import sys

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TEST_FILE = r"[A-Za-z0-9_./-]+\.(?:test|spec)\.[cm]?[jt]sx?"
FILE = re.compile(r"(?<![A-Za-z0-9_./-])(" + TEST_FILE + r")(?::([0-9]+))?(?=[: ,\s]|$)")
ANNOTATION = re.compile(r"file=(" + TEST_FILE + r")(?:,line=([0-9]+))?")
RELEASE = re.compile(r"/(release-gates|release-contract)\.mjs:([0-9]+):[0-9]+")


def summarize(lines, tracked):
    tests = {}
    releases = set()
    for raw in lines:
        line = ANSI.sub("", raw)
        if re.match(r"^\s*(?:FAIL\s|[❯×✗✘]\s|::error\b)", line):
            matches = FILE.finditer(line) if "::error" not in line else ANNOTATION.finditer(line)
            for match in matches:
                path = match[1].removeprefix("./")
                if path in tracked and (path in tests or len(tests) < 4):
                    tests[path] = match[2] or tests.get(path, "")
        releases.update(RELEASE.findall(line))
    result = [p + (":" + n if n else "") for p, n in tests.items()]
    result += [f"{file}:{line}" for file, line in sorted(releases)[:3]]
    return ", ".join(result)[:165]


if __name__ == "__main__":
    files = subprocess.check_output(["git", "ls-files", "-z"], text=True).split("\0")
    print(summarize(sys.stdin, set(files)))
