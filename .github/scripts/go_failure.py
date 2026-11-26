"""Summarize failed Go tests for the Actions checks list without copying test data."""

import json
import re
import sys


def summarize(lines):
    failures = []
    build_locations = []
    test_locations = {}
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            event = {}
        if not isinstance(event, dict):
            continue
        test = event.get("Test", "")
        if event.get("Action") == "fail" and re.fullmatch(r"Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_.-]+)*", test):
            failures.append(test)
        output = event.get("Output", "") if event else line
        match = re.search(r"(?:^|\s)([\w./-]+\.go:\d+(?::\d+)?):", output)
        if match:
            location = match[1].rsplit("/", 1)[-1]
            if test:
                test_locations.setdefault(test, []).append(location)
            else:
                build_locations.append(location)
    locations = [loc for test in failures for loc in test_locations.get(test, [])]
    parts = list(dict.fromkeys(failures[:3] + (locations + build_locations)[:6]))
    return ", ".join(parts)[:208]


if __name__ == "__main__":
    print("failure=" + summarize(sys.stdin))
