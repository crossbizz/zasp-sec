#!/usr/bin/env python3
"""Validate the fixed ownership-write component contract, never native acceptance."""
import argparse
import json
from pathlib import Path
import re
import sys

from validate_agent_read_components import (
    EvidenceRejected, check_sources, decode_json, load_events, validate_events,
)

ROOT = Path(__file__).resolve().parent.parent
ROSTER = ROOT / '.github/agent-ownership-write-component-roster.json'
PACKAGES = {
    'github.com/zasp-ai/zasp-sec/services/platform/' + name
    for name in ('apiserver', 'agentsec-api', 'agentsec-migrate', 'migrations')
}
GUARDS = {
    'scripts/validate_agent_read_components.py',
    'scripts/validate_agent_ownership_write_components.py',
    'scripts/validate_agent_ownership_write_components_test.py',
    '.github/workflows/agents-ownership-write-components.yml',
    '.github/agent-ownership-write-component-roster.json',
    'scripts/validate_agent_exposure_components.py',
    '.github/agent-exposure-component-roster.json',
}


def load_contract():
    with ROSTER.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise EvidenceRejected('oversized fixed roster')
    spec = decode_json(raw)
    if not isinstance(spec, dict) or set(spec) != {
        'schema', 'expected_total_named', 'expected_top_heads', 'packages', 'required_source_paths'
    } or spec['schema'] != 'zasp-agent-ownership-write-components-v1' or type(spec['expected_total_named']) is not int or type(spec['expected_top_heads']) is not int or spec['expected_total_named'] != 52 or spec['expected_top_heads'] != 6:
        raise EvidenceRejected('unexpected component contract')
    expected = {}
    for package in spec['packages']:
        if not isinstance(package, dict) or set(package) != {'package', 'relative_package', 'run_regex', 'expected_names'}:
            raise EvidenceRejected('invalid package contract')
        name, names = package['package'], package['expected_names']
        if name not in PACKAGES or name in expected or package['relative_package'] != './' + name.rsplit('/', 1)[-1] or not isinstance(names, list) or not names or any(not isinstance(n, str) or re.fullmatch(r'TestAgent(?:CurrentOwnershipWrite|OwnershipWrite)[A-Za-z0-9_]*(?:/[A-Za-z0-9_#.-]+)*', n) is None for n in names) or len(set(names)) != len(names):
            raise EvidenceRejected('invalid or duplicate component roster')
        for test in names:
            parts = test.split('/')
            if any(not part for part in parts) or any('/'.join(parts[:n]) not in names for n in range(1, len(parts))):
                raise EvidenceRejected('missing ancestor')
        heads = [n for n in names if '/' not in n]
        if package['run_regex'] != '^(' + '|'.join(heads) + ')$':
            raise EvidenceRejected('selector differs from exact heads')
        expected[name] = names
    if set(expected) != PACKAGES or sum(map(len, expected.values())) != 52 or sum('/' not in n for names in expected.values() for n in names) != 6:
        raise EvidenceRejected('incomplete component contract')
    paths = spec['required_source_paths']
    if not isinstance(paths, list) or any(not isinstance(p, str) or Path(p).is_absolute() or '..' in Path(p).parts or Path(p).as_posix() != p for p in paths) or len(set(paths)) != len(paths) or not GUARDS.issubset(paths):
        raise EvidenceRejected('invalid required source contract')
    return expected, frozenset(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', nargs='?')
    parser.add_argument('--go-exit-code', type=int)
    parser.add_argument('--check-sources')
    args = parser.parse_args()
    try:
        expected, required = load_contract()
        # The roster is fixed repository source and is verified with the same
        # full manifest as the application and shared validator, never user input.
        custody = check_sources(ROOT, args.check_sources or ROOT / '.github/connector-native-compile-source-pins.json', required)
        if args.check_sources:
            if args.evidence is not None or args.go_exit_code is not None:
                raise EvidenceRejected('incompatible modes')
            print(json.dumps(custody))
        else:
            if args.evidence is None or args.go_exit_code is None:
                raise EvidenceRejected('missing execution evidence')
            print(json.dumps(validate_events(load_events(args.evidence), args.go_exit_code, expected)))
    except (EvidenceRejected, OSError, TypeError, KeyError, ValueError, re.error):
        print('Agent ownership write component evidence rejected', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
