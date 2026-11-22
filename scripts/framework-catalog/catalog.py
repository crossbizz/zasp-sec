"""Verify a reviewed release's source and extract published index metadata only."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'services/platform/compliancemap/data'
LOCKS = Path(__file__).with_name('releases.json')


def owasp(source, framework, edition):
    if framework == 'owasp_llm_top10' and edition == '2026':
        content = source.decode()
        table = re.compile(r'^\| (LLM\d\d):2026 (.+?) \| ', re.M)
    else:
        # Poppler reads stdin; the two published PDF indexes have different TOCs.
        content = subprocess.run(
            ['pdftotext', '-layout', '-', '-'], input=source,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.decode()
        if framework == 'owasp_agentic_top10':
            table = re.compile(r'^\s*(ASI\d\d): (.+?)\s{2,}\d+\s*$', re.M)
        else:
            table = re.compile(r'^\s*(LLM\d\d):(?:2025)? (.+?) \. (?:\. )+\d+\s*$', re.M)
    rows = [dict(id=i, title=t, kind='risk') for i, t in table.findall(content)]
    prefix = 'ASI' if framework == 'owasp_agentic_top10' else 'LLM'
    if [r['id'] for r in rows] != [f'{prefix}{i:02d}' for i in range(1, 11)]:
        raise ValueError('expected the ten distinct ordered headings in the published index')
    return rows


def atlas(source, edition):
    import yaml  # Import-time tool only. The production binary embeds plain JSON.
    release = yaml.safe_load(source)
    if release['format-version'] != '6.1.0' or release['collection']['version'] != edition:
        raise ValueError('unexpected ATLAS content or schema version')
    entries = []
    for group in ('techniques', 'mitigations'):
        for ident, record in release[group].items():
            expected = r'AML\.T\d{4}(?:\.\d{3})?' if group == 'techniques' else r'AML\.M\d{4}'
            if not re.fullmatch(expected, ident) or ident != record['id']:
                raise ValueError('invalid ATLAS identifier')
            kind = 'mitigation' if group == 'mitigations' else 'technique'
            entry = dict(id=ident, title=record['name'], kind=kind, identity=record['uuid'])
            if ident.count('.') == 2:
                entry.update(kind='subtechnique', parent=ident.rsplit('.', 1)[0])
                if entry['parent'] not in release['techniques']:
                    raise ValueError('subtechnique without its parent')
            entries.append(entry)
    counts = Counter(entry['kind'] for entry in entries)
    if counts != {'technique': 129, 'subtechnique': 92, 'mitigation': 44}:
        raise ValueError(f'unreviewed release counts {counts}')
    # Zasp's legacy reference is absent in this release. Keep the historical
    # label for lookup, outside the published active denominator.
    entries.append(dict(id='AML.T0057', title='LLM Data Leakage', kind='technique', status='retired'))
    return entries


def enterprise(source):
    records = json.loads(source)['objects']
    if len(records) != 1 or records[0]['type'] != 'attack-pattern':
        raise ValueError('expected one reviewed Enterprise technique')
    record = records[0]
    ids = [x.get('external_id') for x in record['external_references'] if x['source_name'] == 'mitre-attack']
    if ids != ['T1059'] or record.get('revoked') or record.get('x_mitre_deprecated'):
        raise ValueError('unexpected Enterprise object')
    return [dict(id=ids[0], title=record['name'], kind='technique', identity=record['id'])]


def build_release(lock, source):
    digest = 'sha256:' + hashlib.sha256(source).hexdigest()
    if digest != lock['source_digest']:
        raise ValueError('source bytes differ from the reviewed release lock')
    framework, edition = lock['framework'], lock['edition']
    if framework == 'mitre_atlas':
        rows = atlas(source, edition)
    elif framework == 'mitre_attack_enterprise':
        rows = enterprise(source)
    else:
        rows = owasp(source, framework, edition)
    if len({r['id'] for r in rows}) != len(rows) or any(not r['title'].strip() for r in rows):
        raise ValueError('missing title or duplicate identity')
    return {**lock, 'entries': sorted(rows, key=lambda row: row['id'])}


def changes(previous, current):
    if previous['framework'] != current['framework']:
        raise ValueError('compare editions of the same framework')
    old, new = ({row['id']: row for row in release['entries']} for release in (previous, current))
    result = []
    for ident in sorted(old.keys() | new.keys()):
        a, b = old.get(ident), new.get(ident)
        if a is None:
            result.append(dict(id=ident, change='added', title=b['title']))
        elif b is None:
            result.append(dict(id=ident, change='removed', title=a['title']))
        elif a != b:
            if b.get('status') == 'retired' and a.get('status') != 'retired':
                change = 'removed'
            elif a.get('identity') and b.get('identity') and a['identity'] != b['identity']:
                change = 'reassigned'
            elif a['title'] != b['title']:
                # OWASP ranks are not stable identities. Treat semantic changes
                # as requiring reassignment review, even when a title looks close.
                change = 'renamed' if a.get('identity') == b.get('identity') and a.get('identity') else 'reassignment_review'
            else:
                change = 'modified'
            result.append(dict(id=ident, change=change, previous=a['title'], current=b['title']))
    return result


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cmd = cli.add_subparsers(dest='operation', required=True)
    load = cmd.add_parser('import')
    load.add_argument('framework')
    load.add_argument('edition')
    load.add_argument('source', type=Path)
    load.add_argument('--check', action='store_true', help='compare with the checked-in output')
    diff = cmd.add_parser('diff')
    diff.add_argument('previous', type=Path)
    diff.add_argument('current', type=Path)
    args = cli.parse_args()
    if args.operation == 'diff':
        before, after = (json.loads(f.read_text()) for f in (args.previous, args.current))
        print(json.dumps(changes(before, after), indent=2))
        return
    locks = json.loads(LOCKS.read_text())
    lock = next((x for x in locks if (x['framework'],x['edition']) == (args.framework,args.edition)), None)
    if lock is None:
        cli.error('unreviewed framework or edition')
    result = build_release(lock, args.source.read_bytes())
    path = CATALOG / f'{args.framework}-{args.edition}.json'
    data = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.check:
        if path.read_text() != data:
            sys.exit(f'{path.name} differs from its verified source')
    else:
        path.write_text(data)


if __name__ == '__main__':
    main()
