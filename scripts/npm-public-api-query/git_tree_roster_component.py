"""Offline, content-addressed advisory-tree metadata; no upstream admission.

This step1a capacity component does not acquire HTTP, read advisory blobs, or
grant release clearance. All sizes are API declarations, not Git-hashed data.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from cursor_component import exact_json, Refused, LIMITS

REPOSITORY = 'https://github.com/github/advisory-database'
API = 'https://api.github.com/repos/github/advisory-database'
ROUTE = '/repos/github/advisory-database/git/trees/'
ROOTS = ('advisories/github-reviewed', 'advisories/unreviewed')
BOUNDS = dict(response=LIMITS['response'], aggregate=LIMITS['aggregate'],
              requests=LIMITS['requests'], members=LIMITS['members'],
              expanded=300000, evidence=32 << 20, commit=1 << 20,
              path=4096, depth=64)
NONPROOF_FLAGS = ('releaseAccepted', 'upstreamTransportAuthenticated',
                  'fullCorpusContentsVerified', 'fullGitRepositoryClosure',
                  'npmClassificationVerified', 'malwareCoverageVerified',
                  'commitSignatureVerified', 'parentHistoryVerified')


def refuse():
    raise Refused('official advisory roster component refused')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def oid(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) is not None


def shape(value, names):
    return isinstance(value, dict) and set(value) == set(names)


def integer(value):
    return type(value) is int and 0 <= value <= 9007199254740991


def encoded_path(value):
    if not isinstance(value, str):
        refuse()
    try:
        raw = value.encode('utf-8', errors='strict')
    except UnicodeError:
        refuse()
    parts = value.split('/')
    if (not raw or len(raw) > BOUNDS['path'] or len(parts) > BOUNDS['depth']
            or '\\' in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
            or any(part in ('', '.', '..') for part in parts)):
        refuse()
    return raw


def commit_root(expected, raw):
    if not oid(expected) or not isinstance(raw, bytes) or not 0 < len(raw) <= BOUNDS['commit']:
        refuse()
    actual = hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if actual != expected:
        refuse()
    header, separator, _ = raw.partition(b'\n\n')
    if not separator or b'\0' in header or b'\r' in header:
        refuse()
    lines = header.split(b'\n')
    if not re.fullmatch(b'tree [0-9a-f]{40}', lines[0]):
        refuse()
    counts = {}
    previous = None
    for line in lines:
        if line.startswith(b' '):
            if previous not in (b'gpgsig', b'gpgsig-sha256', b'mergetag'):
                refuse()
            continue
        key, space, value = line.partition(b' ')
        if not space or not value or key not in (b'tree', b'parent', b'author', b'committer', b'encoding', b'gpgsig', b'gpgsig-sha256', b'mergetag'):
            refuse()
        counts[key] = counts.get(key, 0) + 1
        if key != b'parent' and counts[key] != 1:
            refuse()
        if key == b'parent' and not re.fullmatch(b'[0-9a-f]{40}', value):
            refuse()
        previous = key
    if any(counts.get(key) != 1 for key in (b'tree', b'author', b'committer')):
        refuse()
    return lines[0][5:].decode('ascii')


def verify_tree_rows(rows, root_oid, recursive):
    """Return verified immediate-child lists keyed by relative directory path."""
    if not isinstance(rows, list) or len(rows) > BOUNDS['members'] or not oid(root_oid) or type(recursive) is not bool:
        refuse()
    trees, children, seen = {'': root_oid}, {}, set()
    for row in rows:
        if not isinstance(row, dict) or not {'path', 'mode', 'type', 'sha'} <= set(row) or set(row) - {'path', 'mode', 'type', 'sha', 'size', 'url'}:
            refuse()
        relative = row['path']
        encoded_path(relative)
        if relative in seen or (not recursive and '/' in relative) or not oid(row['sha']):
            refuse()
        seen.add(relative)
        pair = row['mode'], row['type']
        if not isinstance(row['mode'], str) or not isinstance(row['type'], str):
            refuse()
        if pair not in (('040000', 'tree'), ('100644', 'blob'), ('100755', 'blob'), ('120000', 'blob'), ('160000', 'commit')):
            refuse()
        if row['type'] == 'blob':
            if not integer(row.get('size')):
                refuse()
        elif 'size' in row:
            refuse()
        if 'url' in row:
            segment = {'tree': 'trees', 'blob': 'blobs', 'commit': 'commits'}[row['type']]
            if row['url'] != API + '/git/' + segment + '/' + row['sha']:
                refuse()
        parent, _, name = relative.rpartition('/')
        child = dict(row, path=name)
        children.setdefault(parent, []).append(child)
        if row['type'] == 'tree':
            trees[relative] = row['sha']
    if any(parent not in trees for parent in children):
        refuse()
    verified = {}
    for relative, expected in trees.items():
        if relative and not recursive:
            continue
        direct = children.get(relative, [])
        ordered = sorted(direct, key=lambda r: (r['path'] + ('/' if r['type'] == 'tree' else '')).encode('utf-8'))
        # This payload is bounded by the already charged response/member/path limits.
        parts = [row['mode'].lstrip('0').encode() + b' ' + row['path'].encode('utf-8') + b'\0' + bytes.fromhex(row['sha']) for row in ordered]
        body = b''.join(parts)
        actual = hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        if actual != expected:
            refuse()
        verified[relative] = direct
    return verified


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def verify_git_tree_roster(expected_commit, raw_commit, captures):
    root_oid = commit_root(expected_commit, raw_commit)
    if not isinstance(captures, list) or not 0 < len(captures) <= BOUNDS['requests']:
        refuse()
    objects, origins, captured, captured_oids, blob_sizes = {}, {}, [], set(), {}
    total = members = 0
    for capture in captures:
        if not shape(capture, ('request_path', 'raw_body')):
            refuse()
        route, raw = capture['request_path'], capture['raw_body']
        match = re.fullmatch(re.escape(ROUTE) + '([0-9a-f]{40})(\\?recursive=1)?', route) if isinstance(route, str) else None
        if not match or not isinstance(raw, bytes) or not 0 < len(raw) <= BOUNDS['response']:
            refuse()
        total += len(raw)
        if total > BOUNDS['aggregate'] or match[1] in captured_oids:
            refuse()
        captured_oids.add(match[1])
        value = exact_json(raw)
        if (not shape(value, ('sha', 'url', 'tree', 'truncated')) or value['sha'] != match[1]
                or value['url'] != API + '/git/trees/' + match[1] or value['truncated'] is not False
                or not isinstance(value['tree'], list)):
            refuse()
        members += len(value['tree'])
        if members > BOUNDS['members']:
            refuse()
        if any(not isinstance(row, dict) or 'url' not in row for row in value['tree']):
            refuse()
        verified = verify_tree_rows(value['tree'], match[1], bool(match[2]))
        relative_oids = {'': match[1]}
        for row in value['tree']:
            if row['type'] == 'tree':
                relative_oids[row['path']] = row['sha']
            elif row['type'] == 'blob':
                if row['sha'] in blob_sizes and blob_sizes[row['sha']] != row['size']:
                    refuse()
                blob_sizes[row['sha']] = row['size']
        for relative, rows in verified.items():
            tree_oid = relative_oids[relative]
            # Consistent shared subtree expansions may be reused across paths;
            # conflicting size observations or tree content must refuse.
            normalized = sorted(rows, key=lambda row: row['path'].encode('utf-8'))
            if tree_oid in objects and objects[tree_oid] != normalized:
                refuse()
            objects[tree_oid] = normalized
            origins.setdefault(tree_oid, set()).add(match[1])
        captured.append(dict(requestPath=route, rawSHA256=digest(raw), rawBytes=len(raw)))

    used, reachable_objects, visited_work = set(), set(), 0

    def children(tree_oid):
        nonlocal visited_work
        visited_work += 1
        if visited_work > BOUNDS['expanded'] or tree_oid not in objects:
            refuse()
        reachable_objects.add(tree_oid)
        used.update(origins[tree_oid])
        return objects[tree_oid]

    root_rows = children(root_oid)
    advisory_rows = [row for row in root_rows if row['path'] == 'advisories']
    if len(advisory_rows) != 1 or advisory_rows[0]['type'] != 'tree':
        refuse()
    categories = children(advisory_rows[0]['sha'])
    if {row['path'] for row in categories} != {'github-reviewed', 'unreviewed'} or any(row['type'] != 'tree' for row in categories):
        refuse()
    roster, expanded, evidence_bytes = [], 0, 0
    per_root = {}

    def walk(tree_oid, prefix, ancestors, totals):
        nonlocal expanded, evidence_bytes, visited_work
        encoded_path(prefix)
        if tree_oid in ancestors:
            refuse()
        for row in children(tree_oid):
            expanded += 1
            visited_work += 1
            if expanded > BOUNDS['expanded'] or visited_work > BOUNDS['expanded']:
                refuse()
            relative = prefix + '/' + row['path']
            encoded_path(relative)
            if row['type'] == 'tree':
                totals['directories'] += 1
                walk(row['sha'], relative, ancestors | {tree_oid}, totals)
            elif row['type'] == 'blob' and row['mode'] == '100644':
                candidate = relative.endswith('.json')
                totals['allRegularFiles'] += 1
                totals['jsonCandidateFiles'] += int(candidate)
                totals['nonJSONFiles'] += int(not candidate)
                totals['declaredBytes'] += row['size']
                totals['jsonCandidateDeclaredBytes'] += row['size'] if candidate else 0
                totals['maxDeclaredBlobBytes'] = max(totals['maxDeclaredBlobBytes'], row['size'])
                if any(not integer(value) for value in totals.values()):
                    refuse()
                entry = dict(path=relative, mode=row['mode'], type=row['type'], blobOID=row['sha'], declaredSize=row['size'])
                evidence_bytes += len(canonical(entry)) + 1
                if evidence_bytes > BOUNDS['evidence']:
                    refuse()
                roster.append(entry)
            else:
                refuse()

    fields = ('allRegularFiles', 'jsonCandidateFiles', 'nonJSONFiles', 'declaredBytes', 'jsonCandidateDeclaredBytes', 'maxDeclaredBlobBytes', 'directories')
    for category in categories:
        prefix = 'advisories/' + category['path']
        totals = dict.fromkeys(fields, 0)
        walk(category['sha'], prefix, {root_oid, advisory_rows[0]['sha']}, totals)
        per_root[prefix] = totals
    if used != captured_oids or not captured_oids <= reachable_objects:
        refuse()
    roster.sort(key=lambda row: row['path'].encode('utf-8'))
    totals = {key: sum(value[key] for value in per_root.values()) for key in fields}
    totals['maxDeclaredBlobBytes'] = max(value['maxDeclaredBlobBytes'] for value in per_root.values())
    if any(not integer(value) for value in totals.values()):
        refuse()
    result = dict(format='official-advisory-git-roster-metadata-component-v1', repository=REPOSITORY,
                  commitOID=expected_commit, rawCommitSHA256=digest(raw_commit), rootTreeOID=root_oid,
                  captures=sorted(captured, key=lambda cap: cap['requestPath']), manifest=roster,
                  manifestSHA256=digest(canonical(roster)), perRoot=per_root, totals=totals,
                  metadataTopologyCompleteWithinTwoRoots=True,
                  sizeBasis='API-declared; not authenticated by Git tree hash or blob content',
                  capacityComparison=dict(basis='declared metadata only; not blob/disk admission',
                                          originalFullFilesCap=100000, originalFullBytesCap=1 << 30,
                                          originalPerBlobCap=1 << 20, originalNpmBytesCap=512 << 20,
                                          declaredFullFilesWithinCap=totals['allRegularFiles'] <= 100000,
                                          declaredFullBytesWithinCap=totals['declaredBytes'] <= 1 << 30,
                                          declaredPerBlobWithinCap=totals['maxDeclaredBlobBytes'] <= 1 << 20,
                                          npmBytesWithinCap=None),
                  scope='Selected Git topology and JSON candidate metadata only; no OSV parsing, blob content, freshness or official origin verification.')
    result.update(dict.fromkeys(NONPROOF_FLAGS, False))
    if len(canonical(result)) > BOUNDS['evidence']:
        refuse()
    return result


def metadata(value):
    return tuple(getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def safe_path(value):
    if not isinstance(value, str) or '\0' in value or not os.path.isabs(value) or os.path.normpath(value) != value:
        refuse()
    if len(os.fsencode(value)) > 4096:
        refuse()
    return Path(value)


def read_bound(value, cap):
    path = safe_path(value)
    if path.resolve(strict=True) != path:
        refuse()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or not 0 < before.st_size <= cap or metadata(before) != metadata(path.lstat()):
            refuse()
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, cap - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                refuse()
            chunks.append(chunk)
        if metadata(before) != metadata(os.fstat(fd)) or metadata(before) != metadata(path.lstat()) or path.resolve(strict=True) != path:
            refuse()
        return b''.join(chunks), metadata(before)
    finally:
        os.close(fd)


def directory_identity(value):
    return tuple(getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def parent_chain(parent):
    if parent.resolve(strict=True) != parent:
        refuse()
    chain = []
    for directory in (parent, *parent.parents):
        value = directory.lstat()
        if not stat.S_ISDIR(value.st_mode):
            refuse()
        chain.append((str(directory), directory_identity(value)))
    return chain


def verify_parent(parent, parent_fd, expected_chain):
    if parent_chain(parent) != expected_chain or directory_identity(os.fstat(parent_fd)) != expected_chain[0][1]:
        refuse()


def run_offline(manifest_path, output_path):
    output = safe_path(output_path)
    # Retain the selected directory before parsing or verifying caller inputs.
    # Every publication/cleanup operation stays relative to this descriptor.
    chain = parent_chain(output.parent)
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        verify_parent(output.parent, parent_fd, chain)
        return _run_offline(manifest_path, output, parent_fd, chain)
    finally:
        os.close(parent_fd)


def _run_offline(manifest_path, output, parent_fd, chain):
    manifest_raw, manifest_meta = read_bound(manifest_path, 1 << 20)
    value = exact_json(manifest_raw)
    if (not shape(value, ('format', 'repository', 'expectedCommit', 'rawCommit', 'captures'))
            or value['format'] != 'official-advisory-git-tree-captures-v1' or value['repository'] != REPOSITORY
            or not shape(value['rawCommit'], ('path', 'sha256')) or not isinstance(value['captures'], list)
            or not 0 < len(value['captures']) <= BOUNDS['requests']):
        refuse()
    pins = {manifest_path: (digest(manifest_raw), manifest_meta, 1 << 20)}

    def source(spec, cap):
        if not isinstance(spec['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', spec['sha256']) or spec['path'] in pins:
            refuse()
        raw, meta = read_bound(spec['path'], cap)
        if digest(raw) != spec['sha256']:
            refuse()
        pins[spec['path']] = (digest(raw), meta, cap)
        return raw

    raw_commit = source(value['rawCommit'], BOUNDS['commit'])
    captures, charged = [], 0
    for spec in value['captures']:
        if not shape(spec, ('requestPath', 'path', 'sha256')):
            refuse()
        remaining = BOUNDS['aggregate'] - charged
        if remaining <= 0:
            refuse()
        raw = source(spec, min(BOUNDS['response'], remaining))
        charged += len(raw)
        captures.append(dict(request_path=spec['requestPath'], raw_body=raw))
    if str(output) in pins:
        refuse()
    result = verify_git_tree_roster(value['expectedCommit'], raw_commit, captures)
    result['captureManifestSHA256'] = digest(manifest_raw)
    raw = canonical(result) + b'\n'
    if len(raw) > BOUNDS['evidence']:
        refuse()
    for file, (expected_hash, expected_meta, cap) in pins.items():
        reread, current_meta = read_bound(file, cap)
        if current_meta != expected_meta or digest(reread) != expected_hash:
            refuse()
    verify_parent(output.parent, parent_fd, chain)
    fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    created = os.fstat(fd)
    try:
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    refuse()
                offset += written
            os.fsync(fd)
            for file, (expected_hash, expected_meta, cap) in pins.items():
                reread, current_meta = read_bound(file, cap)
                if current_meta != expected_meta or digest(reread) != expected_hash:
                    refuse()
            published = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != (created.st_dev, created.st_ino) or published.st_nlink != 1 or published.st_size != len(raw):
                refuse()
            verify_parent(output.parent, parent_fd, chain)
            os.fsync(parent_fd)
            verify_parent(output.parent, parent_fd, chain)
        except BaseException:
            # Remove only the file this invocation created. Never remove a
            # pre-existing/replaced caller file or leave a success-shaped result.
            try:
                published = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
                if (published.st_dev, published.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(output.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(fd)
    return dict(outputSHA256=digest(raw), bytes=len(raw), releaseAccepted=False)


def main():
    try:
        argv = sys.argv[1:]
        if len(argv) != 4 or set(argv[::2]) != {'--capture-manifest', '--output'}:
            refuse()
        args = dict(zip(argv[::2], argv[1::2]))
        result = run_offline(args['--capture-manifest'], args['--output'])
        sys.stdout.write(json.dumps(result, sort_keys=True) + '\n')
        return 0
    except BaseException:
        sys.stderr.write('official advisory roster component refused\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
