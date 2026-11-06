"""Explicit offline component controls; all Git objects here are synthetic."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import git_tree_roster_component as c


def git_oid(kind, body):
    return hashlib.sha1(kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body).hexdigest()


def fixture(extra_category=False, second_blob_size=None):
    objects = {}

    def tree(entries):
        entries = sorted(entries, key=lambda e: (e['path'] + ('/' if e['type'] == 'tree' else '')).encode())
        body = b''.join(e['mode'].lstrip('0').encode() + b' ' + e['path'].encode() + b'\0' + bytes.fromhex(e['sha']) for e in entries)
        oid = git_oid('tree', body)
        objects[oid] = entries
        return oid

    blob = dict(path='GHSA-2345-2345-2345.json', mode='100644', type='blob', sha=git_oid('blob', b'{}'), size=2)
    shared = tree([blob])
    reviewed = tree([dict(path='2026', mode='040000', type='tree', sha=shared)])
    unreviewed = shared if second_blob_size is None else tree([dict(blob, path='other.json', size=second_blob_size)])
    category_rows = [dict(path='github-reviewed', mode='040000', type='tree', sha=reviewed), dict(path='unreviewed', mode='040000', type='tree', sha=unreviewed)]
    if extra_category:
        category_rows.append(dict(path='unknown', mode='040000', type='tree', sha=shared))
    categories = tree(category_rows)
    root = tree([dict(path='advisories', mode='040000', type='tree', sha=categories)])
    raw_commit = f'tree {root}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nsynthetic fixture\n'.encode()

    def capture(oid, recursive=False):
        rows = []

        def walk(current, prefix=''):
            for row in objects[current]:
                entry = dict(row, path=prefix + row['path'], url=c.API + '/git/' + ('trees/' if row['type'] == 'tree' else 'blobs/') + row['sha'])
                rows.append(entry)
                if recursive and row['type'] == 'tree':
                    walk(row['sha'], entry['path'] + '/')
        walk(oid)
        return dict(request_path=c.ROUTE + oid + ('?recursive=1' if recursive else ''), raw_body=json.dumps(dict(sha=oid, url=c.API + '/git/trees/' + oid, tree=rows, truncated=False)).encode())

    direct = [capture(oid) for oid in objects]
    recursive = [capture(root), capture(categories), capture(reviewed, True), capture(unreviewed, True)]
    return git_oid('commit', raw_commit), raw_commit, direct, recursive


class RosterComponent(unittest.TestCase):
    def test_complete_direct_recursive_reused_dag_and_metadata_nonproof(self):
        commit, raw, direct, recursive = fixture()
        first = c.verify_git_tree_roster(commit, raw, direct)
        second = c.verify_git_tree_roster(commit, raw, recursive)
        self.assertEqual(first['manifest'], second['manifest'])
        self.assertEqual(first['totals']['jsonCandidateFiles'], 2)
        self.assertEqual(first['totals']['allRegularFiles'], 2)
        self.assertEqual(first['totals']['declaredBytes'], 4)
        self.assertEqual(first['totals']['directories'], 1)
        self.assertTrue(first['metadataTopologyCompleteWithinTwoRoots'])
        for key in c.NONPROOF_FLAGS:
            self.assertIs(first[key], False)
        changed = copy.deepcopy(direct)
        for capture in changed:
            value = json.loads(capture['raw_body'])
            for row in value['tree']:
                if row['type'] == 'blob':
                    row['size'] = 100
            capture['raw_body'] = json.dumps(value).encode()
        observed = c.verify_git_tree_roster(commit, raw, changed)
        self.assertEqual(first['rootTreeOID'], observed['rootTreeOID'])
        self.assertNotEqual(first['manifestSHA256'], observed['manifestSHA256'])
        self.assertEqual(observed['totals']['declaredBytes'], 200)
        self.assertEqual(observed['sizeBasis'], 'API-declared; not authenticated by Git tree hash or blob content')
        # Different tree objects may name the same blob, but size observations
        # for that blob cannot contradict one another within one transcript.
        same_commit, same_raw, same_captures, _ = fixture(second_blob_size=2)
        self.assertEqual(c.verify_git_tree_roster(same_commit, same_raw, same_captures)['totals']['declaredBytes'], 4)
        bad_commit, bad_raw, bad_captures, _ = fixture(second_blob_size=100)
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster(bad_commit, bad_raw, bad_captures)

    def test_closed_authority_topology_parser_and_bounds(self):
        commit, raw, direct, recursive = fixture()
        variants = []
        for change in [lambda d: d.update(truncated=True), lambda d: d.update(truncated=0), lambda d: d.update(sha='0' * 40), lambda d: d.update(extra=True), lambda d: d['tree'].append(d['tree'][0]), lambda d: d['tree'][0].update(path='../unsafe'), lambda d: d['tree'][0].update(mode='120000', type='blob', size=2), lambda d: d['tree'][0].update(size=True)]:
            altered = copy.deepcopy(direct)
            target = next(i for i, cap in enumerate(altered) if json.loads(cap['raw_body'])['tree'][0]['type'] == 'blob')
            value = json.loads(altered[target]['raw_body'])
            change(value)
            altered[target]['raw_body'] = json.dumps(value).encode()
            variants.append(altered)
        variants.extend([direct[:-1], direct + [direct[0]], direct + [recursive[2]], [dict(direct[0], request_path='/repos/attacker/db/git/trees/' + '0' * 40)] + direct[1:], [dict(direct[0], raw_body=b'{"sha":1,"sha":2}')] + direct[1:]])
        for captures in variants:
            with self.subTest(captures=variants.index(captures)), self.assertRaises(c.Refused):
                c.verify_git_tree_roster(commit, raw, captures)
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster('0' * 40, raw, direct)
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster(commit, raw + b'changed', direct)
        # Five unique API rows fit; reused-DAG traversal still spends eight
        # visits, and must refuse independently of the distinct-row budget.
        for field, value in [('expanded', 7), ('response', 1), ('aggregate', 1), ('requests', 1), ('members', 1), ('evidence', 1), ('commit', 1), ('path', 2), ('depth', 1)]:
            with self.subTest(bound=field), patch.dict(c.BOUNDS, {field: value}), self.assertRaises(c.Refused):
                c.verify_git_tree_roster(commit, raw, direct)

    def test_git_order_empty_tree_and_unknown_category_refusal(self):
        empty = git_oid('tree', b'')
        rows = [dict(path='foo.bar', mode='100644', type='blob', sha='1' * 40, size=1), dict(path='foo', mode='040000', type='tree', sha=empty)]
        ordered = sorted(rows, key=lambda r: (r['path'] + ('/' if r['type'] == 'tree' else '')).encode())
        body = b''.join(r['mode'].lstrip('0').encode() + b' ' + r['path'].encode() + b'\0' + bytes.fromhex(r['sha']) for r in ordered)
        self.assertEqual(c.verify_tree_rows(rows, git_oid('tree', body), True)[''], rows)
        commit, raw, direct, _ = fixture()
        # Tree rows are untrusted even when advisory-looking: no unknown root category can be omitted.
        with self.assertRaises(c.Refused):
            c.verify_tree_rows([dict(rows[0], path='x/absent-parent')], git_oid('tree', body), True)
        malformed = raw.replace(b'author ', b'tree ')
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster(git_oid('commit', malformed), malformed, direct)
        other_commit, other_raw, other_direct, _ = fixture(extra_category=True)
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster(other_commit, other_raw, other_direct)
        # A capture of an unreachable tree must not become "used" just because
        # its recursive rows also contain a reachable, reused subtree object.
        shared = json.loads(direct[0]['raw_body'])['sha']
        entry = dict(path='unused', mode='040000', type='tree', sha=shared,
                     url=c.API + '/git/trees/' + shared)
        body = b'40000 unused\0' + bytes.fromhex(shared)
        unreachable = git_oid('tree', body)
        nested_blob = dict(json.loads(direct[0]['raw_body'])['tree'][0])
        nested_blob['path'] = 'unused/' + nested_blob['path']
        capture = dict(request_path=c.ROUTE + unreachable + '?recursive=1', raw_body=json.dumps(dict(sha=unreachable, url=c.API + '/git/trees/' + unreachable, tree=[entry, nested_blob], truncated=False)).encode())
        with self.assertRaises(c.Refused):
            c.verify_git_tree_roster(commit, raw, direct + [capture])

    def test_actual_offline_entrypoint_create_only_and_safe_sources(self):
        commit, raw, captures, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            commit_file = directory / 'commit'
            commit_file.write_bytes(raw)
            rows = []
            for index, capture in enumerate(captures):
                file = directory / str(index)
                file.write_bytes(capture['raw_body'])
                rows.append(dict(requestPath=capture['request_path'], path=str(file), sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
            manifest = dict(format='official-advisory-git-tree-captures-v1', repository=c.REPOSITORY, expectedCommit=commit, rawCommit=dict(path=str(commit_file), sha256=hashlib.sha256(raw).hexdigest()), captures=rows)
            source = directory / 'input.json'
            source.write_text(json.dumps(manifest))
            output = directory / 'output.json'
            argv = [sys.executable, '-B', str(Path(c.__file__)), '--capture-manifest', str(source), '--output', str(output)]
            result = subprocess.run(argv, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            self.assertIs(json.loads(result.stdout)['releaseAccepted'], False)
            self.assertEqual(json.loads(output.read_bytes())['totals']['jsonCandidateFiles'], 2)
            before = output.read_bytes()
            self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=10).returncode, 0)
            self.assertEqual(output.read_bytes(), before)
            output.unlink()
            # Replace an ancestor after input acquisition/verification begins.
            # The pinned parent must refuse without writing into the redirect.
            original_verify = c.verify_git_tree_roster
            original_write = c.os.write
            for phase in ('verify', 'write'):
                parent = directory / ('ancestor-' + phase) / 'selected'
                parent.mkdir(parents=True)
                redirect = directory / ('redirect-' + phase)
                (redirect / 'selected').mkdir(parents=True)
                moved = directory / ('original-ancestor-' + phase)
                replaced = []

                def replace_parent():
                    if not replaced:
                        parent.parent.rename(moved)
                        parent.parent.symlink_to(redirect, target_is_directory=True)
                        replaced.append(True)

                def replace_during_verify(*args):
                    result = original_verify(*args)
                    replace_parent()
                    return result

                def replace_during_write(fd, data):
                    replace_parent()
                    return original_write(fd, data)

                target, method, callback = (c, 'verify_git_tree_roster', replace_during_verify) if phase == 'verify' else (c.os, 'write', replace_during_write)
                with self.subTest(parentReplacement=phase), patch.object(target, method, side_effect=callback), self.assertRaises(c.Refused):
                    c.run_offline(str(source), str(parent / 'result.json'))
                self.assertTrue(replaced)
                self.assertFalse((redirect / 'selected' / 'result.json').exists())
                self.assertFalse((moved / 'selected' / 'result.json').exists())
            commit_file.rename(directory / 'real-commit')
            commit_file.symlink_to(directory / 'real-commit')
            refused = subprocess.run(argv, capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b'')
            self.assertEqual(refused.stderr, b'official advisory roster component refused\n')
            self.assertFalse(output.exists())
            refused = subprocess.run(argv + ['--secret-value-that-must-not-be-logged'], capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stderr, b'official advisory roster component refused\n')


if __name__ == '__main__':
    unittest.main()
