import json
import unittest

from catalog import build_release, changes, CATALOG, LOCKS


class ReleaseTests(unittest.TestCase):
    def test_locked_provenance_and_bad_input(self):
        for lock in json.loads(LOCKS.read_text()):
            data = json.loads((CATALOG / f"{lock['framework']}-{lock['edition']}.json").read_text())
            self.assertEqual({k: data[k] for k in lock}, lock)
            with self.assertRaisesRegex(ValueError, 'source bytes'):
                build_release(lock, b'substituted contents')

    def test_cross_edition_preserves_semantic_review(self):
        old, new = (json.loads((CATALOG / f'owasp_llm_top10-{year}.json').read_text()) for year in ['2025', '2026'])
        diff = changes(old, new)
        self.assertEqual([x['id'] for x in diff], [f'LLM{n:02d}' for n in range(3, 11)])
        self.assertTrue(all(x['change'] == 'reassignment_review' for x in diff))

    def test_stable_identity_distinguishes_removed_renamed_and_reassigned(self):
        def snapshot(rows):
            return {'framework': 'mitre_atlas', 'entries': rows}
        before = [dict(id=c, title=c, identity=c) for c in 'abcd']
        after = [dict(id='a', title='A', identity='a'), dict(id='b', title='B', identity='new'),
                 dict(id='d', title='d', identity='d', status='retired')]
        delta = changes(snapshot(before), snapshot(after))
        self.assertEqual([x['change'] for x in delta], ['renamed', 'reassigned', 'removed', 'removed'])
