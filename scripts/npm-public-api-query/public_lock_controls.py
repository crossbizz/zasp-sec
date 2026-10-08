"""No-network source controls; fake acquisitions carry no upstream authority."""
import base64
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import public_lock_adapter as adapter
from cursor_component import Refused


def fixture():
    lock=dict(lockfileVersion=3,packages={'':{},'node_modules/public-fixture':dict(version='1.0.0',resolved='https://registry.npmjs.org/public-fixture/-/public-fixture-1.0.0.tgz',integrity='sha512-'+base64.b64encode(bytes(64)).decode())})
    return json.dumps(lock,separators=(',',':')).encode()


def fake_rows(kind,identifier='GHSA-2345-6789-cfgh'):
    return [dict(ghsa_id=identifier,type=kind,vulnerabilities=[dict(package=dict(ecosystem='npm',name='public-fixture'),vulnerable_version_range='<= 1.0.0')])]


def http(rows,link=None):
    body=json.dumps(rows,separators=(',',':')).encode()
    headers=[('Content-Type','application/json')]
    if link:headers.append(('Link',link))
    return 200,headers,body,len(body)+1024


def scoped_fixture(callback):
    raw=fixture()
    with patch.object(adapter,'PUBLIC_LOCK_SHA256',hashlib.sha256(raw).hexdigest()):
        return adapter.collect_public_lock(raw,callback,lambda:None)


class Controls(unittest.TestCase):
    def test_actual_public_lock_whole_hash_and_complete_projection(self):
        raw=Path(os.environ['PUBLIC_NPM_LOCK_FOR_CONTROLS']).read_bytes()
        rows=adapter.public_inventory(raw);groups=adapter.groups_for(rows)
        self.assertEqual(len(rows),209);self.assertEqual(len(groups),19)
        wanted={r['name']+'@'+r['version'] for r in rows}
        self.assertEqual(set(sum(groups,[])),wanted);self.assertEqual(len(wanted),185)
        calls=[]
        def acquire(target,allowance):calls.append(target);return http([])
        result=adapter.collect_public_lock(raw,acquire,lambda:None)
        self.assertEqual(len(calls),57)
        for query in calls:
            p=parse_qs(urlsplit(query).query)
            self.assertEqual(p['ecosystem'],['npm']);self.assertNotIn('is_withdrawn',p)
            self.assertNotIn('severity',p)
        self.assertEqual({p['type'] for group in result['coverage'] for p in group['streams']},{'reviewed','unreviewed','malware'})
        self.assertTrue(result['allIssuedPublicLockQueriesTraversed'])
        self.assertFalse(result['releaseAccepted']);self.assertFalse(result['immutableSnapshot'])
        self.assertFalse(result['authenticatedUpstream'])

    def test_changed_or_private_lock_refused_before_any_acquisition(self):
        calls=[]
        with self.assertRaises(Refused):adapter.collect_public_lock(fixture(),lambda *a:calls.append(a),lambda:None)
        self.assertEqual(calls,[])

    def test_cursor_keeps_exact_public_group_binding(self):
        seen=[]
        def acquire(target,allowance):
            seen.append(target);q=parse_qs(urlsplit(target).query)
            if q['type']==['reviewed'] and 'after' not in q:
                return http(fake_rows('reviewed'),'<https://api.github.com'+target+'&after=cursor1>; rel="next"')
            return http([])
        result=scoped_fixture(acquire)
        self.assertEqual(len(seen),4)
        self.assertIn('affects=public-fixture%401.0.0',seen[1])
        self.assertIn('after=cursor1',seen[1]);self.assertEqual(len(result['upstreamMatchedObservations']),1)

    def test_raw_link_bound_before_normalization(self):
        valid='<https://api.github.com/advisories?ecosystem=npm&type=reviewed&per_page=100&sort=updated&direction=asc&after=x&affects=public-fixture%401.0.0>; rel="next"'
        with self.assertRaises(Refused):adapter.normalize_link(' '*20000+valid,'public-fixture@1.0.0')

    def test_swapped_missing_or_extra_group_in_next_link_refused(self):
        for link in ['https://api.github.com/advisories?ecosystem=npm&type=reviewed&per_page=100&sort=updated&direction=asc&after=x',
                     'https://api.github.com/advisories?ecosystem=npm&type=reviewed&per_page=100&sort=updated&direction=asc&after=x&affects=other%401.0.0',
                     'https://api.github.com/advisories?ecosystem=npm&type=reviewed&per_page=100&sort=updated&direction=asc&after=x&affects=public-fixture%401.0.0&affects=public-fixture%401.0.0']:
            with self.subTest(link=link),self.assertRaises(Refused):
                scoped_fixture(lambda *a:http(fake_rows('reviewed'),'<'+link+'>; rel="next"'))

    def test_global_request_and_byte_budgets_cannot_reset_per_group(self):
        for field,value in [('requests',2),('aggregate',1000)]:
            with self.subTest(field=field),patch.dict(adapter.LIMITS,{field:value}),self.assertRaises(Refused):
                scoped_fixture(lambda *a:http([]))

    def test_versions_and_nonregistry_link_are_closed(self):
        for v in ['01.0.0','1.0.0-01','1.0.0+','1.0','*','1.0.0-..x']:
            with self.subTest(version=v):self.assertFalse(adapter.canonical_version(v))
        self.assertTrue(adapter.canonical_version('1.2.3-beta.1+build'))
        for delta in [dict(link=True),dict(resolved='https://foreign.invalid/a.tgz'),dict(version='01.0.0')]:
            lock=json.loads(fixture());lock['packages']['node_modules/public-fixture'].update(delta)
            raw=json.dumps(lock,separators=(',',':')).encode()
            with self.subTest(delta=delta),patch.object(adapter,'PUBLIC_LOCK_SHA256',hashlib.sha256(raw).hexdigest()),self.assertRaises(Refused):adapter.public_inventory(raw)

    def test_cancellation_and_non200_cannot_complete(self):
        calls=[]
        def stop():raise Refused('public npm query adapter refused')
        raw=fixture()
        with patch.object(adapter,'PUBLIC_LOCK_SHA256',hashlib.sha256(raw).hexdigest()),self.assertRaises(Refused):adapter.collect_public_lock(raw,lambda *a:calls.append(a),stop)
        self.assertEqual(calls,[])
        with self.assertRaises(Refused):scoped_fixture(lambda *a:(403,[],b'[]',1024))


if __name__=='__main__':unittest.main()
