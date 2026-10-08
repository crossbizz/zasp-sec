"""Synthetic protocol controls only. No network or authority fixtures."""
import copy
import json
import unittest
from cursor_component import collect, endpoint, next_endpoint, exact_json, Refused, LIMITS


def row(kind, suffix='2345', withdrawn=None):
    return dict(ghsa_id='GHSA-2345-6789-'+suffix, type=kind,
                withdrawn_at=withdrawn,
                vulnerabilities=[dict(package=dict(ecosystem='npm', name='public-fixture'),
                                      vulnerable_version_range='<= 1.0.0')])


def page(rows, link=None):
    raw=json.dumps(rows,separators=(',', ':')).encode()
    headers=[('Content-Type','application/json')]
    if link is not None:headers.append(('Link',link))
    return 200,headers,raw,len(raw)+1024


def baseline():
    # Withdrawals remain in the normal stream, matching actual observed API
    # behavior. No synthesized mutually-exclusive withdrawal partition.
    return {endpoint('reviewed'):page([row('reviewed')]),
            endpoint('unreviewed'):page([row('unreviewed','cfgh','2021-10-01T22:04:28Z')]),
            endpoint('malware'):page([row('malware','jmpq')])}


def run(pages, guard=lambda:None):
    calls=[]
    def acquire(target, allowance):
        calls.append(target)
        return pages[target]
    return collect(acquire,guard),calls


class Controls(unittest.TestCase):
    def test_complete_three_types_preserves_withdrawn_and_scope(self):
        result,calls=run(baseline())
        self.assertEqual(calls,[endpoint(k) for k in ('reviewed','unreviewed','malware')])
        self.assertEqual(len(result['rows']),3)
        self.assertTrue(result['apiTraversalComplete'])
        for key in ('immutableSnapshot','authenticatedUpstream','osvTranslation','vulnerabilityMatching','releaseAccepted'):
            self.assertFalse(result[key])

    def test_cursor_chain_requires_terminal_and_hashes_all_pages(self):
        pages=baseline()
        following=endpoint('reviewed','cursor1')
        pages[endpoint('reviewed')]=page([row('reviewed')],'<https://api.github.com'+following+'>; rel="next"')
        pages[following]=page([row('reviewed','rvwx')])
        result,calls=run(pages)
        self.assertEqual(len(result['rows']),4)
        self.assertEqual(calls[:2],[endpoint('reviewed'),following])
        self.assertEqual(result['pages'][0]['nextEndpoint'],following)
        self.assertEqual(result['streams'][0]['rows'],2)

    def test_next_url_boundary_refusals(self):
        valid='https://api.github.com'+endpoint('reviewed','cursor1')
        changes=[valid.replace('api.github.com','foreign.invalid'),
                 valid.replace('ecosystem=npm','ecosystem=Go'),
                 valid+'&affects=private-package',valid+'&after=duplicate',
                 valid.replace('https:','http:'),valid+'#fragment',
                 valid.replace('/advisories?','/foreign?')]
        for changed in changes:
            with self.subTest(changed=changed),self.assertRaises(Refused):
                next_endpoint('<'+changed+'>; rel="next"','reviewed')

    def test_missing_type_duplicate_id_and_npm_filter_refused(self):
        for mode in ('wrong-type','duplicate-id','no-npm','missing-malware'):
            with self.subTest(mode=mode):
                pages=baseline()
                if mode=='wrong-type':pages[endpoint('reviewed')]=page([row('malware')])
                elif mode=='duplicate-id':pages[endpoint('malware')]=page([row('malware')])
                elif mode=='no-npm':
                    x=row('reviewed');x['vulnerabilities'][0]['package']['ecosystem']='Go'
                    pages[endpoint('reviewed')]=page([x])
                else:del pages[endpoint('malware')]
                # Missing-page callback raises KeyError; both outcomes refuse
                # completion. This fixture does not pretend to be API 404.
                with self.assertRaises((Refused,KeyError)):run(pages)

    def test_exact_json_grammar(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":"\xff"}',b'[] trailing',b'[NaN]',b'['*65+b']'*65):
            with self.subTest(raw=raw),self.assertRaises(Refused):exact_json(raw)

    def test_status_link_and_response_bounds(self):
        original=baseline()
        variants=[]
        p=copy.deepcopy(original);p[endpoint('reviewed')]=(403,[],b'[]',1024);variants.append(p)
        p=copy.deepcopy(original);p[endpoint('reviewed')]=(200,[('Content-Type','text/html')],b'[]',1024);variants.append(p)
        p=copy.deepcopy(original);p[endpoint('reviewed')]=(200,[('Content-Type','application/json')],b'[]',LIMITS['response']+1);variants.append(p)
        p=copy.deepcopy(original);p[endpoint('reviewed')]=page([], '<https://api.github.com'+endpoint('reviewed','cursor1')+'>; rel="next"');variants.append(p)
        p=copy.deepcopy(original);p[endpoint('reviewed')]=page([row('reviewed')]*101);variants.append(p)
        for p in variants:
            with self.subTest(page=p[endpoint('reviewed')]),self.assertRaises(Refused):run(p)

    def test_aggregate_reserved_before_parse_and_repeat_cursor_refused(self):
        old=LIMITS['aggregate']
        try:
            LIMITS['aggregate']=10
            with self.assertRaises(Refused):run(baseline())
        finally:LIMITS['aggregate']=old
        pages=baseline();following=endpoint('reviewed','repeat')
        link='<https://api.github.com'+following+'>; rel="next"'
        pages[endpoint('reviewed')]=page([row('reviewed')],link)
        pages[following]=page([row('reviewed','rvwx')],link)
        with self.assertRaises(Refused):run(pages)

    def test_cancellation_before_acquisition(self):
        acquired=[]
        def guard():raise Refused('public npm cursor component refused')
        with self.assertRaises(Refused):collect(lambda *args:acquired.append(args),guard)
        self.assertEqual(acquired,[])


if __name__=='__main__':unittest.main()
