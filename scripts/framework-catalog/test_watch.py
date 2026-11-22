import base64
import json
import unittest
from urllib.parse import quote
from catalog import LOCKS
from watch import review, scan, release_parts

SAME='a'*40
NEW='b'*40
class FakeGitHub:
    def __init__(self,items):
        self.items=items
    def get(self,repo,path):
        return self.items[path]

def file(sha, data=b''):
    return {'type':'file','sha':sha,'encoding':'base64','size':len(data),'content':base64.b64encode(data).decode()}

class UpstreamReviewTests(unittest.TestCase):
    def setUp(self):
        self.locks=json.loads(LOCKS.read_text())
    def test_new_enterprise_tag_and_individual_control_diff(self):
        lock=next(x for x in self.locks if x['framework']=='mitre_attack_enterprise')
        repo,pin,p=release_parts(lock)
        old=file(SAME)
        newer={'objects':[{'type':'attack-pattern','name':'Changed heading','id':'attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830','external_references':[{'source_name':'mitre-attack','external_id':'T1059'}]}]}
        data={'/contents/'+p+'?ref='+pin:old, '/contents/'+p+'?ref=master':old, '/tags?per_page=100':[{'name':'ATT&CK-v20.1','commit':{'sha':NEW}}],
              '/git/ref/tags/'+quote('ATT&CK-v19.1',safe=''):{'object':{'type':'tag','sha':SAME}},
              '/git/tags/'+SAME:{'object':{'type':'commit','sha':pin}},
              '/contents/'+p+'?ref='+NEW:file(NEW,json.dumps(newer).encode())}
        result=review(lock,FakeGitHub(data))
        self.assertEqual(result['status'],'review_required')
        self.assertEqual(result['changes'][0]['control_changes'][0]['change'],'renamed')
        self.assertEqual(result['changes'][0]['edition'],'20.1')
        data['/git/tags/'+SAME]={'object':{'type':'commit','sha':NEW}}
        self.assertIn('pinned_tag_moved',[e['change'] for e in review(lock,FakeGitHub(data))['changes']])
    def test_owasp_draft_directories_do_not_claim_publication(self):
        lock=next(x for x in self.locks if x['framework']=='owasp_agentic_top10')
        repo,pin,p=release_parts(lock)
        endpoint='/contents/corpus/agentic-top10?ref=main'
        items={'/contents/'+p+'?ref='+pin:file(SAME),'/contents/'+p+'?ref=main':file(SAME),endpoint:[{'type':'dir','name':'2028-draft'}]}
        self.assertEqual(review(lock,FakeGitHub(items))['status'],'unchanged')
        items[endpoint].append({'type':'dir','name':'2027-final'})
        items['/contents/'+p+'?ref=main']=None
        self.assertEqual([e['change'] for e in review(lock,FakeGitHub(items))['changes']],['pinned_path_removed','final_edition_directory_added'])
    def test_lost_access_is_explicit_and_never_rewrites_locks(self):
        before=LOCKS.read_bytes()
        self.assertTrue(all(x['status']=='unavailable' for x in scan(self.locks,FakeGitHub({}))))
        self.assertEqual(LOCKS.read_bytes(),before)
