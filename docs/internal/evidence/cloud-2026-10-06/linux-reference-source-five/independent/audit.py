from pathlib import Path
import hashlib,json,re
R=Path('/workspace/zasp-sec'); P=Path('/workspace/.zasp-cloud-owned/linux-successor-source-tdd'); A=P/'linux-source-assembly-7egctdb2'; O=Path('/tmp/zasp-cloud-evidence/linux-successor-independent-review-kPMJEiIG');checks=[]
def h(b):return hashlib.sha256(b).hexdigest()
def check(n,b):
 checks.append({'check':n,'passed':bool(b)})
 if not b:raise Exception(n)
receipt=json.loads((P/'linux-successor-source-only-receipt.json').read_text());summary=json.loads((A/'summary.json').read_text());tools=R/'services/platform/migrations/tools'
check('receipt hash',h((P/'linux-successor-source-only-receipt.json').read_bytes())=='d34f8d0707fb188824f0affde590f34b7452326219470188b505a04f0ec5f2f7')
check('summary hash',h((A/'summary.json').read_bytes())==receipt['summarySHA256'])
for name,digest in receipt['sourceFiles'].items():
 check('shared exact source '+name,h((tools/name).read_bytes())==digest)
 check('private assembly exact source '+name,h((A/'source/services/platform/migrations/tools'/name).read_bytes())==digest)
for record in summary['records']:
 check(record['label']+' actual log and record',record['exit']==0 and record['directProcessJoined'] and not record['timedOut'] and h((A/(record['label']+'.log')).read_bytes())==record['logSHA256'] and json.loads((A/(record['label']+'-record.json')).read_text())==record)
p=json.loads((tools/'ordered-current-linux-provenance-v1.json').read_text());wpath=Path('/tmp/zasp-cloud-evidence/runtime-continuation/pg-build-identity-plan/independent-actual-outcome-c1ab.json');w=json.loads(wpath.read_text());capture=Path(w['actualRootDirectory']);s=json.loads((capture/'summary.json').read_text())
check('independent witness hash',h(wpath.read_bytes())==p['evidence']['independentReviewSHA256'])
for name,key in [('summary.json','summarySHA256'),('actual-build-identity.json','identitySHA256'),('root-execution-receipt.json','rootExecutionReceiptSHA256')]:check('actual capture '+name,h((capture/name).read_bytes())==p['evidence'][key])
check('identity raw literal exact original bytes',(capture/'actual-build-identity.json').read_bytes()==p['identityRawUTF8'].encode())
check('actual identity semantic',json.loads(p['identityRawUTF8'])==p['identity']==w['actualIdentity'])
check('runtime descriptor all60 exact witnessed bindings',p['runtimeFiles']=={x['path']:x['sha256'] for x in w['actualPostbinding']} and len(p['runtimeFiles'])==60)
check('binding and static review from original summary',s['binding_sha256']==p['evidence']['runtimeBindingSHA256'] and s['static_review_sha256']==p['evidence']['runtimeStaticReviewSHA256'])
check('actual cleanup',s['normal_pg_ctl_stop'] and s['foreground_wait_exit']==0 and s['unix_endpoint_clear'] and s['postmaster_pidfile_clear'] and w['checks']['actualCurrentSurvivors']==[])
root=A/'source/services/platform/migrations/ordered_current';nroot=root/'linux-successor-v1'
for name,digest in summary['baselineEightPins'].items():check('baseline output '+name,h((root/name).read_bytes())==digest)
for name,pin in summary['newEight'].items():check('new output '+name,len((nroot/name).read_bytes())==pin['bytes'] and h((nroot/name).read_bytes())==pin['sha256'])
b=json.loads((root/'development-manifest.json').read_text());n=json.loads((nroot/'development-manifest.json').read_text());key=lambda f:(f['kind'],f['identity']);bm={key(f):f for f in b['facts']};nm={key(f):f for f in n['facts']};changes=[k for k in bm if bm[k]!=nm[k]]
check('actual10052 facts exact10051 functional unchanged',len(bm)==len(nm)==10052 and bm.keys()==nm.keys() and changes==[('build','provenance')])
check('noninstallable manifests no entries',not b['installable'] and not n['installable'] and b['entries']==n['entries']==[])
bmtext=(root/'development-module.sql').read_text();nmtext=(nroot/'development-module.sql').read_text();bl=bmtext.splitlines(keepends=True);nl=nmtext.splitlines(keepends=True);differ=[i for i,(x,y) in enumerate(zip(bl,nl)) if x!=y]
check('emitted actual module only2lines',len(bl)==len(nl) and len(differ)==2)
check('two approved lines',any("('build','provenance'" in bl[i] for i in differ) and any('INSERT INTO zasp_authorization80_ordered_current.registration' in bl[i] for i in differ))
index=bmtext.index('INSERT INTO zasp_authorization80_ordered_current.registration');prefix=bmtext[:index]
check('actual common installation prefix exact359244',prefix==nmtext[:index] and len(prefix.encode())==359244 and h(prefix.encode())=='fcfdb9af45e0c00f72a0ecbc4ec2457d8527d977a6b59dcd74213e87891e42ea')
check('eight private functions unchanged',len(re.findall(r'^CREATE FUNCTION ',prefix,re.M))==8)
guard="IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;";check('exact version guard preserved',guard in bmtext and guard in nmtext)
d=json.loads((A/'full-source-delta.log').read_text());check('complete delta original hash',h((A/'full-source-delta.log').read_bytes())==receipt['completeDeltaSHA256'])
check('exact fact ledger correspondence',d['changed'][0]['before']==bm[changes[0]]['fact'] and d['changed'][0]['after']==nm[changes[0]]['fact'] and not d['added'] and not d['removed'])
check('all589/6348 source programs',len(d['programs'])==589 and len({x['id'] for x in d['programs']})==589 and sum(len(x['steps']) for x in d['programs'])==6348)
check('manifest-only539 steps/520controls',sum(s['beforeSQLSHA256']!=s['proposedSQLSHA256'] for c in d['programs'] for s in c['steps'])==539 and sum(any(s['beforeSQLSHA256']!=s['proposedSQLSHA256'] for s in c['steps']) for c in d['programs'])==520 and all(span['kind']=='manifest-payload' for c in d['programs'] for s in c['steps'] for span in s['literalSpans']))
check('retained4MiB and38240 caps',d['limits']['maxRows']==38240 and all(next(x for x in d['phases'] if x['id']=='forged-entry')['limits'][k]==v for k,v in {'maxRows':2048,'maxBytes':4194304}.items()))
scan=P/'source-five-scan-kykgb7ym';sr=json.loads((scan/'record.json').read_text());findings=json.loads((scan/'report.json').read_text());cl=json.loads((scan/'public-digest-classification.json').read_text())
check('actual scannerFAIL2 unchanged',sr['exit']==1 and sr['findingCount']==len(findings)==2 and h((scan/'record.json').read_bytes())=='8f7bd10df7c6c70b6d73195cc6c5152555964e6d6c34869a601ab0bfc187b682')
check('classification hash',h((scan/'public-digest-classification.json').read_bytes())=='c084905c53d87c365dcaa042204454cc86291f3d66f023a7602758c9af1dfec6')
check('exact scan source5',{f.name:h(f.read_bytes()) for f in (scan/'source').iterdir()}==receipt['sourceFiles'])
for f,c in zip(sorted(findings,key=lambda x:x['StartLine']),cl['findings']):
 check('exact redacted finding '+str(c['line']),Path(f['File']).name==c['file'] and f['StartLine']==c['line'] and f['RuleID']==c['rule'] and h(f['Secret'].encode())==c['literalSHA256'])
 for path in c['actualRehashedPaths']:check('actual public binary digest '+path,h(Path(path).read_bytes())==f['Secret']==p['runtimeFiles'][path])
log=(O/'source9.log').read_text();check('independent source9 actualPASS', '# tests 9' in log and '# pass 9' in log and '# fail 0' in log and '# skipped 0' in log)
report={'status':'PASS-BOUNDED-INDEPENDENT-LINUX-SUCCESSOR-SOURCE-ONLY','scope':'Exact five source files, author source output/delta/witness evidence, independent pinned Node9 tests; no runtime admission/PG/Go/native execution','sourceSHA256':receipt['sourceFiles'],'checks':checks,'checkCount':len(checks),'independentTests':{'exit':0,'tests':9,'pass':9,'fail':0,'skip':0,'duration_ms':float(re.search(r'# duration_ms ([\d.]+)',log).group(1)),'log':str(O/'source9.log'),'logSHA256':h((O/'source9.log').read_bytes())},'security':{'originalScanExit':1,'originalFindings':2,'classification':'Both exact computed public runtime binary digests independently verified against actual file bytes','unknown':0,'exceptionsAdded':0,'scannerClearance':False},'limits':['No observed SQL/native execution from this source batch','539 steps/520controls are exact manifest literal source proposals, not complete successor runtime compilation','Full separately versioned packet must recompile all metadata/preimages/control structures','No RR/frame/capacity/installed/production/deployed acceptance','Authentic historical failures and Darwin/reference originals preserved; full/source guard clearance not inferred'],'issues':[]}
(O/'review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(O/'review.json'),'sha256':h((O/'review.json').read_bytes()),'checks':len(checks)}))
