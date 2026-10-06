import pathlib,json,hashlib,tempfile,subprocess,os,time,signal
base=pathlib.Path('/workspace/.zasp-cloud-owned/linux-successor-source-tdd');repo=pathlib.Path('/workspace/zasp-sec');f=pathlib.Path('/workspace/.zasp-cloud-owned/native379-v2-combined-foundation-vg_j3yv2');node=f/'module-cache/owned-tools/node/bin/node';assert hashlib.sha256(node.read_bytes()).hexdigest()=='93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068'
private=pathlib.Path(tempfile.mkdtemp(prefix='linux-source-assembly-',dir=base));source=private/'source';source.mkdir();(private/'tmp').mkdir(mode=0o700)
envelope=json.loads((f/'outputs/frozen-source-preparation/native379-v2-envelope-candidate.json').read_text());print('envelope keys',list(envelope),flush=True)
# Fixed reviewed v2 source union, exact original regular source bytes plus ONLY the five author-owned files.
index=json.loads((repo/'services/platform/migrations/tools/ordered-current-native379-packet-v2-artifacts/source-inputs.json').read_text());files=index['files']
for rel,pin in files.items():
 p=repo/rel;raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==pin;dest=source/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
# Nine source-only envelope additions are the exact independently bound packet/module companion files.
extra=envelope.get('node_inputs',envelope.get('NodeInputs',{}));print('extra type',type(extra).__name__,flush=True)
if isinstance(extra,list):extra={x.get('path',x.get('Path')):x.get('sha256',x.get('SHA256')) for x in extra}
for rel,pin in extra.items():
 if rel in files:continue
 p=repo/rel;raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==pin;dest=source/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
new=['build-ordered-current-linux-successor-v1.mjs','ordered-current-linux-provenance-v1.mjs','ordered-current-linux-provenance-v1.json','build-ordered-current-linux-successor-v1.test.mjs','ordered-current-linux-provenance-v1.test.mjs'];prefix='services/platform/migrations/tools/'
for name in new:
 raw=(repo/prefix/name).read_bytes();(source/prefix/name).write_bytes(raw)
newsha={name:hashlib.sha256((repo/prefix/name).read_bytes()).hexdigest() for name in new};env={'PATH':str(node.parent)+':/usr/bin:/bin','TMPDIR':str(private/'tmp'),'LANG':'C','TZ':'UTC'};records=[]
def run(label,args,cap=90):
 start=time.monotonic();p=subprocess.Popen([str(node),*args],cwd=source,env=env,start_new_session=True,stdout=(private/(label+'.log')).open('wb'),stderr=subprocess.STDOUT)
 try:code=p.wait(timeout=cap);timed=False
 except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);code=p.wait(timeout=15);timed=True
 record={'label':label,'argv':[str(node),*args],'cwd':str(source),'environment':env,'exit':code,'timedOut':timed,'directProcessJoined':True,'seconds':time.monotonic()-start,'logSHA256':hashlib.sha256((private/(label+'.log')).read_bytes()).hexdigest()};records.append(record);(private/(label+'-record.json')).write_text(json.dumps(record,indent=2)+'\n');assert code==0 and not timed
run('baseline-eight',[prefix+'build-ordered-current-development.mjs','--write'])
oldpath=source/'services/platform/migrations/ordered_current';before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in oldpath.iterdir() if p.is_file()};identities=json.loads((repo/prefix/'ordered-current-native379-packet-v2-artifacts/generated-identities.json').read_text());assert all(before[n]==pin for n,pin in identities['outputPins'].items())
run('successor-eight',[prefix+'build-ordered-current-linux-successor-v1.mjs','--write']);successor=oldpath/'linux-successor-v1';generated={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in successor.iterdir()};assert len(generated)==8
run('successor-check',[prefix+'build-ordered-current-linux-successor-v1.mjs','--check']);run('successor-repeat',[prefix+'build-ordered-current-linux-successor-v1.mjs','--write']);assert generated=={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in successor.iterdir()};assert all(hashlib.sha256((oldpath/name).read_bytes()).hexdigest()==pin for name,pin in before.items())
run('source-group',['--test',prefix+'ordered-current-linux-provenance-v1.test.mjs',prefix+'build-ordered-current-linux-successor-v1.test.mjs'],120)
run('full-source-delta',['--input-type=module','-e',"import {analyzeOrderedCurrentLinuxSuccessorV1} from './"+prefix+"build-ordered-current-linux-successor-v1.mjs'; console.log(JSON.stringify(analyzeOrderedCurrentLinuxSuccessorV1()));"],120)
assert all(hashlib.sha256((repo/prefix/name).read_bytes()).hexdigest()==pin for name,pin in newsha.items())
summary={'scope':'SOURCE-ONLY; no PG/native/control SQL/runtime packet admission','newSourceSHA256':newsha,'baselineEightPins':identities['outputPins'],'newEight':generated,'baselineSharedSourceInputs':len(files),'sourceEnvelopeUnion':len(set(files)|set(extra)),'oldPrivateEightUnmodifiedBySuccessor':True,'generatedCheckRepeatExact':True,'records':records,'pending':'Independent source/delta review; separately compiled successor runtime packet, frozen full envelope and root native launch remain required.'};(private/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
for p in private.iterdir():
 if p.is_file():p.chmod(0o400)
(base/'latest-source-assembly.json').write_text(json.dumps({'private':str(private),'summarySHA256':hashlib.sha256((private/'summary.json').read_bytes()).hexdigest()},indent=2)+'\n');print(private,flush=True)
