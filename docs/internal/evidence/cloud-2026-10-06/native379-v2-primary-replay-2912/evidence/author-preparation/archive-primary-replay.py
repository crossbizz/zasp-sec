import pathlib,json,hashlib,gzip,subprocess,tempfile,os,shutil,tarfile
P=pathlib.Path;r=P(__file__).parent;s=r/'source';t=s/'services/platform/migrations/tools';out=P(tempfile.mkdtemp(prefix='candidate-a6e8-',dir=r));out.chmod(0o700);node=P('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r/module-cache/owned-tools/node/bin/node');h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();assert h(node)=='93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068'
raw=out/'canonical-wire.json'
with raw.open('xb') as f:subprocess.run(['/usr/bin/timeout','-k','5s','180s',str(node),str(t/'ordered-current-native379-packet-v2.mjs'),'--json'],cwd=s,env={'PATH':str(node.parent)+':/usr/bin:/bin','LANG':'C','TZ':'UTC','TMPDIR':str(r/'tmp')},stdout=f,stderr=subprocess.DEVNULL,check=True)
data=raw.read_bytes();packet=json.loads(data);oldfile=P('/workspace/.zasp-cloud-owned/native379-v2-safe-diagnostic-3mutfah8/candidate-6d02-dp9pgin8/canonical-wire.json');assert h(oldfile)=='5d18ca5f38c6f86c7cccda46fde1fb43008f6491b3c2a8319515592f7279a25a';old=json.loads(oldfile.read_bytes());assert set(packet)==set(old);same={k:packet[k]==old[k] for k in packet if k!='authority'};assert all(same.values())
gz=out/'canonical-wire.json.gz'
with gz.open('xb') as f:
 with gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as z:z.write(data)
assert gzip.decompress(gz.read_bytes())==data
sources=[t/'ordered-current-native379-packet-v2.mjs',t/'ordered-current-native379-packet-v2.test.mjs',t/'ordered-current-native379-source-schema-v2.mjs',t/'ordered-current-native379-source-schema-v2.test.mjs',*(t/'ordered-current-native379-packet-v2-artifacts').glob('*.json'),s/'services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go'];roster={}
for p in sources:shutil.copyfile(p,out/p.name);roster[str(p.relative_to(s))]=h(p)
base={}
with tarfile.open(r/'baseline.tar') as tar:
 for member in tar:
  if member.isfile():base[member.name]=hashlib.sha256(tar.extractfile(member).read()).hexdigest()
now={str(p.relative_to(s)):h(p) for p in s.rglob('*') if p.is_file()};assert set(base)==set(now);delta=[{'path':p,'baselineGitBlobSHA256':base[p],'privateSHA256':now[p]} for p in sorted(base) if base[p]!=now[p]];assert len(delta)==4
companion=s/'services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go';assert h(companion)=='468734a003d41cad8ce4a5ffe31963ba37f49838ae8c5f5744c5ce6d5638850a';assert roster[str(sources[-1].relative_to(s))]=='a6e8befd933d9b02c0b513f7e982f6a7f3f9b7ce9b969122111d4fbff9be1cb2'
for name,value in [('source-sha256.json',roster),('private-source-delta.json',{'baselineCommit':'512beb183a0f7994f8769fc6765e3e1b80af4523','baselineSourceFiles':len(base),'privateSourceFiles':len(now),'changedPaths':delta,'packetNonAuthorityExactEqualityToReviewed5d18':same,'historicalEmbeddedOutputsRewritten':False,'companionUnchangedSHA256':h(companion)})]: (out/name).write_text(json.dumps(value,indent=2)+'\n')
summary={'directory':str(out),'wireSHA256':h(raw),'wireBytes':len(data),'gzipSHA256':h(gz),'gzipBytes':gz.stat().st_size,'sourceManifestSHA256':packet['authority']['sourceInventorySHA256'],'rules':len(packet['rules']),'facts':len(packet['expectedFacts']),'sites':len(packet['sourceInventory']['sites']),'controls':len(packet['controls']),'steps':sum(len(c['program']['steps']) for c in packet['controls']),'allNonAuthorityFieldsExact5d18':True,'actualSourceFiles':len(now),'actualChangedPaths':len(delta),'scope':'PRIVATE-SOURCE-ONLY-PRIMARY-FALSE-REPLAY-DIAGNOSTIC; noPG/native; stalecompanion notnew executionauthorization'}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
for p in out.iterdir():p.chmod(0o400)
(r/'candidate-archive-path.txt').write_text(str(out)+'\n');print(json.dumps(summary))
