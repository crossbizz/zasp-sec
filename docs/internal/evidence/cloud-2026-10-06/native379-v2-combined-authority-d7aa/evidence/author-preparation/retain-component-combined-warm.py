import pathlib,subprocess,os,json,hashlib,time
r=pathlib.Path(__file__).parent; f=pathlib.Path('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r'); out=r/'component-review-combined-warm';out.mkdir(mode=0o700)
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=r/'source/services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go'; assert h(source)=='2912b71c0189819c24250e585ac0090ba983547b36ef83ca58fb4c96ed9c31a0'
env={'HOME':'/home/agent','PATH':str(f/'go/bin')+':'+str(f/'module-cache/owned-tools/node/bin')+':/usr/bin:/bin','TMPDIR':str(r/'tmp'),'GOROOT':str(f/'go'),'GOMODCACHE':str(f/'module-cache'),'GOCACHE':str(r/'build-cache'),'GOTOOLCHAIN':'local','GOENV':'off','GOWORK':'off','GOPROXY':'off','GOSUMDB':'off','GOFLAGS':'-mod=readonly','CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','ZASP_NATIVE379_V2_REPLAY_SOURCE_MODULE':str(f/'module-cache/owned-source/services/platform/migrations/ordered_current/development-module.sql')}
bin=out/'apiserver-source-review.test';records=[]
for name,argv,cwd in [('compile',['/usr/bin/timeout','-k','5s','240s',str(f/'go/bin/go'),'test','-c','-mod=readonly','-o',str(bin),'./apiserver'],r/'source/services/platform'),('activation',['/usr/bin/timeout','-k','5s','240s',str(bin),'-test.run=^TestP7AuthorizationActivationPreparesRuntimePins$','-test.count=1','-test.v'],r/'source/services/platform/apiserver'),('full23',['/usr/bin/timeout','-k','5s','240s',str(bin),'-test.run=^TestNative379V2','-test.count=1','-test.v'],r/'source/services/platform/apiserver')]:
 log=out/(name+'.log'); start=time.time()
 with log.open('xb') as stream: p=subprocess.run(argv,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
 log.chmod(0o400);records.append({'name':name,'argv':argv,'cwd':str(cwd),'elapsedSeconds':time.time()-start,'exitCode':p.returncode,'logSHA256':h(log)})
 if p.returncode:break
 if name=='compile':bin.chmod(0o500)
receipt={'sourceManifestSHA256':h(r/'source/services/platform/migrations/tools/ordered-current-native379-packet-v2-artifacts/source-inputs.json'),'reviewedWarmTransactionSHA256':h(r/'source/services/platform/apiserver/authorization_transaction.go'),'reviewedWarmActivationTestSHA256':h(r/'source/services/platform/apiserver/authorization_runtime_activation_test.go'),'actualConsumedSourceMembers':1545,'currentRootWholeGitIdentityClaim':False,'scope':'retained source-only component review; no frozen native envelope or PostgreSQL execution','sourceSHA256':h(source),'binarySHA256':h(bin) if bin.exists() else None,'environment':env,'records':records}
(out/'identity.json').write_text(json.dumps(receipt,indent=2)+'\n');(out/'identity.json').chmod(0o400)
print(json.dumps(receipt));assert len(records)==3 and all(x['exitCode']==0 for x in records)
