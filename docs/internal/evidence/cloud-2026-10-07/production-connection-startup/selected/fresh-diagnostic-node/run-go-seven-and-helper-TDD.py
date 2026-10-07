import os,pathlib,hashlib,json,subprocess,time,signal,tempfile
R=pathlib.Path('/workspace/zasp-sec'); P=pathlib.Path('/tmp/full-verify-epoch29-0z96r_91/project/services/platform');O=pathlib.Path(__file__).parent;S=pathlib.Path(tempfile.mkdtemp(prefix='diagnostic-go-seven-',dir='/dev/shm'));G=pathlib.Path('/tmp/zasp-cloud-tools/go/bin/go')
keys=['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns']
def bind(p):
 with p.open('rb') as f:
  a={k:getattr(os.fstat(f.fileno()),k) for k in keys};h=hashlib.sha256()
  while True:
   b=f.read(65536)
   if not b:break
   h.update(b)
  z={k:getattr(os.fstat(f.fileno()),k) for k in keys};assert a==z=={k:getattr(p.stat(),k) for k in keys}
 return {'sha256':h.hexdigest(),'security':z}
files=[G]+list(sorted((P/'agentsec-api').glob('*.go')))+list(sorted((P/'runtimepostgres').glob('*.go')))+[P/'go.mod',P/'go.sum']
for name in ['runtime_dependency_diagnostic.go','runtime_dependency_diagnostic_test.go','production_runtime.go','compliance_browser_process_test.go']:
 assert bind(P/'agentsec-api'/name)['sha256']==bind(R/'services/platform/agentsec-api'/name)['sha256']
pre={str(p):bind(p) for p in files}
for name in ['runtime_dependency_diagnostic.go','runtime_dependency_diagnostic_test.go']:(S/name).write_bytes((P/'agentsec-api'/name).read_bytes())
env={'PATH':'/tmp/zasp-cloud-tools/go/bin:/usr/bin:/bin','HOME':'/home/agent','GOROOT':'/tmp/zasp-cloud-tools/go','GOPATH':str(S/'gopath'),'GOMODCACHE':'/tmp/zasp-go-module-cache-current','GOCACHE':'/dev/shm/zasp-go-cache-current','GOTMPDIR':str(S),'TMPDIR':str(S),'GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOFLAGS':'-mod=readonly','GOMEMLIMIT':'512MiB','GOGC':'50','GOMAXPROCS':'2','CGO_ENABLED':'1','LC_ALL':'C'}
def floors():
 for path,floor in [('/workspace',1500000000),('/tmp',100000000),('/dev/shm',100000000)]:
  s=os.statvfs(path);assert s.f_bavail*s.f_frsize>=floor,'floor refused'
 c=pathlib.Path('/sys/fs/cgroup');maximum=(c/'memory.max').read_text().strip();current=int((c/'memory.current').read_text());assert maximum=='max' or int(maximum)-current>=100000000,'memory floor refused'
baseline=S/'original-parser.go';baseline.write_text('package runtimepostgres\nimport "github.com/jackc/pgx/v5/pgxpool"\nfunc ParsePoolConfig(dsn string)(*pgxpool.Config,error){return pgxpool.ParseConfig(dsn)}\n');overlay=S/'original-parser-overlay.json';overlay.write_text(json.dumps({'Replace':{str(P/'runtimepostgres/config.go'):str(baseline)}}))
rows=[];startall=time.monotonic();failure=None
stages=[('diagnostic-three',S,[str(G),'test','-race','-p=1','-count=1','-timeout=30s','-json','runtime_dependency_diagnostic.go','runtime_dependency_diagnostic_test.go']),('sentinel-four',P,[str(G),'test','-race','-p=1','-count=1','-timeout=30s','-json','./agentsec-api','-run','^(TestAuditExportFactoryBuildRejectsAuthorityBeforeDatabaseDial|TestAuditExportRuntimeCompositionLateCancellation|TestAuditPublicPageCompositionSelectedAndLegacy|TestAuditPublicPageCompositionSelectedStartupRefusal)$'])]
stages.extend([('helper-original-parser-red',P,[str(G),'test','-race','-p=1','-count=1','-timeout=30s','-json','-overlay='+str(overlay),'./runtimepostgres']),('helper-current-green',P,[str(G),'test','-race','-p=1','-count=1','-timeout=30s','-json','./runtimepostgres'])])
try:
 for label,cwd,argv in stages:
  floors();t=time.monotonic();forced=False
  with (O/(label+'.stdout.log')).open('wb') as out,(O/(label+'.stderr.log')).open('wb') as err:
   p=subprocess.Popen(argv,cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True)
   while p.poll() is None:
    try:
     floors();assert time.monotonic()-t<90 and time.monotonic()-startall<300,'deadline refused'
    except BaseException:
     forced=True;os.killpg(p.pid,signal.SIGTERM)
     try:p.wait(timeout=10)
     except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10)
     raise
    time.sleep(.15)
   rc=p.wait()
  events=[json.loads(x) for x in (O/(label+'.stdout.log')).read_text().splitlines()]
  top=[x for x in events if x.get('Action')=='pass' and x.get('Test') and '/' not in x['Test']]
  rows.append({'stage':label,'exitCode':rc,'normalWait':True,'forced':forced,'seconds':time.monotonic()-t,'topPassNames':[x['Test'] for x in top],'fail':sum(x.get('Action')=='fail' for x in events),'skip':sum(x.get('Action')=='skip' for x in events)})
  if label=='helper-original-parser-red':
   fails=[x for x in events if x.get('Action')=='fail' and x.get('Test')]
   assert rc==1 and len(top)==2 and [x['Test'] for x in fails]==['TestOwnedPoolAvoidsReadinessJIT'] and not rows[-1]['skip']
  else:
   assert rc==0 and len(top)==(4 if label=='sentinel-four' else 3) and not rows[-1]['fail'] and not rows[-1]['skip']
except BaseException as e:failure=type(e).__name__
post={str(p):bind(p) for p in files};unchanged=pre==post
v={'status':'PASS' if failure is None and unchanged and len(rows)==4 else 'FAIL','failureClass':failure,'scope':'Fresh diagnostic3+unchanged public sentinel4 and same-case original parser helper3 RED/current helper3 GREEN/race. No provider/service/kernel-trace or original CI cause acceptance.','sourceBefore':pre,'sourceAfter':post,'sourceUnchanged':unchanged,'stages':rows,'seconds':time.monotonic()-startall,'scratch':str(S)}
p=O/'go-seven-and-helper-TDD-result.json';p.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'status':v['status'],'stages':rows}),flush=True)
raise SystemExit(0 if v['status']=='PASS' else 1)
