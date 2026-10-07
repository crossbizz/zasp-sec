import pathlib,os,json,subprocess,time,signal,hashlib
B=pathlib.Path('/tmp/unchanged-native80-spec29-ingpnppe');R=pathlib.Path('/workspace/zasp-sec');G=pathlib.Path('/tmp/zasp-cloud-tools/go/bin/go')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for x in iter(lambda:f.read(1048576),b''):h.update(x)
 return h.hexdigest()
paths=[R/'services/platform/runtimepostgres/config.go',R/'services/platform/runtimepostgres/config_test.go',R/'services/platform/go.mod',R/'services/platform/go.sum',G,pathlib.Path('/tmp/zasp-cloud-tools/bin/tini'),pathlib.Path('/usr/bin/python3').resolve(),pathlib.Path('/usr/bin/timeout'),*pathlib.Path('/tmp/zasp-pg183-current/pg-bin-v2').iterdir(),*pathlib.Path('/tmp/zasp-pg183-current/root/usr/lib/postgresql/18/bin').glob('*')]
paths+=[p.resolve() for p in pathlib.Path('/tmp/zasp-pg183-current/pg-non-glibc-libs').iterdir()];paths+=[pathlib.Path('/tmp/zasp-pg183-current/root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')]
paths += [R/pathlib.Path(p) for p in subprocess.check_output(['git','ls-files','services/platform'],cwd=R,text=True).splitlines() if (R/p).is_file()]
paths=list(dict.fromkeys(paths));before={str(p):{'sha256':sha(p),'bytes':p.stat().st_size,'dev':p.stat().st_dev,'ino':p.stat().st_ino,'mtime_ns':p.stat().st_mtime_ns,'ctime_ns':p.stat().st_ctime_ns} for p in paths if p.is_file()};(B/'bindings-before.json').write_text(json.dumps(before,sort_keys=True)+'\n')
args=[str(G),'test','-mod=readonly','-c','-o',str(B/'native80.test'),'./apiserver'];env=dict(os.environ,GOROOT='/tmp/zasp-cloud-tools/go',GOTOOLCHAIN='local',GOCACHE='/dev/shm/zasp-go-cache-current',GOMODCACHE='/tmp/zasp-go-module-cache-current',GOPATH='/tmp/zasp-go-path',TMPDIR='/tmp',GOPROXY='off');begin=time.monotonic();forced=False;failure=None
with (B/'compile.stdout').open('wb') as o,(B/'compile.stderr').open('wb') as e:
 child=subprocess.Popen(args,cwd=R/'services/platform',env=env,stdout=o,stderr=e,start_new_session=True)
 while child.poll() is None:
  if time.monotonic()-begin>240 or any(os.statvfs(p).f_bavail*os.statvfs(p).f_frsize<f for p,f in [('/workspace',1500000000),('/tmp',100000000),('/dev/shm',100000000)]):
   forced=True;failure='deadline_or_storage_floor';os.killpg(child.pid,signal.SIGTERM)
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
   break
  time.sleep(.1)
 rc=child.wait()
after={str(p):{'sha256':sha(p),'bytes':p.stat().st_size,'dev':p.stat().st_dev,'ino':p.stat().st_ino,'mtime_ns':p.stat().st_mtime_ns,'ctime_ns':p.stat().st_ctime_ns} for p in paths if p.is_file()};assert before==after;(B/'bindings-compile-after.json').write_text(json.dumps(after,sort_keys=True)+'\n')
d={'scope':'Fresh unchanged native80 apiserver compile only','argv':args,'exit':rc,'normalJoined':True,'forced':forced,'failure':failure,'elapsed':time.monotonic()-begin,'bindingCount':len(before),'bindingsBeforeSHA256':sha(B/'bindings-before.json'),'bindingsAfterSHA256':sha(B/'bindings-compile-after.json'),'binarySHA256':sha(B/'native80.test') if rc==0 else None};p=B/'compile-result.json';p.write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d))
