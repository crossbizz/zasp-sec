import ctypes,hashlib,json,os,pathlib,re,shutil,signal,subprocess,time
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:raise RuntimeError("subreaper_unavailable")
D=pathlib.Path('/dev/shm/readiness80-leaf-jit-464aj5ll');R=pathlib.Path('/workspace/zasp-sec');BASE=pathlib.Path('/tmp/zasp-native-supported-tools-h0zqa978')
start=time.monotonic();deadline=start+650;proc=None;failure=None;cancel=[];observations=[]
binary=D/'apiserver-native79.test';compile_result=json.loads((D/'compile-result.json').read_text());inputs=json.loads((D/'compile-inputs-after.json').read_text());wrappers=json.loads((BASE/'pg-fixture-wrapper-manifest.json').read_text())
def write(name,x):
 with (D/name).open('x') as f:json.dump(x,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def record(p):
 p=pathlib.Path(p);s=p.stat();h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return {'sha256':h.hexdigest(),'bytes':s.st_size,'mode':s.st_mode,'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'resolved_path':str(p.resolve())}
def guard():
 values={p:shutil.disk_usage(p).free for p in ['/workspace','/tmp','/dev/shm']};observations.append({'elapsed':time.monotonic()-start,'free':values})
 if values['/workspace']<1500000000 or values['/tmp']<100000000 or values['/dev/shm']<100000000:raise RuntimeError('storage_floor')
 current=int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text());limit=pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()
 if limit!='max' and int(limit)-current<100000000:raise RuntimeError('memory_floor')
 if time.monotonic()>=deadline:raise RuntimeError('outer_deadline')
 if cancel:raise RuntimeError('cancelled')
 # This current80 module-only stage has no FGA or live parent dependency.
 s=binary.stat();expected=compile_result['binary']
 if any(getattr(s,'st_'+field)!=expected[key] for field,key in [('size','bytes'),('mode','mode'),('dev','dev'),('ino','ino'),('mtime_ns','mtime_ns'),('ctime_ns','ctime_ns')]):raise RuntimeError('binary_metadata_drift')
 for member in wrappers['members']:
  if record(member['path'])['sha256']!=member['sha256']:raise RuntimeError('wrapper_drift')
if record(binary)!=compile_result['binary']:raise RuntimeError('binary_drift_before')
inputs_before={p:record(p) for p in inputs}
if inputs_before!=inputs:raise RuntimeError('source_drift_before')
write('sql80-inputs-before.json',inputs_before)
for member in wrappers['members']:inputs_before[member['path']]=record(member['path'])
write('sql80-tools-before.json',{p:record(p) for p in [str(BASE/'pg-fixture-wrapper-manifest.json')]+[m['path'] for m in wrappers['members']]})
env={'PATH':str(BASE/'pg-fixture-bin')+':/usr/bin:/bin','HOME':'/home/agent','LC_ALL':'C','TMPDIR':str(D),'LD_LIBRARY_PATH':str(BASE/'pg-non-glibc-libs')}
argv=[str(binary),'-test.run=^TestOwnedCurrent80ReadinessLeafDiagnostic$','-test.v','-test.timeout=10m']
def signal_received(sig,_):cancel.append(sig)
signal.signal(signal.SIGTERM,signal_received);signal.signal(signal.SIGINT,signal_received)
try:
 guard()
 with (D/'sql80.stdout').open('xb') as out,(D/'sql80.stderr').open('xb') as err:
  proc=subprocess.Popen(argv,cwd=R/'services/platform/apiserver',env=env,stdout=out,stderr=err,start_new_session=True)
  fields=pathlib.Path('/proc/'+str(proc.pid)+'/stat').read_text().rsplit(')',1)[1].split()
  write('sql80-process-binding.json',{'pid':proc.pid,'start_ticks':fields[19],'pgid':os.getpgid(proc.pid),'argv':argv,'cwd':str(R/'services/platform/apiserver'),'env':env,'binary_sha256':compile_result['binary']['sha256'],'started_monotonic':start})
  while proc.poll() is None:
   guard()
   if sum((D/n).stat().st_size for n in ['sql80.stdout','sql80.stderr'])>4000000:raise RuntimeError('output_cap')
   time.sleep(.25)
  if proc.wait()!=0:failure='test_exit'
except BaseException as e:failure=type(e).__name__+':'+str(e)
finally:
 if proc is not None and proc.poll() is None:
  os.killpg(proc.pid,signal.SIGTERM)
  try:proc.wait(timeout=15)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
 code=None if proc is None else proc.returncode
 if record(binary)!=compile_result['binary']:failure=failure or 'binary_drift_after'
 after={p:record(p) for p in inputs_before};unchanged=after==inputs_before;write('sql80-inputs-after.json',after)
 try:guard()
 except BaseException as e:failure=failure or type(e).__name__+':'+str(e)
 stdout=(D/'sql80.stdout').read_text() if (D/'sql80.stdout').exists() else ''
 passed=len(re.findall(r'^--- PASS: TestOwnedCurrent80ReadinessLeafDiagnostic \(',stdout,re.M));skipped=len(re.findall(r'^--- SKIP:',stdout,re.M));cleanup='joined owned PostgreSQL pid=' in stdout
 survivors=[]
 if proc:
  for p in pathlib.Path('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    f=(p/'stat').read_text().rsplit(')',1)[1].split()
    if int(f[2])==proc.pid:survivors.append({'pid':int(p.name),'state':f[0]})
   except FileNotFoundError:pass
 result={'completed':not failure and code==0 and unchanged and not survivors and not cancel and passed==1 and skipped==0 and cleanup,'failure':failure,'exit':code,'wait_joined':proc is not None and code is not None,'survivors':survivors,'source_inputs_unchanged':unchanged,'top_pass':passed,'skip':skipped,'fixture_postgres_cleanup_log':cleanup,'elapsed':time.monotonic()-start,'observations':observations,'stdout_sha256':hashlib.sha256(stdout.encode()).hexdigest(),'scope':'Diagnostic direct SELECT timings of four fixed leaf predicates once each plus explicitly separate read-only SET LOCAL jit=off current68 comparison after same78/80 install with ownPG18.3. Private appended test overlay, original suite unchanged. No FGA/current80 acceptance/native379/browser claim.'}
 if proc:
  for child in survivors:
   if child['state']=='Z':
    try:os.waitpid(child['pid'],os.WNOHANG)
    except ChildProcessError:pass
 write('sql80-result.json',result)
 print(json.dumps({k:result[k] for k in ['completed','failure','exit','elapsed','top_pass','skip','fixture_postgres_cleanup_log','source_inputs_unchanged','survivors']}),flush=True)
 raise SystemExit(0 if result['completed'] else 1)
