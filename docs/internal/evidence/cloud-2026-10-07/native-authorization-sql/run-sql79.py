import ctypes,hashlib,json,os,pathlib,re,shutil,signal,subprocess,time
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:raise RuntimeError("subreaper_unavailable")
D=pathlib.Path('/dev/shm/native-projection79-fixture-31112e09c7');R=pathlib.Path('/workspace/zasp-sec');BASE=pathlib.Path('/tmp/zasp-native-supported-tools-h0zqa978');READY=pathlib.Path('/tmp/zr-ff87e0004e/service-ready.json')
start=time.monotonic();deadline=start+180;proc=None;failure=None;cancel=[];observations=[]
ready=json.loads(READY.read_text());proofs=ready['ownedListenerProofs'];token=pathlib.Path(ready['tokenFile']);token_stat=token.stat();binary=D/'apiserver-native79.test';compile_result=json.loads((D/'compile-result.json').read_text());inputs=json.loads((D/'compile-inputs-after.json').read_text());wrappers=json.loads((BASE/'pg-fixture-wrapper-manifest.json').read_text())
def write(name,x):
 with (D/name).open('x') as f:json.dump(x,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def record(p):
 p=pathlib.Path(p);s=p.stat();h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return {'sha256':h.hexdigest(),'bytes':s.st_size,'mode':s.st_mode,'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'resolved_path':str(p.resolve())}
def service_guard():
 if record(READY)!=ready_record:raise RuntimeError('ready_drift')
 for proof in proofs:
  pid=proof['pid'];root=pathlib.Path('/proc')/str(pid);fields=(root/'stat').read_text().rsplit(')',1)[1].split()
  if fields[0]=='Z' or fields[19]!=str(proof['startTicks']) or os.readlink(root/'exe')!=proof['exe'] or os.readlink(root/'ns/net')!=proof['netNamespace']:raise RuntimeError('owned_service_identity')
  links=[]
  for path in (root/'fd').iterdir():
   try:links.append(os.readlink(path))
   except FileNotFoundError:pass
  if 'socket:['+str(proof['socketInode'])+']' not in links:raise RuntimeError('owned_service_socket')
 s=token.stat()
 if (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(token_stat.st_dev,token_stat.st_ino,token_stat.st_mode,token_stat.st_uid,token_stat.st_nlink,token_stat.st_size,token_stat.st_mtime_ns,token_stat.st_ctime_ns):raise RuntimeError('token_metadata_drift')
def guard():
 values={p:shutil.disk_usage(p).free for p in ['/workspace','/tmp','/dev/shm']};observations.append({'elapsed':time.monotonic()-start,'free':values})
 if values['/workspace']<1500000000 or values['/tmp']<100000000 or values['/dev/shm']<100000000:raise RuntimeError('storage_floor')
 current=int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text());limit=pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()
 if limit!='max' and int(limit)-current<100000000:raise RuntimeError('memory_floor')
 if time.monotonic()>=deadline:raise RuntimeError('outer_deadline')
 if cancel:raise RuntimeError('cancelled')
 service_guard()
 s=binary.stat();expected=compile_result['binary']
 if any(getattr(s,'st_'+field)!=expected[key] for field,key in [('size','bytes'),('mode','mode'),('dev','dev'),('ino','ino'),('mtime_ns','mtime_ns'),('ctime_ns','ctime_ns')]):raise RuntimeError('binary_metadata_drift')
 for member in wrappers['members']:
  if record(member['path'])['sha256']!=member['sha256']:raise RuntimeError('wrapper_drift')
if record(binary)!=compile_result['binary']:raise RuntimeError('binary_drift_before')
ready_record=record(READY);inputs_before={p:record(p) for p in inputs}
if inputs_before!=inputs:raise RuntimeError('source_drift_before')
write('sql79-inputs-before.json',inputs_before)
for member in wrappers['members']:inputs_before[member['path']]=record(member['path'])
write('sql79-tools-before.json',{p:record(p) for p in [str(BASE/'pg-fixture-wrapper-manifest.json')]+[m['path'] for m in wrappers['members']]})
env={'PATH':str(BASE/'pg-fixture-bin')+':/usr/bin:/bin','HOME':'/home/agent','LC_ALL':'C','TMPDIR':str(D),'LD_LIBRARY_PATH':str(BASE/'pg-non-glibc-libs'),'ZASP_P6_MODEL_TEST':'1','ZASP_P6_NATIVE_OPENFGA_URL':ready['fgaURL'],'ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE':str(token)}
argv=[str(binary),'-test.run=^TestAuthorizationProjectionPostgres$','-test.v','-test.timeout=10m']
def signal_received(sig,_):cancel.append(sig)
signal.signal(signal.SIGTERM,signal_received);signal.signal(signal.SIGINT,signal_received)
try:
 guard()
 with (D/'sql79.stdout').open('xb') as out,(D/'sql79.stderr').open('xb') as err:
  proc=subprocess.Popen(argv,cwd=R/'services/platform/apiserver',env=env,stdout=out,stderr=err,start_new_session=True)
  fields=pathlib.Path('/proc/'+str(proc.pid)+'/stat').read_text().rsplit(')',1)[1].split()
  write('sql79-process-binding.json',{'pid':proc.pid,'start_ticks':fields[19],'pgid':os.getpgid(proc.pid),'argv':argv,'cwd':str(R/'services/platform/apiserver'),'env':env,'binary_sha256':compile_result['binary']['sha256'],'ready_file_sha256':ready_record['sha256'],'started_monotonic':start})
  while proc.poll() is None:
   guard()
   if sum((D/n).stat().st_size for n in ['sql79.stdout','sql79.stderr'])>4000000:raise RuntimeError('output_cap')
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
 after={p:record(p) for p in inputs_before};unchanged=after==inputs_before;write('sql79-inputs-after.json',after)
 try:guard()
 except BaseException as e:failure=failure or type(e).__name__+':'+str(e)
 stdout=(D/'sql79.stdout').read_text() if (D/'sql79.stdout').exists() else ''
 passed=len(re.findall(r'^--- PASS: TestAuthorizationProjectionPostgres \(',stdout,re.M));skipped=len(re.findall(r'^--- SKIP:',stdout,re.M));cleanup='joined owned PostgreSQL pid=' in stdout
 survivors=[]
 if proc:
  for p in pathlib.Path('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    f=(p/'stat').read_text().rsplit(')',1)[1].split()
    if int(f[2])==proc.pid:survivors.append({'pid':int(p.name),'state':f[0]})
   except FileNotFoundError:pass
 result={'completed':not failure and code==0 and unchanged and not survivors and not cancel and passed==1 and skipped==0 and cleanup,'failure':failure,'exit':code,'wait_joined':proc is not None and code is not None,'survivors':survivors,'source_inputs_unchanged':unchanged,'top_pass':passed,'skip':skipped,'fixture_postgres_cleanup_log':cleanup,'elapsed':time.monotonic()-start,'observations':observations,'native_ready_sha256':ready_record['sha256'],'stdout_sha256':hashlib.sha256(stdout.encode()).hexdigest(),'scope':'Selected unchanged SQL79 projection/reconcile/ack using real ownedFGA1.21 and ownPG18.3 with explicit source overlay. Not current80/fullAPI/native379/deployed acceptance.'}
 if proc:
  for child in survivors:
   if child['state']=='Z':
    try:os.waitpid(child['pid'],os.WNOHANG)
    except ChildProcessError:pass
 write('sql79-result.json',result)
 print(json.dumps({k:result[k] for k in ['completed','failure','exit','elapsed','top_pass','skip','fixture_postgres_cleanup_log','source_inputs_unchanged','survivors']}),flush=True)
 raise SystemExit(0 if result['completed'] else 1)
