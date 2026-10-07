import hashlib,json,os,pathlib,shutil,signal,subprocess,time
D=pathlib.Path('/dev/shm/native-projection79-fixture-31112e09c7');R=pathlib.Path('/workspace/zasp-sec');BASE='/tmp/zasp-native-supported-tools-h0zqa978'
start=time.monotonic();deadline=start+300;proc=None;failure=None;observations=[]
def write(name,obj):
 p=D/name
 with p.open('x') as f:json.dump(obj,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def stat_record(path):
 p=pathlib.Path(path);s=p.stat();h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return {'sha256':h.hexdigest(),'bytes':s.st_size,'mode':s.st_mode,'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'resolved_path':str(p.resolve())}
def guard():
 values={p:shutil.disk_usage(p).free for p in ['/workspace','/tmp','/dev/shm']};observations.append({'elapsed':time.monotonic()-start,'free':values})
 if values['/workspace']<1500000000 or values['/tmp']<100000000 or values['/dev/shm']<100000000:raise RuntimeError('storage_floor')
 current=int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text());maximum=pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()
 if maximum!='max' and int(maximum)-current<100000000:raise RuntimeError('memory_floor')
 if time.monotonic()>=deadline:raise RuntimeError('compile_deadline')
env={'PATH':'/tmp/zasp-cloud-tools/go/bin:/usr/bin:/bin','GOROOT':'/tmp/zasp-cloud-tools/go','GOPATH':'/home/agent/go','GOMODCACHE':BASE+'/module-cache','GOCACHE':BASE+'/go-cache','GOTMPDIR':'/dev/shm/security-agent-deadline-tdd/tmp','TMPDIR':'/dev/shm/security-agent-deadline-tdd/tmp','HOME':'/home/agent','GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOFLAGS':'-mod=readonly','CGO_ENABLED':'1'}
argv=['/tmp/zasp-cloud-tools/go/bin/go','test','-c','-race','-p=1','-overlay='+str(D/'overlay.json'),'-o',str(D/'apiserver-native79.test'),'./apiserver']
head_before=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip();inputs=json.loads((D/'compile-inputs-before.json').read_text());cancel=[]
def cancelled(sig,_):cancel.append(sig)
signal.signal(signal.SIGTERM,cancelled);signal.signal(signal.SIGINT,cancelled)
try:
 guard()
 if any(stat_record(p)!=v for p,v in inputs.items()):raise RuntimeError('input_drift_before')
 with (D/'compile.stdout').open('xb') as out,(D/'compile.stderr').open('xb') as err:
  proc=subprocess.Popen(argv,cwd=R/'services/platform',env=env,stdout=out,stderr=err,start_new_session=True)
  stat=pathlib.Path('/proc/'+str(proc.pid)+'/stat').read_text().rsplit(')',1)[1].split()
  write('compile-process-binding.json',{'pid':proc.pid,'start_ticks':stat[19],'pgid':os.getpgid(proc.pid),'argv':argv,'cwd':str(R/'services/platform'),'env':env,'head':head_before,'started_monotonic':start})
  while proc.poll() is None:
   guard()
   if cancel:raise RuntimeError('cancelled')
   if (D/'compile.stderr').stat().st_size>2000000:raise RuntimeError('output_cap')
   time.sleep(.25)
  if proc.wait()!=0:failure='compiler_exit'
except BaseException as e:failure=type(e).__name__+':'+str(e)
finally:
 if proc is not None and proc.poll() is None:
  os.killpg(proc.pid,signal.SIGTERM)
  try:proc.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
 post={p:stat_record(p) for p in inputs};write('compile-inputs-after.json',post)
 unchanged=post==inputs
 try:guard()
 except BaseException as e:failure=failure or type(e).__name__+':'+str(e)
 survivors=[]
 if proc:
  for p in pathlib.Path('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    fields=(p/'stat').read_text().rsplit(')',1)[1].split()
    if int(fields[2])==proc.pid:survivors.append({'pid':int(p.name),'state':fields[0]})
   except FileNotFoundError:pass
 code=None if proc is None else proc.returncode
 result={'completed':not failure and code==0 and unchanged and not survivors and not cancel,'failure':failure,'exit':code,'wait_joined':proc is not None and code is not None,'survivors':survivors,'source_inputs_unchanged':unchanged,'input_files':len(inputs),'elapsed':time.monotonic()-start,'head_before':head_before,'head_after':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'observations':observations,'binary':stat_record(D/'apiserver-native79.test') if (D/'apiserver-native79.test').exists() else None,'scope':'Compilation only of selected native79 fixture overlay; no tests or native services executed.'}
 write('compile-result.json',result)
 print(json.dumps({k:result[k] for k in ['completed','failure','exit','elapsed','input_files','source_inputs_unchanged','survivors']}),flush=True)
 raise SystemExit(0 if result['completed'] else 1)
