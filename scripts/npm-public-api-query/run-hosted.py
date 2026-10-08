import pathlib,os,json,subprocess,hashlib,time,signal,tempfile,stat,ctypes
from pathlib import Path
BASE=pathlib.Path(__file__).parent
import sys
OWNER_STARTED=time.monotonic()
if len(sys.argv)!=3 or not Path(sys.argv[1]).is_absolute() or len(sys.argv[2])!=64 or any(c not in '0123456789abcdef' for c in sys.argv[2]):raise RuntimeError('issued plan path/hash required')
PLAN_PATH=Path(sys.argv[1]);EXPECTED_PLAN_SHA=sys.argv[2]
def acquire_plan():
 p=PLAN_PATH;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size>1048576 or before.st_uid!=os.geteuid() or before.st_nlink!=1:raise RuntimeError('plan regularity/bound')
  raw=os.read(fd,1048577)
  if len(raw)>1048576:raise RuntimeError('plan byte cap')
  after=os.fstat(fd);path=p.lstat()
  fields=lambda v:[v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns]
  if fields(before)!=fields(after) or fields(after)!=fields(path) or hashlib.sha256(raw).hexdigest()!=EXPECTED_PLAN_SHA:raise RuntimeError('plan binding refusal')
  return json.loads(raw.decode('utf-8','strict')),dict(requested=str(p),resolved=str(p),sha256=EXPECTED_PLAN_SHA,metadata=fields(before),requestedMetadata=fields(path))
 finally:os.close(fd)
PLAN,PLAN_BINDING=acquire_plan()
OUT=pathlib.Path(tempfile.mkdtemp(prefix='official-public-lock-advisory-query-actual-',dir='/tmp'));END=OWNER_STARTED+600;CANCELLED=False;TERMINAL=False;CHILD=None;RECORDS=[];REQUESTS=0;TOTAL=0;MEMBERS=0;COUNTS={};FORCED=False;CLEANUPS=[];GH=PLAN['ghExecutable']
def stop(sig,frame):
 global CANCELLED
 CANCELLED=True
 if TERMINAL:
  try:
   data=(json.dumps({'signal':sig,'scope':'Late cancellation supersedes any result complete=true; normal ROOT exit0 required.'})+'\n').encode()
   if len(data)>1024:raise RuntimeError('late refusal byte cap')
   fd=os.open(OUT/'late-refusal.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:
    offset=0
    while offset<len(data):
     count=os.write(fd,data[offset:])
     if count<=0:raise RuntimeError('late refusal write progress')
     offset+=count
    os.fsync(fd)
   finally:os.close(fd)
   directory=os.open(OUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(directory)
   finally:os.close(directory)
  except BaseException:pass
  finally:os._exit(1)
MEMORY_BOOTSTRAP_VERIFIED=False
MEMORY_PROBES={'normalJoins':0,'minimumAvailableBytes':None,'last':None}
def guard():
 global MEMORY_BOOTSTRAP_VERIFIED,FORCED
 if CANCELLED or time.monotonic()>=END:raise RuntimeError('cancel/deadline')
 for p,floor in [(PLAN['workspacePath'],1500000000),('/tmp',1000000000)]:
  v=os.statvfs(p)
  if v.f_bavail*v.f_frsize<floor:raise RuntimeError('filesystem floor')
 if not MEMORY_BOOTSTRAP_VERIFIED:
  # Bounded source/tool bootstrap before running the metadata-only observer.
  # Static official Node and exact reused module hashes are independently pinned.
  selected=[p for p in PLAN['tools']+PLAN['inputs'] if p['resolved'] in [PLAN['nodeExecutable'],PLAN['memoryCLI'],PLAN['memoryModule']]]
  if len(selected)!=3:raise RuntimeError('memory observer binding count')
  fixed={PLAN['nodeExecutable']:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',PLAN['memoryModule']:'70c2ae837d040be4756842e4016acbc4eebd6bae3d8c992aba2a80e2a097ba75',PLAN['memoryCLI']:'fe3eab2c4f6afb0bb9368a679c70b49d1c65b1384093a508042d090e022afd1a'}
  for pin in selected:
   p=Path(pin['resolved']);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
   try:
    before=os.fstat(fd);h=hashlib.sha256();total=0
    if not stat.S_ISREG(before.st_mode) or before.st_size>134217728:raise RuntimeError('memory observer input cap')
    while True:
     if CANCELLED or time.monotonic()>=END:raise RuntimeError('cancel/deadline')
     chunk=os.read(fd,1048576)
     if not chunk:break
     total+=len(chunk)
     if total>134217728:raise RuntimeError('memory observer input cap')
     h.update(chunk)
    fields=lambda x:[x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
    if fields(before)!=fields(os.fstat(fd)) or fields(before)!=fields(p.lstat()) or fields(before)!=pin['metadata'] or h.hexdigest()!=pin['sha256'] or h.hexdigest()!=fixed[str(p)]:raise RuntimeError('memory observer binding refusal')
   finally:os.close(fd)
  MEMORY_BOOTSTRAP_VERIFIED=True
 try:
  observed=subprocess.run([PLAN['nodeExecutable'],PLAN['memoryCLI']],env={'PATH':'/usr/bin:/bin'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=max(.01,min(2,END-time.monotonic())))
 except subprocess.TimeoutExpired:
  FORCED=True;raise RuntimeError('memory observer timeout')
 if observed.returncode!=0 or observed.stderr or len(observed.stdout)>4096:raise RuntimeError('memory observer normal join refusal')
 value=json.loads(observed.stdout.decode('utf-8','strict'),object_pairs_hook=no_duplicates)
 expected={'availableBytes','hostAvailableBytes','finiteAncestorLimits','visibleGroupsObserved','basis'}
 if not isinstance(value,dict) or set(value)!=expected or any(type(value[k]) is not int or value[k]<0 for k in expected-{'basis'}) or value['basis']!='minimum-host-MemAvailable-and-all-visible-finite-cgroup-ancestors':raise RuntimeError('memory observer shape refusal')
 MEMORY_PROBES['normalJoins']+=1;MEMORY_PROBES['last']=value
 previous=MEMORY_PROBES['minimumAvailableBytes'];MEMORY_PROBES['minimumAvailableBytes']=value['availableBytes'] if previous is None else min(previous,value['availableBytes'])
 if value['availableBytes']<100000000:raise RuntimeError('memory floor')
 if CANCELLED or time.monotonic()>=END:raise RuntimeError('cancel/deadline')
def no_duplicates(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise RuntimeError('duplicate JSON')
  d[k]=v
 return d
def oid(v):return isinstance(v,str) and len(v)==40 and all(c in '0123456789abcdef' for c in v)
def verify(rows,root_oid,recursive):
 if not isinstance(rows,list):raise RuntimeError('tree rows')
 trees={'':root_oid};entries={};seen=set()
 for i,r in enumerate(rows):
  if i%256==0:guard()
  path=r.get('path');mode=r.get('mode');typ=r.get('type');sha=r.get('sha')
  if not isinstance(path,str) or path in seen or path.startswith('/') or any(x in ['', '.', '..'] for x in path.split('/')) or '\x00' in path or not oid(sha):raise RuntimeError('tree path/oid')
  seen.add(path)
  if not recursive and '/' in path:raise RuntimeError('direct tree path')
  if (mode,typ) not in [('040000','tree'),('100644','blob'),('100755','blob'),('120000','blob'),('160000','commit')]:raise RuntimeError('tree mode/type')
  parent,name=path.rsplit('/',1) if '/' in path else ('',path)
  entries.setdefault(parent,[]).append((name,mode,sha,typ))
  if typ=='tree':trees[path]=sha
  if typ=='blob' and (type(r.get('size')) is not int or r['size']<0):raise RuntimeError('blob size')
 for parent in entries:
  if parent not in trees:raise RuntimeError('missing parent tree')
 for parent,expected in trees.items():
  if not recursive and parent:continue
  children=entries.get(parent,[]);body=b''
  for name,mode,sha,typ in sorted(children,key=lambda r:(r[0]+('/' if r[3]=='tree' else '')).encode()):body+=mode.lstrip('0').encode()+b' '+name.encode('utf-8')+b'\0'+bytes.fromhex(sha)
  actual=hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
  if actual!=expected:raise RuntimeError('Git tree object SHA mismatch')
 return rows
def proc_row(pid,end):
 if time.monotonic()>=end:raise RuntimeError('session_observation_deadline')
 path=Path('/proc',str(pid))
 def read_leaf(name):
  with (path/name).open('rb') as f:
   data=f.read(16385)
  if len(data)>16384:raise RuntimeError('proc_metadata_cap')
  return data.decode('ascii')
 before=read_leaf('stat');tail=before.rsplit(') ',1)[1].split()
 if int(before.split(' ',1)[0])!=pid or len(tail)<20:raise RuntimeError('proc_identity_unknown')
 return {'pid':pid,'startTicks':tail[19],'ppid':int(tail[1]),'pgid':int(tail[2]),'sid':int(tail[3]),'state':tail[0]}

def stable(row):
 return tuple(row[k] for k in ('pid','startTicks','ppid','pgid','sid'))

def credential_row(pid,end):
 r=proc_row(pid,end)
 with Path('/proc',str(pid),'status').open('rb') as f:body=f.read(16385)
 if len(body)>16384:raise RuntimeError('proc_metadata_cap')
 selected={}
 for line in body.decode('ascii').splitlines():
  key,sep,value=line.partition(':')
  if key in ('Pid','PPid','Uid'):
   if key in selected:raise RuntimeError('proc_credential_duplicate')
   selected[key]=[int(v) for v in value.split()]
 after=proc_row(pid,end)
 if stable(r)!=stable(after) or selected.get('Pid')!=[pid] or selected.get('PPid')!=[r['ppid']] or selected.get('Uid')!=[os.geteuid()]*4:raise RuntimeError('owned_session_identity_unknown')
 after['uids']=selected['Uid'];return after

def owned_signal(row,sig,end):
 fd=os.pidfd_open(row['pid'],0)
 try:
  fresh=credential_row(row['pid'],end)
  if stable(fresh)!=stable(row) or fresh['uids']!=row['uids'] or fresh['state']=='Z':raise RuntimeError('pre_signal_identity_unknown')
  signal.pidfd_send_signal(fd,sig,None,0)
 finally:os.close(fd)

def owned_session(sid,end):
 members=[]
 for entry in os.scandir('/proc'):
  if time.monotonic()>=end:raise RuntimeError('session_observation_deadline')
  if not entry.name.isdigit():continue
  pid=int(entry.name)
  try:r=proc_row(pid,end)
  except FileNotFoundError:continue
  if r['sid']!=sid:continue
  try:after=credential_row(pid,end)
  except FileNotFoundError:continue
  if stable(r)!=stable(after):raise RuntimeError('owned_session_identity_unknown')
  r=after
  members.append(r)
 return members

def end_child(p):
 global FORCED
 end=time.monotonic()+8
 result={'scope':'exact original owned SID only; no escaped-session/global/fleet claim','sid':p.pid,'membersBefore':[],'membersAfter':None,'signals':[],'completed':False,'unknown':False,'intervened':False}
 try:
  result['membersBefore']=owned_session(p.pid,end)
  if p.poll() is None:
   result['intervened']=True
   for row in owned_session(p.pid,end):
    if row['state']=='Z':continue
    owned_signal(row,signal.SIGTERM,end);result['signals'].append({'pid':row['pid'],'startTicks':row['startTicks'],'signal':'TERM'})
  term_until=min(end,time.monotonic()+5)
  while time.monotonic()<end:
   if p.poll() is not None:p.wait(timeout=.1)
   rows=owned_session(p.pid,end)
   if not rows:
    time.sleep(.01);result['membersAfter']=owned_session(p.pid,end)
    if not result['membersAfter']:
     result['completed']=p.poll() is not None
     return result
   for row in rows:
    # The owner is an actual subreaper. Reap only its exact adopted/direct child.
    if row['state']=='Z' and row['ppid']==os.getpid():
     again=credential_row(row['pid'],end)
     if stable(again)!=stable(row) or again['uids']!=row['uids'] or again['state']!='Z':raise RuntimeError('pre_reap_identity_unknown')
     try:os.waitpid(row['pid'],os.WNOHANG)
     except ChildProcessError:raise RuntimeError('owned_child_reap_unknown')
    elif row['state']!='Z':
     result['intervened']=True

     sig=signal.SIGKILL if time.monotonic()>=term_until else signal.SIGTERM
     if sig==signal.SIGKILL:FORCED=True
     owned_signal(row,sig,end);result['signals'].append({'pid':row['pid'],'startTicks':row['startTicks'],'signal':'KILL' if sig==signal.SIGKILL else 'TERM'})
   time.sleep(.025)
  result['unknown']=True;return result
 except BaseException as e:
  result['unknown']=True;result['error']=type(e).__name__;return result


import sys,re,selectors
SOURCE=Path(PLAN['sourceBase'])
sys.path.insert(0,str(SOURCE))

def secure_snapshot():
 rows=[]
 for pin in [PLAN_BINDING]+PLAN['inputs']+PLAN['tools']:
  guard();requested=Path(pin['requested']);resolved=Path(pin['resolved'])
  alias=requested.lstat();fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_size>134217728:raise RuntimeError('input regularity/byte cap')
   h=hashlib.sha256();size=0
   while True:
    guard();chunk=os.read(fd,1<<20)
    if not chunk:break
    size+=len(chunk)
    if size>134217728:raise RuntimeError('input byte cap')
    h.update(chunk)
   after=os.fstat(fd);path_after=resolved.lstat();alias_after=requested.lstat()
   fields=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
   if fields(before)!=fields(after) or fields(after)!=fields(path_after) or fields(alias)!=fields(alias_after) or str(requested.resolve(strict=True))!=str(resolved) or h.hexdigest()!=pin['sha256'] or fields(before)!=pin['metadata'] or fields(alias)!=pin['requestedMetadata']:raise RuntimeError('input source/tool refusal')
   rows.append(dict(requested=str(requested),resolved=str(resolved),sha256=h.hexdigest(),metadata=fields(before),requestedMetadata=fields(alias)))
  finally:os.close(fd)
 guard();return rows

def acquire(endpoint,allowance):
 global REQUESTS,TOTAL,CHILD
 guard();REQUESTS+=1
 if REQUESTS>256 or not isinstance(endpoint,str) or not endpoint.startswith('/advisories?') or len(endpoint)>8192:raise RuntimeError('public query request bound')
 request_cap=min(20971520,allowance,134217728-TOTAL)
 if request_cap<=0:raise RuntimeError('public query aggregate cap')
 tag=str(REQUESTS).zfill(3);out=OUT/(tag+'.http');err=OUT/(tag+'.stderr');start=time.monotonic();deadline=min(END,start+30)
 allowed=['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy','SSL_CERT_FILE','SSL_CERT_DIR','CURL_CA_BUNDLE','REQUESTS_CA_BUNDLE','GH_TOKEN','GITHUB_TOKEN','GH_CONFIG_DIR','HOME']
 env={k:os.environ[k] for k in allowed if k in os.environ};env.update(PATH='/usr/local/bin:/usr/bin:/bin',GH_PROMPT_DISABLED='1',GH_PAGER='cat')
 with out.open('xb') as f,err.open('xb') as e:
  guard();CHILD=subprocess.Popen([GH,'api','--include','--hostname','github.com',endpoint],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  counts={'stdout':0,'stderr':0};selector=None
  try:
   credential_row(CHILD.pid,min(END,time.monotonic()+2));selector=selectors.DefaultSelector()
   for pipe,name,destination in [(CHILD.stdout,'stdout',f),(CHILD.stderr,'stderr',e)]:
    os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,(name,destination))
   while selector.get_map():
    guard()
    if time.monotonic()>=deadline:raise RuntimeError('public query request deadline')
    for key,events in selector.select(.05):
     name,destination=key.data;limit=request_cap if name=='stdout' else 65536
     chunk=os.read(key.fd,min(65536,limit-counts[name]+1))
     if not chunk:selector.unregister(key.fileobj);continue
     if len(chunk)>limit-counts[name]:raise RuntimeError('public query byte cap')
     destination.write(chunk);counts[name]+=len(chunk)
   rc=CHILD.wait(timeout=max(.01,deadline-time.monotonic()));guard()
  finally:
   if selector is not None:selector.close()
   for pipe in [CHILD.stdout,CHILD.stderr]:
    if pipe is not None:pipe.close()
   try:
    for stream in (f,e):stream.flush();os.fsync(stream.fileno())
    directory=os.open(OUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
   finally:
    p=CHILD;cleanup=end_child(p);CLEANUPS.append(cleanup);CHILD=None
    if not cleanup['completed'] or cleanup['unknown'] or cleanup['intervened'] or FORCED:raise RuntimeError('owned public query cleanup refusal')
 raw=out.read_bytes();TOTAL+=len(raw)
 if rc!=0 or TOTAL>134217728:raise RuntimeError('public query upstream refusal')
 header,sep,body=raw.partition(b'\r\n\r\n')
 if not sep:header,sep,body=raw.partition(b'\n\n')
 if not sep or len(header)>65536:raise RuntimeError('public query HTTP grammar')
 lines=header.decode('ascii','strict').splitlines()
 m=re.fullmatch(r'HTTP/(?:1\.[01]|2(?:\.0)?) ([0-9]{3})(?: .*)?',lines[0])
 if not m:raise RuntimeError('public query HTTP status grammar')
 headers=[]
 for line in lines[1:]:
  k,sep,v=line.partition(':')
  if not sep or not re.fullmatch(r'[A-Za-z0-9-]+',k):raise RuntimeError('public query HTTP header grammar')
  headers.append((k,v.strip()))
 RECORDS.append(dict(request=REQUESTS,endpoint=endpoint,exit=rc,normalJoined=True,responseBytes=len(raw),responseSHA256=hashlib.sha256(raw).hexdigest(),seconds=time.monotonic()-start))
 guard();return int(m[1]),headers,body,len(raw)

def persist(name,value):
 raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
 if len(raw)>33554432:raise RuntimeError('result evidence cap')
 fd=os.open(OUT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  offset=0
  while offset<len(raw):
   n=os.write(fd,raw[offset:])
   if n<=0:raise RuntimeError('result write progress')
   offset+=n
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(OUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return hashlib.sha256(raw).hexdigest()

def main():
 global TERMINAL
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 complete=False;failure=None;before=None;after=None;value=None
 libc=ctypes.CDLL(None,use_errno=True);old_subreaper=ctypes.c_int();acquired=False
 if libc.prctl(37,ctypes.byref(old_subreaper),0,0,0)!=0:raise RuntimeError('subreaper state unknown')
 try:
  guard();before=secure_snapshot()
  if libc.prctl(36,1,0,0,0)!=0:raise RuntimeError('subreaper refused')
  acquired=True
  from public_lock_adapter import collect_public_lock
  # Exact issued published lock, bound by secure_snapshot and component SHA.
  raw=Path(PLAN['publicLock']).read_bytes()
  value=collect_public_lock(raw,acquire,guard)
  after=secure_snapshot()
  if before!=after:raise RuntimeError('source/tool postcondition refusal')
  guard();complete=True
 except BaseException as error:failure=type(error).__name__
 finally:
  if acquired and libc.prctl(36,old_subreaper.value,0,0,0)!=0:complete=False;failure='subreaper restore refused'
  try:guard()
  except BaseException:complete=False
  if any(not c['completed'] or c['unknown'] or c['intervened'] for c in CLEANUPS) or FORCED:complete=False
  TERMINAL=True
  result=dict(format='root-owned-official-public-lock-query-observation-v1',completeIssuedQueries=complete,failureClass=failure,forced=FORCED,cancelled=CANCELLED,requests=RECORDS,ownedSessionCleanup=CLEANUPS,sourceToolsBefore=before,sourceToolsAfter=after,elapsedSeconds=600-(END-time.monotonic()),component=value,portableMemoryObservations=MEMORY_PROBES,scope='Actual public API pages only when complete+ROOT normal0/no late-refusal. Current issued publiclock209 coverage, upstream affects semantics, no immutable snapshot/localOSV/allunrelatedmalware/Go/images/SBOM/release clearance.',releaseAccepted=False)
  digest=persist('result.json',result);print(json.dumps(dict(result=str(OUT/'result.json'),sha256=digest,complete=complete)),flush=True)
  try:guard()
  except BaseException:return 1
  return 0 if complete else 1
if __name__=='__main__':raise SystemExit(main())
