import os,pathlib,json,hashlib,stat,time,signal,sys
BASE=pathlib.Path('/tmp/zasp-cloud-evidence/default-Go-cache-lossless-plan-rpjizha4');PLAN=BASE/'bucket3a-plan.json';PIN='aa45817a7744a9823a221d939ba7d2539c7edd0fe58ab9dedbe0a3aed91db603';START=time.monotonic();CANCEL=False;TERMINAL=False
FIELDS=['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns']
def cancel(sig,frame):
 global CANCEL
 CANCEL=True
 if TERMINAL:raise SystemExit(1)
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(sig,cancel)
def meta(s):return {'dev':str(s.st_dev),'ino':str(s.st_ino),'mode':s.st_mode&0o7777,'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink,'size':s.st_size,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'atimeNs':s.st_atime_ns}
def same(a,b):return all(getattr(a,k)==getattr(b,k) for k in FIELDS)
def guard():
 if CANCEL or time.monotonic()-START>=180:raise RuntimeError('cancel or recovery deadline')
 for path,floor in [('/tmp',100000000),('/dev/shm',100000000)]:
  s=os.statvfs(path)
  if s.f_bavail*s.f_frsize<floor:raise RuntimeError('recovery destination reserve')
def writers():
 guard();zombies=[]
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  guard()
  try:
   f=(p/'stat').read_text().rsplit(')',1)[1].split();comm=(p/'comm').read_text().strip()
  except FileNotFoundError:continue
  if f[0]=='Z':
   if comm in ['go','compile','link','migrations.test']:zombies.append({'pid':int(p.name),'comm':comm,'startTicks':f[19],'state':'Z'})
   continue
  if comm in ['go','compile','link']:raise RuntimeError('active compiler; writer HOLD required')
 return zombies
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def durable(path,obj):
 b=(json.dumps(obj,sort_keys=True,indent=2)+'\n').encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 try:
  off=0
  while off<len(b):
   n=os.write(fd,b[off:]);assert n>0;off+=n
  os.fsync(fd)
 finally:os.close(fd)
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
def read_regular(path,expected=None):
 guard();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid();h=hashlib.sha256();size=0
  if expected:
   m=meta(s);assert all(m[k]==expected['metadata'][k] for k in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'])
  while True:
   guard();b=os.read(fd,1024*1024)
   if not b:break
   size+=len(b);assert size<=s.st_size;h.update(b)
  assert size==s.st_size and same(s,os.fstat(fd)) and same(s,path.lstat())
  if expected:assert h.hexdigest()==expected['sha256']
  return {'metadata':meta(s),'sha256':h.hexdigest()}
 finally:os.close(fd)
def source_roster(root):
 e=plan['directories'][0]['metadata'];m=meta(root.lstat());fields=['dev','ino','mode','uid','gid','nlink','size','mtimeNs']+([] if root==QUARANTINE else ['ctimeNs']);assert all(m[k]==e[k] for k in fields)
 assert root.is_dir() and not root.is_symlink();actual={p.relative_to(root).as_posix() for p in root.rglob('*')};expected={r['relativePath'].removeprefix('3a/') for r in plan['regularFiles']}|{r['relativePath'].removeprefix('3a/') for r in plan['directories'] if r['relativePath']!='3a'};assert actual==expected
 for r in plan['regularFiles']:read_regular(root/r['relativePath'].removeprefix('3a/'),r)
def protected(full=False):
 guard();raw=pathlib.Path(plan['wholeInventoryPath']).read_bytes();assert hashlib.sha256(raw).hexdigest()==plan['wholeInventorySHA256'];whole=json.loads(raw);root=pathlib.Path(plan['sourceCache'])
 assert {p.name for p in root.iterdir()}=={r['relativePath'].split('/')[0] for r in whole['regularFiles']}|{r['relativePath'].split('/')[0] for r in whole['directories']}
 expected={r['relativePath'] for r in whole['regularFiles'] if not r['relativePath'].startswith('3a/')}|{r['relativePath'] for r in whole['directories'] if r['relativePath']!='3a' and not r['relativePath'].startswith('3a/')}
 actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.relative_to(root).as_posix()!='3a' and not p.relative_to(root).as_posix().startswith('3a/')}
 assert actual==expected
 for r in whole['regularFiles']:
  if not r['relativePath'].startswith('3a/'):
   p=root/r['relativePath'];m=meta(p.lstat());assert stat.S_ISREG(p.lstat().st_mode) and all(m[k]==r['metadata'][k] for k in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'])
   if full:read_regular(p,r)
 for r in whole['directories']:
  if r['relativePath']!='3a' and not r['relativePath'].startswith('3a/'):
   p=root/r['relativePath'];m=meta(p.lstat());assert stat.S_ISDIR(p.lstat().st_mode) and all(m[k]==r['metadata'][k] for k in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'])
 return len(whole['regularFiles'])-len(plan['regularFiles'])
def destination_verified():
 guard();assert DEST.is_dir() and not DEST.is_symlink() and not DEST.parent.is_symlink();assert DEST.parent.stat().st_uid==os.getuid() and stat.S_IMODE(DEST.parent.stat().st_mode)==0o700;assert stat.S_IMODE(DEST.stat().st_mode)==plan['directories'][0]['metadata']['mode'] and DEST.stat().st_uid==plan['directories'][0]['metadata']['uid'] and DEST.stat().st_gid==plan['directories'][0]['metadata']['gid'];assert {p.relative_to(DEST).as_posix() for p in DEST.rglob('*')}=={r['relativePath'].removeprefix('3a/') for r in plan['regularFiles']}
 result={}
 for r in plan['regularFiles']:
  rel=r['relativePath'].removeprefix('3a/');row=read_regular(DEST/rel);m=row['metadata'];e=r['metadata'];assert row['sha256']==r['sha256'] and all(m[k]==e[k] for k in ['mode','uid','gid','nlink','size','mtimeNs']);result[rel]=row
 return result
def copy_one(row):
 rel=row['relativePath'].removeprefix('3a/');src=SOURCE/rel;dst=DEST/rel;guard();sf=os.open(src,os.O_RDONLY|os.O_NOFOLLOW);df=None
 try:
  before=os.fstat(sf);e=row['metadata'];assert all(meta(before)[k]==e[k] for k in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs']);assert before.st_nlink==1
  df=os.open(dst,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,e['mode']);h=hashlib.sha256();nbytes=0
  while True:
   guard();b=os.read(sf,1024*1024)
   if not b:break
   nbytes+=len(b);assert nbytes<=e['size'];h.update(b);off=0
   while off<len(b):n=os.write(df,b[off:]);assert n>0;off+=n
  assert nbytes==e['size'] and h.hexdigest()==row['sha256'] and same(before,os.fstat(sf)) and same(before,src.lstat());os.fchmod(df,e['mode']);os.utime(df,ns=(e['atimeNs'],e['mtimeNs']));os.fsync(df);written=os.fstat(df);assert stat.S_ISREG(written.st_mode) and written.st_nlink==1;os.lseek(df,0,os.SEEK_SET);h=hashlib.sha256();nbytes=0
  while True:
   guard();b=os.read(df,1024*1024)
   if not b:break
   nbytes+=len(b);assert nbytes<=e['size'];h.update(b)
  assert h.hexdigest()==row['sha256'] and nbytes==e['size'] and same(written,os.fstat(df)) and same(written,dst.lstat());os.utime(df,ns=(e['atimeNs'],e['mtimeNs']))
 finally:
  os.close(sf)
  if df is not None:os.close(df)
raw=PLAN.read_bytes();assert hashlib.sha256(raw).hexdigest()==PIN;plan=json.loads(raw);SOURCE=pathlib.Path(plan['sourceBucket']);QUARANTINE=pathlib.Path(plan['quarantine']);DEST=pathlib.Path(plan['destinationBucket']);phase=sys.argv[1] if len(sys.argv)>=2 else '';assert phase in ['prepare','finalize'];assert len(sys.argv)==(2 if phase=='prepare' else 3)
result={'phase':phase,'status':'REFUSED','planSHA256':PIN,'unlinkedReturned':[]};error=None;startedSwitch=False;copyComplete=False
try:
 zombies=writers();source_roster(SOURCE);protectedCount=protected()
 if phase=='prepare':
  assert not DEST.parent.exists() and not QUARANTINE.exists();assert os.statvfs('/dev/shm').f_bavail*os.statvfs('/dev/shm').f_frsize>=plan['logicalBytes']+100000000;DEST.parent.mkdir(mode=0o700);DEST.mkdir(mode=plan['directories'][0]['metadata']['mode'])
  for row in plan['regularFiles']:copy_one(row)
  for row in plan['directories']:
   e=row['metadata'];os.utime(DEST,ns=(e['atimeNs'],e['mtimeNs']))
  destinationRows=destination_verified();copyComplete=True;syncdir(DEST);syncdir(DEST.parent);syncdir(DEST.parent.parent);source_roster(SOURCE);protected();writers();guard();durable(BASE/'prepared.json',{'format':'exact-Go-cache-bucket3a-prepared-v1','status':'COMPLETE-BYTE-VERIFIED-COPIES-NO-SOURCE-MUTATION','planSHA256':PIN,'sourceBucket':str(SOURCE),'destinationBucket':str(DEST),'destinationFiles':destinationRows,'sourceFiles':len(plan['regularFiles']),'logicalBytes':plan['logicalBytes'],'protectedOtherFiles':protectedCount,'knownZombies':zombies});result['status']='PREPARED'
 else:
  preparedPath=BASE/'prepared.json';fd=os.open(preparedPath,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and s.st_size<128*1024;b=os.read(fd,s.st_size+1);assert len(b)==s.st_size and same(s,os.fstat(fd)) and same(s,preparedPath.lstat())
  finally:os.close(fd)
  assert hashlib.sha256(b).hexdigest()==sys.argv[2];prepared=json.loads(b);assert prepared['planSHA256']==PIN and prepared['status']=='COMPLETE-BYTE-VERIFIED-COPIES-NO-SOURCE-MUTATION' and prepared['sourceBucket']==str(SOURCE) and prepared['destinationBucket']==str(DEST);current=destination_verified();copyComplete=True;assert set(current)==set(prepared['destinationFiles']);assert all(current[k]['sha256']==prepared['destinationFiles'][k]['sha256'] and all(current[k]['metadata'][f]==prepared['destinationFiles'][k]['metadata'][f] for f in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs']) for k in current);source_roster(SOURCE);writers();guard();assert not QUARANTINE.exists();durable(BASE/'finalize-intent.json',{'planSHA256':PIN,'preparedSHA256':sys.argv[2],'sourceBucket':str(SOURCE),'quarantine':str(QUARANTINE),'destination':str(DEST),'logicalBytes':plan['logicalBytes']});os.rename(SOURCE,QUARANTINE);startedSwitch=True;syncdir(SOURCE.parent);SOURCE.symlink_to(DEST,target_is_directory=True);syncdir(SOURCE.parent);assert SOURCE.is_symlink() and SOURCE.resolve()==DEST;destination_verified();source_roster(QUARANTINE)
  journal=os.open(BASE/'unlink-returned.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
  try:
   for row in plan['regularFiles']:
    guard();writers();rel=row['relativePath'].removeprefix('3a/');p=QUARANTINE/rel;read_regular(p,row);dest=read_regular(DEST/rel);assert dest['sha256']==row['sha256'];assert SOURCE.is_symlink() and SOURCE.resolve()==DEST;guard();assert all(meta(p.lstat())[k]==row['metadata'][k] for k in ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs']);os.unlink(p);syncdir(QUARANTINE);record=(json.dumps({'relativePath':rel,'state':'UNLINK_RETURNED','sha256':row['sha256']},sort_keys=True)+'\n').encode();off=0
    while off<len(record):
     n=os.write(journal,record[off:]);assert n>0;off+=n
    os.fsync(journal);result['unlinkedReturned'].append(rel)
  finally:os.close(journal)
  syncdir(QUARANTINE);QUARANTINE.rmdir();syncdir(SOURCE.parent);destination_verified();protected(full=True);writers();s=os.statvfs('/workspace');assert s.f_bavail*s.f_frsize>=1500000000;result.update({'status':'LOSSLESS-BUCKET-CUSTODY-COMPLETE','originalPathNow':'symlink-to-complete-SHM-copy','originalPhysicalDirectoryAbsent':not QUARANTINE.exists(),'protectedOtherFiles':protectedCount,'sourceAccessAllSHA':True,'knownZombies':zombies,'workspaceFreeBytesAfter':s.f_bavail*s.f_frsize})
except BaseException as e:error=type(e).__name__;result['status']='REFUSED';result['failureClass']=error
finally:
 if startedSwitch and not SOURCE.exists() and QUARANTINE.exists():
  try:os.rename(QUARANTINE,SOURCE);syncdir(SOURCE.parent);result['recovery']='Original directory restored after incomplete switch'
  except BaseException:result['recovery']='UNKNOWN; completeSHMcopy and quarantine retained'
 result['custodyStates']={'completeSHMCopyVerified':copyComplete,'destinationRetained':DEST.exists(),'oldPathIsSymlink':SOURCE.is_symlink(),'oldPathExists':SOURCE.exists(),'quarantineRetained':QUARANTINE.exists(),'quarantineRemainingFiles':len(list(QUARANTINE.rglob('*'))) if QUARANTINE.exists() else 0,'reversibilityScope':'Complete byte copy retains every cache payload; original physical metadata cannot be restored after successful unlink. No promise original inode/dev/ctime survive relocation.'};result['elapsedSeconds']=time.monotonic()-START;result['scope']='Filesystem recovery only; all cachebytes retained, no task/file attribution or runtime/test acceptance; originaldev/ino/ctime historical, copiesnecessarilynew.';TERMINAL=True
 try:guard()
 except BaseException:result['status']='REFUSED';error=error or 'TerminalRefusal'
 durable(BASE/(phase+'-result.json'),result);print(json.dumps({'status':result['status'],'resultPath':str(BASE/(phase+'-result.json'))}),flush=True)
 try:guard()
 except BaseException:error=error or 'TerminalRefusal'
 raise SystemExit(1 if error else 0)
