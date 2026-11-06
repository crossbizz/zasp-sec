"""Versioned complete-source stream. Actual transport is owned by streaming_producer.mjs.

The importable verifier grants no network provenance or release authority. The CLI
uses only fixed official HTTPS, a private bare transport and framed output.
"""
import os,sys,json,hashlib,time,stat,subprocess,selectors,struct,tarfile,urllib.request,signal
from pathlib import Path
from cursor_component import exact_json
sys.dont_write_bytecode=True
MAX_TREE=8<<20; MAX_TREE_TOTAL=128<<20; MAX_STACK=32<<20
MAX_FRAME=1<<20; MAX_FILES=500000; MAX_WORK=1000000
MAX_SELECTED=1<<30; MAX_NPM=512<<20; MAX_ARCHIVE=256<<20; MAX_EXPANDED=2<<30
class Refused(ValueError):pass
def refuse():raise Refused('official advisory stream refused')
def sha(b):return hashlib.sha256(b).hexdigest()
def git_oid(kind,b):return hashlib.sha1(kind.encode()+b' '+str(len(b)).encode()+b'\0'+b).hexdigest()
def valid_oid(x):return isinstance(x,str) and len(x)==40 and all(c in '0123456789abcdef' for c in x)
def checked_tree(oid,raw):
 if not valid_oid(oid) or not isinstance(raw,bytes) or len(raw)>MAX_TREE or git_oid('tree',raw)!=oid:refuse()
 return raw

def tree_entries(raw):
 i=0;previous=None;names=set()
 while i<len(raw):
  j=raw.find(b' ',i);k=raw.find(b'\0',j+1)
  if j<0 or k<0 or k+21>len(raw):refuse()
  mode=raw[i:j];name=raw[j+1:k];oid=raw[k+1:k+21].hex();i=k+21
  try:text=name.decode('utf8','strict')
  except UnicodeError:refuse()
  if mode not in (b'40000',b'100644',b'100755',b'120000',b'160000') or not name or text in ('.','..') or any(c in text for c in '/\\') or any(ord(c)<32 or ord(c)==127 for c in text):refuse()
  order=name+(b'/' if mode==b'40000' else b'')
  if previous is not None and order<=previous:refuse()
  if name in names:refuse()
  names.add(name);previous=order;yield mode,text,oid

def walk_tree(root,read_tree,guard):
 total=work=0;seen_objects=0
 def walk(oid,prefix,depth,retained):
  nonlocal total,work,seen_objects
  guard();raw=checked_tree(oid,read_tree(oid));total+=len(raw);seen_objects+=1;retained+=len(raw)
  if total>MAX_TREE_TOTAL or seen_objects>MAX_FILES or retained>MAX_STACK or depth>64:refuse()
  if prefix=='advisories' and {(m,n) for m,n,o in tree_entries(raw)}!={(b'40000','github-reviewed'),(b'40000','unreviewed')}:refuse()
  for mode,name,child in tree_entries(raw):
   guard();work+=1
   if work>MAX_WORK:refuse()
   path=prefix+'/'+name if prefix else name
   if len(path.encode())>4096:refuse()
   yield path,mode,child
   if mode==b'40000':yield from walk(child,path,depth+1,retained)
 yield from walk(root,'',0,0)

def emit_frame(value,output):
 raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
 if not 0<len(raw)<=MAX_FRAME:refuse()
 frame=struct.pack('>I',len(raw))+raw
 view=memoryview(frame)
 while view:
  n=output.write(view)
  if n is None:n=len(view)
  if n<=0:refuse()
  view=view[n:]
 output.flush()

def validate_pax(headers,commit):
 if not isinstance(headers,dict) or set(headers)-{'comment','path','mtime'}:refuse()
 if 'comment' in headers and headers['comment']!=commit:refuse()
 if 'mtime' in headers:
  value=headers['mtime']
  if not isinstance(value,str) or len(value)>32 or not value.replace('.','',1).isdigit():refuse()
 if 'path' in headers:
  value=headers['path']
  if not isinstance(value,str) or len(value.encode())>4096 or '\0' in value:refuse()

class Counted:
 def __init__(self,source,maximum,guard):self.source=source;self.maximum=maximum;self.guard=guard;self.count=0
 def read(self,n=-1):
  self.guard()
  if n<0:n=min(65536,self.maximum-self.count+1)
  b=self.source.read(min(n,self.maximum-self.count+1));self.count+=len(b)
  if self.count>self.maximum:refuse()
  self.guard();return b

def verify_archive(source,root,read_tree,commit,emit,guard,probe=False):
 if not valid_oid(commit):refuse()
 expected=iter(walk_tree(root,read_tree,guard));prefix='advisory-database-'+commit
 totals={'selectedFiles':0,'selectedBytes':0,'npmRecords':0,'npmBytes':0,'allArchiveMembers':0};digest=hashlib.sha256();types={};roots=set();first=True;probe_bytes=0
 counted=Counted(source,(1<<20) if probe else MAX_EXPANDED,guard)
 with tarfile.open(fileobj=counted,mode='r|') as archive:
  for member in archive:
   guard();totals['allArchiveMembers']+=1
   if totals['allArchiveMembers']>MAX_WORK+128:refuse()
   validate_pax(member.pax_headers,commit)
   name=member.name.rstrip('/')
   if first:
    if name!=prefix or not member.isdir():refuse()
    first=False
    continue
   if not name.startswith(prefix+'/'):refuse()
   relative=name[len(prefix)+1:]
   if not relative or len(relative.encode())>4096 or '\\' in relative or any(p in ('','.','..') for p in relative.split('/')) or any(ord(c)<32 or ord(c)==127 for c in relative):refuse()
   try:path,mode,oid=next(expected)
   except StopIteration:refuse()
   if relative!=path or member.issym() or member.islnk() or member.isdev() or member.issparse():refuse()
   if member.isdir():
    if mode!=b'40000' or member.size!=0:refuse()
    if probe and totals['allArchiveMembers']>=128:return {'type':'probe','prefix':prefix,'pax':member.pax_headers,'membersVerified':totals['allArchiveMembers']-1,'lastCanonicalPath':path,'expandedBytesRead':counted.count,'releaseAccepted':False}
    continue
   if not member.isfile() or mode not in (b'100644',b'100755') or bool(member.mode&0o111)!=(mode==b'100755') or not 0<=member.size<=MAX_FRAME:refuse()
   selected=relative.startswith(('advisories/github-reviewed/','advisories/unreviewed/'))
   if selected and mode!=b'100644':refuse()
   body=archive.extractfile(member)
   if body is None:refuse()
   raw=body.read(MAX_FRAME+1)
   if len(raw)!=member.size or len(raw)>MAX_FRAME or git_oid('blob',raw)!=oid:refuse()
   if probe and totals['allArchiveMembers']>=128:return {'type':'probe','prefix':prefix,'pax':member.pax_headers,'membersVerified':totals['allArchiveMembers']-1,'lastCanonicalPath':path,'expandedBytesRead':counted.count,'releaseAccepted':False}
   if not selected:continue
   roots.add(relative.split('/')[1]);totals['selectedFiles']+=1;totals['selectedBytes']+=len(raw)
   if totals['selectedFiles']>MAX_FILES or totals['selectedBytes']>MAX_SELECTED:refuse()
   digest.update(json.dumps([relative,oid,len(raw),sha(raw)],ensure_ascii=False,separators=(',',':')).encode()+b'\n')
   if relative.endswith('.json') and not probe:
    record=exact_json(raw)
    if not isinstance(record,dict) or not isinstance(record.get('affected'),list):refuse()
    npm=False
    for entry in record['affected']:
     if not isinstance(entry,dict) or not isinstance(entry.get('package'),dict) or not isinstance(entry['package'].get('ecosystem'),str) or not isinstance(entry['package'].get('name'),str):refuse()
     npm|=entry['package']['ecosystem']=='npm'
    if npm:
     totals['npmRecords']+=1;totals['npmBytes']+=len(raw)
     if totals['npmRecords']>MAX_FILES or totals['npmBytes']>MAX_NPM:refuse()
     emit({'type':'npm','path':relative,'blobOID':oid,'sha256':sha(raw),'record':record})
  while True:
   tail=archive.fileobj.read(65536)
   if not tail:break
   if any(tail):refuse()
 if first or roots!={'github-reviewed','unreviewed'}:refuse()
 if probe:return {'type':'probe','prefix':prefix,'pax':{},'membersVerified':totals['allArchiveMembers']-1,'lastCanonicalPath':path,'expandedBytesRead':counted.count,'releaseAccepted':False}
 try:next(expected);refuse()
 except StopIteration:pass
 # Drain and charge all trailing tar padding; nonzero trailing data is ambiguous.
 while True:
  tail=counted.read(65536)
  if not tail:break
  if any(tail):refuse()
 return {**totals,'fullSelectedRosterSHA256':digest.hexdigest(),'expandedArchiveBytes':counted.count,'releaseAccepted':False}

class BatchTrees:
 def __init__(self,git,repository,guard):
  self.guard=guard;self.total=0;env=dict(os.environ);env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0')
  self.p=subprocess.Popen([git,'-c','protocol.allow=never','-C',repository,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,bufsize=0)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ);self.selector.register(self.p.stderr,selectors.EVENT_READ);self.buffer=bytearray();self.errors=0
 def fill(self,n):
  while len(self.buffer)<n:
   self.guard()
   for key,_ in self.selector.select(.1):
    b=os.read(key.fileobj.fileno(),min(65536,n-len(self.buffer)) if key.fileobj is self.p.stdout else 4096)
    if key.fileobj is self.p.stderr:
     self.errors+=len(b)
     if self.errors>65536 or b:refuse()
    elif not b:refuse()
    else:self.buffer.extend(b)
  out=bytes(self.buffer[:n]);del self.buffer[:n];return out
 def read(self,oid,kind='tree',maximum=MAX_TREE):
  if not valid_oid(oid):refuse()
  self.guard();self.p.stdin.write(oid.encode()+b'\n');header=bytearray()
  while not header.endswith(b'\n'):
   if len(header)>=128:refuse()
   header.extend(self.fill(1))
  fields=bytes(header[:-1]).split(b' ')
  if len(fields)!=3 or fields[0]!=oid.encode() or fields[1]!=kind.encode() or not fields[2].isdigit():refuse()
  size=int(fields[2]);self.total+=size
  if size>maximum or self.total>MAX_TREE_TOTAL:refuse()
  raw=self.fill(size)
  if self.fill(1)!=b'\n' or git_oid(kind,raw)!=oid:refuse()
  return raw
 def close(self):
  self.p.stdin.close()
  try:
   while self.p.poll() is None:self.guard();time.sleep(.01)
   if self.p.wait()!=0 or self.buffer or self.p.stdout.read(1) or self.p.stderr.read(65537):refuse()
  finally:self.selector.close()
 def stop(self):
  if self.p.poll() is None:
   self.p.terminate()
   try:self.p.wait(timeout=2)
   except subprocess.TimeoutExpired:self.p.kill();self.p.wait()
  self.selector.close()
  for stream in (self.p.stdin,self.p.stdout,self.p.stderr):
   if not stream.closed:stream.close()

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def transport(args):
 commit,workspace,git,gitpin,locksha,mode=args
 if not valid_oid(commit) or mode not in ('probe','scan') or len(locksha)!=64:refuse()
 work=Path(workspace)
 if work.resolve()!=work or not work.is_dir() or stat.S_IMODE(work.stat().st_mode)!=0o700 or work.stat().st_uid!=os.geteuid():refuse()
 gitpath=Path(git)
 if not gitpath.is_absolute() or gitpath.resolve()!=gitpath:refuse()
 fd=os.open(gitpath,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size>128<<20:refuse()
  digest=hashlib.sha256();read=0
  while True:
   part=os.read(fd,min(65536,(128<<20)-read+1))
   if not part:break
   read+=len(part)
   if read>128<<20:refuse()
   digest.update(part)
  after=os.fstat(fd);last=gitpath.lstat()
  identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
  if digest.hexdigest()!=gitpin or identity(before)!=identity(after) or identity(before)!=identity(last):refuse()
 finally:os.close(fd)
 work_identity=(work.stat().st_dev,work.stat().st_ino)
 end=time.monotonic()+600;cancelled=False;last_disk=[0]
 def stop(sig,frame):
  nonlocal cancelled
  cancelled=True
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
 def guard():
  if cancelled or time.monotonic()>=end:refuse()
  if time.monotonic()-last_disk[0]<.25:return
  last_disk[0]=time.monotonic()
  live=work.lstat()
  if not stat.S_ISDIR(live.st_mode) or (live.st_dev,live.st_ino)!=work_identity or work.resolve()!=work:refuse()
  if os.statvfs(work).f_bavail*os.statvfs(work).f_frsize<1536*1024*1024:refuse()
  size=0
  for base,dirs,files in os.walk(work,followlinks=False):
   for name in dirs:
    if stat.S_ISLNK(os.lstat(os.path.join(base,name)).st_mode):refuse()
   for name in files:
    st=os.lstat(os.path.join(base,name))
    if not stat.S_ISREG(st.st_mode):refuse()
    size+=st.st_size
  bare=0
  if (work/'transport.git').exists():
   for base,dirs,files in os.walk(work/'transport.git',followlinks=False):
    for name in files:
     n=os.lstat(os.path.join(base,name)).st_size
     if n>64<<20:refuse()
     bare+=n
  if bare>128<<20 or size>(MAX_ARCHIVE+MAX_TREE_TOTAL+(64<<20)):refuse()
 rewrite=subprocess.run([git,'config','--get-regexp',r'^url\..*\.(insteadOf|pushInsteadOf)$'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
 if rewrite.returncode!=1:refuse()
 repo=work/'transport.git'
 def command(argv):
  guard()
  with (work/'git-log').open('ab') as log:
   def file_limit():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE,(64<<20,64<<20))
   p=subprocess.Popen([git,*argv],stdin=subprocess.DEVNULL,stdout=log,stderr=log,preexec_fn=file_limit)
   try:
    while p.poll() is None:
     guard()
     if (work/'git-log').stat().st_size>1<<20 or b'filtering not recognized by server' in (work/'git-log').read_bytes().lower():refuse()
     time.sleep(.02)
    if p.wait()!=0:refuse()
   finally:
    if p.poll() is None:
     p.terminate()
     try:p.wait(timeout=2)
     except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
 command(['init','--bare',str(repo)])
 command(['-c','pack.threads=1','-c','fetch.unpackLimit=0','-C',str(repo),'fetch','--depth=1','--filter=blob:none','--no-tags','--no-recurse-submodules','--no-auto-maintenance','https://github.com/github/advisory-database.git',commit])
 reader=BatchTrees(git,str(repo),guard)
 try:
  raw=reader.read(commit,'commit',1<<20)
  from git_tree_roster_component import commit_root
  root=commit_root(commit,raw)
  root_rows=list(tree_entries(checked_tree(root,reader.read(root))))
  if not any(mode==b'100644' and name=='README.md' and oid=='55953843e49d9e4596d5d4784f2124678618cfdb' for mode,name,oid in root_rows):refuse()
  emit_frame({'type':'start','profile':'official-github-complete-source-stream-v2','commit':commit,'root':root,'lockSHA256':locksha},sys.stdout.buffer)
  url='https://codeload.github.com/github/advisory-database/tar.gz/'+commit
  opener=urllib.request.build_opener(NoRedirect)
  with opener.open(urllib.request.Request(url,headers={'User-Agent':'zasp-official-advisory-source-v2'}),timeout=30) as response:
   if response.status!=200:refuse()
   length=response.headers.get('Content-Length')
   if length is not None and (not length.isdigit() or int(length)>MAX_ARCHIVE):refuse()
   archivepath=work/'official.tar.gz'
   compressed_hash=hashlib.sha256()
   with archivepath.open('xb') as retained:
    class Tee:
     def read(self,n=-1):
      b=response.read(n);retained.write(b);compressed_hash.update(b);return b
    import gzip
    compressed=Counted(Tee(),(1<<20) if mode=='probe' else MAX_ARCHIVE,guard)
    expanded=gzip.GzipFile(fileobj=compressed,mode='rb')
    result=verify_archive(expanded,root,reader.read,commit,lambda value:emit_frame(value,sys.stdout.buffer),guard,mode=='probe')
    retained.flush();os.fsync(retained.fileno())
  reader.close();guard()
  result.update(type='probe' if mode=='probe' else 'final',commit=commit,root=root,lockSHA256=locksha,compressedBytes=compressed.count,compressedSHA256=compressed_hash.hexdigest())
  emit_frame(result,sys.stdout.buffer)
 finally:reader.stop()

if __name__=='__main__':
 try:
  if len(sys.argv)!=7:refuse()
  transport(sys.argv[1:])
 except BaseException:
  sys.stderr.write('official advisory stream refused\n');sys.exit(1)
