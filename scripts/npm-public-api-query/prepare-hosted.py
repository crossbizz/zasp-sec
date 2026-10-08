"""Hosted metadata/source formation only; no HTTP, secrets or package installs."""
from pathlib import Path
import os,sys,json,hashlib,stat,shutil
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  while True:
   b=f.read(1048576)
   if not b:break
   h.update(b)
 return h.hexdigest()
def descriptor(p):
 p=Path(p);r=p.resolve(strict=True);a=p.lstat();fd=os.open(r,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size>134217728:raise ValueError('tool/source bound')
  h=hashlib.sha256();total=0
  while True:
   raw=os.read(fd,1048576)
   if not raw:break
   total+=len(raw)
   if total>134217728:raise ValueError('tool/source bound')
   h.update(raw)
  f=lambda x:[x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
  if f(before)!=f(os.fstat(fd)) or f(before)!=f(r.lstat()) or f(a)!=f(p.lstat()):raise ValueError('tool/source changed')
  return dict(requested=str(p),resolved=str(r),sha256=h.hexdigest(),metadata=f(before),requestedMetadata=f(a))
 finally:os.close(fd)
def main():
 if len(sys.argv)!=2 or not Path(sys.argv[1]).is_absolute():raise ValueError('output argument')
 out=Path(sys.argv[1]);source_manifest=BASE/'source-manifest.json';source=json.loads(source_manifest.read_bytes());inputs=[]
 for row in source['files']:
  p=ROOT/row['path'];d=descriptor(p)
  if d['sha256']!=row['sha256']:raise ValueError('source manifest mismatch')
  inputs.append(d)
 inputs.append(descriptor(source_manifest));lock=ROOT/'package-lock.json';d=descriptor(lock)
 if d['sha256']!='0e8b7fa1332878386816dd73ba0118fb8dfc8a414b7912f90e95f2dda8bae51c':raise ValueError('issued public lock mismatch')
 inputs.append(d)
 node=Path(shutil.which('node')).resolve(strict=True);gh=Path(shutil.which('gh')).resolve(strict=True)
 tools=[descriptor(p) for p in [node,gh,Path(sys.executable),Path(shutil.which('timeout')),Path(shutil.which('env'))]]
 if tools[0]['sha256']!='93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068':raise ValueError('official Node22 byte pin')
 value=dict(format='hosted-public-lock-query-plan-v1',sourceBase=str(BASE),publicLock=str(lock),workspacePath=str(ROOT),nodeExecutable=str(node),ghExecutable=str(gh),memoryCLI=str(BASE/'memory-cli.mjs'),memoryModule=str(ROOT/'scripts/hosted-memory-observation.mjs'),inputs=inputs,tools=tools,scope='Tool bytes/security formed on actual hosted runner; Node22 known artifact pin, other preinstalled runner tools observed hashes—not separately claimed vendor archive verification.')
 raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  offset=0
  while offset<len(raw):
   n=os.write(fd,raw[offset:])
   if n<=0:raise ValueError('write progress')
   offset+=n
  os.fsync(fd)
 finally:os.close(fd)
 directory=os.open(out.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(directory)
 finally:os.close(directory)
 print(hashlib.sha256(raw).hexdigest())
if __name__=='__main__':main()
