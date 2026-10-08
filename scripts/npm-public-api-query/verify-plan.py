from pathlib import Path
import sys,json,hashlib,importlib.util,os,stat
p=Path(sys.argv[1]);expected=sys.argv[2]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 if not stat.S_ISREG(before.st_mode) or before.st_size>1048576:raise ValueError('plan bound')
 raw=os.read(fd,1048577)
 fields=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
 if len(raw)>1048576 or fields(before)!=fields(os.fstat(fd)) or fields(before)!=fields(p.lstat()):raise ValueError('plan changed')
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('plan hash')
spec=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare-hosted.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
plan=json.loads(raw)
for pin in plan['inputs']+plan['tools']:
 if module.descriptor(pin['requested'])!=pin:raise ValueError('source/tool changed')
print('source/tool full bytes and metadata unchanged')
