"""Bounded offline grouped controls; no advisory HTTP acquisition."""
from pathlib import Path
import os,sys,tempfile,subprocess,json,hashlib,time
BASE=Path(__file__).resolve().parent
OUT=Path(sys.argv[1]);OUT.mkdir(mode=0o700,parents=True,exist_ok=True)
projection=Path(tempfile.mkdtemp(prefix='npm-query-omitted-malware-',dir='/tmp'))
for name in ['cursor_component.py','public_lock_adapter.py','public_lock_controls.py']:
 raw=(BASE/name).read_bytes()
 if name=='cursor_component.py':
  old=b"KINDS = ('reviewed', 'unreviewed', 'malware')"
  if raw.count(old)!=1:raise ValueError('baseline inverse count')
  raw=raw.replace(old,b"KINDS = ('reviewed', 'unreviewed')")
 (projection/name).write_bytes(raw)
rows=[]
env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
for name,cwd,args,expected in [
 ('omitted-malware-red',projection,[sys.executable,'-B','public_lock_controls.py','-v','Controls.test_actual_public_lock_whole_hash_and_complete_projection'],1),
 ('grouped-green',BASE,[sys.executable,'-B','-m','unittest','discover','-s',str(BASE),'-p','*controls.py','-v'],0)]:
 started=time.monotonic()
 with (OUT/(name+'.stdout')).open('xb') as out,(OUT/(name+'.stderr')).open('xb') as err:
  child=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=10s','30s',*args],cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
  rc=child.wait()
  out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
 raw=(OUT/(name+'.stderr')).read_bytes()
 if len(raw)+(OUT/(name+'.stdout')).stat().st_size>4194304:raise ValueError('control capture bound')
 text=raw.decode('utf-8','strict')
 if rc!=expected:raise ValueError('control exit refusal')
 if name=='omitted-malware-red' and not all(s in text for s in ['38 != 57','Ran 1 test','FAILED (failures=1)']):raise ValueError('causal baseline refusal')
 if name=='grouped-green' and not all(s in text for s in ['Ran 16 tests','\nOK\n']):raise ValueError('grouped census refusal')
 rows.append(dict(stage=name,normalWaitExit=rc,elapsedSeconds=time.monotonic()-started,stdoutSHA256=hashlib.sha256((OUT/(name+'.stdout')).read_bytes()).hexdigest(),stderrSHA256=hashlib.sha256(raw).hexdigest()))
(OUT/'controls-result.json').write_text(json.dumps(dict(stages=rows,scope='Offline source-adapted omission RED and sixteen grouped component controls only; no upstream acquisition or release clearance.'),indent=2)+'\n')
