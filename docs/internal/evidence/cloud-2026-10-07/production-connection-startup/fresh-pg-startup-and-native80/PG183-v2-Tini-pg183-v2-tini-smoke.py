import pathlib,os,json,subprocess,time,tempfile,hashlib,socket
base=pathlib.Path('/tmp/zasp-pg183-current');v2=base/'pg-bin-v2'
out=pathlib.Path(tempfile.mkdtemp(prefix='pg183-v2-owned-tool-smoke-',dir='/tmp'));sock=out/'socket';sock.mkdir();data=out/'data';port=54397;records=[];started=False;pid=None;failure=None;begin=time.monotonic()
env=dict(os.environ,TMPDIR=str(out));minimum={}
def guard():
 assert time.monotonic()-begin<90
 for p,f in [('/workspace',1500000000),('/tmp',100000000)]:
  free=os.statvfs(p).f_bavail*os.statvfs(p).f_frsize;minimum[p]=min(minimum.get(p,free),free);assert free>=f
def run(label,args,limit=20):
 guard();r=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=limit);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);records.append({'stage':label,'exit':r.returncode,'stdoutBytes':len(r.stdout),'stderrBytes':len(r.stderr),'stdoutSHA256':hashlib.sha256(r.stdout).hexdigest(),'stderrSHA256':hashlib.sha256(r.stderr).hexdigest()});assert r.returncode==0;return r
s=socket.socket();s.bind(('127.0.0.1',port));s.close()
try:
 run('initdb',[str(v2/'initdb'),'-D',str(data),'-U','zasp_tool_smoke','-A','trust','--locale=C'])
 run('start',[str(v2/'pg_ctl'),'-D',str(data),'-l',str(out/'server.log'),'-w','-t','15','start','-o',f'-h 127.0.0.1 -p {port} -k {sock}']);started=True;pid=int((data/'postmaster.pid').read_text().splitlines()[0])
 run('ready',[str(v2/'pg_isready'),'-h','127.0.0.1','-p',str(port),'-U','zasp_tool_smoke'])
 run('select',[str(v2/'psql'),'-h',str(sock),'-p',str(port),'-U','zasp_tool_smoke','-d','postgres','-Atc','SELECT 1'])
except Exception as e:failure=type(e).__name__
finally:
 if (data/'postmaster.pid').exists():
  try:run('normal-stop',[str(v2/'pg_ctl'),'-D',str(data),'-w','-t','15','-m','fast','stop'])
  except Exception as e:failure=failure or 'cleanup_'+type(e).__name__
reap_end=time.monotonic()+2
while pid is not None and pathlib.Path('/proc',str(pid)).exists() and time.monotonic()<reap_end:time.sleep(.02)
absent=pid is not None and not pathlib.Path('/proc',str(pid)).exists();bindable=False
try:s=socket.socket();s.bind(('127.0.0.1',port));s.close();bindable=True
except OSError:pass
result={'format':'fresh-PG183-v2-Tini-owned-tool-smoke-v1','scope':'Fresh Tini foreground subreaper owned initdb/start/readiness/SELECT1/normalstop only; no application/native80/PG internals acceptance.','failure':failure,'records':records,'directServerPID':pid,'directServerAbsent':absent,'portBindable':bindable,'port':port,'postmasterPIDFileAbsent':not (data/'postmaster.pid').exists(),'minimumFreeBytes':minimum,'elapsed':time.monotonic()-begin,'wrapperPins':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in v2.iterdir()},'completed':failure is None and absent and bindable}
p=out/'result.json';p.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'directory':str(out),'resultSHA256':hashlib.sha256(p.read_bytes()).hexdigest(),'result':result}))
