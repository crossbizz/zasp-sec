import os,pathlib,subprocess,time,signal,json,secrets,socket,urllib.request,uuid,sys,select
BASE=pathlib.Path('/tmp/zasp-native-supported-tools-h0zqa978')
OUT=pathlib.Path('/tmp/zr-'+uuid.uuid4().hex[:10]);OUT.mkdir(mode=0o700)
PG=BASE/'pg-bin';FGA=BASE/'openfga-complete/openfga';records=[];children=[];failed=None
stop=False;received=[];serving=False;renewals=0;terminal=False

def early_signal(sig,frame):
 global stop
 received.append(sig);stop=True
 if terminal:raise SystemExit(1)
signal.signal(signal.SIGTERM,early_signal);signal.signal(signal.SIGINT,early_signal)
pgport=54389;httpport=8088;grpcport=8089
for port in [pgport,httpport,grpcport]:
 s=socket.socket();s.bind(('127.0.0.1',port));s.close()
pw=secrets.token_hex(24);token=secrets.token_hex(32)
for name,value in [('pg-password',pw),('fga-token',token)]:
 fd=os.open(OUT/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,value.encode());os.fsync(fd);os.close(fd)
env={'HOME':'/home/agent','PATH':str(PG)+':/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(OUT)}
def floor():
 if stop and not serving:raise RuntimeError('signal before service-ready')
 for where,minimum in [('/workspace',1500000000),('/tmp',100000000)]:
  st=os.statvfs(where)
  if st.f_bavail*st.f_frsize<minimum:raise RuntimeError('unchanged storage floor')
def command(label,args,environment=env,seconds=30):
 floor();started=time.monotonic()
 with (OUT/(label+'.log')).open('xb') as log:
  proc=subprocess.Popen(args,env=environment,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  try:code=proc.wait(timeout=seconds)
  except BaseException:
   os.killpg(proc.pid,signal.SIGTERM)
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
   raise
 records.append({'phase':label,'returncode':code,'elapsedSeconds':time.monotonic()-started})
 if code:raise RuntimeError(label+' refused')
def spawn(label,args,environment):
 floor();log=(OUT/(label+'.log')).open('xb');proc=subprocess.Popen(args,env=environment,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);children.append((label,proc,log));return proc
def listener_owned(proc,port,expected):
 if proc.poll() is not None or os.path.realpath('/proc/'+str(proc.pid)+'/exe')!=str(expected):raise RuntimeError('Owned executable refused')
 raw=pathlib.Path('/proc/'+str(proc.pid)+'/stat').read_text();start=raw.rsplit(')',1)[1].split()[19]
 sockets=set()
 for entry in pathlib.Path('/proc/'+str(proc.pid)+'/fd').iterdir():
  try:target=os.readlink(entry)
  except FileNotFoundError:raise RuntimeError('Owned descriptor race')
  if target.startswith('socket:['):sockets.add(target[8:-1])
 wanted='0100007F:'+format(port,'04X');matches=[]
 for line in pathlib.Path('/proc/'+str(proc.pid)+'/net/tcp').read_text().splitlines()[1:]:
  fields=line.split()
  if fields[1]==wanted and fields[3]=='0A' and fields[9] in sockets:matches.append(fields[9])
 if len(matches)!=1 or pathlib.Path('/proc/'+str(proc.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]!=start:raise RuntimeError('Owned loopback listener refused')
 return {'pid':proc.pid,'startTicks':start,'port':port,'socketInode':matches[0],'exe':str(expected),'netNamespace':os.readlink('/proc/'+str(proc.pid)+'/ns/net')}
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
 data=OUT/'pgdata';command('initdb',[str(PG/'initdb'),'-D',str(data),'-L',str(BASE/'postgres18.3-root/usr/share/postgresql/18'),'--no-locale','--encoding=UTF8','--username=zasp_native','--pwfile='+str(OUT/'pg-password'),'--auth-local=trust','--auth-host=scram-sha-256'])
 pg=spawn('postgres',[str(PG/'postgres'),'-D',str(data),'-h','127.0.0.1','-p',str(pgport),'-k',str(OUT)],env)
 for _ in range(100):
  if pg.poll() is not None:raise RuntimeError('owned postgres exited')
  r=subprocess.run([str(PG/'pg_isready'),'-h','127.0.0.1','-p',str(pgport),'-U','zasp_native'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if r.returncode==0:break
  time.sleep(.1)
 else:raise RuntimeError('postgres readiness refused')
 command('create-fga-db',[str(PG/'psql'),'-h',str(OUT),'-p',str(pgport),'-U','zasp_native','-d','postgres','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE openfga'])
 fenv={'HOME':'/home/agent','PATH':'/usr/bin:/bin','TMPDIR':str(OUT),'OPENFGA_DATASTORE_ENGINE':'postgres','OPENFGA_DATASTORE_URI':'postgres://zasp_native:'+pw+'@127.0.0.1:'+str(pgport)+'/openfga?sslmode=disable','OPENFGA_HTTP_ADDR':'127.0.0.1:'+str(httpport),'OPENFGA_GRPC_ADDR':'127.0.0.1:'+str(grpcport),'OPENFGA_AUTHN_METHOD':'preshared','OPENFGA_AUTHN_PRESHARED_KEYS':token,'OPENFGA_PLAYGROUND_ENABLED':'false','OPENFGA_METRICS_ENABLED':'false','OPENFGA_LOG_LEVEL':'error'}
 command('fga-migrate',[str(FGA),'migrate'],fenv,30)
 fga=spawn('openfga',[str(FGA),'run'],fenv)
 for _ in range(100):
  floor()
  if fga.poll() is not None:raise RuntimeError('owned FGA exited')
  try:
   with opener.open('http://127.0.0.1:'+str(httpport)+'/healthz',timeout=1) as response:
    if response.status==200:break
  except Exception:pass
  time.sleep(.1)
 else:raise RuntimeError('FGA health refused')
 proofs=[listener_owned(pg,pgport,BASE/'postgres18.3-root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'),listener_owned(fga,httpport,FGA),listener_owned(fga,grpcport,FGA)]
 info={'ownedListenerProofs':proofs,'scope':'Owned native PG18.3 and authenticated FGA1.21 diagnostic service, not docPG17.7 or product-ready','pid':os.getpid(),'postgresPID':pg.pid,'fgaPID':fga.pid,'pgPort':pgport,'fgaURL':'http://127.0.0.1:'+str(httpport),'grpcPort':grpcport,'tokenFile':str(OUT/'fga-token'),'passwordFile':str(OUT/'pg-password'),'output':str(OUT),'modelSource':'/workspace/zasp-sec/services/platform/authorization/model.json','records':records}
 (OUT/'service-ready.json').write_text(json.dumps(info,indent=2)+'\n');os.chmod(OUT/'service-ready.json',0o600)
 print(json.dumps(info),flush=True)
 serving=True
 serviceStart=time.monotonic();until=serviceStart+900
 while not stop and time.monotonic()<until:
  floor()
  if any(proc.poll() is not None for _,proc,_ in children):raise RuntimeError('owned service exited')
  listener_owned(pg,pgport,BASE/'postgres18.3-root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2');listener_owned(fga,httpport,FGA);listener_owned(fga,grpcport,FGA)
  ready,_,_=select.select([sys.stdin],[],[],.2)
  if ready:
   line=sys.stdin.readline().strip()
   if line=='STOP':stop=True
   elif line=='RENEW' and renewals==0:
    renewals+=1;until=min(serviceStart+1800,time.monotonic()+900)
   elif line:raise RuntimeError('closed owner control refused')
   else:time.sleep(.2)
 if received:failed='SignalRefusal'
 elif not stop:failed='ServiceDeadlineRefusal'
except BaseException as exc:
 failed=type(exc).__name__;print(json.dumps({'failureClass':failed,'output':str(OUT)}),flush=True)
finally:
 cleanup=[]
 for label,proc,log in reversed(children):
  try:
   if proc.poll() is None:
    if label=='postgres':subprocess.run([str(PG/'pg_ctl'),'-D',str(OUT/'pgdata'),'-m','fast','-w','stop'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    else:os.killpg(proc.pid,signal.SIGTERM)
   code=proc.wait(timeout=15);cleanup.append({'name':label,'returncode':code,'joined':True})
  except BaseException as exc:
   cleanup.append({'name':label,'joined':False,'failureClass':type(exc).__name__});failed=failed or 'CleanupRefusal'
   try:
    if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL)
    proc.wait(timeout=5)
   except BaseException:pass
  log.close()
 for _,proc,_ in children:
  if proc.poll() is None:failed=failed or 'OwnedProcessAbsenceRefusal'
 for port in [pgport,httpport,grpcport]:
  try:
   with socket.socket() as check:check.bind(('127.0.0.1',port))
  except OSError:failed=failed or 'ListenerAbsenceRefusal'
 try:
  for where,minimum in [('/workspace',1500000000),('/tmp',100000000)]:
   st=os.statvfs(where)
   if st.f_bavail*st.f_frsize<minimum:failed=failed or 'FinalStorageFloorRefusal'
 except OSError:failed=failed or 'FinalStorageUnknown'
 if received:failed=failed or 'SignalRefusal'
 terminal=True
 result={'failureClass':failed,'signals':received,'renewals':renewals,'records':records,'cleanup':cleanup,'scope':'Owned service lifecycle only; actual SDK/domain test evidence separate'}
 (OUT/'service-final.json').write_text(json.dumps(result,indent=2)+'\n');os.chmod(OUT/'service-final.json',0o600)
 raise SystemExit(1 if failed else 0)
