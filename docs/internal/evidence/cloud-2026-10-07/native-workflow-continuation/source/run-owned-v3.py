import pathlib,os,json,subprocess,time,signal,socket,secrets,hashlib,yaml,re
OUT=pathlib.Path('/tmp/zasp-live-cleanup-continuation-d64usjal');BASE=pathlib.Path('/tmp/zasp-native-supported-tools-h0zqa978');PG=BASE/'pg-bin';SERVER=BASE/'temporal-server-complete/temporal-server';SQL=BASE/'temporal-server-complete/temporal-sql-tool';PORT=54391
STOP=False;TERMINAL=False;children=[];records=[];began=time.monotonic();deadline=began+330;failure=None;forced=False

def cancel(sig,frame):
 global STOP
 STOP=True
 if TERMINAL:raise SystemExit(1)
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(sig,cancel)
def guard():
 if STOP or time.monotonic()>deadline:raise RuntimeError('cancel or aggregate deadline')
 for place,floor in [('/workspace',1500000000),('/tmp',100000000)]:
  s=os.statvfs(place)
  if s.f_bavail*s.f_frsize<floor:raise RuntimeError('storage reserve')
def fixed_inputs():
 guard()
 raw=(OUT/'consumed-inputs.json').read_bytes()
 assert hashlib.sha256(raw).hexdigest()=='cec0823e401d2211cba5b2f84fe60ba06ca8e843a52c6e2c90174ab4aff737ed'
 for row in json.loads(raw)['inputs']:
  guard();p=pathlib.Path(row['path'])
  assert str(p.resolve())==row['resolvedPath'] and p.stat().st_size==row['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256']
 for row in json.loads((OUT/'preflight.json').read_bytes())['sourceFiles']:
  assert hashlib.sha256(pathlib.Path(row['path']).read_bytes()).hexdigest()==row['sha256']
 guard()
def launch(label,args,env,cwd=OUT,stdin=None):
 guard();log=(OUT/(label+'.private.log')).open('xb');proc=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);children.append((label,proc,log));start=(pathlib.Path('/proc')/str(proc.pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
 if stdin is not None:proc.stdin.write(stdin);proc.stdin.close()
 return proc,start
def command(label,args,env,seconds=30,stdin=None):
 start=time.monotonic();proc,ticks=launch(label,args,env,stdin=stdin)
 while proc.poll() is None:
  guard()
  if time.monotonic()-start>seconds:raise RuntimeError('command deadline')
  time.sleep(.05)
 records.append({'phase':label,'pid':proc.pid,'startTicks':ticks,'returncode':proc.returncode,'normalJoined':True,'elapsedSeconds':time.monotonic()-start})
 if proc.returncode:raise RuntimeError(label+' refusal')
def listener(proc,port,expected):
 guard();root=pathlib.Path('/proc')/str(proc.pid);before=(root/'stat').read_text().rsplit(')',1)[1].split()[19]
 if os.path.realpath(root/'exe')!=str(expected):raise RuntimeError('owned executable')
 sockets=set()
 for f in (root/'fd').iterdir():
  try:x=os.readlink(f)
  except FileNotFoundError:continue
  if x.startswith('socket:['):sockets.add(x[8:-1])
 matches=[r.split()[9] for r in (root/'net/tcp').read_text().splitlines()[1:] if r.split()[1]=='0100007F:'+format(port,'04X') and r.split()[3]=='0A' and r.split()[9] in sockets]
 if len(matches)!=1 or (root/'stat').read_text().rsplit(')',1)[1].split()[19]!=before:raise RuntimeError('owned listener')
 return {'pid':proc.pid,'startTicks':before,'port':port,'socketInode':matches[0],'exe':str(expected)}
pw=secrets.token_hex(24);rolepw=secrets.token_hex(24);pwpath=OUT/'pg-password';pwpath.write_text(pw);pwpath.chmod(0o600)
penv={'HOME':'/home/agent','PATH':str(PG)+':/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(OUT),'LD_LIBRARY_PATH':str(BASE/'pg-non-glibc-libs')}
tenv={'HOME':'/home/agent','PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(OUT)}
try:
 fixed_inputs()
 for port in [PORT,7233,7234,7235,7239,6933,6934,6935,6939,9090]:
  with socket.socket() as s:s.bind(('127.0.0.1',port))
 assert hashlib.sha256(SERVER.read_bytes()).hexdigest()=='c054d42ddfd63c9358a7db15a05fa106e7f4ef52b06d08bd5566ac2ad400fb9e'
 assert hashlib.sha256(SQL.read_bytes()).hexdigest()=='20e0a62ba2de523cd54c6a481d372d18acf3bafccabef3ee5ee7d4cdd5b1ef0c'
 compiled=json.loads((OUT/'compile-result.json').read_bytes());assert compiled['returncode']==0 and compiled['failureClass'] is None
 assert hashlib.sha256((OUT/'orchestration.test').read_bytes()).hexdigest()==compiled['binarySHA256']
 command('initdb',[str(PG/'initdb'),'-D',str(OUT/'pgdata'),'-L',str(BASE/'postgres18.3-root/usr/share/postgresql/18'),'--no-locale','--encoding=UTF8','--username=zasp_native','--pwfile='+str(pwpath),'--auth-local=trust','--auth-host=scram-sha-256'],penv)
 pg,pgticks=launch('postgres',[str(PG/'postgres'),'-D',str(OUT/'pgdata'),'-h','127.0.0.1','-p',str(PORT),'-k',str(OUT)],penv)
 until=time.monotonic()+20
 while True:
  guard()
  if pg.poll() is not None:raise RuntimeError('postgres exited')
  try:pgbinding=listener(pg,PORT,BASE/'postgres18.3-root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2');break
  except (RuntimeError,FileNotFoundError):
   if time.monotonic()>until:raise
   time.sleep(.1)
 sqltext=("CREATE ROLE zt_exec LOGIN PASSWORD '"+rolepw+"';\nCREATE ROLE zt_vis LOGIN PASSWORD '"+rolepw+"';\nCREATE DATABASE zt_execution OWNER zt_exec;\nCREATE DATABASE zt_visibility OWNER zt_vis;\n").encode()
 command('owned-databases',[str(PG/'psql'),'-h',str(OUT),'-p',str(PORT),'-U','zasp_native','-d','postgres','-v','ON_ERROR_STOP=1'],penv,stdin=sqltext)
 for domain,role,db in [('temporal','zt_exec','zt_execution'),('visibility','zt_vis','zt_visibility')]:
  env={**tenv,'SQL_HOST':'127.0.0.1','SQL_PORT':str(PORT),'SQL_PLUGIN':'postgres12','SQL_USER':role,'SQL_PASSWORD':rolepw,'SQL_DATABASE':db}
  command('setup-'+domain,[str(SQL),'setup-schema','-v','0.0'],env)
  command('update-'+domain,[str(SQL),'update-schema','-d','/tmp/zasp-temporal132-schema-intake/schema/postgresql/v12/'+domain+'/versioned'],env)
 config=yaml.safe_load(pathlib.Path('/tmp/zasp-temporal132-pg-qafobrl1/private-temporal.yaml').read_bytes())
 stores=config['persistence']['datastores']
 for key,role,db in [('default','zt_exec','zt_execution'),('visibility','zt_vis','zt_visibility')]:
  stores[key]['sql'].update({'connectAddr':'127.0.0.1:'+str(PORT),'user':role,'password':rolepw,'databaseName':db})
 conf=OUT/'private-temporal.yaml';conf.write_text(yaml.safe_dump(config,sort_keys=False));conf.chmod(0o600)
 temporal,tticks=launch('temporal',[str(SERVER),'--config-file',str(conf),'--allow-no-auth','start'],tenv)
 until=time.monotonic()+45
 while True:
  guard()
  if temporal.poll() is not None:raise RuntimeError('Temporal exited')
  try:tbinding=listener(temporal,7233,SERVER);break
  except (RuntimeError,FileNotFoundError):
   if time.monotonic()>until:raise
   time.sleep(.1)
 (OUT/'readiness.json').write_text(json.dumps({'postgres':pgbinding,'temporal':tbinding,'scope':'Owned loopback listeners; test outcome separately recorded'},sort_keys=True,indent=2)+'\n')
 testenv={**tenv,'ZASP_SINGLE_TEST_LIVE_TEMPORAL':'true'}
 command('actual-original-test',[str(OUT/'orchestration.test'),'-test.run=^TestSingleTestLiveCleanupContinuation$','-test.v','-test.count=1','-test.timeout=150s'],testenv,seconds=155)
except BaseException as e:failure=type(e).__name__
finally:
 cleanup=[]
 for label,proc,log in reversed(children):
  try:
   if proc.poll() is None:
    if label=='postgres':
     r=subprocess.run([str(PG/'pg_ctl'),'-D',str(OUT/'pgdata'),'-m','fast','-w','stop'],env=penv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
     if r.returncode:raise RuntimeError('pg_ctl refusal')
    else:os.killpg(proc.pid,signal.SIGTERM)
   proc.wait(timeout=30)
   cleanup.append({'phase':label,'pid':proc.pid,'returncode':proc.returncode,'normalJoined':True,'pidAbsent':not pathlib.Path('/proc',str(proc.pid)).exists()})
  except BaseException as e:
   forced=True;failure=failure or 'CleanupRefusal'
   if proc.poll() is None:
    try:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
    except BaseException:pass
   cleanup.append({'phase':label,'pid':proc.pid,'normalJoined':False,'failureClass':type(e).__name__})
  log.close()
 ports={}
 for port in [PORT,7233,7234,7235,7239,6933,6934,6935,6939,9090]:
  try:
   with socket.socket() as s:s.bind(('127.0.0.1',port))
   ports[str(port)]=True
  except OSError:ports[str(port)]=False;failure=failure or 'PortAbsenceRefusal'
 unchanged=True
 for row in json.loads((OUT/'preflight.json').read_bytes())['sourceFiles']:
  if hashlib.sha256(pathlib.Path(row['path']).read_bytes()).hexdigest()!=row['sha256']:unchanged=False;failure=failure or 'SourceDrift'
 if STOP:failure=failure or 'SignalRefusal'
 try:
  fixed_inputs()
  text=(OUT/'actual-original-test.private.log').read_text()
  assert re.findall(r'^=== RUN   (.+)$',text,re.M)==['TestSingleTestLiveCleanupContinuation']
  assert re.findall(r'^--- PASS: ([^ ]+)',text,re.M)==['TestSingleTestLiveCleanupContinuation']
  assert not re.search(r'^--- (?:SKIP|FAIL):',text,re.M) and re.search(r'^PASS$',text,re.M)
 except BaseException as e:failure=failure or 'FinalAcceptanceRefusal'
 TERMINAL=True
 try:guard()
 except BaseException:failure=failure or 'TerminalAcceptanceRefusal'
 result={'status':'PASS' if failure is None else 'FAILED','failureClass':failure,'forcedCleanup':forced,'records':records,'cleanup':cleanup,'portsBindable':ports,'sourceUnchanged':unchanged,'elapsedSeconds':time.monotonic()-began,'scope':'Original real-app cleanup continuation test with controlled Product only; no full API/production/provider acceptance.'}
 (OUT/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({'resultPath':str(OUT/'result.json'),'status':result['status'],'failureClass':failure}),flush=True)
 try:guard()
 except BaseException:
  failure=failure or 'TerminalAcceptanceRefusal';result['status']='FAILED';result['failureClass']=failure
  (OUT/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 raise SystemExit(1 if failure else 0)
