import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, chmod, lstat, statfs, stat, readdir } from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import {openSync,writeSync,fsyncSync,closeSync,constants} from 'node:fs';
import { captureStart, observeOwnedListener } from './owned-listener.mjs';
import { spawnOwnedCommand } from './owned-command.mjs';
import { loadOfficialHeldTool, spawnHeldTool, closeHeldTool, verifyHeldTool } from './official-held-tools.mjs';

// Exact original application test; no new test cases, credentials or deployment.
const image = 'postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba';
const pins = {
 'services/platform/apiserver/connector_enqueue_provenance_postgres_test.go':'d6039cfa0d1673a5cf29e68e209b73c2cb6aeefd715e4d7805d3690b8ab0afde',
 'services/platform/migrations/sql/connector_enqueue_provenance.sql':'32b3f8cbe175b5256ff4542cdff044d6d060e0240d24632bf3d057f3553a5c13',
 'services/platform/migrations/production_connector_enqueue_provenance.go':'809041eced547701b1e3ac3c1f68ac45d7b403336f5de6df4dda13b10db83267',
};
const top='TestConnectorCapturedEnqueueOriginalAuthorizationPostgres';
const cases=['authentic_capture_and_exact_replay','wrong_signed_purpose','wrong_selected_scope','modified_signed_envelope','existing_originless_effect_refused','later_transaction_failure_rolls_back_enqueue_and_origin','own_catalog_drift_refused','outbox_consumer_cannot_capture','required_inputs_concurrent_replay_and_savepoint_ownership'];
const helperPins={
 "scripts/owned-command.mjs": "044e151c9260b9356ac78e5cde6b59dbbdd7b934d66ad06732288346831ad47e",
 "scripts/owned-fixed-fd-command.mjs": "15c38bd9d627124b7d81e5fe9b96dd3c4af8757b33f2204a9dce4b86e93e5693",
 "scripts/official-held-tools.mjs": "451dad7212561fc02e1f5b03280672c9d900a5ac644a665c022deafa9f72dfdd",
 "scripts/owned-listener.mjs": "3e5a4357fb53a412d0c38ab608c49543cf1bf74b2bb624022791a8bb6d1a43de",
 "services/platform/apiserver/postgres_integration_test.go": "0d908c53cdea021e4c60adc412a04d631fd58c0b0544e7cce723884ea4002a42",
 "services/platform/apiserver/approval_maintenance_owned_fga_test.go": "e505c27d07bde5948d7ec4f4612ffc28ccb2b68f37bebc842e91cec0d5066647"
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root=process.cwd();const selfSHA256=hash(await readFile(new URL(import.meta.url)));
assert.equal(process.version,'v22.23.1');
assert.ok(path.isAbsolute(process.env.RUNNER_TEMP??''));
const out=await mkdtemp(path.join(process.env.RUNNER_TEMP,'connector-nine-'));
const end=performance.now()+1500_000;
let tokenForRedaction='', canceled=false, finished=false, refused=false, container, tool, fga, fgaPort, grpcPort, fgaStart;
const owners=new Set();let phase='source-admission';
const receipt={scope:'original connector captured-inactive native integration only',completed:false,activated:false,production:false,testPins:pins,helperPins,selfSHA256,pgImage:image,commands:[],authStatuses:[],normalCleanup:false};
function lateRefusal(reason){let fd;try{fd=openSync(path.join(out,'late-refusal.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);const bytes=Buffer.from(JSON.stringify({completed:false,reason})+'\n');let offset=0;while(offset<bytes.length){const written=writeSync(fd,bytes,offset,bytes.length-offset);assert.ok(written>0);offset+=written;}fsyncSync(fd);closeSync(fd);fd=undefined;const directory=openSync(out,constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(directory);}finally{closeSync(directory);}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}finally{if(fd!==undefined)try{closeSync(fd);}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}}}
function signal(){canceled=true; if(finished){lateRefusal('late-signal');process.exit(1);} for(const owner of owners)void owner.stop().catch(()=>{refused=true;});}
process.on('SIGTERM',signal);process.on('SIGINT',signal);
function guard(){assert.ok(!canceled&&!refused&&performance.now()<end,'owned integration refused');}
async function floors(){for(const [dir,min]of [[root,1500000000],[out,100000000]]){const v=await statfs(dir);assert.ok(v.bavail*v.bsize>=min);}const maximum=(await readFile('/sys/fs/cgroup/memory.max','utf8')).trim();let available;if(maximum!=='max'){const current=Number((await readFile('/sys/fs/cgroup/memory.current','utf8')).trim());available=Number(maximum)-current;receipt.memoryObservationBasis='cgroup-max-minus-current';}else{const match=/^MemAvailable:\s+([0-9]+) kB$/m.exec(await readFile('/proc/meminfo','utf8'));assert.ok(match);available=Number(match[1])*1024;receipt.memoryObservationBasis='host-MemAvailable-unlimited-cgroup';}assert.ok(available>=268435456);}
let sampling, samplingStopped=false;const sampler=setInterval(()=>{if(samplingStopped||sampling)return;sampling=floors().catch(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});}).finally(()=>{sampling=undefined;});},250);const aggregateTimer=setTimeout(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});},1500_000);
const closed={PATH:process.env.PATH,LANG:'C.UTF-8',HOME:path.join(out,'home'),TMPDIR:out,GOENV:'off',GOWORK:'off',GOTOOLCHAIN:'local',GOFLAGS:'',GOPRIVATE:'',GONOPROXY:'',GONOSUMDB:'',GOSUMDB:'sum.golang.org',GOPROXY:'https://proxy.golang.org',GOCACHE:path.join(out,'go-cache'),GOMODCACHE:path.join(out,'module-cache'),GOMEMLIMIT:'256MiB',GOGC:'20',GOMAXPROCS:'2',PGOPTIONS:'-c jit=off'};
for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy','SSL_CERT_FILE','CURL_CA_BUNDLE'])if(typeof process.env[key]==='string')closed[key]=process.env[key];
async function run(exe,args,seconds=60,env=closed,cleanup=false){if(!cleanup){guard();await floors();guard();}const owner=spawnOwnedCommand(exe,args,{cwd:root,env,maxOutputBytes:8*1024*1024});owners.add(owner);let timed=false;const timer=setTimeout(()=>{timed=true;void owner.stop().catch(()=>{refused=true;});},cleanup?seconds*1000:Math.min(seconds*1000,end-performance.now()));let result;
 try{result=await owner.completed;receipt.commands.push({command:exe==='docker'?'docker':path.basename(exe),status:result.status,signal:result.signal,outputLimitExceeded:result.outputLimitExceeded,stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr),stdoutSHA256:hash(result.stdout),stderrSHA256:hash(result.stderr)});assert.ok(!timed&&(cleanup||!canceled)&&result.status===0&&!result.signal&&!result.outputLimitExceeded,'owned command refused');if(!cleanup)guard();return result;}
 finally{clearTimeout(timer);await owner.stop();owners.delete(owner);}
}
async function port(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const value=server.address().port;await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));return value;}
async function absent(pid){try{process.kill(pid,0);return false;}catch(error){assert.equal(error.code,'ESRCH');return true;}}
async function sessionEmpty(sid){const names=(await readdir('/proc')).filter(name=>/^[0-9]+$/.test(name));assert.ok(names.length<=8192);for(const name of names){let row;try{row=await readFile('/proc/'+name+'/stat','utf8');}catch(error){if(error.code==='ENOENT')continue;throw error;}assert.ok(row.length<=16384);const fields=row.slice(row.lastIndexOf(')')+1).trim().split(/\s+/);if(Number(fields[3])===sid)return false;}return true;}
async function bindable(value){const s=net.createServer();await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(value,'127.0.0.1',resolve);});await new Promise(resolve=>s.close(resolve));}
async function auth(url,token){guard();const response=await fetch(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(5000),headers:token?{Authorization:'Bearer '+token}: {}});try{let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;assert.ok(bytes<=65536);}return response.status;}finally{await response.body?.cancel().catch(()=>{});}}
async function sourcePins(){assert.equal(hash(await readFile(new URL(import.meta.url))),selfSHA256);for(const [file,pin]of Object.entries({...pins,...helperPins}))assert.equal(hash(await readFile(path.join(root,file))),pin);}
try{
 await floors();await sourcePins();for(const name of ['home','go-cache','module-cache'])await mkdir(path.join(out,name),{mode:0o700});
 assert.match((await run('go',['version'],5)).stdout,/^go version go1\.26\.8 linux\/amd64\n$/);
 const sums={};for(const file of ['services/platform/go.mod','services/platform/go.sum'])sums[file]=hash(await readFile(path.join(root,file)));
 phase='locked-module-prime';await run('go',['list','-C','services/platform','-mod=readonly','-deps','-test','./apiserver'],300);
 for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
 phase='pinned-postgres-intake';await run('docker',['--host=unix:///var/run/docker.sock','pull',image],180);
 const inspected=JSON.parse((await run('docker',['--host=unix:///var/run/docker.sock','image','inspect',image])).stdout);assert.ok(inspected.length===1&&inspected[0].RepoDigests.includes(image));
 container=(await run('docker',['--host=unix:///var/run/docker.sock','create','--name','zasp-connector-pg-extract-'+randomBytes(8).toString('hex'),'--network=none','--read-only','--entrypoint=/bin/true',image])).stdout.trim();assert.match(container,/^[a-f0-9]{64}$/);
 const pg=path.join(out,'pg');await mkdir(pg,{mode:0o700});
 for(const [source,destination]of [['/usr/local',path.join(pg,'local')],['/usr/lib/x86_64-linux-gnu',path.join(pg,'lib')],['/lib64/ld-linux-x86-64.so.2',path.join(pg,'loader')]])await run('docker',['--host=unix:///var/run/docker.sock','cp','-L',container+':'+source,destination]);
 await run('docker',['--host=unix:///var/run/docker.sock','rm',container]);container=undefined;
 const bin=path.join(pg,'bin');await mkdir(bin,{mode:0o700});
 assert.ok((await lstat(path.join(pg,'local/share/postgresql/postgres.bki'))).isFile());
 for(const name of ['postgres','initdb','pg_ctl','pg_isready','psql','pg_config']){
  const binary=path.join(pg,'local/bin',name);assert.ok((await lstat(binary)).isFile());
  const prefix=name==='initdb'?`set -- -L '${pg}/local/share/postgresql' "$@"\n`:name==='pg_ctl'?`set -- -p '${bin}/postgres' "$@"\n`:name==='pg_config'?`if [ "$#" -eq 1 ] && [ "$1" = --bindir ]; then printf '%s\\n' '${bin}'; exit 0; fi\n`:'';
  await writeFile(path.join(bin,name),`#!/bin/sh\nset -eu\n${prefix}exec '${pg}/loader' --library-path '${pg}/lib:${pg}/local/lib' '${binary}' "$@"\n`,{mode:0o500,flag:'wx'});
 }
 const testEnv={...closed,GOPROXY:'off',PATH:bin+':'+closed.PATH,ZASP_P7_MODEL_TEST:'1'};
 assert.match((await run(path.join(bin,'postgres'),['--version'],5,testEnv)).stdout,/PostgreSQL\) 18\.3\n$/);
 phase='pinned-openfga-intake';const archive=path.join(out,'openfga.tar.gz');
 await run('/usr/bin/curl',['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-time','90','--max-filesize','21232870','--output',archive,'https://github.com/openfga/openfga/releases/download/v1.21.0/openfga_1.21.0_linux_amd64.tar.gz'],95);await chmod(archive,0o400);
 tool=await loadOfficialHeldTool('openfga',archive,path.join(out,'openfga-held'));receipt.fgaTool=await verifyHeldTool(tool);
 const token=tokenForRedaction=randomBytes(32).toString('hex'),tokenFile=path.join(out,'token');await writeFile(tokenFile,token,{mode:0o600,flag:'wx'});
 fgaPort=await port();grpcPort=await port();assert.notEqual(fgaPort,grpcPort);
 phase='owned-openfga-start';fga=await spawnHeldTool(tool,['run'],{cwd:out,env:{PATH:'/usr/bin:/bin',HOME:closed.HOME,TMPDIR:out,OPENFGA_HTTP_ADDR:'127.0.0.1:'+fgaPort,OPENFGA_GRPC_ADDR:'127.0.0.1:'+grpcPort,OPENFGA_DATASTORE_ENGINE:'memory',OPENFGA_AUTHN_METHOD:'preshared',OPENFGA_AUTHN_PRESHARED_KEYS:token,OPENFGA_PLAYGROUND_ENABLED:'false',OPENFGA_METRICS_ENABLED:'false',OPENFGA_LOG_LEVEL:'warn'},maxOutputBytes:65536});owners.add(fga);fgaStart=await captureStart(fga.child.pid);const executable=await stat('/proc/'+fga.child.pid+'/exe');assert.equal(executable.dev,receipt.fgaTool.device);assert.equal(executable.ino,receipt.fgaTool.inode);
 let serviceExited=false;void fga.completed.then(()=>{serviceExited=true;},()=>{serviceExited=true;});
 const url='http://127.0.0.1:'+fgaPort,readyEnd=performance.now()+30000;
 for(;;){guard();assert.ok(!serviceExited&&performance.now()<readyEnd);try{await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:fgaPort});await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:grpcPort});const health=await auth(url+'/healthz',null),denied=await auth(url+'/stores',null),wrong=await auth(url+'/stores',randomBytes(32).toString('hex')),allowed=await auth(url+'/stores',token);if(health===200&&denied===401&&wrong===401&&allowed===200){receipt.authStatuses=[health,denied,wrong,allowed];break;}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}await new Promise(resolve=>setTimeout(resolve,100));}
 testEnv.ZASP_P6_NATIVE_OPENFGA_URL=url;testEnv.ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE=tokenFile;
 phase='original-singleton-nine';const test=await run('go',['test','-C','services/platform','-json','-race','-p=1','-count=1','-timeout=10m','-run','^'+top+'$','./apiserver'],650,testEnv);
 phase='exact-roster-and-postgres-cleanup';const rows=test.stdout.trim().split('\n').map(line=>JSON.parse(line));assert.ok(rows.every(row=>row.Action!=='fail'&&row.Action!=='skip'));
 const expected=[top,...cases.map(name=>top+'/'+name)];for(const action of ['run','pass'])assert.deepEqual(rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test).sort(),expected.slice().sort());assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,1);
 const outputs=rows.map(row=>row.Output??'').join('');const joined=[...outputs.matchAll(/joined owned PostgreSQL pid=(\d+).*pg_ctl exit=0 server Wait exit=0 normal-exit/g)];assert.equal(joined.length,1);assert.ok(await absent(Number(joined[0][1])));
 assert.ok(!test.stdout.includes(token)&&!test.stderr.includes(token));receipt.test={names:expected,tops:1,subcases:9,skips:0,packagePass:true,postgresNormalJoined:true,postgresPIDAbsent:true};
 await sourcePins();for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
}catch{receipt.failedPhase=phase;refused=true;}
finally{phase='owned-service-cleanup';
 for(const owner of [...owners].reverse()){try{await owner.stop();const result=await owner.completed;if(owner===fga){assert.ok(result.status===0&&!result.signal&&!result.outputLimitExceeded);assert.ok(!result.stdout.includes(tokenForRedaction)&&!result.stderr.includes(tokenForRedaction));receipt.fgaNormalJoined=true;receipt.fgaPIDAbsent=await absent(owner.child.pid);assert.ok(receipt.fgaPIDAbsent);receipt.fgaSessionAbsent=await sessionEmpty(owner.child.pid);assert.ok(receipt.fgaSessionAbsent);}}catch{refused=true;}owners.delete(owner);}
 if(tool)try{await closeHeldTool(tool);}catch{refused=true;}
 if(container)try{await run('docker',['--host=unix:///var/run/docker.sock','rm',container],30,closed,true);container=undefined;}catch{refused=true;}
 if(fgaPort&&grpcPort)try{await bindable(fgaPort);await bindable(grpcPort);receipt.fgaPortsBindable=true;}catch{refused=true;}
}
samplingStopped=true;clearInterval(sampler);clearTimeout(aggregateTimer);if(sampling)await sampling;
try{await floors();await sourcePins();}catch{refused=true;}
receipt.normalCleanup=owners.size===0&&!container&&receipt.fgaNormalJoined===true&&receipt.fgaPortsBindable===true&&receipt.fgaSessionAbsent===true;
receipt.completed=!refused&&!canceled&&performance.now()<end&&receipt.normalCleanup&&receipt.test?.packagePass===true;
await writeFile(path.join(out,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
finished=true;console.log(JSON.stringify(receipt));
if(!receipt.completed||canceled||refused||performance.now()>=end){console.error('::error title=Connector capture native integration::Original singleton nine-case test or owned cleanup refused; no deployment readiness established.');process.exitCode=1;}else console.log('Connector captured-inactive integration: original 1 top / 9 subcases PASS; owned PG/FGA normal cleanup. No runtime activation or deployment acceptance.');

if(canceled||refused||performance.now()>=end){lateRefusal('terminal-refusal');process.exitCode=1;}
