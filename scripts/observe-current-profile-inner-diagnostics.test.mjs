import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyInnerDiagnosticRun,runInnerDiagnosticObserver,describeInnerDiagnosticRefusal} from './observe-current-profile-inner-diagnostics.mjs';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {readFile} from 'node:fs/promises';
export const steps=['up-temporal-domain','up-temporal-executor','up-temporal-workflow','up-temporal-compatibility','up-temporal-legacy-tests','up-temporal-discovery','up-temporal-admission','up-temporal-test-executor','up-temporal-test-selector','up-temporal-human-admission','up-temporal-automatic-sources','up-temporal-finding-response','up-authorization-temporal-identity-profile','up-authorization-worker-profile'];
export const failure='TestAuthorizationRuntimeProfileInnerFailureDiagnostic',success='TestAuthorizationRuntimeProfileInnerSuccessOrder',pkg='github.com/zasp-ai/zasp-sec/services/platform/agentsec-migrate';
export function transcript(green=false){
 const rows=[];
 const emit=(Action,Test,Output)=>{rows.push({Time:'2026-10-04T02:00:00Z',Action,Package:pkg,...(Test?{Test}:{}),...(Output===undefined?{}:{Output}),...(['pass','fail'].includes(Action)?{Elapsed:0.001}:{} )});};
 emit('start');emit('run',failure);emit('output',failure,`=== RUN   ${failure}\n`);
 for(const step of steps)for(const stage of ['install','forward-readiness']){
  const name=`${failure}/${step}/${stage}`;emit('run',name);emit('output',name,`=== RUN   ${name}\n`);
  if(!green)emit('output',name,'    authorization_runtime_profile_inner_diagnostic_test.go:70: closed inner step/stage diagnostic absent\n');
  emit('output',name,`    --- ${green?'PASS':'FAIL'}: ${name} (0.00s)\n`);emit(green?'pass':'fail',name);
 }
 emit('output',failure,`--- ${green?'PASS':'FAIL'}: ${failure} (0.00s)\n`);emit(green?'pass':'fail',failure);
 emit('run',success);emit('output',success,`=== RUN   ${success}\n`);emit('output',success,`--- PASS: ${success} (0.00s)\n`);emit('pass',success);
 emit('output',undefined,`${green?'PASS':'FAIL'}\n`);emit('output',undefined,`${green?'ok  \t':'FAIL\t'}${pkg}\t0.001s\n`);emit(green?'pass':'fail');
 return rows;
}
export function encode(rows){return rows.map(r=>JSON.stringify(r)).join('\n')+'\n';}
const classify=(rows,exit=1,stderr='')=>classifyInnerDiagnosticRun({stdout:encode(rows),stderr,exitCode:exit,normalClose:true});
test('exact actual-source body RED is distinguished from generic failure',()=>assert.deepEqual(classify(transcript()),{classification:'genuine-body-red',topCount:2,subCount:28}));
test('future exact thirty-test pass requires exit zero',()=>{assert.equal(classify(transcript(true),0).classification,'all-tests-pass');assert.equal(classify(transcript(true),1).classification,'unclassified-refusal');});
test('order cause formatting and setup failures cannot count as diagnostic RED',()=>{
 for(const message of ['original terminal refusal identity lost','actual composite crossed or reordered a terminal boundary','diagnostic formatting disclosed a cause or nonclosed content','finite actual composite success refused']){
  const rows=transcript();rows.find(r=>r.Output?.includes('closed inner')).Output='    authorization_runtime_profile_inner_diagnostic_test.go:70: '+message+'\n';assert.equal(classify(rows).classification,'unclassified-refusal');
 }
});
test('missing duplicate unknown test and terminal drift refuse',()=>{
 const cases=[transcript().filter(r=>r.Test!==success),[...transcript(),transcript().find(r=>r.Action==='run')],transcript().map(r=>r.Test===success?{...r,Test:'Unknown'}:r),transcript().filter(r=>!(r.Action==='fail'&&r.Test?.endsWith('/install'))),transcript().map(r=>r.Action==='fail'&&r.Test?.endsWith('/install')?{...r,Action:'skip'}:r)];
 for(const rows of cases)assert.equal(classify(rows).classification,'unclassified-refusal');
});
test('malformed build panic stderr signal and raw-output injection refuse without disclosure',()=>{
 const base={stdout:encode(transcript()),stderr:'',exitCode:1,normalClose:true};
 for(const patch of [{stdout:'{bad}\n'},{stdout:base.stdout+'{"Action":"build-output","Output":"private data"}\n'},{stderr:'private warning\n'},{exitCode:null},{normalClose:false}]){
  const result=classifyInnerDiagnosticRun({...base,...patch});assert.deepEqual(result,{classification:'unclassified-refusal',topCount:0,subCount:0});assert.equal(JSON.stringify(result).includes('private'),false);
 }
 const rows=transcript();rows.find(r=>r.Output?.includes('closed inner')).Output+='private-data\n';assert.equal(classify(rows).classification,'unclassified-refusal');
});
test('package footer and test run order cannot precede completed source boundaries',()=>{
 const rows=transcript();const footer=rows.find(r=>r.Action==='output'&&!r.Test&&r.Output.startsWith('FAIL\t'));
 const before=rows.filter(r=>r!==footer);before.splice(1,0,footer);assert.equal(classify(before).classification,'unclassified-refusal');
 const reordered=transcript();const i=reordered.findIndex(r=>r.Action==='run'&&r.Test===success);const moved=reordered.splice(i,1)[0];reordered.splice(1,0,moved);assert.equal(classify(reordered).classification,'unclassified-refusal');
});
const sourceBytes=await readFile(new URL('../services/platform/agentsec-migrate/authorization_runtime_profile_inner_diagnostic_test.go',import.meta.url));
function adapters({green=false,code=green?0:1,hold=false,groupPresent=false,postDrift=false}={}){
 const child=new EventEmitter();child.pid=12345;child.stdout=new PassThrough();child.stderr=new PassThrough();
 const timers=new Map();let serial=0,reads=0,groupGone=!groupPresent;const calls=[],annotations=[],signals=[];
 const emitClose=()=>child.emit('close',code,null);
 const deps={
  readFile:async()=>{reads++;return postDrift&&reads===2?Buffer.from('changed input'):sourceBytes;},
  spawn:(executable,args,options)=>{calls.push({executable,args,options});if(!hold)queueMicrotask(()=>{child.stdout.emit('data',Buffer.from(encode(transcript(green))));emitClose();});return child;},
  kill:(pid,signal)=>{signals.push({pid,signal});if(signal==='SIGTERM'||signal==='SIGKILL')groupGone=true;if(signal===0&&groupGone){const error=new Error('closed');error.code='ESRCH';throw error;}},
  emit:text=>annotations.push(text),
  timers:{setTimeout:(fn,ms)=>{const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id)},
 };
 return {deps,child,calls,annotations,signals,timers,emitClose};
}
test('actual observer preserves fixed argv environment original Go1 and constant-only annotation',async()=>{
 const a=adapters();assert.equal(await runInnerDiagnosticObserver(a.deps),1);assert.equal(a.calls.length,1);
 assert.equal(a.calls[0].executable,'go');assert.deepEqual(a.calls[0].args,['test','-C','services/platform','-mod=readonly','-p=1','-count=1','-json','-timeout=2m','./agentsec-migrate','-run','^TestAuthorizationRuntimeProfileInner(FailureDiagnostic|SuccessOrder)$']);
 for(const [key,value]of Object.entries({GOTOOLCHAIN:'local',GOENV:'off',GOWORK:'off',GOFLAGS:'',GOPROXY:'off',GOSUMDB:'off',CGO_ENABLED:'0'}))assert.equal(a.calls[0].options.env[key],value);
 assert.equal(a.annotations.join(''),'::error::Current profile inner diagnostics: genuine-body-red; tops=2; subtests=28.\n');assert.equal(a.timers.size,0);
});
test('actual observer future normal pass needs source postcheck and empty descendant group',async()=>{
 for(const options of [{green:true},{green:true,groupPresent:true},{green:true,postDrift:true}]){
  const a=adapters(options);assert.equal(await runInnerDiagnosticObserver(a.deps),options.groupPresent||options.postDrift?1:0);assert.equal(a.calls.length,1);
 }
});
test('timeout abort cannot publish or return before child close and cannot become TDD',async()=>{
 const a=adapters({hold:true});let settled=false;const p=runInnerDiagnosticObserver(a.deps).then(value=>{settled=true;return value;});await new Promise(resolve=>setImmediate(resolve));
 const timeout=[...a.timers.values()].find(t=>t.ms===240000);assert.ok(timeout);timeout.fn();await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);assert.equal(a.annotations.length,0);assert.equal(a.signals[0].signal,'SIGTERM');
 const escalation=[...a.timers.values()].find(t=>t.ms===2000);assert.ok(escalation);escalation.fn();assert.equal(a.signals.at(-1).signal,'SIGKILL');a.emitClose();assert.equal(await p,1);assert.equal(a.annotations.join(''),'::error::Current profile inner diagnostics: unclassified-refusal; tops=0; subtests=0.\n::error::Current profile inner diagnostic refusal: deadline.\n');
});
test('output cap abort waits close without rendering untrusted bytes',async()=>{
 const a=adapters({hold:true});let settled=false;const p=runInnerDiagnosticObserver(a.deps).then(value=>{settled=true;return value;});await new Promise(resolve=>setImmediate(resolve));
 a.child.stdout.emit('data',Buffer.alloc(8*1024*1024+1,120));await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);assert.equal(a.annotations.length,0);a.emitClose();assert.equal(await p,1);assert.equal(a.annotations.join('').includes('xxx'),false);
});
test('input refusal launches nothing and arbitrary nonzero status is preserved',async()=>{
 const a=adapters();a.deps.readFile=async()=>Buffer.from('wrong fixed source');assert.equal(await runInnerDiagnosticObserver(a.deps),1);assert.equal(a.calls.length,0);
 const b=adapters({code:45});assert.equal(await runInnerDiagnosticObserver(b.deps),45);assert.equal(b.calls.length,1);assert.equal(b.annotations.join('').includes('genuine-body-red'),false);
});

const tick=()=>new Promise(resolve=>setImmediate(resolve));
for(const timedOut of [false,true])test(timedOut?'timeout direct-close retains survivor escalation until group disappears':'normal direct-close cleans surviving group before return',async()=>{
 const child=new EventEmitter();child.pid=12345;child.stdout=new PassThrough();child.stderr=new PassThrough();
 const timers=new Map(),signals=[],annotations=[];let serial=0,gone=false,settled=false;
 const deps={readFile:async()=>sourceBytes,spawn:()=>child,emit:text=>annotations.push(text),kill:(pid,signal)=>{signals.push(signal);if(signal===0&&gone){const error=new Error('gone');error.code='ESRCH';throw error;}},timers:{setTimeout:(fn,ms)=>{const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id)}};
 const p=runInnerDiagnosticObserver(deps).then(value=>{settled=true;return value;});await tick();
 try{
  if(timedOut)[...timers.values()].find(t=>t.ms===240000).fn();
  child.emit('close',1,timedOut?'SIGTERM':null);await tick();
  assert.equal(settled,false,'must await survivor group cleanup before resolving');assert.equal(annotations.length,0,'must not emit summary before survivor cleanup');assert.ok(signals.includes('SIGTERM'),'survivor group must receive TERM');
  const escalation=[...timers.values()].find(t=>t.ms===2000);assert.ok(escalation,'close must retain survivor KILL escalation');escalation.fn();assert.ok(signals.includes('SIGKILL'));
  gone=true;for(const t of [...timers.values()])if(t.ms===25)t.fn();await tick();assert.equal(await p,1);assert.equal(annotations.join(''),`::error::Current profile inner diagnostics: unclassified-refusal; tops=0; subtests=0.\n::error::Current profile inner diagnostic refusal: ${timedOut?'deadline':'group-cleanup'}.\n`);
 }finally{
  gone=true;for(let i=0;i<4;i++){for(const t of [...timers.values()])if(t.ms===25)t.fn();await tick();}await p;
 }
});

test('deferred converter parent-summary output accepts deepest-before-parent terminals',()=>{
 const original=transcript();
 const failureRows=original.filter(r=>r.Test===failure);
 const before=original.filter(r=>r.Test?.startsWith(failure+'/')&&r.Action!=='fail'&&!r.Output?.includes('--- FAIL:'));
 const reports=original.filter(r=>r.Test?.startsWith(failure+'/')&&(r.Action==='fail'||r.Output?.includes('--- FAIL:')));
 const after=original.filter(r=>!r.Test?.startsWith(failure+'/')&&r.Test!==failure&&r.Action!=='start');
 const rows=[original[0],...failureRows.filter(r=>r.Action==='run'||r.Output?.startsWith('=== RUN')),...before,...failureRows.filter(r=>r.Output?.startsWith('--- FAIL:')),...reports,...failureRows.filter(r=>r.Action==='fail'),...after];
 assert.equal(classify(rows).classification,'genuine-body-red');
});
test('bounded unresolved group cleanup stays refusal and never becomes normal close',async()=>{
 const child=new EventEmitter();child.pid=12345;child.stdout=new PassThrough();child.stderr=new PassThrough();const pending=new Map(),signals=[],annotations=[];let serial=0;
 const deps={readFile:async()=>sourceBytes,spawn:()=>child,emit:value=>annotations.push(value),kill:(pid,signal)=>signals.push(signal),timers:{setTimeout:(fn,ms)=>{const id=++serial;pending.set(id,{fn,ms});return id;},clearTimeout:id=>pending.delete(id)}};
 const p=runInnerDiagnosticObserver(deps);await tick();child.emit('close',0,null);await tick();assert.equal(annotations.length,0);
 for(let i=0;i<160;i++){const next=[...pending].reverse().find(([,t])=>t.ms===25);if(!next)break;pending.delete(next[0]);next[1].fn();}
 assert.equal(await p,1);assert.ok(signals.includes('SIGTERM'));assert.ok(signals.includes('SIGKILL'));assert.equal(annotations.join(''),'::error::Current profile inner diagnostics: unclassified-refusal; tops=0; subtests=0.\n::error::Current profile inner diagnostic refusal: group-cleanup.\n');
});

test('companion reason leaves original exact outcome unchanged for schema build stderr and unknown output',()=>{
 const base={stdout:'{}\n',stderr:'',exitCode:1,normalClose:true};
 const build=JSON.stringify({Time:'2026-10-04T00:00:00Z',Action:'build-output',ImportPath:pkg,Output:'PRIVATE_TRACE_CANARY'})+'\n';
 const unknown=transcript();unknown.find(row=>row.Output?.includes('closed inner')).Output='PRIVATE_TRACE_CANARY\n';
 for(const [input,reason]of [[base,'trace-schema'],[{...base,stdout:build},'build-trace-refusal'],[{...base,stderr:'PRIVATE_TRACE_CANARY'},'stderr-present'],[{...base,stdout:encode(unknown)},'unknown-output'],[{...base,stdout:encode(transcript(true))},'body-result']]){
  assert.deepEqual(classifyInnerDiagnosticRun(input),{classification:'unclassified-refusal',topCount:0,subCount:0});assert.equal(describeInnerDiagnosticRefusal(input),reason);
 }
 assert.equal(describeInnerDiagnosticRefusal({...base,stdout:encode(transcript())}),null);
 assert.deepEqual(classifyInnerDiagnosticRun(base,()=>{throw Error('PRIVATE_SINK_CANARY');}),{classification:'unclassified-refusal',topCount:0,subCount:0});
});
test('actual runner observes source before and after spawn refusal without rendering private exceptions',async()=>{
 for(const [mode,reason]of [['before','source-before'],['after','source-after'],['spawn','spawn']]){
  const a=adapters({green:true});if(mode==='before')a.deps.readFile=async()=>{throw Error('PRIVATE_SOURCE_CANARY');};
  if(mode==='after'){let reads=0;a.deps.readFile=async()=>{if(++reads===2)throw Error('PRIVATE_SOURCE_CANARY');return sourceBytes;};}
  if(mode==='spawn')a.deps.spawn=()=>{throw Error('PRIVATE_SPAWN_CANARY');};
  assert.equal(await runInnerDiagnosticObserver(a.deps),1);assert.equal(a.annotations.at(-1),`::error::Current profile inner diagnostic refusal: ${reason}.\n`);assert.equal(a.annotations.join('').includes('PRIVATE_'),false);
 }
});
test('actual runner bounds and stderr observations remain refusal and preserve joined child status',async()=>{
 for(const [mode,reason]of [['stdout','stdout-bound'],['stderr-cap','stderr-bound'],['stderr','stderr-present'],['schema','trace-schema'],['build','build-trace-refusal']]){
  const a=adapters({hold:true});const pending=runInnerDiagnosticObserver(a.deps);await tick();
  if(mode==='stdout')a.child.stdout.emit('data',Buffer.alloc(8*1024*1024+1,120));
  else if(mode==='stderr-cap')a.child.stderr.emit('data',Buffer.alloc(256*1024+1,120));
  else if(mode==='stderr'){a.child.stderr.emit('data',Buffer.from('PRIVATE_STDERR_CANARY'));a.child.stdout.emit('data',Buffer.from(encode(transcript())));}
  else if(mode==='schema')a.child.stdout.emit('data',Buffer.from('{}\n'));
  else a.child.stdout.emit('data',Buffer.from(JSON.stringify({Action:'build-fail',ImportPath:pkg,Output:'PRIVATE_BUILD_CANARY'})+'\n'));
  a.emitClose();assert.equal(await pending,1);assert.equal(a.annotations.at(-1),`::error::Current profile inner diagnostic refusal: ${reason}.\n`);assert.equal(a.annotations.join('').includes('PRIVATE_'),false);assert.equal(a.timers.size,0);
 }
});
test('actual abnormal child close preserves nonzero and never accepts a complete body transcript',async()=>{
 const a=adapters({code:45});assert.equal(await runInnerDiagnosticObserver(a.deps),45);assert.equal(a.annotations.at(-1),'::error::Current profile inner diagnostic refusal: abnormal-close.\n');
});

test('known actual fixture prerequisite assertions have only closed fixed reasons, never body RED',()=>{
 const cases=[['original terminal refusal identity lost','prior-cause-identity'],['actual composite crossed or reordered a terminal boundary','prior-dispatch-order'],['diagnostic formatting disclosed a cause or nonclosed content','safe-formatting'],['finite actual composite success refused','success-refused'],['actual complete fourteen-step order changed','success-order']];
 for(const [message,reason]of cases){const rows=transcript();rows.find(row=>row.Output?.includes('closed inner')).Output=`    authorization_runtime_profile_inner_diagnostic_test.go:135: ${message}\n`;const input={stdout:encode(rows),stderr:'',exitCode:1,normalClose:true};assert.deepEqual(classifyInnerDiagnosticRun(input),{classification:'unclassified-refusal',topCount:0,subCount:0});assert.equal(describeInnerDiagnosticRefusal(input),reason);
 rows.find(row=>row.Output?.includes(message)).Output+='PRIVATE_CANARY';assert.equal(describeInnerDiagnosticRefusal({...input,stdout:encode(rows)}),'unknown-output');}
});

const unknownShapes=[['run','=== RUN   PRIVATE_OTHER\n','unknown-run-output'],['terminal','--- FAIL: PRIVATE_OTHER (0.00s)\n','unknown-terminal-output'],['assertion','    authorization_runtime_profile_inner_diagnostic_test.go:135: PRIVATE_ASSERTION\n','unknown-assertion-output'],['panic','panic: PRIVATE_PANIC\n','unknown-panic-output'],['malformed-diagnostic','authorization_runtime_profile_inner_diagnostic_test.go:149: closed inner step/stage diagnostic absent\n','unknown-assertion-output']];
for(const [kind,Output,reason]of unknownShapes)test(`unknown ${kind} shape observes only fixed refusal label without disclosure or acceptance`,async()=>{
 const rows=[{Time:'2026-10-05T00:00:00Z',Action:'start',Package:pkg},{Time:'2026-10-05T00:00:00Z',Action:'run',Package:pkg,Test:failure},{Time:'2026-10-05T00:00:00Z',Action:'output',Package:pkg,Test:failure,Output}];
 const input={stdout:encode(rows),stderr:'',exitCode:1,normalClose:true};
 assert.deepEqual(classifyInnerDiagnosticRun(input),{classification:'unclassified-refusal',topCount:0,subCount:0});assert.equal(describeInnerDiagnosticRefusal(input),reason);
 const a=adapters({hold:true});const pending=runInnerDiagnosticObserver(a.deps);await tick();a.child.stdout.emit('data',Buffer.from(input.stdout));a.emitClose();assert.equal(await pending,1);assert.equal(a.timers.size,0);
 assert.deepEqual(a.annotations,['::error::Current profile inner diagnostics: unclassified-refusal; tops=0; subtests=0.\n',`::error::Current profile inner diagnostic refusal: ${reason}.\n`]);
 assert.equal(a.annotations.join('').includes('PRIVATE'),false);assert.equal(a.annotations.join('').includes(Output),false);
 rows[2].Output+='extra caller data';assert.equal(describeInnerDiagnosticRefusal({...input,stdout:encode(rows)}),'unknown-output');
});

// A timeout is observational only; it can never admit an incomplete Go trace.
test('exact current Go deadline panic remains refused with a closed timeout label',async()=>{
 const rows=[{Time:'2026-10-06T00:00:00Z',Action:'start',Package:pkg},{Time:'2026-10-06T00:00:00Z',Action:'run',Package:pkg,Test:failure},{Time:'2026-10-06T00:00:00Z',Action:'output',Package:pkg,Test:failure,Output:'panic: test timed out after 2m0s\n'}];
 const input={stdout:encode(rows),stderr:'',exitCode:1,normalClose:true};
 assert.deepEqual(classifyInnerDiagnosticRun(input),{classification:'unclassified-refusal',topCount:0,subCount:0});
 assert.equal(describeInnerDiagnosticRefusal(input),'test-timeout-2m');
 const a=adapters({hold:true});const pending=runInnerDiagnosticObserver(a.deps);await tick();a.child.stdout.emit('data',Buffer.from(input.stdout));a.emitClose();assert.equal(await pending,1);assert.equal(a.timers.size,0);
 assert.deepEqual(a.annotations,['::error::Current profile inner diagnostics: unclassified-refusal; tops=0; subtests=0.\n','::error::Current profile inner diagnostic refusal: test-timeout-2m.\n']);
 for(const Output of ['panic: test timed out after 1m0s\n','panic: test timed out after 2m0s PRIVATE_CANARY\n','panic: test timed out after 2m0s\nPRIVATE_CANARY']){rows[2].Output=Output;assert.equal(describeInnerDiagnosticRefusal({...input,stdout:encode(rows)}),Output.endsWith('\n')?'unknown-panic-output':'unknown-output');}
});
