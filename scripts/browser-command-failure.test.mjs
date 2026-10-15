import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {spawn} from 'node:child_process';
import {browserCommandFailureAnnotation} from './browser-command-failure.mjs';
const src=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const start=src.indexOf('async function command(executable, args, options = {}) {');
const end=src.indexOf('\nasync function reservePort()',start);
assert.ok(start>0&&end>start);
const commandSource=src.slice(start,end);
const build=['build','-o','/owned/CANARY_SECRET','./agentsec-migrate'];
function harness({deadline=false,status=0,signal=null}={}){
 const annotations=[],events=[],children=[],ownedCommands=new WeakMap();let settle;
 const completed=deadline?new Promise(resolve=>{settle=resolve;}):Promise.resolve({status,signal,stdout:'CANARY_STDOUT',stderr:'CANARY_STDERR'});
 const child={};
 const owned={child,completed,stop:async()=>{events.push('stop');settle({status:null,signal:'SIGTERM',stdout:'',stderr:''});}};
 const spawn=(executable,args,options)=>{events.push({executable,args,options});return owned;};
 const fakeSet=(cb,ms)=>{events.push({deadline:ms});if(deadline)queueMicrotask(cb);return 1;};
 const command=new Function('spawnOwnedCommand','auditBrowserEnvironment','children','ownedCommands','temporaryRoot','root','existingTestMountedMode','path','setTimeout','clearTimeout','browserCommandFailureAnnotation','console','const currentComplianceFailure=undefined,currentComplianceClosing=false,currentComplianceServices=undefined;'+commandSource+'\nreturn command;')(spawn,x=>x,children,ownedCommands,'/owned/tmp','/repo',false,path,fakeSet,()=>events.push('clear'),browserCommandFailureAnnotation,{error:x=>annotations.push(x)});
 return {command,annotations,events,children,ownedCommands,child};
}
test('fixed command classes never include arguments, paths or unknown failure text',()=>{
 for(const [args,label]of [[build,'go-migration-build'],[['test','-c','-o','CANARY','./agentsec-api'],'go-api-test-compile'],[['test','-c','-o','CANARY','./agentsec-worker'],'go-worker-test-compile']]){
 const a=browserCommandFailureAnnotation('go',args,'deadline');assert.ok(a.includes(label));assert.doesNotMatch(a,/CANARY|owned|agentsec/);
 }
 assert.equal(browserCommandFailureAnnotation('CANARY_EXEC',['CANARY_ARG'],'CANARY_FAILURE'),null);
 assert.equal(browserCommandFailureAnnotation('/secret/go',build,'nonzero-exit'),'::error title=Compliance browser command failed::Observed command class: other-command; failure: nonzero-exit.');
});
test('actual command timeout retains stop/throw/default30s and emits only fixed class',async()=>{
 const h=harness({deadline:true});await assert.rejects(h.command('go',build,{env:{FIXTURE:'owned'},cwd:'/platform'}),{message:'go exceeded its deadline'});
 assert.deepEqual(h.annotations,['::error title=Compliance browser command failed::Observed command class: go-migration-build; failure: deadline.']);assert.ok(h.events.includes('stop'));assert.ok(h.events.includes('clear'));assert.equal(h.events[1].deadline,30000);assert.equal(h.events[0].options.env.GOTMPDIR,'/owned/tmp');assert.equal(h.events[0].options.cwd,'/platform');assert.equal(h.children.length,1);assert.ok(h.ownedCommands.has(h.child));
});
test('actual command nonzero retains original error, explicit deadline and options',async()=>{
 const h=harness({status:37});let started;await assert.rejects(h.command('go',build,{timeout:120000,input:'owned-input',onStarted:child=>{started=child;}}),{message:'go failed (37): CANARY_STDERR'});assert.equal(h.events[1].deadline,120000);assert.equal(h.events[0].options.input,'owned-input');assert.equal(started,h.child);assert.deepEqual(h.annotations,['::error title=Compliance browser command failed::Observed command class: go-migration-build; failure: nonzero-exit.']);assert.doesNotMatch(h.annotations.join(''),/CANARY/);assert.ok(h.events.includes('clear'));assert.ok(!h.events.includes('stop'));
});
test('actual command success and explicit nonreject remain unchanged without annotations',async()=>{
 for(const status of [0,9]){const h=harness({status});const r=await h.command('go',build,{reject:false});assert.equal(r.status,status);assert.deepEqual(h.annotations,[]);assert.ok(h.events.includes('clear'));}
});

import * as phaseHelpers from './browser-command-failure.mjs';
import ts from 'typescript';

const parsed=ts.createSourceFile('runner.mjs',src,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
const mainTry=parsed.statements.find(n=>ts.isTryStatement(n));
assert.ok(mainTry?.finallyBlock);
function fatalHarness({phase='services',mode=true,emitterFails=false,cleanupError}={}){
 assert.ok(mainTry.catchClause,'actual fatal catch is required');
 const annotations=[],events=[];
 const emit=x=>{if(emitterFails)throw Error('CANARY_EMITTER');annotations.push(x);};
 const cleanupController={run:async()=>{events.push('cleanup');if(cleanupError)throw cleanupError;},dispose:()=>events.push('dispose')};
 const run=new Function('body','events','cleanupController','complianceBrowserMode','compliancePhase','emitComplianceBrowserPhaseFailure','console',`return (async()=>{try{await body();events.push('after');}${mainTry.catchClause.getText(parsed)}finally${mainTry.finallyBlock.getText(parsed)}})();`);
 return {annotations,events,run:body=>run(body,events,cleanupController,mode,phase,phaseHelpers.emitComplianceBrowserPhaseFailure,{error:emit})};
}
test('actual fatal catch uses four fixed phases and preserves Error identity plus original cleanup',async()=>{
 for(const phase of ['services','command-builds','schema-bootstrap','browser-assertions']){
  const h=fatalHarness({phase});const error=Error('CANARY_URL_SECRET_TENANT');let seen;
  try{await h.run(async()=>{throw error;});}catch(e){seen=e;}
  assert.equal(seen,error);assert.deepEqual(h.events,['cleanup','dispose']);assert.deepEqual(h.annotations,[`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]);assert.doesNotMatch(h.annotations.join(''),/CANARY|SECRET|TENANT/);
 }
});
test('actual fatal catch preserves success silence, noncompliance silence and emitter failure',async()=>{
 const success=fatalHarness();await success.run(async()=>{});assert.deepEqual(success.annotations,[]);assert.deepEqual(success.events,['after','cleanup','dispose']);
 for(const options of [{mode:false},{emitterFails:true}]){const h=fatalHarness(options),error=Error('CANARY');await assert.rejects(h.run(async()=>{throw error;}),e=>e===error);assert.deepEqual(h.annotations,[]);assert.deepEqual(h.events,['cleanup','dispose']);}
 const poison=fatalHarness({phase:'CANARY_RAW'});await assert.rejects(poison.run(async()=>{throw Error('CANARY');}));assert.deepEqual(poison.annotations,['::error title=Compliance browser phase failed::Observed phase: unavailable.']);
});
test('actual fatal catch retains existing cleanup failure semantics and dispose ordering',async()=>{
 const error=Error('original'),cleanupError=Error('cleanup'),h=fatalHarness({cleanupError});await assert.rejects(h.run(async()=>{throw error;}),e=>e===cleanupError);assert.deepEqual(h.events,['cleanup']);assert.equal(h.annotations.length,1);
});
const migrationDeclaration=mainTry.tryBlock.statements.find(n=>ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(parsed)==='migrationResult'));
const migrationBranch=mainTry.tryBlock.statements.find(n=>ts.isIfStatement(n)&&n.expression.getText(parsed)==='migrationResult.status !== 0');
assert.ok(migrationDeclaration&&migrationBranch);
test('actual handled migration branch annotates nonzero only without changing status/diagnostic/throw',async()=>{
 for(const [status,mode,emitterFails]of [[0,true,false],[37,true,false],[37,false,false],[37,true,true]]){
  const calls=[],annotations=[],made=[];const OwnedError=function(message){const e=Error(message);made.push(e);return e;};
  const command=async(executable,args,options)=>{calls.push({executable,args,options});return args[0]==='up-to-48'?{status,stdout:'CANARY_STDOUT',stderr:'CANARY_STDERR'}:{status:0,stdout:'CANARY_SCHEMA',stderr:''};};
  const source=`return (async()=>{${migrationDeclaration.getText(parsed)}${migrationBranch.getText(parsed)}return migrationResult;})();`;
  const execute=new Function('command','migrate','migrationEnvironment','existingTestMountedMode','postgres','postgresBin','dsn','path','complianceBrowserMode','emitComplianceMigrationFailure','console','Error',source);
  const result=execute(command,'/owned/migrate',{FIXTURE:'CANARY_ENV'},false,{},'/owned/bin','CANARY_URL',path,mode,phaseHelpers.emitComplianceMigrationFailure,{error:x=>{if(emitterFails)throw Error('CANARY_EMITTER');annotations.push(x);}},OwnedError);
  if(status===0){assert.equal((await result).status,0);assert.equal(calls.length,1);assert.deepEqual(annotations,[]);}else{await assert.rejects(result,e=>e===made[0]&&e.message==='agentsec-migrate failed at installed releases CANARY_SCHEMA: CANARY_STDERR');assert.equal(calls.length,2);assert.deepEqual(calls[1].options,{reject:false});assert.deepEqual(annotations,mode&&!emitterFails?['::error title=Compliance browser schema bootstrap failed::Observed branch: up-to-48 migration returned nonzero.']:[]);}
  assert.deepEqual(calls[0],{executable:'/owned/migrate',args:['up-to-48'],options:{reject:false,env:{FIXTURE:'CANARY_ENV'}}});assert.doesNotMatch(annotations.join(''),/CANARY|SECRET|TENANT|owned/);
 }
});


test('readiness observations preserve only bounded unique closed fixture outcomes', async () => {
 const { emitComplianceAPIReadinessObservations } = await import('./browser-command-failure.mjs');
 const messages = [];
 const valid = ['services:passed', 'core-metadata:deadline', 'security-agent-metadata:cancelled', 'components:refused'];
 emitComplianceAPIReadinessObservations(valid.map(value => 'ZASP_COMPLIANCE_READINESS=' + value + '\n').join(''), value => messages.push(value));
 assert.equal(messages.length, 1);
 for (const value of valid) assert.ok(messages[0].includes(value));
 const marker = 'ZASP_COMPLIANCE_READINESS=services:passed\n';
 for (const output of [marker + marker, marker.trimEnd(), 'untrusted ' + marker, marker.replace('passed', 'unknown'), marker.replace('services', 'secret-value'), marker + 'ZASP_COMPLIANCE_READINESS=components:refused', 'x'.repeat(16_384) + marker, Array.from({length:17}, () => marker).join('')]) {
  const refused = [];
  emitComplianceAPIReadinessObservations(output, value => refused.push(value));
  assert.deepEqual(refused, []);
 }
 assert.doesNotThrow(() => emitComplianceAPIReadinessObservations(marker, () => { throw new Error('untrusted emitter'); }));
});

function observedAPIChild(){const child=new EventEmitter();child.exitCode=null;child.signalCode=null;child.stdout=new PassThrough();child.stderr=new PassThrough();return child;}
test('joined API exit metadata survives oversized poisoned markers without disclosing output',async()=>{
 const child=observedAPIChild(),observe=phaseHelpers.observeComplianceAPIChild(child);
 child.stderr.write('CANARY_DSN_SECRET\n'+'x'.repeat(17000)+'\nZASP_COMPLIANCE_API_FAILED_STAGE=serve\nZASP_COMPLIANCE_API_FAILED_STAGE=runtime-build\npanic: CANARY_PROVIDER_PAYLOAD\n');
 child.exitCode=2;child.emit('exit',2,null);child.emit('close',2,null);
 const observation=await observe(),messages=[];
 phaseHelpers.emitComplianceAPIChildFailure('x'.repeat(16385),x=>messages.push(x),undefined,observation);
 assert.deepEqual(messages,['::error title=Compliance API startup failed::Observed child stage: unavailable.','::error title=Compliance API child exit::Observed exit=2; signal=none; outputLimitExceeded=false; truncated=true; fatal=panic.']);
 assert.doesNotMatch(messages.join(''),/CANARY|DSN|SECRET|PAYLOAD|PROVIDER/);
});
test('API metadata never waits for a live child and joins exited streams before observing',async()=>{
 const child=observedAPIChild(),observe=phaseHelpers.observeComplianceAPIChild(child);
 assert.equal(await observe(),undefined);
 child.exitCode=1;child.emit('exit',1,null);
 let settled=false;const pending=observe().then(value=>{settled=true;return value;});await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);
 child.stderr.write('--- FAIL: TestComplianceBrowserAPIProcess (1.00s)\nCANARY_SECRET\n');child.emit('close',1,null);
 const observation=await pending,messages=[];phaseHelpers.emitComplianceAPIChildFailure('',x=>messages.push(x),undefined,observation);
 assert.match(messages.at(-1),/exit=1; signal=none;.*fatal=testfail/);
});
test('fatal categories, signals and malformed receipts remain closed scalar observations',async()=>{
 for(const [line,category] of [['panic: test timed out after 1m0s\n','testtimeout'],['fatal error: CANARY_FATAL\n','runtimefatal'],['panic: CANARY_PANIC\n','panic'],['FAIL\n','testfail'],['CANARY_UNKNOWN\n','unknown'],['x'.repeat(1025)+'panic: CANARY_SECRET\n','unknown']]){
  const child=observedAPIChild(),observe=phaseHelpers.observeComplianceAPIChild(child);for(const part of [line.slice(0,3),line.slice(3)])child.stderr.write(part);child.signalCode='SIGKILL';child.emit('close',null,'SIGKILL');const observation=await observe(),messages=[];phaseHelpers.emitComplianceAPIChildFailure('',x=>messages.push(x),undefined,observation);assert.match(messages.at(-1),new RegExp('exit=unavailable; signal=SIGKILL;.*fatal='+category+'\\.$'));assert.doesNotMatch(messages.join(''),/CANARY/);
 }
 for(const observation of [{status:1,signal:'SIGCANARY',truncated:true,fatal:'panic'},null,{},Object.create(null)]){const messages=[];phaseHelpers.emitComplianceAPIChildFailure('',x=>messages.push(x),undefined,observation);assert.equal(messages.length,1);}
});
test('actual runner child hook binds closed process status while preserving the existing output tail',async()=>{
 const declaration=parsed.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='startChild');assert.ok(declaration);
 const children=[],start=new Function('spawn','root','auditBrowserEnvironment','children','currentComplianceFailure','currentComplianceClosing','currentComplianceServices','observeComplianceAPIChild',`return (${declaration.getText(parsed)});`)(spawn,process.cwd(),value=>value,children,false,false,undefined,phaseHelpers.observeComplianceAPIChild);
 const child=start(process.execPath,['-e',`process.stderr.write('CANARY_SECRET\\n'+'x'.repeat(17000)+'\\npanic: CANARY_PAYLOAD\\n');process.exitCode=2;`],{env:process.env,observeComplianceFailure:true});
 await new Promise(resolve=>child.once('exit',resolve));const observation=await child.failureObservation(),messages=[];
 phaseHelpers.emitComplianceAPIChildFailure(child.output(),value=>messages.push(value),undefined,observation);
 assert.equal(child.output().length,16384);assert.equal(children[0],child);assert.match(messages.at(-1),/exit=2; signal=none;.*truncated=true; fatal=panic/);assert.doesNotMatch(messages.join(''),/CANARY|SECRET|PAYLOAD/);
});
test('constructor observations accept only fixed failed lanes and preserve original byte and count caps',()=>{
 const phases=['maintenance-owner','connector-config','connector-authorizer','connector-key','connector-pool','connector-executor','connector-authority','connector-repository','connector-reconciler','approval-config','approval-authorizer','approval-key','approval-pool','approval-executor','approval-reconciler'];
 for(const phase of phases)for(const outcome of ['refused','deadline','cancelled']){const output=[],line=`ZASP_COMPLIANCE_READINESS=${phase}:${outcome}\n`;phaseHelpers.emitComplianceAPIReadinessObservations(line,x=>output.push(x));assert.equal(output.length,1);assert.ok(output[0].includes(phase+':'+outcome));assert.doesNotMatch(output[0],/CANARY/);}
 for(const line of ['ZASP_COMPLIANCE_READINESS=connector-executor:passed\n','ZASP_COMPLIANCE_READINESS=approval-CANARY_SECRET:refused\n','ZASP_COMPLIANCE_READINESS=connector-executor:CANARY\n','ZASP_COMPLIANCE_READINESS=connector-executor:refused\n'.repeat(17),'x'.repeat(16385)+'ZASP_COMPLIANCE_READINESS=connector-executor:refused\n']){const output=[];phaseHelpers.emitComplianceAPIReadinessObservations(line,x=>output.push(x));assert.deepEqual(output,[]);}
});
