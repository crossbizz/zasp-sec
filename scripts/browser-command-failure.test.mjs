import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
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
