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
 const command=new Function('spawnOwnedCommand','auditBrowserEnvironment','children','ownedCommands','temporaryRoot','root','existingTestMountedMode','path','setTimeout','clearTimeout','browserCommandFailureAnnotation','console',commandSource+'\nreturn command;')(spawn,x=>x,children,ownedCommands,'/owned/tmp','/repo',false,path,fakeSet,()=>events.push('clear'),browserCommandFailureAnnotation,{error:x=>annotations.push(x)});
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
