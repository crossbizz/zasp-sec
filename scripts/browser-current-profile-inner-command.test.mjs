import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
const raw=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url));
const src=raw.toString('utf8'),start=src.indexOf('async function command(executable, args, options = {}) {'),end=src.indexOf('\nasync function reservePort()',start);assert.ok(start>0&&end>start);
const commandSource=src.slice(start,end);
const witness='ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=up-temporal-domain;STAGE=install\n';
function fixture({status=37,deadline=false,operationError}={}){
 const events=[],annotations=[],made=[],ownedCommands=new WeakMap(),children=[];let resolveStop;
 const completed=operationError?Promise.reject(operationError):deadline?new Promise(resolve=>{resolveStop=resolve;}):Promise.resolve({status,signal:null,stdout:'fixture-out',stderr:witness});
 const owned={child:{},completed,stop:async()=>{events.push('stop');resolveStop?.({status:null,signal:'SIGTERM',stdout:'',stderr:witness});events.push('joined');}};
 const OwnedError=function(message){const error=Error(message);made.push(error);return error;};
 const command=new Function('spawnOwnedCommand','auditBrowserEnvironment','children','ownedCommands','temporaryRoot','root','existingTestMountedMode','path','setTimeout','clearTimeout','browserCommandFailureAnnotation','console','Error','const currentComplianceFailure=undefined,currentComplianceClosing=false,currentComplianceServices=undefined;'+commandSource+'\nreturn command;')(
  (...args)=>{events.push(['spawn',...args]);return owned;},x=>x,children,ownedCommands,'/fixture/tmp','/fixture/repo',false,path,(callback,ms)=>{events.push(['deadline',ms]);if(deadline)queueMicrotask(callback);return 1;},()=>events.push('clear'),(...args)=>{annotations.push(args);return 'fixed-annotation';},{error:x=>events.push(['emit',x])},OwnedError);
 return{command,events,annotations,made,children,ownedCommands,owned};
}
test('actual nonzero command forwards exact captured stderr and preserves original thrown Error/options/ownership',async()=>{
 const f=fixture();let started;
 await assert.rejects(f.command('/fixture/agentsec-migrate',['up-authorization-runtime-profile'],{timeout:300000,env:{FIXTURE:'closed'},input:'fixture-input',onStarted:x=>{started=x;}}),error=>error===f.made[0]&&error.message===`agentsec-migrate failed (37): ${witness}`);
 assert.equal(f.annotations.length,1);assert.deepEqual(f.annotations[0],['/fixture/agentsec-migrate',['up-authorization-runtime-profile'],'nonzero-exit',witness],'captured stderr not forwarded to existing annotation helper');
 assert.equal(started,f.owned.child);assert.deepEqual(f.children,[f.owned.child]);assert.equal(f.ownedCommands.get(f.owned.child),f.owned);assert.equal(f.events[1][1],300000);assert.ok(f.events.includes('clear'));assert.deepEqual(f.events[0][3],{cwd:'/fixture/repo',env:{FIXTURE:'closed'},input:'fixture-input'});
});
test('actual deadline joins stop before original error and does not forward partial stderr',async()=>{
 const f=fixture({deadline:true});await assert.rejects(f.command('/fixture/agentsec-migrate',['up-authorization-runtime-profile']),error=>error===f.made[0]&&error.message==='agentsec-migrate exceeded its deadline');
 assert.deepEqual(f.annotations,[['/fixture/agentsec-migrate',['up-authorization-runtime-profile'],'deadline']]);assert.ok(f.events.indexOf('stop')<f.events.indexOf('joined'));assert.ok(f.events.includes('clear'));assert.equal(f.events[1][1],30000);
});
test('actual successful reject-false and operation-error paths preserve original result/failure without annotations',async()=>{
 for(const config of [{status:0},{status:37}]){const f=fixture(config);const result=await f.command('/fixture/agentsec-migrate',['up-authorization-runtime-profile'],{reject:false});assert.equal(result.status,config.status);assert.deepEqual(f.annotations,[]);assert.ok(f.events.includes('clear'));}
 const original=Error('fixture-owned-failure'),f=fixture({operationError:original});await assert.rejects(f.command('/fixture/agentsec-migrate',['up-authorization-runtime-profile']),error=>error===original);assert.deepEqual(f.annotations,[]);assert.ok(f.events.includes('clear'));
});
