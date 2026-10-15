import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import http from 'node:http';
import {once} from 'node:events';
import ts from 'typescript';
import {spawnOwnedCommand} from './owned-command.mjs';
import {OwnedProjectionCleanupIncomplete} from './owned-current80-composition.mjs';

const source=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const tree=ts.createSourceFile('actual-runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
assert.equal(tree.parseDiagnostics.length,0);
const declaration=name=>tree.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text===name);
const exercise=declaration('exerciseComplianceBrowser').body.statements;
const begin=exercise.findIndex(node=>node.getText(tree).startsWith('const publicOrigin='));
const end=exercise.findIndex((node,index)=>index>begin&&node.getText(tree).includes('compliancePhase = "web-startup"'));
assert.ok(begin>=0&&end>begin);
const bootstrap=exercise.slice(begin,end).map(node=>node.getText(tree)).join('\n');
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const turn=()=>new Promise(resolve=>setImmediate(resolve));

function harness(hooks={}){
 const events=[],controller=new AbortController();let removed=false;
 const server=name=>({name,listening:true,closeAllConnections(){events.push(name+' connections closed');},close(callback){events.push(name+' close');this.listening=false;if(hooks.close)hooks.close(name,callback);else callback?.();}});
 const context=vm.createContext({console:{log(){},error(){}},AggregateError,Error,Date,Promise,AbortController,setTimeout:hooks.timer??setTimeout,clearTimeout:hooks.clearTimer??clearTimeout,
  configuration:{currentRuntimeEnvironment:{}},productHostname:'owned.invalid',proxyPort:1234,apiPort:1235,healthPort:1236,postgresPort:1237,identityPort:1238,policyHistoryPort:1239,object:'/owned/object',apiBinary:'/owned/api',
  complianceBrowserMode:true,compliancePhase:'compliance-fixture-provisioning',combinedAPIEnvironment:()=>({}),closedOwnedAmbientEnvironment:()=>({}),process,
  ownedResourceCleanupStarted:false,currentComplianceClosing:false,currentComplianceFailure:undefined,currentCompliancePreparation:Promise.resolve(),currentComplianceRuntimeStartup:undefined,currentComplianceProjectionController:controller,currentComplianceProjectionLoop:undefined,currentComplianceStateRoot:'/owned/state',
  currentComplianceServices:{close:async()=>{events.push('services closed');}},currentCompliancePostgres:{stop:async()=>{events.push('postgres stopped');}},
  currentProjection:{refresh:async signal=>{events.push('refresh');if(hooks.refresh)return hooks.refresh(signal,context);}},
  startIdentityServer:async()=>{events.push('identity start');return hooks.identity?hooks.identity(server('identity')):server('identity');},
  startPolicyHistoryServer:async()=>{events.push('policy start');return hooks.policy?hooks.policy(server('policy')):server('policy');},
  startChild:()=>{events.push('api start');return {name:'api',output:()=>'',failureObservation:async()=>undefined};},
  waitForOwnedAPIStartup:async()=>{events.push('api wait');if(hooks.ready)await hooks.ready(context);events.push('api ready');},emitComplianceAPIChildFailure:()=>{},
  runOwnedProjectionLoop:(_projection,signal)=>{events.push('loop');return new Promise(resolve=>{signal.addEventListener('abort',()=>{events.push('loop joined');resolve();},{once:true});});},
  precisionBrowserCheckpoint:undefined,mountedRuntimeProofs:[],runtimePipelineChild:undefined,runtimeGraphDependency:undefined,redTeamRuntimeProof:{close:async()=>{}},runtimePipelineDependencies:{close:async()=>{}},
  exportBrowserProfiles:[],exportBrowserAPILifetimes:[],secondBrowserTab:undefined,browser:undefined,task4Workers:[],api:undefined,proxy:undefined,identity:undefined,policyHistory:undefined,web:undefined,auditExportProvider:undefined,postgres:undefined,
  stopChild:async child=>{events.push(child.name+' stopped');hooks.stopAPI?.();},closeServer:async value=>{events.push(value.name+' global close');await new Promise((resolve,reject)=>value.close(error=>error?reject(error):resolve()));},
  children:[],ownedCommands:new Map(),temporaryRoot:'/owned/tmp',root:process.cwd(),exportBrowserEvidenceDirectory:null,automaticDiscoveryEvidenceDirectory:null,rm:async()=>{removed=true;events.push('files removed');},
  spawnOwnedCommand:(file,args,options)=>spawnOwnedCommand(file,args,{...options,graceMs:50,killMs:500}),auditBrowserEnvironment:()=>process.env,existingTestMountedMode:false,OwnedProjectionCleanupIncomplete,browserCommandFailureAnnotation:()=>'',
 });
 vm.runInContext(`${declaration('cleanupOwnedResources').getText(tree)}\n${declaration('command').getText(tree)}\nasync function bootstrapUnderTest(){${bootstrap}\nreturn startAPI;}`,context);
 return {context,events,controller,server,removed:()=>removed,boot:()=>context.bootstrapUnderTest(),cleanup:()=>context.cleanupOwnedResources()};
}

test('initial installation retains full Ack but does not launch periodic projection',()=>{
 const prepare=declaration('prepareOwnedCurrentComplianceRuntime').getText(tree);
 assert.match(prepare,/await installOwnedCurrent80\(/);
 assert.doesNotMatch(prepare,/runOwnedProjectionLoop\(/);
 assert.match(prepare,/currentComplianceProjectionController=new AbortController\(\)/);
});

test('actual bootstrap forces full projection before API admission and starts unchanged loop only after ready',async()=>{
 const ready=deferred();const h=harness({ready:()=>ready.promise});const boot=h.boot();
 try{await turn();assert.deepEqual(h.events,['identity start','policy start','refresh','api start','api wait']);assert.equal(h.context.currentComplianceProjectionLoop,undefined);ready.resolve();const restart=await boot;assert.deepEqual(h.events.slice(0,7),['identity start','policy start','refresh','api start','api wait','api ready','loop']);await restart(true);assert.equal(h.events.filter(x=>x==='loop').length,1);assert.equal(h.events.filter(x=>x==='refresh').length,1);}finally{ready.resolve();await boot.catch(()=>{});await h.cleanup();}
});

for(const lane of ['identity','policy'])test(`cleanup joins an unpublished late ${lane} listener before closing state`,async()=>{
 const returned=deferred(),closed=deferred();const h=harness({[lane]:value=>returned.promise.then(()=>value),close:(name,callback)=>name===lane?closed.promise.then(()=>callback?.()):callback?.()});
 const boot=h.boot().then(()=>undefined,error=>error);await turn();const cleanup=h.cleanup();await turn();
 try{assert.equal(h.removed(),false);returned.resolve();await turn();assert.ok(h.events.includes(lane+' close'));assert.equal(h.context[lane==='identity'?'identity':'policyHistory'],undefined);assert.equal(h.removed(),false);assert.ok(!h.events.includes('refresh'));assert.ok(!h.events.includes('api start'));assert.ok(!h.events.includes('loop'));}finally{closed.resolve();returned.resolve();await Promise.allSettled([boot,cleanup]);}
 assert.match((await boot).message,/startup after cleanup refused/);await cleanup;assert.equal(h.removed(),true);
});

test('late listener close failure retains the same ownership error and owned files',async()=>{
 const returned=deferred(),failure=Error('owned close refused');const h=harness({identity:value=>returned.promise.then(()=>value),close:(_name,callback)=>callback(failure)});
 const boot=h.boot().then(()=>undefined,error=>error);await turn();const cleanup=h.cleanup().then(()=>undefined,error=>error);returned.resolve();
 assert.equal(await boot,failure);const error=await cleanup;assert.ok(error instanceof AggregateError);assert.ok(error.errors.includes(failure));assert.equal(h.removed(),false);assert.ok(!h.events.includes('loop'));
});

test('late listener close deadline refuses the ownership join within the original bound',async()=>{
 const returned=deferred();let expire,cleared=false;const h=harness({identity:value=>returned.promise.then(()=>value),close:()=>{},timer:(callback,milliseconds)=>{assert.equal(milliseconds,2000);expire=callback;return 1;},clearTimer:()=>{cleared=true;}});
 const boot=h.boot().then(()=>undefined,error=>error);await turn();const cleanup=h.cleanup().then(()=>undefined,error=>error);returned.resolve();await turn();assert.equal(h.removed(),false);expire();const failure=await boot;
 assert.equal(failure.message,'owned current bootstrap server cleanup incomplete');assert.ok((await cleanup).errors.includes(failure));assert.equal(cleared,true);assert.equal(h.removed(),false);
});

test('late real listener is closed through its actual callback before preparation joins',async()=>{
 const returned=deferred(),listener=http.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');
 const h=harness({identity:()=>returned.promise.then(()=>listener)});const boot=h.boot().then(()=>undefined,error=>error);await turn();const cleanup=h.cleanup();const close=once(listener,'close');
 try{returned.resolve();await close;await cleanup;assert.match((await boot).message,/startup after cleanup refused/);assert.equal(listener.listening,false);assert.equal(h.context.identity,undefined);assert.equal(h.removed(),true);}finally{if(listener.listening)await new Promise(resolve=>listener.close(resolve));}
});

test('original API readiness error survives and cannot publish projection loop',async()=>{
 const failure=Error('original readiness refusal');const h=harness({ready:async()=>{throw failure;}});const error=await h.boot().then(()=>undefined,error=>error);
 assert.equal(error.message,`${failure.message}; `);assert.ok(!h.events.includes('loop'));await h.cleanup();assert.equal(h.removed(),true);
});

test('cleanup stops API before joining admission and refuses work after the ready race',async()=>{
 const ready=deferred();const h=harness({ready:()=>ready.promise,stopAPI:()=>ready.resolve()});const boot=h.boot().then(()=>undefined,error=>error);await turn();
 await h.cleanup();assert.ok(h.events.indexOf('api stopped')<h.events.indexOf('services closed'));assert.ok(!h.events.includes('loop'));assert.match((await boot).message,/startup after cleanup refused/);assert.equal(h.removed(),true);
});

test('original owned runner cancellation joins the real refresh process before closing services', {timeout:10000},async()=>{
 const started=deferred();let owned;
 const h=harness({refresh:async(signal,context)=>{const command=context.command(process.execPath,['-e',"process.stdout.write('ready');setInterval(()=>{},1000)"],{signal,timeout:5000,onStarted:child=>{owned=child;child.stdout.once('data',()=>started.resolve());}});await command;}});
 const boot=h.boot().then(()=>undefined,error=>error);await Promise.race([started.promise,boot.then(()=>{throw Error('refresh did not start its owned process');})]);assert.equal(owned.exitCode,null);await h.cleanup();await boot;
 assert.ok(owned.exitCode!==null||owned.signalCode!==null);assert.ok(!h.events.includes('api start'));assert.ok(!h.events.includes('loop'));assert.equal(h.removed(),true);
});
