import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import * as lifetime from './owned-runtime-lifetime.mjs';
import * as services from './owned-runtime-services.mjs';
import {recordOwnedRuntimeStartupFailure,ownedRuntimeStartupFailureAnnotation,withOwnedRuntimeStartupDiagnostics}from './owned-runtime-startup-diagnostics.mjs';
const describe=error=>lifetime.describeOwnedRuntimeStartupFailure?.(error)??null;
const config={stateRoot:'/owned-state',archiveRoot:'/owned-archive',rawRoot:'/owned-raw',run:'0123456789abcdef'};
function harness(){
 const calls=[];const adapters={observe:async()=>({free:4_000_000_000n,allocated:100_000_000n}),reopen:async name=>{calls.push('reopen-'+name);return {path:'/tools/'+name,archive:'fixture',sha256:'0'.repeat(64)};},closeTool:async tool=>calls.push('close-'+path.basename(tool.path)),setTimer:()=>1,clearTimer:()=>calls.push('timer-clear'),start:async()=>{throw Error('finite service start refused');}};
 return {calls,adapters};
}
async function failure(action){try{await action();assert.fail('actual source refusal required');}catch(error){return error;}}
test('actual retained config refusal has closed startup boundary',async()=>{const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime({}));assert.deepEqual(describe(error),{phase:'retained-input',kind:'refused'});});
test('actual retained initial allocation refusal is distinct before custody',async()=>{const h=harness();h.adapters.observe=async()=>{throw Error('private observation data');};const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.deepEqual(h.calls,[]);assert.deepEqual(describe(error),{phase:'retained-allocation-observe',kind:'refused'});});
test('actual retained startup reserve guard remains unchanged and gets fixed boundary',async()=>{const h=harness();h.adapters.observe=async()=>({free:2_900_000_000n,allocated:100_000_000n});const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.deepEqual(h.calls,[]);assert.deepEqual(describe(error),{phase:'retained-startup-budget',kind:'refused'});});
test('actual partial openfga custody refusal joins first tool before diagnostic result',async()=>{
 const h=harness();const original=Error('private custody material');h.adapters.reopen=async name=>{h.calls.push('reopen-'+name);if(name==='openfga')throw original;return {path:'/tools/'+name,archive:'fixture',sha256:'0'.repeat(64)};};
 const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.equal(error,original);assert.deepEqual(h.calls,['reopen-temporal','reopen-openfga','timer-clear','close-temporal']);assert.deepEqual(describe(error),{phase:'retained-openfga-custody',kind:'refused'});
});
test('actual nested service verification boundary survives lifetime catch without raw cause',async()=>{
 const h=harness();const original=Error('private verification detail');h.adapters.start=(cfg,unused,signal)=>services.startOwnedRuntimeServices(cfg,{verify:async()=>{throw original;}},signal);
 const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.equal(error,original);assert.deepEqual(h.calls.slice(-3),['timer-clear','close-temporal','close-openfga']);assert.deepEqual(describe(error),{phase:'service-tool-verification',kind:'refused'});
});
test('actual service generic error replacement preserves fixed token boundary only',async()=>{
 const h=harness();let removed=false;h.adapters.start=(cfg,unused,signal)=>services.startOwnedRuntimeServices(cfg,{verify:async()=>{},makeRoot:async()=>'/owned-private',token:()=> '1'.repeat(64),writeToken:async()=>{throw Error('private token-path detail');},removeRoot:async()=>{removed=true;}},signal);
 const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.equal(error.message,'owned runtime fixture unavailable');assert.equal(removed,true);assert.deepEqual(describe(error),{phase:'service-token-file',kind:'refused'});
});
test('annotation is fixed, does not inspect private errors, and emission cannot replace error identity',async()=>{
 const original=Error('private endpoint and credentials');original.phase='caller-controlled';
 assert.equal(ownedRuntimeStartupFailureAnnotation(original),'::error::Observed owned runtime startup: phase=unattributed; failure=refused.\n');
 recordOwnedRuntimeStartupFailure(original,'retained-temporal-custody');recordOwnedRuntimeStartupFailure(original,'service-model-readback','refused');
 assert.equal(ownedRuntimeStartupFailureAnnotation(original),'::error::Observed owned runtime startup: phase=retained-temporal-custody; failure=refused.\n');
 await assert.rejects(withOwnedRuntimeStartupDiagnostics(async()=>{throw original;},true,()=>{throw Error('emitter failed');}),error=>error===original);
 let emitted=false;await assert.rejects(withOwnedRuntimeStartupDiagnostics(async()=>{throw original;},false,()=>{emitted=true;}),error=>error===original);assert.equal(emitted,false);
 const poison=new Proxy({}, {get:()=>{throw Error('must not inspect');}});assert.equal(ownedRuntimeStartupFailureAnnotation(poison),'::error::Observed owned runtime startup: phase=unattributed; failure=refused.\n');
});
test('annotation waits partial custody cleanup before original error escapes',async()=>{
 const h=harness(),original=Error('private partial failure'),annotations=[];let finish,closing=false,settled=false;
 h.adapters.reopen=async name=>{if(name==='openfga')throw original;return {path:'/tools/'+name,archive:'fixture',sha256:'0'.repeat(64)};};
 h.adapters.closeTool=async()=>{closing=true;await new Promise(resolve=>{finish=resolve;});};
 const pending=withOwnedRuntimeStartupDiagnostics(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters),true,text=>annotations.push(text)).catch(error=>{settled=true;return error;});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(closing,true);assert.equal(settled,false);assert.deepEqual(annotations,[]);finish();assert.equal(await pending,original);
 assert.deepEqual(annotations,['::error::Observed owned runtime startup: phase=retained-openfga-custody; failure=refused.\n']);
});
test('existing cleanup failure precedence survives fixed diagnostic metadata',async()=>{
 const h=harness();h.adapters.start=(cfg,unused,signal)=>services.startOwnedRuntimeServices(cfg,{verify:async()=>{},makeRoot:async()=>'/owned-private',token:()=> '1'.repeat(64),writeToken:async()=>{throw Error('private original failure');},removeRoot:async()=>{throw Error('private cleanup failure');}},signal);
 const error=await failure(()=>lifetime.startRetainedOwnedRuntimeLifetime(config,h.adapters));assert.equal(error.message,'owned runtime cleanup incomplete');assert.deepEqual(describe(error),{phase:'service-startup-cleanup',kind:'cleanup-incomplete'});assert.deepEqual(h.calls.slice(-2),['close-temporal','close-openfga']);
});

test('actual preparation state allocation refusal preserves original error, emits fixed phase and never starts services',async()=>{
 const source=await readFile(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
 const start=source.indexOf('async function prepareOwnedCurrentComplianceRuntime(configuration,complianceFixtureSQL){');
 const end=source.indexOf('\nasync function exerciseComplianceBrowser(configuration)',start);assert.ok(start>=0&&end>start);
 const original=Error('private state directory data');let servicesStarted=0,allocations=0;const emitted=[];
 const context={ownedResourceCleanupStarted:false,currentComplianceClosing:false,currentCompliancePreparation:undefined,currentComplianceRuntimeStartup:undefined,assert,process:{env:{ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:'/owned/archive',ZASP_BROWSER_RUNTIME_RAW_ROOT:'/owned/raw'}},complianceBrowserMode:true,compliancePhase:null,currentComplianceStateRoot:null,currentComplianceServices:null,
 mkdtemp:async prefix=>{assert.equal(prefix,'/tmp/zasp-browser-current-runtime-');allocations++;throw original;},startRetainedOwnedRuntimeLifetime:async()=>{servicesStarted++;throw Error('must not start');},recordOwnedRuntimeStartupFailure,
 withOwnedRuntimeStartupDiagnostics:(action,enabled)=>withOwnedRuntimeStartupDiagnostics(action,enabled,text=>emitted.push(text))};
 vm.createContext(context);vm.runInContext(`${source.slice(start,end)}\nglobalThis.prepare=prepareOwnedCurrentComplianceRuntime;`,context);
 await assert.rejects(context.prepare({migrate:'owned',migrationEnvironment:{},proxyPort:1234},'fixture'),error=>error===original);
 assert.equal(allocations,1);assert.equal(servicesStarted,0);assert.equal(context.currentComplianceStateRoot,null);assert.equal(context.currentComplianceServices,null);
 assert.deepEqual(describe(original),{phase:'state-allocation',kind:'refused'});
 assert.deepEqual(emitted,['::error::Observed owned runtime startup: phase=state-allocation; failure=refused.\n']);
});
