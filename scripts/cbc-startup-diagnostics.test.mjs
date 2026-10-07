import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { OwnedAPIStartupError } from './owned-api-startup-wait.mjs';
import * as diagnostic from './browser-command-failure.mjs';
const { emitComplianceAPIChildFailure, emitComplianceAPIStartupFailure, emitComplianceBrowserPhaseFailure } = diagnostic;
const source=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const tree=ts.createSourceFile('actual-runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
assert.equal(tree.parseDiagnostics.length,0);
const mounted=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='exerciseComplianceBrowser');
const startAPI=mounted.body.statements.find(n=>n.getText(tree).startsWith('const startAPI=async(')).getText(tree);
const annotation=reason=>`::error title=Compliance API readiness failed::Observed readiness reason: ${reason}.`;
function apiHarness(error,{mode=true,emitterFails=false}={}) {
 const calls=[],annotations=[],wrappers=[];
 const run=new Function('startChild','waitForOwnedAPIStartup','apiEnvironment','apiBinary','healthPort','complianceBrowserMode','emitComplianceAPIChildFailure','console','Error',`return(async()=>{let api;let compliancePhase='browser-assertions';${startAPI}try{await startAPI(false);}catch(error){return {error,phase:compliancePhase};}})();`);
 const result=run(()=>{calls.push('spawn');return {output:()=>{calls.push('output');return 'CANARY_SECRET_PROVIDER_BODY';}};},async()=>{calls.push('ready');throw error;},{KEEP:'fixed'},'/owned/api',13,mode,emitComplianceAPIChildFailure,{error:x=>{if(emitterFails)throw Error('CANARY_EMITTER');annotations.push(x);}},function(message){const wrapped=Error(message);wrappers.push(wrapped);return wrapped;});
 return {result,calls,annotations,wrappers};
}
test('actual owned readiness failure exposes fixed reason without replacing wrapper',async()=>{
 const h=apiHarness(new OwnedAPIStartupError('deadline'));const r=await h.result;
 assert.equal(r.error,h.wrappers[0]);assert.equal(r.phase,'api-ready');assert.deepEqual(h.calls,['spawn','ready','output','output']);
 assert.deepEqual(h.annotations,['::error title=Compliance API startup failed::Observed child stage: unavailable.',annotation('deadline')]);
 assert.doesNotMatch(h.annotations.join(''),/CANARY|SECRET|PROVIDER|BODY/);
});
test('startup reasons are typed closed and unknown errors disclose only unavailable',async()=>{
 assert.equal(typeof emitComplianceAPIStartupFailure,'function');
 for(const reason of ['inputs','child-exited','canceled','deadline','body-limit']){const h=apiHarness(new OwnedAPIStartupError(reason));await h.result;assert.equal(h.annotations[1],annotation(reason));}
 for(const error of [new Error('owned API startup refused: deadline'),new OwnedAPIStartupError('CANARY_SECRET'),new OwnedAPIStartupError('deadline\n::error SECRET'),null,{message:'CANARY_SECRET'},Object.defineProperty(new OwnedAPIStartupError('deadline'),'message',{get(){throw Error('CANARY_GETTER');}})]){const emitted=[];emitComplianceAPIStartupFailure(error,x=>emitted.push(x));assert.deepEqual(emitted,[annotation('unavailable')]);}
 for(const options of [{mode:false},{emitterFails:true}]){const h=apiHarness(new OwnedAPIStartupError('deadline'),options);const r=await h.result;assert.equal(r.error,h.wrappers[0]);assert.deepEqual(h.annotations,[]);}
});
const prepare=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='prepareOwnedCurrentComplianceRuntime');
const tryBlock=prepare.body.statements.find(ts.isTryStatement);
const stop=tryBlock.tryBlock.statements.find(n=>n.getText(tree).startsWith('const publicOrigin='));assert.ok(stop);
const preparePrefix=source.slice(prepare.getStart(tree),stop.getStart(tree))+'\n} finally { finishPreparation(); }\n}';
function fixtureHarness(fail,mode=true){
 const calls=[],owned=Error('CANARY_DSN_SQL_SECRET'),annotations=[];const call=name=>{calls.push(name);if(name===fail)throw owned;};
 const env={ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:'/owned/archive',ZASP_BROWSER_RUNTIME_RAW_ROOT:'/owned/raw'};
 const deps={path,assert,process:{env},complianceBrowserMode:mode,mkdtemp:async()=>{call('state');return '/owned/state';},rm:async()=>{},randomBytes:()=>({toString:()=> 'fixed'}),withOwnedRuntimeStartupDiagnostics:async f=>f(),recordOwnedRuntimeStartupFailure:e=>e,
 startRetainedOwnedRuntimeLifetime:async()=>{call('services');return {environment:{},completed:new Promise(()=>{})};},complianceRuntimeBindings:()=>{},reservePort:async()=>54321,createOwnedBrowserPostgres:()=>({start:async()=>{call('postgres');}}),provisionPostgresPrincipals:async()=>{call('principals');},closedOwnedAmbientEnvironment:()=>({}),seedPostgres:async dsn=>{assert.equal(dsn,'postgres://zasp_e2e@127.0.0.1:54321/postgres?sslmode=disable');call('seed');},postgresBin:'/owned/pg',command:async(executable,args,options)=>{if(executable==='/owned/migrate'){assert.deepEqual(args,['up-to-56']);assert.equal(options.timeout,300000);call('schema');}else if(args.at(-1)==='CANARY_FIXTURE_SQL'){assert.deepEqual(args.slice(1),['-X','-v','ON_ERROR_STOP=1','-c','CANARY_FIXTURE_SQL']);call('fixture-sql');}else call('roles');return {};},cleanupController:{run:async()=>{}},emitComplianceBrowserPhaseFailure,Error};
 const run=new Function(...Object.keys(deps),`return(async()=>{let ownedResourceCleanupStarted=false,currentComplianceClosing=false,currentComplianceServices,currentComplianceStateRoot,currentComplianceRuntimeStartup,currentCompliancePreparation,currentCompliancePostgres,currentComplianceFailure;let compliancePhase='services';${preparePrefix}try{await prepareOwnedCurrentComplianceRuntime({migrate:'/owned/migrate',migrationEnvironment:{},proxyPort:7},'CANARY_FIXTURE_SQL');return {phase:compliancePhase};}catch(error){return {error,phase:compliancePhase};}finally{await currentCompliancePreparation;}})();`);
 return {calls,owned,annotations,result:run(...Object.values(deps))};
}
test('actual current fixture prefix identifies seed and SQL refusal with original calls intact',async()=>{
 const order=['state','services','postgres','principals','roles','schema','seed','fixture-sql'];
 for(const fail of ['seed','fixture-sql']){const h=fixtureHarness(fail);const r=await h.result;assert.equal(r.error,h.owned);assert.deepEqual(h.calls,order.slice(0,order.indexOf(fail)+1));assert.equal(r.phase,fail==='seed'?'compliance-current-seed':'compliance-current-fixture-sql');const emitted=[];emitComplianceBrowserPhaseFailure(r.phase,x=>emitted.push(x));assert.deepEqual(emitted,[`::error title=Compliance browser phase failed::Observed phase: ${r.phase}.`]);assert.doesNotMatch(emitted.join(''),/CANARY|DSN|SQL_SECRET/);}
 const h=fixtureHarness();assert.equal((await h.result).phase,'compliance-current-fixture');assert.deepEqual(h.calls,order);
 const ordinary=fixtureHarness('fixture-sql',false);assert.equal((await ordinary.result).phase,'services');assert.equal((await ordinary.result).error,ordinary.owned);
});
test('new fixture labels remain exact and diagnostic emitter faults are contained',()=>{
 for(const label of ['compliance-current-seed','compliance-current-fixture-sql']){const emitted=[];emitComplianceBrowserPhaseFailure(label,x=>emitted.push(x));assert.deepEqual(emitted,[`::error title=Compliance browser phase failed::Observed phase: ${label}.`]);}
 for(const label of ['compliance-current-seed\nSECRET','compliance-current-fixture-sql ','CANARY_SECRET']){const emitted=[];emitComplianceBrowserPhaseFailure(label,x=>emitted.push(x));assert.deepEqual(emitted,['::error title=Compliance browser phase failed::Observed phase: unavailable.']);}
 assert.doesNotThrow(()=>emitComplianceAPIStartupFailure(new OwnedAPIStartupError('deadline'),()=>{throw Error('CANARY_EMITTER');}));
});
