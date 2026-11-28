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
const prepareSource=prepare.getText(tree);
function fixtureHarness(fail,mode=true){
 const calls=[],owned=Error('CANARY_DSN_SQL_SECRET');
 const call=name=>{calls.push(name);if(name===fail)throw owned;};
 const operatorDSN='postgres://zasp_operator@127.0.0.1:54321/postgres?sslmode=disable';
 const env={ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:'/owned/archive',ZASP_BROWSER_RUNTIME_RAW_ROOT:'/owned/raw'};
 const deps={
  path,assert,process:{env},complianceBrowserMode:mode,productHostname:'browser.test',postgresBin:'/owned/pg',temporaryRoot:'/owned',platform:'/owned/platform',
  mkdtemp:async()=>{call('state');return '/owned/state';},randomBytes:size=>Buffer.alloc(size),
  withOwnedRuntimeStartupDiagnostics:async action=>action(),
  startRetainedOwnedRuntimeLifetime:async()=>{call('services');return {environment:{},completed:new Promise(()=>{})};},
  complianceRuntimeBindings:()=>{},reservePort:async()=>54321,createOwnedBrowserPostgres:()=>({start:async()=>call('postgres')}),
  closedOwnedAmbientEnvironment:()=>({}),combinedAPIEnvironment:()=>({}),
  writeFile:async file=>call(path.basename(file)),
  seedCurrentComplianceIdentity:async dsn=>{assert.equal(dsn,operatorDSN);call('seed');},
  command:async(executable,args)=>{
   if(executable==='go'){call('reconcile-build');return;}
   assert.equal(executable,'/owned/pg/psql');
   assert.deepEqual(args,[operatorDSN,'-X','-v','ON_ERROR_STOP=1','-c','CANARY_FIXTURE_SQL']);
   call('fixture-sql');
  },
  installOwnedCurrent80:async({seedCurrent})=>{
   call('install');
   await seedCurrent(operatorDSN);
   call('seed-complete');
   return {environment:{},apiDSN:'owned-api-dsn'};
  },
  runOwnedProjectionLoop:()=>{call('projection');return new Promise(()=>{});},
  AbortController,
 };
 const run=new Function(...Object.keys(deps),`return(async()=>{
  let ownedResourceCleanupStarted=false,currentComplianceClosing=false,currentComplianceServices,currentComplianceStateRoot,currentComplianceRuntimeStartup,currentCompliancePreparation,currentCompliancePostgres,currentComplianceFailure,currentComplianceProjectionController,currentComplianceProjectionLoop;
  let compliancePhase='services';
  ${prepareSource}
  try {
   const {configuration}=await prepareOwnedCurrentComplianceRuntime({migrate:'/owned/migrate',proxyPort:7},'CANARY_FIXTURE_SQL');
   return {phase:compliancePhase,dsn:configuration.dsn};
  }catch(error){return {error,phase:compliancePhase};}finally{await currentCompliancePreparation;}
 })();`);
 return {calls,owned,operatorDSN,result:run(...Object.values(deps))};
}
test('actual current fixture identifies seed and SQL refusal in the baseline installation',async()=>{
 const order=['state','services','postgres','forward.seed','compensation.seed','approval.seed','reconcile-build','install','seed','fixture-sql','seed-complete','projection'];
 for(const [fail,phase] of [['seed','compliance-current-seed'],['fixture-sql','compliance-current-fixture-sql']]){
  const h=fixtureHarness(fail);const r=await h.result;
  assert.equal(r.error,h.owned);assert.deepEqual(h.calls,order.slice(0,order.indexOf(fail)+1));assert.equal(r.phase,phase);
  const emitted=[];emitComplianceBrowserPhaseFailure(r.phase,x=>emitted.push(x));
  assert.deepEqual(emitted,[`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]);
  assert.doesNotMatch(emitted.join(''),/CANARY|DSN|SQL_SECRET/);
 }
 const h=fixtureHarness();
 assert.deepEqual(await h.result,{phase:'compliance-fixture-provisioning',dsn:h.operatorDSN});
 assert.deepEqual(h.calls,order);
 const ordinary=fixtureHarness('fixture-sql',false);assert.equal((await ordinary.result).phase,'services');assert.equal((await ordinary.result).error,ordinary.owned);
});
test('new fixture labels remain exact and diagnostic emitter faults are contained',()=>{
 for(const label of ['compliance-current-seed','compliance-current-fixture-sql']){const emitted=[];emitComplianceBrowserPhaseFailure(label,x=>emitted.push(x));assert.deepEqual(emitted,[`::error title=Compliance browser phase failed::Observed phase: ${label}.`]);}
 for(const label of ['compliance-current-seed\nSECRET','compliance-current-fixture-sql ','CANARY_SECRET']){const emitted=[];emitComplianceBrowserPhaseFailure(label,x=>emitted.push(x));assert.deepEqual(emitted,['::error title=Compliance browser phase failed::Observed phase: unavailable.']);}
 assert.doesNotThrow(()=>emitComplianceAPIStartupFailure(new OwnedAPIStartupError('deadline'),()=>{throw Error('CANARY_EMITTER');}));
});
