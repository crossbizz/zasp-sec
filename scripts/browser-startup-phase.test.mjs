import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import {emitComplianceBrowserPhaseFailure,emitComplianceAPIChildFailure} from './browser-command-failure.mjs';
const source=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const tree=ts.createSourceFile('published-runner.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
assert.equal(tree.parseDiagnostics.length,0);
const main=tree.statements.find(ts.isTryStatement);
const body=main.tryBlock.statements;
const index=name=>body.findIndex(n=>n.getText(tree).includes(name));
const start=index('postgres = await startPostgres(');
const end=index('console.log("combined E2E: disposable PostgreSQL ready")');
// Include the candidate's compliance-only assignment immediately before PG.
const first=ts.isIfStatement(body[start-1])&&body[start-1].getText(tree).includes('compliancePhase')?start-1:start;
const initial=body.slice(first,end+1).map(n=>n.getText(tree)).join('\n');
const mounted=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='exerciseComplianceBrowser');
const stop=mounted.body.statements.find(n=>n.getText(tree)==='const continuityCheckpoints=[];');
assert.ok(main.catchClause&&main.finallyBlock&&start>0&&end>start&&stop);
const mountedPrefix=source.slice(mounted.getStart(tree),stop.getStart(tree))+'\n}';
const labels={postgres:'postgres-startup',instrument:'postgres-instrumentation',principals:'postgres-principal-provisioning','sql-schema':'compliance-fixture-provisioning','sql-fixture':'compliance-fixture-provisioning','current-runtime':'compliance-fixture-provisioning',storage:'compliance-fixture-provisioning',identity:'controlled-identity-startup',history:'policy-history-startup','api-environment':'api-startup','api-spawn':'api-startup','api-ready':'api-ready','web-spawn':'web-startup','web-ready':'web-ready',tls:'tls-provisioning',proxy:'proxy-startup',browser:'browser-startup'};
const mountedOrder=['sql-schema','sql-fixture','current-runtime','storage','identity','history','api-environment','api-spawn','api-ready','web-spawn','web-ready','tls','proxy','browser'];
function harness({kind='mounted',fail,mode=true,emitterFails=false}={}){
 const calls=[],annotations=[],wrappers=[],owned=Error('CANARY_SECRET_ENV_URL_TENANT');let sqlCalls=0;
 const call=(name,args)=>{calls.push({name,args});if(name===fail)throw owned;};
 const cleanupController={run:async()=>{call('cleanup',[]);},dispose:()=>{call('dispose',[]);}};
 const configuration={dsn:'CANARY_DSN',apiBinary:'/owned/api',workerE2EBinary:'/owned/worker',postgresPort:10,identityPort:11,policyHistoryPort:12,apiPort:13,healthPort:14,webPort:15,proxyPort:16,chromePort:17};
 const deps={assert,path,configuration,complianceBrowserMode:mode,cleanupController,emitComplianceBrowserPhaseFailure,emitComplianceAPIChildFailure,
 prepareOwnedCurrentComplianceRuntime:async value=>{assert.equal(value,configuration);call('current-runtime',[]);return {configuration:{...value,currentRuntimeEnvironment:{}},projection:{refresh:async()=>{}}};},closedOwnedAmbientEnvironment:()=>({}),
 console:{log:()=>{},error:x=>{if(emitterFails)throw Error('CANARY_EMITTER');annotations.push(x);}},process:{env:{ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC:'1'}},postgresBin:'/owned/pg',postgresPort:10,dsn:'CANARY_DSN',temporaryRoot:'/owned/tmp',root:'/repo',productHostname:'CANARY_HOST',
 startPostgres:async(...args)=>{call('postgres',args);return {owned:true};},provisionPostgresPrincipals:async(...args)=>{call('principals',args);},
 command:async(...args)=>{const name=args[0]==='openssl'?'tls':kind==='initial'?'instrument':++sqlCalls===1?'sql-schema':'sql-fixture';call(name,args);return {stdout:name==='instrument'?'pl':name==='sql-schema'?'56':''};},
 mkdtemp:async(...args)=>{call('storage',args);return '/owned/CANARY_TEMP';},startIdentityServer:async(...args)=>{call('identity',args);return {owned:true};},startPolicyHistoryServer:async(...args)=>{call('history',args);return {owned:true};},
 combinedAPIEnvironment:(...args)=>{call('api-environment',args);return {ZASP_COMPLIANCE_EXPORT_REMOVED:'CANARY_VALUE',KEEP:'owned'};},
 startChild:(...args)=>{call(args[0]===configuration.apiBinary?'api-spawn':'web-spawn',args);return {owned:true,output:()=> 'CANARY_CHILD_OUTPUT'};},
 waitForOwnedAPIStartup:async({target,child})=>{assert.equal(child.owned,true);call('api-ready',[target,child]);},
 waitForHTTP:async(...args)=>{call(args[0].includes('/readyz')?'api-ready':'web-ready',args);},startProxy:async(...args)=>{call('proxy',args);return {owned:true};},startBrowser:async(...args)=>{call('browser',args);return {owned:true,cdp:{}};},
 Error:function(message){const error=Error(message);wrappers.push(error);return error;}};
 const run=new Function(...Object.keys(deps),`return (async()=>{let compliancePhase="${kind==='initial'?'services':'schema-bootstrap'}";let postgres,identity,policyHistory,api,web,proxy,browser;${mountedPrefix}\ntry{${kind==='initial'?initial:'await exerciseComplianceBrowser(configuration);'}}${main.catchClause.getText(tree)}finally${main.finallyBlock.getText(tree)}return compliancePhase;})();`);
 return {calls,annotations,owned,wrappers,run:()=>run(...Object.values(deps))};
}
test('parsed initial PG startup branches retain Error identity, call prefix and actual fatal cleanup',async()=>{
 const order=['postgres','instrument','principals'];
 for(const fail of order){const h=harness({kind:'initial',fail});await assert.rejects(h.run(),e=>e===h.owned);assert.deepEqual(h.calls.map(x=>x.name),[...order.slice(0,order.indexOf(fail)+1),'cleanup','dispose']);assert.deepEqual(h.annotations,[`::error title=Compliance browser phase failed::Observed phase: ${labels[fail]}.`]);assert.doesNotMatch(h.annotations.join(''),/CANARY|SECRET|URL|TENANT/);}
});
test('parsed mounted startup failures distinguish each owned operation without changing wrapper or cleanup',async()=>{
 for(const fail of mountedOrder){
  const h=harness({fail});await assert.rejects(h.run(),e=>e===(fail==='api-ready'?h.wrappers[0]:h.owned));assert.deepEqual(h.calls.map(x=>x.name),[...mountedOrder.slice(0,mountedOrder.indexOf(fail)+1),'cleanup','dispose']);assert.equal(h.wrappers.length,fail==='api-ready'?1:0);assert.deepEqual(h.annotations,[...(fail==='api-ready'?['::error title=Compliance API startup failed::Observed child stage: unavailable.']:[]),`::error title=Compliance browser phase failed::Observed phase: ${labels[fail]}.`]);assert.doesNotMatch(h.annotations.join(''),/CANARY|SECRET|URL|TENANT|owned/);
 }
});
test('parsed success keeps original startup arguments, API deadlines, legacy environment and assertion phase',async()=>{
 const h=harness();assert.equal(await h.run(),'browser-assertions');assert.deepEqual(h.calls.map(x=>x.name),[...mountedOrder,'cleanup','dispose']);assert.deepEqual(h.annotations,[]);
 const api=h.calls.find(x=>x.name==='api-spawn').args;assert.deepEqual(api.slice(0,2),['/owned/api',['-test.run=^TestComplianceBrowserAPIProcess$','-test.v','-test.timeout=21m']]);assert.equal(api[2].env.ZASP_COMPLIANCE_BROWSER_LEGACY,'true');assert.equal(api[2].env.KEEP,'owned');assert.ok(Object.keys(api[2].env).every(k=>!k.startsWith('ZASP_COMPLIANCE_EXPORT_')));
 const readiness=h.calls.find(x=>x.name==='api-ready').args;assert.equal(readiness[0],'http://127.0.0.1:14/readyz');assert.equal(readiness[1].owned,true);assert.deepEqual(h.calls.find(x=>x.name==='web-ready').args,['http://127.0.0.1:15/sign-in',200]);assert.deepEqual(h.calls.find(x=>x.name==='web-spawn').args.slice(0,2),['/repo/node_modules/.bin/vinext',['start','--port','15','--hostname','127.0.0.1']]);
 assert.deepEqual(h.calls.find(x=>x.name==='tls').args.slice(0,2),['openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=CANARY_HOST','-addext','subjectAltName=DNS:CANARY_HOST','-keyout','/owned/tmp/compliance-tls.key','-out','/owned/tmp/compliance-tls.crt']]);
});
test('parsed noncompliance modes retain errors and cleanup with no phase annotations',async()=>{
 for(const kind of ['initial','mounted']){const h=harness({kind,mode:false,fail:kind==='initial'?'principals':'browser'});await assert.rejects(h.run(),e=>e===h.owned);assert.deepEqual(h.annotations,[]);assert.deepEqual(h.calls.slice(-2).map(x=>x.name),['cleanup','dispose']);}
});
test('annotation emitter failure cannot replace a parsed owned startup Error',async()=>{
 const h=harness({fail:'proxy',emitterFails:true});await assert.rejects(h.run(),e=>e===h.owned);assert.deepEqual(h.annotations,[]);assert.deepEqual(h.calls.slice(-2).map(x=>x.name),['cleanup','dispose']);
});
test('parsed API restart restores browser assertion phase only after readiness succeeds',async()=>{
 const declaration=mounted.body.statements.find(n=>n.getText(tree).startsWith('const startAPI=async(')).getText(tree);
 for(const fail of [null,'spawn','ready']){
  const calls=[],owned=Error('CANARY_RESTART'),wrappers=[];
  const run=new Function('complianceBrowserMode','apiEnvironment','apiBinary','healthPort','startChild','waitForOwnedAPIStartup','Error',`const emitComplianceAPIChildFailure=()=>{};const console={error:()=>{}};return(async()=>{let compliancePhase='browser-assertions',api;${declaration}try{await startAPI();return {phase:compliancePhase};}catch(error){return {phase:compliancePhase,error};}})();`);
  const result=await run(true,{KEEP:'fixed'},'/owned/api',14,()=>{calls.push('spawn');if(fail==='spawn')throw owned;return {output:()=> 'CANARY_OUTPUT'};},async({target,child})=>{assert.equal(target,'http://127.0.0.1:14/readyz');assert.equal(typeof child.output,'function');calls.push('ready');if(fail==='ready')throw owned;},function(message){const error=Error(message);wrappers.push(error);return error;});
  assert.deepEqual(calls,fail==='spawn'?['spawn']:['spawn','ready']);assert.equal(result.phase,fail==='spawn'?'api-startup':fail==='ready'?'api-ready':'browser-assertions');assert.equal(result.error,fail==='spawn'?owned:fail==='ready'?wrappers[0]:undefined);
 }
});
test('all fixed startup labels are closed and unknown canary labels emit only unavailable',()=>{
 for(const phase of new Set(Object.values(labels))){const emitted=[];emitComplianceBrowserPhaseFailure(phase,x=>emitted.push(x));assert.deepEqual(emitted,[`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]);}
 for(const phase of ['CANARY_SECRET_ENV_URL_TENANT','api-ready\n::error CANARY',null,{},'postgres-startup ']){const emitted=[];emitComplianceBrowserPhaseFailure(phase,x=>emitted.push(x));assert.deepEqual(emitted,['::error title=Compliance browser phase failed::Observed phase: unavailable.']);}
});
