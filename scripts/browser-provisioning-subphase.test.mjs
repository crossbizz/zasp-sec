import {complianceRuntimeBindings} from './compliance-runtime-prerequisites.mjs';
import {emitComplianceBrowserPhaseFailure} from './browser-command-failure.mjs';
import {withOwnedRuntimeStartupDiagnostics,recordOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import path from 'node:path';
const source=readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const ast=ts.createSourceFile('production-combined-e2e.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
const declarations=ast.statements.filter(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='prepareOwnedCurrentComplianceRuntime');
assert.equal(ast.parseDiagnostics.length,0);
assert.equal(declarations.length,1);
const body=declarations[0].getText(ast);
function fixture({fail,mode=true}={}){
 let randomSequence=0;
 const seedBytes=new Set();
 const annotations=[];const events=[];const marker=new Error('owned finite adapter refusal');const pending=new Promise(()=>{});
 const record=(event)=>{events.push({event,phase:instance.phase()});if(event===fail)throw marker;};
 const runtime={ZASP_ENVIRONMENT:'test',ZASP_RUNTIME_SERVICES_ENABLED:'true',ZASP_RUNTIME_SERVICES_TIMEOUT:'5s',ZASP_TEMPORAL_ADDRESS:'127.0.0.1:17233',ZASP_TEMPORAL_NAMESPACE:'owned-test',ZASP_TEMPORAL_TASK_QUEUE:'owned-main',ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE:'owned-discovery',ZASP_OPENFGA_URL:'http://127.0.0.1:18088',ZASP_OPENFGA_STORE_ID:'01ARZ3NDEKTSV4RRFFQ69G5FAV',ZASP_OPENFGA_MODEL_ID:'01ARZ3NDEKTSV4RRFFQ69G5FAW',ZASP_OPENFGA_TOKEN_FILE:'/fixed/token'};
 const config={migrate:'/fixed/agentsec-migrate',migrationEnvironment:{PATH:'/usr/bin',ZASP_MIGRATION_DB_PRINCIPAL:'owner'},proxyPort:8443};
 const operatorDSN='postgres://zasp_operator@127.0.0.1:15432/postgres?sslmode=disable';
 const apiDSN='postgres://zasp_svc_api@127.0.0.1:15432/postgres?sslmode=disable';
 const dependencies={complianceRuntimeBindings,assert,path,Buffer,AbortController,withOwnedRuntimeStartupDiagnostics:(action,enabled)=>withOwnedRuntimeStartupDiagnostics(action,enabled,text=>annotations.push(text)),recordOwnedRuntimeStartupFailure,complianceBrowserMode:mode,
  process:{env:{ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:'/fixed/archives',ZASP_BROWSER_RUNTIME_RAW_ROOT:'/fixed/raw'}},
  temporaryRoot:'/fixed/tmp',root:'/fixed/repo',platform:'/fixed/repo/services/platform',postgresBin:'/fixed/pg',productHostname:'product.test',
  mkdtemp:async prefix=>{assert.equal(prefix,'/tmp/zasp-browser-current-runtime-');record('state');return '/tmp/zasp-browser-current-runtime-fixed';},
  randomBytes:size=>Buffer.alloc(size,++randomSequence),
  startRetainedOwnedRuntimeLifetime:async value=>{assert.equal(value.archiveRoot,'/fixed/archives');assert.equal(value.rawRoot,'/fixed/raw');record('services');return {environment:runtime,completed:pending};},
  reservePort:async()=>15432,
  createOwnedBrowserPostgres:({port})=>{assert.equal(port,15432);return {start:async()=>record('postgres')};},
  closedOwnedAmbientEnvironment:()=>({PATH:'/usr/bin'}),
  seedCurrentComplianceIdentity:async dsn=>{assert.equal(dsn,operatorDSN);record('seed');},
  combinedAPIEnvironment:()=>({opaque:'identity'}),
  writeFile:async (file,bytes,options)=>{assert.equal(bytes.length,32);assert.deepEqual(options,{flag:'wx',mode:0o400});assert.ok(!seedBytes.has(bytes.toString('hex')));seedBytes.add(bytes.toString('hex'));record(path.basename(file));},
  command:async (exe,args,options)=>{
   if(exe==='/fixed/pg/psql'){
    assert.deepEqual(args,[operatorDSN,'-X','-v','ON_ERROR_STOP=1','-c','fixture-sql']);
    record('fixture');
   }else{assert.equal(exe,'go');assert.deepEqual(args,['build','-o','/fixed/tmp/zasp-authorization-reconcile','./cmd/zasp-authorization-reconcile']);assert.equal(options.cwd,'/fixed/repo/services/platform');assert.equal(options.timeout,120000);record('reconcile-build');}
   return {status:0,signal:null,stdout:''};
  },
  installOwnedCurrent80:async value=>{
   assert.equal(value.port,15432);
   assert.equal(value.migrate,config.migrate);
   assert.equal(value.organization,'pid_10000001-0000-4000-8000-000000000001');
   assert.equal(value.foreignOrganization,'pid_90000001-0000-4000-8000-000000000001');
   assert.deepEqual(value.keyFiles,{forward:'/tmp/zasp-browser-current-runtime-fixed/forward.seed',compensation:'/tmp/zasp-browser-current-runtime-fixed/compensation.seed',approval:'/tmp/zasp-browser-current-runtime-fixed/approval.seed'});
   record('current80');await value.seedCurrent(operatorDSN);
   return {apiDSN,environment:{...runtime,ZASP_WORKER_FORWARD_SEED_FILE:'/fixed/forward.seed'}};
  },
  runOwnedProjectionLoop:()=>{record('projection-loop');return pending;},
  cleanupController:{run:async()=>record('cleanup')}
 };
 const construct=new Function(...Object.keys(dependencies),`let ownedResourceCleanupStarted=false,currentComplianceRuntimeStartup,currentCompliancePreparation;let compliancePhase='compliance-fixture-provisioning';let currentComplianceStateRoot,currentComplianceServices,currentCompliancePostgres,currentComplianceProjectionController,currentComplianceProjectionLoop,currentComplianceFailure;let currentComplianceClosing=false;${body};return {run:prepareOwnedCurrentComplianceRuntime,phase:()=>compliancePhase};`);
 const instance=construct(...Object.values(dependencies));
 return {events,marker,run:()=>instance.run(config,'fixture-sql'),phase:instance.phase};
}
test('current database installs the sealed profile and seeds it as its table owner',async()=>{
 const f=fixture();const out=await f.run();assert.deepEqual(f.events.map(v=>v.event),['state','services','postgres','forward.seed','compensation.seed','approval.seed','reconcile-build','current80','seed','fixture','projection-loop']);
 assert.equal(out.configuration.postgresPort,15432);assert.equal(out.configuration.apiDSN,'postgres://zasp_svc_api@127.0.0.1:15432/postgres?sslmode=disable');assert.equal(out.configuration.dsn,'postgres://zasp_operator@127.0.0.1:15432/postgres?sslmode=disable');assert.equal(out.configuration.currentRuntimeEnvironment.ZASP_ENVIRONMENT,'test');assert.equal(out.configuration.currentRuntimeEnvironment.ZASP_WORKER_FORWARD_SEED_FILE,'/fixed/forward.seed');assert.equal(out.configuration.currentRuntimeEnvironment.ZASP_OPENFGA_MODEL_ID,'01ARZ3NDEKTSV4RRFFQ69G5FAW');assert.equal(f.phase(),'compliance-fixture-provisioning');
});
const stages=[['services','compliance-runtime-services'],['postgres','compliance-current-postgres'],['seed','compliance-current-seed'],['fixture','compliance-current-fixture-sql'],['forward.seed','compliance-current-keys'],['approval.seed','compliance-current-keys'],['reconcile-build','compliance-reconcile-build'],['current80','compliance-current-profile']];
for(const [boundary,phase]of stages)test(`actual ${boundary} failure retains exact error and fixed subphase`,async()=>{
 const f=fixture({fail:boundary});await assert.rejects(f.run(),error=>error===f.marker);assert.equal(f.phase(),phase);assert.equal(f.events.at(-1).event,boundary);
});
test('noncompliance finite helper keeps diagnostic phase unchanged',async()=>{
 const f=fixture({mode:false,fail:'current80'});await assert.rejects(f.run(),error=>error===f.marker);assert.equal(f.phase(),'compliance-fixture-provisioning');
});

test('new subphase labels are finite constants and never reflect a caller secret',()=>{
 for(const [,phase]of stages){const out=[];emitComplianceBrowserPhaseFailure(phase,x=>out.push(x));assert.deepEqual(out,[`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]);}
 for(const value of ['CANARY_SECRET','compliance-current-profile\nsecret',null,{}]){const out=[];emitComplianceBrowserPhaseFailure(value,x=>out.push(x));assert.deepEqual(out,['::error title=Compliance browser phase failed::Observed phase: unavailable.']);}
});
