import test from 'node:test';import assert from 'node:assert/strict';
import {installOwnedCurrent80,closedOwnedAmbientEnvironment,runOwnedProjectionLoop,OwnedProjectionCleanupIncomplete}from './owned-current80-composition.mjs';
function fixture(){const calls=[],organization='pid_10000001-0000-4000-8000-000000000001';const environment={ZASP_RUNTIME_SERVICES_ENABLED:'true',ZASP_ENVIRONMENT:'test',ZASP_RUNTIME_SERVICES_TIMEOUT:'5s',ZASP_TEMPORAL_ADDRESS:'127.0.0.1:32101',ZASP_TEMPORAL_NAMESPACE:'owned',ZASP_TEMPORAL_TASK_QUEUE:'owned-main',ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE:'owned-discovery',ZASP_OPENFGA_URL:'http://127.0.0.1:32102',ZASP_OPENFGA_STORE_ID:'01K00000000000000000000001',ZASP_OPENFGA_MODEL_ID:'01K00000000000000000000002',ZASP_OPENFGA_TOKEN_FILE:'/owned/token'};const revision={organization_id:organization,desired:4,applied:4,generation:2,store_id:environment.ZASP_OPENFGA_STORE_ID,model_id:environment.ZASP_OPENFGA_MODEL_ID};const config={migrate:'/owned/migrate',reconcile:'/owned/reconcile',psql:'/owned/psql',port:32100,organization,runtimeEnvironment:environment,identityEnvironment:{PATH:'/usr/bin:/bin',ZASP_PUBLIC_ORIGIN:'https://fixture.invalid:32103',ZASP_STYTCH_BASE_URL:'http://127.0.0.1:32104',ZASP_STYTCH_PROJECT_ID:'owned-project',ZASP_STYTCH_ORGANIZATION_ID:'owned-org',ZASP_DEPLOYMENT_MODE:'saas',ZASP_ORGANIZATION_ID:'',ZASP_WORKFLOW_SIGNING_KEY:'fixture-input'},seedCurrent:async connection=>{calls.push({action:'seed',connection})},keyFiles:{forward:'/owned/forward',compensation:'/owned/compensation',approval:'/owned/approval'}};config.command=async(executable,args,options)=>{calls.push({executable,args,options});return {status:0,signal:null,stdout:args[0]==='approval-maintenance-checksum'?'a'.repeat(64)+'\n':args.at(-1).includes('activate_projection')?'t\n':executable===config.psql?JSON.stringify(revision):args[1]==='reconcile'?JSON.stringify({organization_id:organization,status:'applied',receipt:{Revision:revision,TupleCount:12,Applied:true}}):'{}'};};return {config,calls,revision};}
test('installs and verifies the published baseline, registers native identities and observes the outbox projection as the API', async () => {
 const {config,calls}=fixture();
 const value=await installOwnedCurrent80(config);
 const order=calls.map(call=>call.action ?? (call.executable===config.migrate ? call.args[0] : call.executable===config.reconcile ? call.args[1] : 'sql'));
 assert.deepEqual(order, ['sql','install-baseline','approval-maintenance-checksum','register-authorization-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier','register-approval-maintenance-verifier','seed','register-identity-session-verifier','register-identity-webhook-verifier','verify-baseline','configure','sql','reconcile','sql']);
 const at=action=>calls[order.indexOf(action)];
 assert.match(calls[0].args[0], /zasp_e2e@/);
 assert.match(calls[0].args.at(-1), /CREATE ROLE zasp_operator .*NOSUPERUSER .*ALTER DATABASE postgres OWNER TO zasp_operator/);
 assert.match(at('install-baseline').options.env.ZASP_POSTGRES_DSN,/zasp_operator@/);
 assert.match(at('seed').connection,/zasp_operator@/);
 assert.equal(at('register-identity-session-verifier').options.env.ZASP_DISCOVERY_API_DB_PRINCIPAL,'zasp_svc_api');
 assert.match(calls[12].args.at(-1),/zasp_approval_maintenance.activate_projection/);
 assert.match(calls.at(-1).args[0], /zasp_svc_api@/);
 assert.match(value.environment.ZASP_SECURITY_AGENT_POSTGRES_DSN,/zasp_svc_security_agent_api@/);
 assert.equal(value.environment.ZASP_POSTGRES_DSN,value.apiDSN);
 assert.match(value.environment.ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN,/zasp_svc_approval_maintenance@/);
 assert.equal(value.environment.ZASP_APPROVAL_MAINTENANCE_KEY_FILE,config.keyFiles.approval);
 assert.equal(value.environment.ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM,'a'.repeat(64));
 assert.equal(at('register-approval-maintenance-verifier').options.env.ZASP_APPROVAL_MAINTENANCE_KEY_FILE,config.keyFiles.approval);
 for(const action of ['reconcile','configure']) {
  const environment=at(action).options.env;
  assert.equal(environment.ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM,'a'.repeat(64));
  assert.equal(environment.ZASP_APPROVAL_MAINTENANCE_KEY_FILE,undefined);
  assert.equal(environment.ZASP_WORKFLOW_SIGNING_KEY,undefined);
 }
 assert.match(at('reconcile').options.env.ZASP_POSTGRES_DSN,/zasp_svc_outbox@/);
 assert.equal(value.applied.desired,value.applied.applied);
 assert.equal(value.acceptance,false);
});
test('initializes and refreshes each owned organization against its own observed revision', async()=>{
 const f=fixture();
 const foreign='pid_90000001-0000-4000-8000-000000000001';
 f.config.foreignOrganization=foreign;
 const command=f.config.command;
 f.config.command=async(executable,args,options)=>{
  const result=await command(executable,args,options);
  if(args.includes(foreign)||args.at(-1).includes(foreign))result.stdout=result.stdout.replaceAll(f.config.organization,foreign);
  return result;
 };
 const projected=await installOwnedCurrent80(f.config);
 assert.deepEqual(f.calls.filter(call=>call.args?.[1]==='reconcile').map(call=>call.args[3]),[f.config.organization,foreign]);
 assert.equal((await projected.refresh(undefined,foreign)).organization_id,foreign);
 assert.throws(()=>projected.refresh(undefined,'pid_90000002-0000-4000-8000-000000000001'));
});
test('a missing or shared maintenance key refuses before opening PostgreSQL',async()=>{
 for(const approval of [undefined,'/owned/compensation','/owned/forward']){
  const f=fixture();f.config.keyFiles.approval=approval;
  await assert.rejects(installOwnedCurrent80(f.config));assert.deepEqual(f.calls,[]);
 }
});
test('a malformed native pin, failed verifier or missing activation prevents projection',async()=>{
 for(const broken of ['approval-maintenance-checksum','register-approval-maintenance-verifier','activate_projection']){
  const f=fixture(),command=f.config.command;
  f.config.command=async(executable,args,options)=>{
   const result=await command(executable,args,options);
   if(args[0]===broken||args.at(-1).includes(broken))return {...result,status:broken.startsWith('register')?1:0,stdout:'f\n'};
   return result;
  };
  await assert.rejects(installOwnedCurrent80(f.config));
  assert.ok(!f.calls.some(call=>call.args?.[1]==='reconcile'));
 }
});
test('missing real runtime model refuses before any installation',async()=>{const f=fixture();delete f.config.runtimeEnvironment.ZASP_OPENFGA_MODEL_ID;await assert.rejects(installOwnedCurrent80(f.config));assert.deepEqual(f.calls,[]);});
for(const field of ['applied','model_id','generation'])test('receipt '+field+' drift refuses instead of claiming acknowledgement',async()=>{const f=fixture();const command=f.config.command;f.config.command=async(...args)=>{const result=await command(...args);if(args[0]===f.config.psql&&args[1].at(-1).includes('zasp_authorization79.revision')){const value=JSON.parse(result.stdout);value[field]=field==='model_id'?'01K00000000000000000000003':value[field]+1;result.stdout=JSON.stringify(value);}return result;};await assert.rejects(installOwnedCurrent80(f.config));});
test('original installer failure stops before verifier or projector invocation',async()=>{const f=fixture();f.config.command=async(...args)=>{f.calls.push(args);return {status:1,signal:null,stdout:''};};await assert.rejects(installOwnedCurrent80(f.config));assert.equal(f.calls.length,1);});
test('closed owner environment removes ambient product settings without suppressing inherited tool metadata',()=>{assert.deepEqual(closedOwnedAmbientEnvironment({PATH:'/usr/bin',ZASP_COMPLIANCE_EXPORT_ROLE_ARN:'ambient',ZASP_RUNTIME_SERVICES_ENABLED:'false',LANG:'C'}),{PATH:'/usr/bin',LANG:'C'});});
test('later projection loop consumes fresh native revisions and stops only after pending pass finalizes',async()=>{const controller=new AbortController(),events=[];let finish,started;const ready=new Promise(resolve=>{started=resolve;});const loop=runOwnedProjectionLoop({refresh:async signal=>{events.push('pass-start');assert.equal(signal,controller.signal);started();await new Promise(resolve=>{finish=resolve;});events.push('pass-finalized');}},controller.signal,()=>assert.fail('unexpected refusal'));await ready;let settled=false;void loop.then(()=>{settled=true;});controller.abort();await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);finish();await loop;assert.deepEqual(events,['pass-start','pass-finalized']);});
test('actual projection failure is reported without publishing a fake applied revision',async()=>{const controller=new AbortController();let refusals=0;await assert.rejects(runOwnedProjectionLoop({refresh:async()=>{throw Error('private');}},controller.signal,()=>{refusals++;}),/^Error: owned authorization projection unavailable$/);assert.equal(refusals,1);});
test('canceled projection cleanup failure remains a refusal and retains failed join',async()=>{const controller=new AbortController();let refusals=0;const failure=new OwnedProjectionCleanupIncomplete();await assert.rejects(runOwnedProjectionLoop({refresh:async()=>{controller.abort();throw failure;}},controller.signal,()=>{refusals++;}),error=>error===failure);assert.equal(refusals,1);});
test('inline grant barriers and owned polling serialize real projection passes',async()=>{const f=fixture(),command=f.config.command;let passes=0,finish;f.config.command=async(...args)=>{if(args[0]===f.config.reconcile&&args[1][1]==='reconcile'){passes++;if(passes===2)await new Promise(resolve=>{finish=resolve;});}return command(...args);};const projector=await installOwnedCurrent80(f.config);const first=projector.refresh(),second=projector.refresh();await new Promise(resolve=>setImmediate(resolve));const started=passes;finish();await Promise.all([first,second]);assert.equal(started,2);assert.equal(passes,3);});
