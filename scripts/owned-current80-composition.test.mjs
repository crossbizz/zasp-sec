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
test('later projection loop consumes fresh native revisions and stops only after pending pass finalizes',async()=>{const controller=new AbortController(),events=[];let finish,started;const ready=new Promise(resolve=>{started=resolve;});const loop=runOwnedProjectionLoop({poll:async signal=>{events.push('pass-start');assert.equal(signal,controller.signal);started();await new Promise(resolve=>{finish=resolve;});events.push('pass-finalized');}},controller.signal,()=>assert.fail('unexpected refusal'));await ready;let settled=false;void loop.then(()=>{settled=true;});controller.abort();await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);finish();await loop;assert.deepEqual(events,['pass-start','pass-finalized']);});
test('actual projection failure is reported without publishing a fake applied revision',async()=>{const controller=new AbortController();let refusals=0;await assert.rejects(runOwnedProjectionLoop({poll:async()=>{throw Error('private');}},controller.signal,()=>{refusals++;}),/^Error: owned authorization projection unavailable$/);assert.equal(refusals,1);});
test('canceled projection cleanup failure remains a refusal and retains failed join',async()=>{const controller=new AbortController();let refusals=0;const failure=new OwnedProjectionCleanupIncomplete();await assert.rejects(runOwnedProjectionLoop({poll:async()=>{controller.abort();throw failure;}},controller.signal,()=>{refusals++;}),error=>error===failure);assert.equal(refusals,1);});
test('inline grant barriers and owned polling serialize real projection passes',async()=>{const f=fixture(),command=f.config.command;let passes=0,finish;f.config.command=async(...args)=>{if(args[0]===f.config.reconcile&&args[1][1]==='reconcile'){passes++;if(passes===2)await new Promise(resolve=>{finish=resolve;});}return command(...args);};const projector=await installOwnedCurrent80(f.config);const first=projector.refresh(),second=projector.refresh();await new Promise(resolve=>setImmediate(resolve));const started=passes;finish();await Promise.all([first,second]);assert.equal(started,2);assert.equal(passes,3);});

async function pendingFixture() {
 const f = fixture();
 const primary = f.config.organization, other = "pid_90000001-0000-4000-8000-000000000001";
 f.config.foreignOrganization = other;
 const revisions = new Map([primary,other].map(id => [id,{...f.revision,organization_id:id}]));
 const command = f.config.command, calls = [];
 const options = {};
 f.config.command = async (executable,args,input) => {
  const result = await command(executable,args,input);
  if (executable === f.config.psql && args.at(-1).includes("zasp_authorization79.revision")) {
   const requested = [...revisions.keys()].filter(id => args.at(-1).includes(id));
   calls.push({kind:"observe",requested,signal:input.signal});
   result.stdout = requested.map(id=>JSON.stringify(revisions.get(id))).join("\n");
  }
  if (executable === f.config.reconcile && args[1] === "reconcile") {
   const forced = args.indexOf("-organization");
   const ids = forced < 0 ? [...revisions.keys()].filter(id=>revisions.get(id).desired>revisions.get(id).applied) : [args[forced+1]];
   calls.push({kind:forced < 0 ? "native-queue" : "forced",ids,args,signal:input.signal,env:input.env});
   if (options.wait) await options.wait();
   const output = ids.map(id=>{
    const row=revisions.get(id);
    row.applied = row.desired;
    return {organization_id:id,status:"applied",receipt:{Revision:{...row},TupleCount:7,Applied:true}};
   });
   if (forced < 0 && options.mutate) options.mutate(output,result);
   result.stdout = output.map(row=>JSON.stringify(row)).join("\n");
  }
  return result;
 };
 const projector = await installOwnedCurrent80(f.config);
 calls.length=0;
 return {projector,primary,other,revisions,calls,options};
}

test("a clean background poll reads both current revisions as the API and performs no snapshot writes",async()=>{
 const {projector,calls,primary,other}=await pendingFixture();
 await projector.poll();
 assert.deepEqual(calls.map(c=>[c.kind,c.requested]),[["observe",[primary,other]]]);
});

test("a dirty poll reconciles pending activation in either organization with the unfiltered production command",async()=>{
 const {projector,calls,other,revisions}=await pendingFixture();
 revisions.get(other).desired++;
 const signal = new AbortController().signal;
 await projector.poll(signal);
 assert.deepEqual(calls.map(c=>c.kind),["observe","native-queue","observe"]);
 assert.deepEqual(calls[1].ids,[other]);
 assert.deepEqual(calls[1].args,["-mode","reconcile","-limit","20","-timeout","2m"]);
 assert.match(calls[1].env.ZASP_POSTGRES_DSN,/zasp_svc_outbox@/);
 assert.ok(calls.every(c=>c.signal===signal));
 calls.length=0;
 await projector.poll();
 assert.deepEqual(calls.map(c=>c.kind),["observe"]);
});

for (const mutation of ["empty","duplicate","unowned","not-applied","older"]) {
 test("dirty native poll rejects " + mutation + " acknowledgements",async()=>{
  const {projector,revisions,primary,options}=await pendingFixture();
  revisions.get(primary).desired++;
  options.mutate = rows=>{
   if(mutation==="empty") rows.length=0;
   if(mutation==="duplicate") rows.push(rows[0]);
   if(mutation==="unowned") rows[0].organization_id="pid_50000001-0000-4000-8000-000000000001";
   if(mutation==="not-applied") rows[0].receipt.Applied=false;
   if(mutation==="older") {rows[0].receipt.Revision.applied--;rows[0].receipt.Revision.desired--;}
  };
  await assert.rejects(projector.poll(),/owned current authorization fixture unavailable/);
 });
}
test("a targeted post-mutation barrier queues behind the ongoing native poll and always proves its revision",async()=>{
 const {projector,calls,revisions,primary,options}=await pendingFixture();
 revisions.get(primary).desired++;
 let started, release;
 const startedPromise=new Promise(r=>{started=r;});
 options.wait=()=>{delete options.wait;started();return new Promise(r=>{release=r;});};
 const poll=projector.poll();await startedPromise;
 const barrier=projector.refresh(undefined,primary);
 assert.deepEqual(calls.map(c=>c.kind),["observe","native-queue"]);
 release();await poll;
 assert.equal((await barrier).applied,revisions.get(primary).desired);
 assert.deepEqual(calls.map(c=>c.kind),["observe","native-queue","observe","forced","observe"]);
});

test("an acknowledged revision remains verifiable when a newer source change is already pending",async()=>{
 const {projector,primary,revisions,options,calls}=await pendingFixture();
 const state=revisions.get(primary);
 state.desired++;
 options.mutate=()=>{delete options.mutate;state.desired++;};
 await projector.poll();
 assert.equal(state.applied,state.desired-1);
 await projector.poll();
 assert.equal(state.applied,state.desired);
 assert.equal(calls.filter(call=>call.kind==="native-queue").length,2);
});

for (const status of ["busy","retry_from_current_state"]) {
 test("a fresh native pass after " + status + " must confirm the remaining organization",async()=>{
  const {projector,primary,other,revisions,options,calls}=await pendingFixture();
  revisions.get(primary).desired++;
  const later=revisions.get(other);
  const previous=later.applied;
  later.desired++;
  options.mutate=(rows,result)=>{
   delete options.mutate;
   const retry=rows.find(row=>row.organization_id===other);
   retry.status=status;
   retry.receipt.Applied=false;
   later.applied=previous;
   later.desired++;
   result.status=1;
  };
  await projector.poll();
  assert.deepEqual(calls.filter(call=>call.kind==="native-queue").map(call=>call.ids),[[primary,other],[other]]);
  assert.deepEqual(calls.at(-1).requested,[primary,other]);
  assert.equal(later.applied,later.desired);
 });
}

for(const failure of ["delivery_failed","invalid_source","pending_configuration","unowned","empty","signaled","successful-exit","positive-busy","unverified-after-retry","exhausted"]){
 test("background projection refuses "+failure+" without claiming delivery",async()=>{
  const {projector,primary,revisions,options,calls}=await pendingFixture();
  const state=revisions.get(primary),previous=state.applied;
  state.desired++;
  options.mutate=(rows,result)=>{
   const event=rows[0];
   event.receipt.Applied=false;
   event.status="busy";
   result.status=1;
   if(["delivery_failed","invalid_source","pending_configuration"].includes(failure)) event.status=failure;
   if(failure==="unowned") event.organization_id="pid_60000001-0000-4000-8000-000000000001";
   if(failure==="empty") rows.splice(0);
   if(failure==="signaled") result.signal="SIGTERM";
   if(failure==="successful-exit") result.status=0;
   if(failure==="positive-busy") event.receipt.Applied=true;
   if(failure==="unverified-after-retry") delete options.mutate;
   else state.applied=previous;
  };
  await assert.rejects(projector.poll(),/owned current authorization fixture unavailable/);
  const expectedAttempts=failure==="exhausted"?4:failure==="unverified-after-retry"?2:1;
  assert.equal(calls.filter(call=>call.kind==="native-queue").length,expectedAttempts);
 });
}
test("a canceled retry wait ends promptly without a subsequent delivery command",async()=>{
 const {projector,primary,revisions,options,calls}=await pendingFixture();
 const controller=new AbortController();
 revisions.get(primary).desired++;
 options.mutate=(rows,result)=>{
  rows[0].status="retry_from_current_state";
  rows[0].receipt.Applied=false;
  result.status=1;
  controller.abort();
 };
 await assert.rejects(projector.poll(controller.signal),{name:"AbortError"});
 assert.equal(calls.filter(call=>call.kind==="native-queue").length,1);
});
