import test from 'node:test';import assert from 'node:assert/strict';
import {installOwnedCurrent80,closedOwnedAmbientEnvironment,runOwnedProjectionLoop,OwnedProjectionCleanupIncomplete}from './owned-current80-composition.mjs';
function fixture(){const calls=[],organization='pid_10000001-0000-4000-8000-000000000001';const environment={ZASP_RUNTIME_SERVICES_ENABLED:'true',ZASP_ENVIRONMENT:'test',ZASP_RUNTIME_SERVICES_TIMEOUT:'5s',ZASP_TEMPORAL_ADDRESS:'127.0.0.1:32101',ZASP_TEMPORAL_NAMESPACE:'owned',ZASP_TEMPORAL_TASK_QUEUE:'owned-main',ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE:'owned-discovery',ZASP_OPENFGA_URL:'http://127.0.0.1:32102',ZASP_OPENFGA_STORE_ID:'01K00000000000000000000001',ZASP_OPENFGA_MODEL_ID:'01K00000000000000000000002',ZASP_OPENFGA_TOKEN_FILE:'/owned/token'};const revision={organization_id:organization,desired:4,applied:4,generation:2,store_id:environment.ZASP_OPENFGA_STORE_ID,model_id:environment.ZASP_OPENFGA_MODEL_ID};const config={migrate:'/owned/migrate',reconcile:'/owned/reconcile',psql:'/owned/psql',port:32100,organization,runtimeEnvironment:environment,identityEnvironment:{PATH:'/usr/bin:/bin',ZASP_PUBLIC_ORIGIN:'https://fixture.invalid:32103',ZASP_STYTCH_BASE_URL:'http://127.0.0.1:32104',ZASP_STYTCH_PROJECT_ID:'owned-project',ZASP_STYTCH_ORGANIZATION_ID:'owned-org',ZASP_DEPLOYMENT_MODE:'saas',ZASP_ORGANIZATION_ID:'',ZASP_WORKFLOW_SIGNING_KEY:'fixture-input'},keyFiles:{forward:'/owned/forward',compensation:'/owned/compensation'}};config.command=async(executable,args,options)=>{calls.push({executable,args,options});return {status:0,signal:null,stdout:executable===config.psql?JSON.stringify(revision):args[1]==='reconcile'?JSON.stringify({organization_id:organization,status:'applied',receipt:{Revision:revision,TupleCount:12,Applied:true}}):'{}'};};return {config,calls,revision};}
test('installs existing closed runtime profile and genuine configure/reconcile before returning read-bound projection',async()=>{const f=fixture();const value=await installOwnedCurrent80(f.config);assert.deepEqual(f.calls.slice(0,8).map(call=>call.args[0]),['up-to-60','up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier']);assert.match(f.calls[8].options.env.ZASP_POSTGRES_DSN,/zasp_e2e@/);assert.match(f.calls[9].options.env.ZASP_POSTGRES_DSN,/zasp_e2e_outbox@/);assert.match(f.calls[10].args[0],/zasp_e2e_api@/);assert.equal(value.applied.desired,value.applied.applied);assert.equal(value.acceptance,false);});
test('missing real runtime model refuses before any installation',async()=>{const f=fixture();delete f.config.runtimeEnvironment.ZASP_OPENFGA_MODEL_ID;await assert.rejects(installOwnedCurrent80(f.config));assert.deepEqual(f.calls,[]);});
test('only the original full projection and scoped revision calls carry fixed diagnostic contexts',async()=>{
 const f=fixture();const projector=await installOwnedCurrent80(f.config);const controller=new AbortController();await projector.refresh(controller.signal);
 const labeled=f.calls.filter(call=>call.options.complianceDiagnostic!==undefined);
 assert.equal(labeled.length,4);
 for(const [index,call]of labeled.entries()){
  const reconcile=index%2===0;
  assert.equal(call.options.complianceDiagnostic,reconcile?'owned-projection-reconcile':'owned-projection-revision');
  assert.equal(call.executable,reconcile?f.config.reconcile:f.config.psql);assert.equal(call.options.timeout,reconcile?125000:5000);
  assert.ok(call.options.signal instanceof AbortSignal);assert.equal(call.options.signal.aborted,false);
  if(reconcile)assert.deepEqual(call.args,['-mode','reconcile','-organization',f.config.organization,'-limit','1','-timeout','2m']);
  else assert.match(call.args.at(-1),/zasp_authorization79\.revision/);
 }
});
for(const field of ['applied','model_id','generation'])test('receipt '+field+' drift refuses instead of claiming acknowledgement',async()=>{const f=fixture();const command=f.config.command;f.config.command=async(...args)=>{const result=await command(...args);if(args[0]===f.config.psql){const value=JSON.parse(result.stdout);value[field]=field==='model_id'?'01K00000000000000000000003':value[field]+1;result.stdout=JSON.stringify(value);}return result;};await assert.rejects(installOwnedCurrent80(f.config));});
test('original installer failure stops before verifier or projector invocation',async()=>{const f=fixture();f.config.command=async(...args)=>{f.calls.push(args);return {status:1,signal:null,stdout:''};};await assert.rejects(installOwnedCurrent80(f.config));assert.equal(f.calls.length,1);});
test('closed owner environment removes ambient product settings without suppressing inherited tool metadata',()=>{assert.deepEqual(closedOwnedAmbientEnvironment({PATH:'/usr/bin',ZASP_COMPLIANCE_EXPORT_ROLE_ARN:'ambient',ZASP_RUNTIME_SERVICES_ENABLED:'false',LANG:'C'}),{PATH:'/usr/bin',LANG:'C'});});
test('later projection loop consumes fresh native revisions and stops only after pending pass finalizes',async()=>{const controller=new AbortController(),events=[];let finish,started;const ready=new Promise(resolve=>{started=resolve;});const loop=runOwnedProjectionLoop({refresh:async signal=>{events.push('pass-start');assert.equal(signal,controller.signal);started();await new Promise(resolve=>{finish=resolve;});events.push('pass-finalized');}},controller.signal,()=>assert.fail('unexpected refusal'));await ready;let settled=false;void loop.then(()=>{settled=true;});controller.abort();await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);finish();await loop;assert.deepEqual(events,['pass-start','pass-finalized']);});
test('actual projection failure is reported without publishing a fake applied revision',async()=>{const controller=new AbortController();let refusals=0;await assert.rejects(runOwnedProjectionLoop({refresh:async()=>{throw Error('private');}},controller.signal,()=>{refusals++;}),/^Error: owned authorization projection unavailable$/);assert.equal(refusals,1);});
test('canceled projection cleanup failure remains a refusal and retains failed join',async()=>{const controller=new AbortController();let refusals=0;const failure=new OwnedProjectionCleanupIncomplete();await assert.rejects(runOwnedProjectionLoop({refresh:async()=>{controller.abort();throw failure;}},controller.signal,()=>{refusals++;}),error=>error===failure);assert.equal(refusals,1);});
test('inline grant barriers and owned polling serialize real projection passes',async()=>{const f=fixture(),command=f.config.command;let passes=0,finish;f.config.command=async(...args)=>{if(args[0]===f.config.reconcile&&args[1][1]==='reconcile'){passes++;if(passes===2)await new Promise(resolve=>{finish=resolve;});}return command(...args);};const projector=await installOwnedCurrent80(f.config);const first=projector.refresh(),second=projector.refresh();await new Promise(resolve=>setImmediate(resolve));const started=passes;finish();await Promise.all([first,second]);assert.equal(started,2);assert.equal(passes,3);});

// Command seams stand for the two real subprocesses, not authorization vendors.
// A permission-affecting write can commit after ACK and before the reader query.
function advancingProjectionFixture(observations,receipts=[]){
 const f=fixture(),command=f.config.command;let active=false,pass=0,read=0;
 f.config.command=async(file,args,options)=>{
  const result=await command(file,args,options);
  if(!active)return result;
  if(file===f.config.reconcile&&args[1]==='reconcile'){
   const selected=receipts[pass++]??{...f.revision,desired:5,applied:5};
   result.stdout=JSON.stringify({organization_id:f.config.organization,status:'applied',receipt:{Revision:selected,TupleCount:12,Applied:true}});
  }else if(file===f.config.psql){result.stdout=JSON.stringify(observations[read++]??{...f.revision,desired:5,applied:5});}
  return result;
 };
 return {...f,activate(){active=true;},counts:()=>({pass,read})};
}

test('fresh full projection converges one concurrent source revision and refuses unsafe drift',async t=>{
 const old={...fixture().revision},pending={...old,desired:5},next={...old,desired:5,applied:5};
 await t.test('a single committed source advance requires another full acknowledged CLI and independent read',async()=>{
  const f=advancingProjectionFixture([pending,next],[old,next]);const projector=await installOwnedCurrent80(f.config);f.activate();
  assert.deepEqual(await projector.refresh(),next);assert.deepEqual(f.counts(),{pass:2,read:2});
  for(const call of f.calls.filter(call=>call.options.complianceDiagnostic))assert.ok(call.options.signal instanceof AbortSignal);
 });
 await t.test('a second source advance exhausts two total full passes instead of accepting pending authority',async()=>{
  const f=advancingProjectionFixture([pending,{...next,desired:6}],[old,next]);const projector=await installOwnedCurrent80(f.config);f.activate();
  await assert.rejects(projector.refresh());assert.deepEqual(f.counts(),{pass:2,read:2});
 });
 for(const [name,observation]of Object.entries({generation:{...pending,generation:3},model:{...pending,model_id:'01K00000000000000000000003'},store:{...pending,store_id:'01K00000000000000000000003'},foreign:{...pending,organization_id:'pid_10000001-0000-4000-8000-000000000099'},unsafe:{...pending,desired:Number.MAX_SAFE_INTEGER+1},applied:{...pending,applied:3},rollback:{...old,desired:3,applied:3},extra:{...pending,extra:true}}))await t.test(name+' drift refuses without retry',async()=>{
  const f=advancingProjectionFixture([observation],[old]);const projector=await installOwnedCurrent80(f.config);f.activate();await assert.rejects(projector.refresh());assert.deepEqual(f.counts(),{pass:1,read:1});
 });
 await t.test('retry cannot return an applied revision older than the previously observed desired',async()=>{
  const f=advancingProjectionFixture([pending,old],[old,old]);const projector=await installOwnedCurrent80(f.config);f.activate();await assert.rejects(projector.refresh());assert.equal(f.counts().pass,2);
 });
});

test('projection convergence retains cancellation, active deadline and exact command cleanup',async t=>{
 await t.test('caller cancellation between passes prevents another command',async()=>{
  const f=fixture(),original=f.config.command,controller=new AbortController();let active=false,reads=0,passes=0;
  f.config.command=async(...args)=>{const result=await original(...args);if(active){if(args[0]===f.config.reconcile)passes++;if(args[0]===f.config.psql){reads++;result.stdout=JSON.stringify({...f.revision,desired:5});controller.abort();}}return result;};
  const projector=await installOwnedCurrent80(f.config);active=true;await assert.rejects(projector.refresh(controller.signal));assert.equal(passes,1);assert.equal(reads,1);
 });
 await t.test('a canceled queued caller cannot start its own subprocess',async()=>{
  const f=fixture(),original=f.config.command;let active=false,release,started,passes=0;const began=new Promise(resolve=>{started=resolve;});
  f.config.command=async(...args)=>{if(active&&args[0]===f.config.reconcile){passes++;started();await new Promise(resolve=>{release=resolve;});}return original(...args);};
  const projector=await installOwnedCurrent80(f.config);active=true;const first=projector.refresh();await began;const controller=new AbortController(),second=projector.refresh(controller.signal);controller.abort();release();await first;await assert.rejects(second);assert.equal(passes,1);
 });
 await t.test('one original active budget covers retries and waits for failed process cleanup',async context=>{
  context.mock.timers.enable({apis:['setTimeout']});
  const f=fixture(),original=f.config.command;let active=false,aborted,join,started,passes=0;const began=new Promise(resolve=>{started=resolve;});
  f.config.command=async(...args)=>{if(active&&args[0]===f.config.reconcile&&++passes===2){const signal=args[2].signal;started();assert.ok(signal instanceof AbortSignal);await new Promise(resolve=>{signal.addEventListener('abort',()=>{aborted=true;join=resolve;},{once:true});});throw new OwnedProjectionCleanupIncomplete();}const result=await original(...args);if(active&&args[0]===f.config.psql){result.stdout=JSON.stringify({...f.revision,desired:5});context.mock.timers.tick(124000);}return result;};
  const projector=await installOwnedCurrent80(f.config);active=true;let settled=false;const pending=projector.refresh().then(()=>{settled=true;},error=>{settled=true;return error;});await Promise.race([began,pending.then(error=>{throw error??Error('projection finished before the second pass');})]);context.mock.timers.tick(999);assert.equal(aborted,undefined);context.mock.timers.tick(1);assert.equal(aborted,true);assert.equal(settled,false);join();assert.ok(await pending instanceof OwnedProjectionCleanupIncomplete);
 });
});
