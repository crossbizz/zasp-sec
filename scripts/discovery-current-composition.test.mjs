import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { mkdtemp, writeFile, readFile, realpath, stat, symlink, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import vm from "node:vm";
import { createHash, webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as currentDiscovery from "./discovery-current-composition.mjs";
import { validateCurrentDiscoveryMode, validateCurrentDiscoveryConfig, runCurrentDiscoveryPreflight, currentDiscoveryProbe } from "./discovery-current-composition.mjs";
import { spawnOwnedCommand } from "./owned-command.mjs";

const profile = "canonical61-temporal78-authorization79-80-worker-v1";
const roles = ["observer", "api", "discovery", "scheduler", "projector", "compensation"];
function config() {
  return {
    format: "zasp-current-discovery-preflight-v1", publicOrigin: "https://approved.example.test",
    scope: { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" },
    profile, canonical61Checksum: "a".repeat(64), workerChecksum: "b".repeat(64),
    provider: { kind: "kubernetes", protectedReference: "approved-cluster" },
    database: { psql: "/approved/bin/psql", serviceFile: "/approved/libpq/services.conf", passwordFile: "/approved/libpq/passwords", connections: Object.fromEntries(roles.map(role => [role, { service: `approved_${role}`, login: `approved_${role}` }])) },
    evidenceDirectory: "/approved/evidence",
  };
}
const ownerObservation = () => ({ session_user: "approved_observer", current_user: "approved_observer", read_only: true, scope_exists: true, canonical_count: 61, canonical_checksum: "a".repeat(64), worker_checksum: "b".repeat(64), catalog_ready: true, runtime_ready: false });

function connectedConfig() {
  return { ...config(),provider:{kind:"kubernetes",protectedReference:"ref:kubernetes/connection/approved-cluster"}, format: "zasp-current-discovery-journey-v1", journey: {
    chrome: "/approved/bin/chrome", integrationName: "Acceptance scoped integration", configuration: { connection_reference: "ref:kubernetes/connection/approved-cluster" },
    source: { nativeID: "kubernetes:deployment:deployment-scheduled-agent", metadataKey: "posture.runtime_policy_supported", before: false, after: true },
    foreignScope: { organizationID: "pid_20000001-0000-4000-8000-000000000001", workspaceID: "pid_20000002-0000-4000-8000-000000000002", environmentID: "pid_20000003-0000-4000-8000-000000000003" },
    temporal: { executable: "/approved/bin/discovery-observe", sha256: "d".repeat(64), config: { Enabled: true, Environment: "production", TemporalAddress: "temporal.internal:7233", Namespace: "approved-discovery", TaskQueue: "agentsec", DiscoveryTaskQueue: "discovery", TemporalCAFile: "/protected/ca", TemporalCertFile: "/protected/cert", TemporalKeyFile: "/protected/key", FGAURL: "https://fga.internal", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/protected/fga", FGACAFile: "/protected/fga-ca", Timeout: 10000000000 } },
  } };
}

test("connected config binds fixed source/checkpoint/observer without accepting write commands or credential values", () => {
  assert.doesNotThrow(() => validateCurrentDiscoveryConfig(connectedConfig()));
  for (const change of [c => c.journey.providerCommand = "kubectl delete", c => c.journey.temporal.url = "https://arbitrary", c => c.journey.source.after = c.journey.source.before,
    c => c.journey.chrome = "chrome", c => c.journey.foreignScope = c.scope, c => c.journey.temporal.config.TemporalKeyFile = "inline-secret",
    c => c.journey.configuration.password = "secret", c => c.journey.source.metadataKey = "credentials", c => c.journey.source.nativeID = "\0invalid",
  ]) { const c = connectedConfig(); change(c); assert.throws(() => validateCurrentDiscoveryConfig(c)); }
});

test("connected configuration accepts the shipped Kubernetes reference and rejects old invented schema",()=>{
  const c=connectedConfig();c.provider.protectedReference="ref:kubernetes/connection/approved-cluster";c.journey.configuration={connection_reference:c.provider.protectedReference};
  assert.doesNotThrow(()=>validateCurrentDiscoveryConfig(c));
  for(const change of [v=>v.journey.configuration={cluster_reference:v.provider.protectedReference},v=>v.provider.protectedReference=v.journey.configuration.connection_reference="approved-cluster",v=>v.journey.configuration.connection_reference="ref:kubernetes/connection/different-cluster"]){const v=structuredClone(c);change(v);assert.throws(()=>validateCurrentDiscoveryConfig(v));}
});

test("configured product identities must be database UUID-v4 and RFC variant",()=>{
  for(const id of ["pid_10000001-0000-3000-8000-000000000001","pid_10000001-0000-4000-7000-000000000001"]){const c=config();c.scope.organizationID=id;assert.throws(()=>validateCurrentDiscoveryConfig(c));}
});

test("connected database observer emits only scoped current tables and fixed read-only joins", () => {
  assert.equal(typeof currentDiscovery.currentDiscoveryStateProbe, "function");
  const c = connectedConfig(), ids = { integrationID: "pid_30000001-0000-4000-8000-000000000001", syncID: "pid_30000002-0000-4000-8000-000000000002", receiptID: "pid_30000003-0000-4000-8000-000000000003", auditID: "pid_30000004-0000-4000-8000-000000000004" };
  for (const kind of ["receipt", "state", "inventory"]) {
    const p = currentDiscovery.currentDiscoveryStateProbe(c, kind, ids);
    assert.match(p.args.at(-1), /^BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY;/);
    for (const id of Object.values(c.scope)) assert.ok(p.args.at(-1).includes(id));
    assert.doesNotMatch(p.args.at(-1), /SET ROLE|\b(?:INSERT|UPDATE|DELETE|CREATE)\b|scheduled_admit|collect|zasp_discovery_schedule_runs|SELECT \*/i);
    assert.deepEqual(p.env, currentDiscoveryProbe(c,"observer").env);
  }
  assert.throws(() => currentDiscovery.currentDiscoveryStateProbe(c, "scheduled_admit", ids));
  assert.throws(() => currentDiscovery.currentDiscoveryStateProbe(c, "state", { ...ids, integrationID: "x';DELETE" }));
});

test("browser boundary retains the actual schedule request for one replay without exporting CSRF", async () => {
  const origin="https://approved.example.test", requests=[];
  const scope={ location:{origin,href:origin+"/connectors"}, document:{body:{innerText:"Connectors"}}, localStorage:{length:0},sessionStorage:{length:0},URL,TextDecoder,Uint8Array,AbortSignal,Error,Object,JSON };
  scope.Request=class extends Request {constructor(input,init){super(typeof input==="string"?new URL(input,origin):input,init);}};
  scope.window={fetch:async(input,init)=>{const r=input instanceof Request?input:new scope.Request(input,init);requests.push({method:r.method,path:new URL(r.url).pathname,csrf:r.headers.get("x-csrf-token"),key:r.headers.get("idempotency-key"),body:await r.text()});return new Response(JSON.stringify({integration_id:"pid_30000001-0000-4000-8000-000000000001",version:1,next_run_at:"2026-09-27T01:00:00Z"}),{status:200,headers:{etag:'"1"',"cache-control":"no-store","x-audit-id":"pid_30000003-0000-4000-8000-000000000003","x-mutation-receipt-id":"pid_30000004-0000-4000-8000-000000000004"}});}};
  vm.runInNewContext(`(${currentDiscovery.installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(origin)})`,scope);
  const route="/api/v1/integrations/pid_30000001-0000-4000-8000-000000000001/schedule";
  const response=await scope.window.fetch(route,{method:"PUT",headers:{"x-csrf-token":"canary-secret","idempotency-key":"wf_retained","if-match":'"0"'},body:'{"cadence_seconds":300,"state":"enabled"}'});
  assert.equal(response.status,200);
  const record=scope.window.__zaspCurrentDiscovery.mutation("PUT",route);
  assert.equal(record.receiptID,"pid_30000004-0000-4000-8000-000000000004");
  assert.doesNotMatch(JSON.stringify(record),/canary|wf_retained|csrf/i);
  const replay=await scope.window.__zaspCurrentDiscovery.replay(route);
  assert.equal(replay.receiptID,record.receiptID);assert.deepEqual(requests[1],requests[0]);
  await assert.rejects(scope.window.__zaspCurrentDiscovery.replay(route));
  assert.equal(requests.length,2);
  assert.equal(scope.window.__zaspCurrentDiscovery.cleanupMutation,undefined);
  assert.equal(scope.window.__zaspCurrentDiscovery.cleanupRead,undefined);
  assert.equal(scope.window.__zaspCurrentDiscovery.bindOwnedIntegration,undefined);
});

test("browser boundary rejects foreign product reads and secret-bearing mutation evidence", async () => {
  const origin="https://approved.example.test";let calls=0;
  const scope={ location:{origin,href:origin+"/connectors"},document:{body:{innerText:"safe"}},localStorage:{length:0},sessionStorage:{length:0},URL,TextDecoder,Uint8Array,AbortSignal,Error,Object,JSON };
  scope.Request=class extends Request{constructor(input,init){super(typeof input==="string"?new URL(input,origin):input,init);}};
  scope.window={fetch:async()=>{calls++;return new Response('{"access_token":"canary-secret"}',{status:200});}};
  vm.runInNewContext(`(${currentDiscovery.installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(origin)})`,scope);
  await assert.rejects(scope.window.__zaspCurrentDiscovery.get("https://foreign.example/api/v1/agents"));assert.equal(calls,0);
  const response=await scope.window.fetch("/api/v1/integrations",{method:"POST",body:"{}"});
  assert.equal(response.status,200);assert.throws(()=>scope.window.__zaspCurrentDiscovery.mutation("POST","/api/v1/integrations"));assert.equal(scope.window.__zaspCurrentDiscovery.leakFree(),false);
});

test("browser cleanup uses exact scope and fresh session CSRF without exposing it or allowing arbitrary writes",async()=>{
  const origin="https://approved.example.test",configured=config().scope,requests=[];let foreign=false;
  const scope={location:{origin,href:origin+"/connectors"},window:{},URL,TextDecoder,Uint8Array,AbortSignal,Error,Object,JSON,crypto:webcrypto};
  scope.window.fetch=async(path,init={})=>{requests.push({path,...init});if(path==="/api/v1/session/bootstrap")return new Response(JSON.stringify({organization_id:foreign?"foreign":configured.organizationID,workspace_id:configured.workspaceID,environment_id:configured.environmentID,csrf_token:"c".repeat(32),fresh_auth_expires_at:new Date(Date.now()+60000).toISOString()}),{headers:{"cache-control":"no-store"}});return new Response(null,{status:204,headers:{"cache-control":"no-store",etag:'"2"',"x-audit-id":"pid_30000003-0000-4000-8000-000000000003","x-mutation-receipt-id":"pid_30000004-0000-4000-8000-000000000004"}});};
  const action={action:"delete-schedule",integrationID:"pid_30000001-0000-4000-8000-000000000001",scope:configured,version:'"1"'};
  const boundary=vm.runInNewContext(`(${currentDiscovery.installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(origin)},${JSON.stringify(configured)},${JSON.stringify(action.integrationID)},true)`,scope);
  assert.equal(typeof boundary.cleanupMutation,"function");
  const r=await boundary.cleanupMutation(action);assert.equal(r.status,204);assert.doesNotMatch(JSON.stringify(r),/cccccccc|csrf/i);
  assert.equal(requests[1].path,`/api/v1/integrations/${action.integrationID}/schedule`);assert.equal(requests[1].method,"DELETE");assert.equal(requests[1].headers["X-CSRF-Token"],"c".repeat(32));assert.equal(requests[1].headers["If-Match"],'"1"');assert.equal(requests[1].headers["X-Zasp-Expected-Scope"],Object.values(configured).join("/"));
  foreign=true;await assert.rejects(boundary.cleanupMutation(action));assert.equal(requests.filter(x=>x.method==="DELETE").length,1);
  const before=requests.length;await assert.rejects(boundary.cleanupMutation({...action,action:"delete-policy"}));assert.equal(requests.length,before);
});

test("connected orchestration consumes runtime refusal before constructing browser or Temporal clients", async () => {
  assert.equal(typeof currentDiscovery.runCurrentDiscoveryJourney,"function");
  let browserCalls=0, temporalCalls=0;
  const result=await currentDiscovery.runCurrentDiscoveryJourney(connectedConfig(),{query:async()=>ownerObservation(),createBrowser:async()=>{browserCalls++;throw Error("browser must not start");},observeTemporal:async()=>{temporalCalls++;throw Error("observer must not start");}});
  assert.equal(result.code,"runtime-closed");assert.equal(result.journey,"not-run");assert.equal(browserCalls,0);assert.equal(temporalCalls,0);
});

function cleanupBoundaryFixture() {
  const origin="https://approved.example.test",configured=config().scope,owned="pid_30000001-0000-4000-8000-000000000001",requests=[];
  let sessionScope={...configured};
  const context={location:{origin},window:{},URL,TextDecoder,Uint8Array,AbortSignal,Error,Object,JSON,crypto:webcrypto};
  context.window.fetch=async(path,init)=>{
    requests.push({path,...init});
    if(path==="/api/v1/session/bootstrap")return new Response(JSON.stringify({organization_id:sessionScope.organizationID,workspace_id:sessionScope.workspaceID,environment_id:sessionScope.environmentID,csrf_token:"c".repeat(32),fresh_auth_expires_at:new Date(Date.now()+60000).toISOString()}),{headers:{"cache-control":"no-store"}});
    return new Response(null,{status:init.method==="DELETE"?204:404,headers:{"cache-control":"no-store",etag:'"2"'}});
  };
  const boundary=vm.runInNewContext(`(${currentDiscovery.installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(origin)},${JSON.stringify(configured)},${JSON.stringify(owned)},true)`,context)??context.window.__zaspCurrentDiscovery;
  return{boundary,context,configured,owned,requests,switchScope(value){sessionScope=value;}};
}

test("cleanup capability refuses other valid tenant and integration before any fetch",async()=>{
  const f=cleanupBoundaryFixture(),action={action:"delete-integration",scope:f.configured,integrationID:f.owned,version:'"1"'};
  const other="pid_40000001-0000-4000-8000-000000000001";
  await assert.rejects(f.boundary.cleanupMutation({...action,scope:{...f.configured,organizationID:other}}));
  assert.equal(f.requests.length,0,"foreign valid tenant must not fetch a session");
  await assert.rejects(f.boundary.cleanupMutation({...action,integrationID:other}));
  assert.equal(f.requests.length,0,"foreign valid integration must not fetch or mutate");
});

test("cleanup scoped absence requires fresh exact session and expected-scope GET",async()=>{
  const f=cleanupBoundaryFixture(),q={scope:f.configured,integrationID:f.owned,resource:"integration"};
  const r=await f.boundary.cleanupRead(q);assert.equal(r.status,404);
  const expected=[f.configured.organizationID,f.configured.workspaceID,f.configured.environmentID].join("/");
  assert.equal(f.requests.length,2);assert.equal(f.requests[0].headers["X-Zasp-Expected-Scope"],expected);assert.equal(f.requests[1].headers["X-Zasp-Expected-Scope"],expected);assert.equal(f.requests[1].method,"GET");
  f.switchScope({...f.configured,workspaceID:"pid_40000001-0000-4000-8000-000000000001"});
  await assert.rejects(f.boundary.cleanupRead(q));assert.equal(f.requests.length,3,"scope switch must refuse before a misleading 404 GET");
  f.switchScope({});await assert.rejects(f.boundary.cleanupRead(q));assert.equal(f.requests.length,4);
  assert.equal(f.context.window.__zaspCurrentDiscovery,undefined,"cleanup object is returned privately, never exposed on the page");
});

test("Node cleanup channel binds once and consumes a private isolated-world object within original budget",async t=>{
  const c=connectedConfig(),owned="pid_30000001-0000-4000-8000-000000000001",other="pid_40000001-0000-4000-8000-000000000001",calls=[],fetches=[];
  const context={location:{origin:c.publicOrigin},window:{},URL,TextDecoder,Uint8Array,AbortSignal,Error,Object,JSON,crypto:webcrypto};
  context.window.fetch=async(path,init)=>{fetches.push({path,...init});return path.endsWith("/bootstrap")?new Response(JSON.stringify({organization_id:c.scope.organizationID,workspace_id:c.scope.workspaceID,environment_id:c.scope.environmentID,csrf_token:"c".repeat(32),fresh_auth_expires_at:new Date(Date.now()+60000).toISOString()}),{headers:{"cache-control":"no-store"}}):new Response(null,{status:404,headers:{"cache-control":"no-store"}});};
  let privateObject,now=Date.now();
  t.mock.method(Date,"now",()=>now);
  const send=async(method,p,timeout)=>{
    calls.push({method,p,timeout});now+=1000;
    if(method==="Page.getFrameTree")return{frameTree:{frame:{id:"owned-frame",url:c.publicOrigin+"/connectors"}}};
    if(method==="Page.createIsolatedWorld"){assert.equal(p.frameId,"owned-frame");assert.equal(p.grantUniveralAccess,false);return{executionContextId:71};}
    if(method==="Runtime.evaluate"){assert.equal(p.contextId,71);assert.equal(p.returnByValue,false);privateObject=vm.runInNewContext(p.expression,context);return{result:{objectId:"opaque-owned-object"}};}
    assert.equal(method,"Runtime.callFunctionOn");assert.equal(p.objectId,"opaque-owned-object");assert.equal(p.arguments[1].value,timeout);
    const fn=vm.runInNewContext(`(${p.functionDeclaration})`,context);
    return{result:{value:await fn.apply(privateObject,p.arguments.map(a=>a.value))}};
  };
  const channel=currentDiscovery.createDiscoveryCleanupChannel(send,c),q={scope:c.scope,integrationID:owned,resource:"integration"};
  await assert.rejects(channel.cleanupRead(q));assert.equal(calls.length,0);
  channel.bindOwnedIntegration(owned);assert.throws(()=>channel.bindOwnedIntegration(other));
  await assert.rejects(channel.cleanupRead({...q,integrationID:other}));
  await assert.rejects(channel.cleanupRead({...q,scope:{...c.scope,organizationID:other}}));assert.equal(calls.length,0);
  assert.equal((await channel.cleanupRead(q)).status,404);
  assert.deepEqual(calls.map(v=>v.timeout),[10000,9000,8000,7000]);
  assert.equal(context.window.__zaspCurrentDiscovery,undefined);assert.equal(fetches.length,2);
  assert.equal((await channel.cleanupRead({...q,resource:"schedule"})).status,404);assert.equal(calls.length,5,"same owned private object reused only for cleanup, with a fresh session per read");assert.equal(fetches.length,4);
});

test("Node cleanup setup exhaustion cannot extend ten seconds or start a resource fetch",async t=>{
  const c=connectedConfig(),owned="pid_30000001-0000-4000-8000-000000000001";let now=0,calls=0;
  t.mock.method(Date,"now",()=>now);
  const channel=currentDiscovery.createDiscoveryCleanupChannel(async(method)=>{
    calls++;assert.equal(method,"Page.getFrameTree");now=10000;return{frameTree:{frame:{id:"owned",url:c.publicOrigin+"/connectors"}}};
  },c);
  channel.bindOwnedIntegration(owned);
  await assert.rejects(channel.cleanupRead({scope:c.scope,integrationID:owned,resource:"integration"}));assert.equal(calls,1);
});

test("scope-switched cleanup emits no absence facts and keeps recovery required",async()=>{
  const f=recordedJourneyBoundary({checkpointFailure:true,cleanupScopeChanged:true});
  const r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);
  assert.equal(r.ownedCleanup.refused,true);assert.equal(r.ownedCleanup.integrationDeleted,false);assert.equal(r.ownedCleanup.scheduleDeleted,false);
  assert.equal(r.ownedCleanup.recovery,"retry-owned-resource-cleanup");assert.equal(f.actions.filter(x=>x.startsWith("cleanup ")).length,0);assert.equal(f.getClosed(),1);
});

test("connected orchestration never replaces missing genuine login by integration mutation", async () => {
  assert.equal(typeof currentDiscovery.runCurrentDiscoveryJourney,"function");
  let closed=0;const actions=[];
  const result=await currentDiscovery.runCurrentDiscoveryJourney(connectedConfig(),{
    query:async(_c,role)=>role==="observer"?{...ownerObservation(),runtime_ready:true}:{session_user:`approved_${role}`,current_user:`approved_${role}`,read_only:true,registered:true,login_role:true,superuser:false},
    readAuthority:async()=>({model_bound:true,verifiers_bound:true,desired:1,applied:1,generation:1}),
    validateRuntime:async()=>true,
    createBrowser:async()=>({navigate:async route=>actions.push(route),click:async label=>{actions.push(label);throw Error("actual login unavailable");},close:async()=>{closed++;}}),
  });
  assert.equal(result.journey,"failed");assert.equal(result.phase,"sign-in");assert.equal(closed,1);assert.deepEqual(actions,["/sign-in?return_to=%2Fconnectors","Continue to sign in"]);
});

test("connected authority model mismatch refuses before any browser or observer launch",async()=>{
  const f=recordedJourneyBoundary();let opened=0;
  f.dependencies.readAuthority=async()=>({model_bound:false,verifiers_bound:true,desired:1,applied:1,generation:1});
  f.dependencies.createBrowser=async()=>{opened++;throw Error("must not launch");};
  const r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);
  assert.equal(r.code,"profile-mismatch");assert.equal(r.journey,"not-run");assert.equal(opened,0);
});

function recordedJourneyBoundary(options={}) {
  // These are complete harness-boundary records, NOT native/provider/browser
  // acceptance. The real orchestrator consumes them; no product call is run.
  const c=connectedConfig(), epoch=Date.now(), at=n=>new Date(epoch+n).toISOString();
  const id=n=>`pid_30000000-0000-4000-8000-${String(n).padStart(12,"0")}`;
  const integration=id(1),agent=id(2),schedule=id(3),manual=id(4),scheduled=id(5),failed=id(6),restored=id(7);
  let stage="baseline",scheduledCreated=false,withdrawn=false,deleted=false,closed=0,serial=10,cleanupVersion=1,cleanupDisabled=false;
  const actions=[];
  const sync=(value,status="succeeded")=>({id:value,integration_id:integration,trigger_kind:value===scheduled?"schedule":"manual",status,attempt:1,requested_at:at(0),started_at:at(1000),completed_at:at(value===manual?2000:302000),discovered_count:2,changed_count:value===manual?2:1,removed_count:0,snapshot_id:status==="succeeded"?id(value===manual?20:value===scheduled?21:22):null,last_error_code:status==="failed"?"provider_unavailable":null,retry_at:null});
  const success=value=>({status:200,noStore:true,value});
  const mutation=(method,path)=>{
    actions.push(`${method} ${path}`);let value,status=200;
    if(path==="/api/v1/integrations"){status=201;value={id:integration,connector_key:"kubernetes",name:c.journey.integrationName,configuration:c.journey.configuration,status:"draft",created_at:at(0),updated_at:at(0)};}
    else if(path.endsWith("/reference-authorization"))value={id:integration,connector_key:"kubernetes",name:c.journey.integrationName,configuration:c.journey.configuration,status:"active",created_at:at(0),updated_at:at(0)};
    else if(path.endsWith("/sync")){status=202;value=sync(stage==="baseline"?manual:stage==="failure"?failed:restored,"queued");}
    else if(path.endsWith("/schedule")){scheduledCreated=true;if(method==="DELETE"){withdrawn=true;status=204;value=null;}else value={integration_id:integration,cadence_seconds:300,state:stage==="failure"?"disabled":"enabled",time_zone:"UTC",next_run_at:at(300000),version:1,created_at:at(0),updated_at:at(0)};}
    else if(method==="DELETE"){deleted=true;status=204;value=null;}
    else throw Error("unexpected actual operation");
    const n=serial++;return{method,path,status,noStore:true,version:'"1"',auditID:id(n),receiptID:id(n+100),value};
  };
  let saved;
  const browser={cleanupMutation:async request=>{const method=request.action==="disable-schedule"?"PUT":"DELETE",path=`/api/v1/integrations/${integration}${request.action==="delete-integration"?"":"/schedule"}`;actions.push(`cleanup ${method} ${path}`);assert.equal(request.integrationID,integration);assert.deepEqual(request.scope,c.scope);assert.equal(request.version,`"${request.action==="delete-integration"?1:cleanupVersion}"`);if(options.cleanupConflict)return{status:409};const r=mutation(method,path);if(method==="PUT")cleanupDisabled=true;const version=request.action==="delete-integration"?2:++cleanupVersion;return{...r,version:`"${version}"`,value:r.value?{...r.value,state:"disabled",version}:null};},close:async()=>{closed++;},sessionWitness:async()=>({start:true,callback:true,bootstrap:true}),openSync:async()=>true,navigate:async route=>actions.push(`navigate ${route}`),reload:async()=>actions.push("reload"),click:async label=>{actions.push(`click ${label}`);return true;},fill:async()=>true,text:async()=>true,leakFree:async()=>true,
    mutation:async(method,path)=>{const value=mutation(method,path);if(path.endsWith("/schedule")&&method==="PUT"&&!saved)saved=value;return value;},replay:async()=>saved,
    get:async(route,foreign)=>{
      if(options.cleanupScopeChanged&&stage!=="baseline"&&route===`/api/v1/integrations/${integration}`)return{status:404,noStore:true};
      if(foreign)return{status:409,noStore:true,value:{code:"scope_stale"}};
      if(route==="/api/v1/session/bootstrap")return success({organization_id:c.scope.organizationID,workspace_id:c.scope.workspaceID,environment_id:c.scope.environmentID,fresh_auth_expires_at:at(3600000)});
      if(route==="/api/v1/integration-catalog")return success({items:[{key:"kubernetes",provider:"Kubernetes",auth_mode:"reference",setup_schema:[{key:"connection_reference",label:"Connection reference",type:"secret_reference",required:true}]}]});
      if(route.endsWith("/setup-status"))return success({integration_id:integration,connector_key:"kubernetes",authorization:{state:"verified",scope_kind:"kubernetes_cluster",scope_label:"approved",permissions:["inventory:read"]},runtime_coverage:{state:"not_applicable",reason:"not_applicable",sensor_count:0,healthy_sensor_count:0},updated_at:at(0)});
      if(route.includes("/syncs/")){const value=route.split("/").at(-1);return success(sync(value,value===failed?"failed":"succeeded"));}
      if(route.endsWith("/freshness"))return success({integration_id:integration,version:2,last_good:{snapshot_id:id(21),collected_at:at(302000),discovered_count:2,changed_count:1,removed_count:0},latest_sync:sync(stage==="failure"?failed:scheduled,stage==="failure"?"failed":"succeeded"),projections:Object.fromEntries(["risk","graph","search"].map(k=>[k,{state:"current",snapshot_id:id(21),completed_at:at(303000),last_error_code:null}])),updated_at:at(303000)});
      if(route===`/api/v1/agents/${agent}`)return success({summary:{id:agent},sources:[{integration_id:options.foreignSource?id(999):integration,provider:"kubernetes",snapshot_id:id(21),evidence_id:id(50),winning:true}],evidence:[{id:id(50),checksum:"sha256:"+"a".repeat(64)}]});
      if(route==="/api/v1/agents?limit=100")return success({items:[{id:agent}],page_info:{has_more:false,next_cursor:null}});
      if(route===`/api/v1/integrations/${integration}`&&deleted)return{status:404,noStore:true,value:{code:"not_found"}};
      if(route===`/api/v1/integrations/${integration}`)return{...success({id:integration,name:c.journey.integrationName,connector_key:"kubernetes"}),version:'"1"'};
      if(route===`/api/v1/integrations/${integration}/schedule`)return scheduledCreated&&!withdrawn?{...success({integration_id:integration,state:cleanupDisabled?"disabled":"enabled",cadence_seconds:300,version:cleanupVersion}),version:`"${cleanupVersion}"`}:{status:404,noStore:true};
      throw Error("unexpected actual read");
    }};
  let cleanupBound=false;
  browser.bindOwnedIntegration=value=>{assert.equal(value,integration);assert.equal(cleanupBound,false);cleanupBound=true;actions.push("owned receipt binding");};
  browser.cleanupRead=async q=>{
    assert.equal(cleanupBound,true);assert.equal(q.integrationID,integration);assert.deepEqual(q.scope,c.scope);
    if(options.cleanupScopeChanged)throw Error("scoped session refused");
    return browser.get(`/api/v1/integrations/${integration}${q.resource==="schedule"?"/schedule":""}`);
  };
  const readState=async kind=>{
    if(kind==="receipt")return{bound:!options.unboundReceipt};
    if(kind==="inventory"){const changed=stage!=="baseline"&&stage!=="restore";return{target:[{id:options.changedID&&changed?id(999):agent,display_name:"default/actual-agent",last_seen_at:changed?at(302000):at(stage==="restore"?700000:2000),snapshot_id:id(changed?21:stage==="restore"?22:20),source_state:"present",metadata:options.unchangedMetadata?false:changed}],unrelated_digest:"unrelated-exact"};}
    const values=[manual,...(stage!=="baseline"?[scheduled]:[]),...(stage==="restore"?[restored]:[])];
    return{database_now:withdrawn?at(601001):stage==="baseline"?at(1000):at(303000),schedules:scheduledCreated?[{id:schedule,state:withdrawn?"deleted":"enabled",version:1,next_run_at:at(stage==="baseline"?300000:600000),anchor:at(300000),acknowledged_revision:1,delivered_revision:1,cadence_seconds:300}]:[],
      runs:values.map(value=>({job_id:id(value===manual?30:value===scheduled?31:32),sync_id:value,schedule_id:value===scheduled?schedule:null,scheduled_for:value===scheduled?at(300000):null,state:"succeeded",admitted_at:at(value===scheduled&&!options.premature?300001:0),outbox_published:true,page_effects:1,apply_commits:options.noCommit?0:1})),
      snapshots:values.map(value=>({id:sync(value).snapshot_id,sync_id:value,complete:true,state:"complete",is_last_good:true,committed_at:at(value===manual?2000:302000),manifest_version:"actual-version",manifest_sha256:"a".repeat(64)}))};
  };
  return{c,actions,getClosed:()=>closed,dependencies:{query:async(_c,role)=>role==="observer"?{...ownerObservation(),runtime_ready:true}:{session_user:`approved_${role}`,current_user:`approved_${role}`,read_only:true,registered:true,login_role:true,superuser:false},readAuthority:async()=>({model_bound:true,verifiers_bound:true,desired:1,applied:1,generation:1}),validateRuntime:async()=>true,createBrowser:async()=>browser,readState,checkpoint:async phase=>{actions.push(`checkpoint ${phase}`);stage=phase;if(options.checkpointFailure)throw Error("external checkpoint interrupted");},observeTemporal:async q=>({kind:q.kind,paused:false,status:q.kind==="occurrence"?2:0,executions:[{workflow_id:"exact-observed-workflow",run_id:"exact-observed-run",scheduled_at:at(300000)}]})}};
}

test("failed changed-provider journey withdraws only owned schedule and retains restoration integration",async()=>{
  const f=recordedJourneyBoundary({checkpointFailure:true}),r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);
  assert.equal(r.journey,"failed");assert.equal(r.providerRestoreRequired,true);assert.equal(r.scheduleDeleted,true);
  assert.equal(r.ownedCleanup.recovery,"restore-provider-confirm-sync-then-delete-owned-integration");assert.equal(r.ownedCleanup.integrationRetained,true);
  assert.equal(f.actions.filter(v=>v.startsWith("cleanup PUT ")).length,1);assert.equal(f.actions.filter(v=>v.startsWith("cleanup DELETE ")).length,1);assert.equal(f.getClosed(),1);
});

test("failure cleanup deletes pre-change owned integration but refuses unproven ownership or conflicts",async()=>{
  const early=recordedJourneyBoundary({noCommit:true}),a=await currentDiscovery.runCurrentDiscoveryJourney(early.c,early.dependencies);
  assert.equal(a.ownedCleanup.integrationDeleted,true);assert.equal(a.providerRestoreRequired,false);assert.equal(early.actions.filter(x=>x.startsWith("cleanup DELETE ")).length,1);
  assert.equal(a.ownedCleanup.recovery,"none");
  const unowned=recordedJourneyBoundary({unboundReceipt:true}),b=await currentDiscovery.runCurrentDiscoveryJourney(unowned.c,unowned.dependencies);
  assert.equal(b.ownedIntegrationCreated,false);assert.equal(unowned.actions.filter(x=>x.startsWith("cleanup ")).length,0);
  assert.equal(unowned.actions.includes("owned receipt binding"),false);
  const conflict=recordedJourneyBoundary({checkpointFailure:true,cleanupConflict:true}),c=await currentDiscovery.runCurrentDiscoveryJourney(conflict.c,conflict.dependencies);
  assert.equal(c.ownedCleanup.refused,true);assert.equal(c.scheduleDeleted,false);assert.equal(conflict.actions.filter(x=>x.startsWith("cleanup ")).length,1);assert.equal(conflict.getClosed(),1);
  assert.equal(c.ownedCleanup.recovery,"retry-owned-resource-cleanup");
});

test("runtime validation refusal precedes browser or product work",async()=>{
  const f=recordedJourneyBoundary();let opened=0,validations=0;f.dependencies.validateRuntime=async()=>{validations++;throw Error("configuration refused");};f.dependencies.createBrowser=async()=>{opened++;throw Error("must not start");};
  const r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);assert.equal(r.phase,"runtime-config");assert.equal(r.journey,"not-run");assert.equal(validations,1);assert.equal(opened,0);
});

test("actual orchestration completes only after observed occurrence, retention, withdrawal and restored sync", async()=>{
  const f=recordedJourneyBoundary(),r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);
  assert.equal(r.journey,"passed",JSON.stringify(r));assert.equal(r.phase,"complete");assert.equal(f.getClosed(),1);
  assert.ok(f.actions.includes("checkpoint change")&&f.actions.includes("checkpoint failure")&&f.actions.includes("checkpoint restore"));
  assert.ok(f.actions.includes("click Delete integration"));assert.equal(f.actions.filter(x=>x==="click Sync inventory now").length,3);
});

test("provider acknowledgement cannot satisfy changed identity, commit, metadata or due evidence",async()=>{
  for(const options of [{changedID:true},{noCommit:true},{unchangedMetadata:true},{premature:true},{unboundReceipt:true},{foreignSource:true}]){
    const f=recordedJourneyBoundary(options),r=await currentDiscovery.runCurrentDiscoveryJourney(f.c,f.dependencies);
    assert.equal(r.journey,"failed");assert.equal(r.code,"evidence-mismatch");assert.equal(f.getClosed(),1);assert.ok(!f.actions.includes("click Delete integration"));
  }
});

test("Agent observation consumes all bounded cursor pages and refuses cycles or duplicate identities",async()=>{
  const id=n=>`pid_30000000-0000-4000-8000-${String(n).padStart(12,"0")}`;
  assert.equal(typeof currentDiscovery.readCurrentAgentIDs,"function");
  const calls=[];
  const values=await currentDiscovery.readCurrentAgentIDs(async route=>{calls.push(route);return {items:[{id:id(calls.length)}],page_info:calls.length===1?{has_more:true,next_cursor:"next-safe"}:{has_more:false,next_cursor:null}};});
  assert.deepEqual(values,[id(1),id(2)]);assert.match(calls[1],/cursor=next-safe$/);
  for(const duplicate of [true,false]){
    let n=0;
    await assert.rejects(currentDiscovery.readCurrentAgentIDs(async()=>({items:[{id:id(duplicate?1:++n)}],page_info:{has_more:true,next_cursor:"cycle"}})));
  }
});

test("only complete observed journey can select a successful command exit",()=>{
  assert.equal(typeof currentDiscovery.currentDiscoveryExitCode,"function");
  assert.equal(currentDiscovery.currentDiscoveryExitCode({journey:"passed",phase:"complete",code:"journey-complete"}),0);
  for(const result of [{journey:"passed"},{journey:"not-run",code:"runtime-closed"},{journey:"failed",phase:"complete",code:"journey-complete"}])assert.equal(currentDiscovery.currentDiscoveryExitCode(result),1);
});

test("exclusive current mode refuses mixed or malformed opt-ins before any setup", () => {
  assert.equal(validateCurrentDiscoveryMode({}), false);
  assert.equal(validateCurrentDiscoveryMode({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true" }), true);
  for (const value of ["", "false", "TRUE", "1"]) assert.throws(() => validateCurrentDiscoveryMode({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: value }));
  for (const key of ["AUTOMATIC_DISCOVERY", "UNKNOWN_FUTURE_MODE", "SECURITY_AGENT_EXPORT"]) assert.throws(() => validateCurrentDiscoveryMode({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", [`ZASP_COMBINED_E2E_${key}`]: "false" }));
  assert.equal(validateCurrentDiscoveryMode({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_COMBINED_E2E_CHROME: "/approved/chrome" }), true);
});

test("closed config refuses insecure origins, legacy profiles, credentials and ambiguous principals", () => {
  assert.doesNotThrow(() => validateCurrentDiscoveryConfig(config()));
  for (const mutate of [
    c => c.publicOrigin = "http://approved.example.test", c => c.publicOrigin += "/foreign", c => c.publicOrigin = "https" + "://user:secret@approved.example.test",
    c => c.profile = "release60", c => c.scope.environmentID = "foreign", c => c.canonical61Checksum = "unknown",
    c => c.database.connections.discovery = c.database.connections.api, c => delete c.database.connections.scheduler,
    c => c.database.dsn = "postgres://password", c => c.provider.token = "secret", c => c.runtime_ready = true,
    c => c.provider.protectedReference = "Bearer secret", c => c.database.psql = "psql", c => c.database.connections.observer.service = "x sslmode=disable",
  ]) { const value = config(); mutate(value); assert.throws(() => validateCurrentDiscoveryConfig(value)); }
});

test("actual closed runtime observation stops after the owner read, with no principal/provider continuation", async () => {
  let reads = 0;
  const result = await runCurrentDiscoveryPreflight(config(), { query: async () => { reads++; return ownerObservation(); } });
  assert.equal(reads, 1);
  assert.deepEqual(result, { phase: "runtime-gate", code: "runtime-closed", journey: "not-run", observedLogins: 1 });
});

test("wrong installed scope/pins/read-only identity and malformed observations fail closed", async () => {
  for (const mutate of [o => o.scope_exists = false, o => o.canonical_count = 60, o => o.worker_checksum = "c".repeat(64), o => o.catalog_ready = false, o => o.session_user = "foreign", o => o.current_user = "role_override", o => o.read_only = false, o => o.runtime_ready = "false", o => o.secret = "never-print"]) {
    const o = ownerObservation(); mutate(o);
    await assert.rejects(runCurrentDiscoveryPreflight(config(), { query: async () => o }));
  }
});

test("even all live principal probes cannot be relabelled as a completed discovery journey", async () => {
  const seen = [];
  const result = await runCurrentDiscoveryPreflight(config(), { query: async (_config, role) => {
    seen.push(role);
    return role === "observer" ? { ...ownerObservation(), runtime_ready: true } : { session_user: `approved_${role}`, current_user: `approved_${role}`, read_only: true, registered: true, login_role: true, superuser: false };
  } });
  assert.deepEqual(seen, roles);
  assert.deepEqual(result, { phase: "preflight", code: "journey-not-implemented", journey: "not-run", observedLogins: 6 });
});

test("missing registration or owner masquerading as a named login refuses immediately", async () => {
  for (const mutation of [o => o.registered = false, o => o.superuser = true, o => o.login_role = false, o => o.session_user = "approved_observer"]) {
    const seen = [];
    await assert.rejects(runCurrentDiscoveryPreflight(config(), { query: async (_config, role) => {
      seen.push(role);
      if (role === "observer") return { ...ownerObservation(), runtime_ready: true };
      const o = { session_user: `approved_${role}`, current_user: `approved_${role}`, read_only: true, registered: true, login_role: true, superuser: false }; mutation(o); return o;
    } }));
    assert.deepEqual(seen, ["observer", "api"]);
  }
});

test("fixed database probes select only approved services and read-only native checks", () => {
  for (const role of roles) {
    const p = currentDiscoveryProbe(config(), role);
    assert.deepEqual(p.env, { LANG: "C", LC_ALL: "C", PGSERVICEFILE: "/approved/libpq/services.conf", PGSYSCONFDIR: "/dev/null", PGPASSFILE: "/approved/libpq/passwords" });
    assert.equal(p.executable, "/approved/bin/psql");
    assert.deepEqual(p.args.slice(0, 6), ["-X", "-w", "-qAt", "-v", "ON_ERROR_STOP=1", "--dbname"]);
    assert.match(p.args[6], new RegExp(`^service=approved_${role} sslmode=verify-full connect_timeout=2 `));
    assert.match(p.args.at(-1), /^BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY;/);
    assert.match(p.args.at(-1), /ROLLBACK;$/);
    assert.doesNotMatch(p.args.at(-1), /SET ROLE|INSERT|UPDATE|DELETE|CREATE|register_|scheduled_admit|collect/i);
  }
});

const root = fileURLToPath(new URL("../", import.meta.url));
function runCombined(env, guarded = false) {
  // The RED run must never reach legacy browser/database/infra setup. This
  // subprocess guard is test-only and intercepts all native child creation.
  const preload = `import c from 'node:child_process';import{syncBuiltinESMExports}from'node:module';for(const k of ['spawn','exec','execFile','execFileSync','spawnSync','execSync'])c[k]=()=>{throw Error('legacy setup reached')};syncBuiltinESMExports();`;
  const args = [...(guarded ? ["--import", `data:text/javascript,${encodeURIComponent(preload)}`] : []), "scripts/production-combined-e2e.mjs"];
  try { return { code: 0, stdout: execFileSync(process.execPath, args, { cwd: root, env, encoding: "utf8", timeout: 5000, maxBuffer: 8192, stdio: ["ignore", "pipe", "pipe"] }), stderr: "" }; }
  catch (e) { return { code: e.status, stdout: String(e.stdout ?? ""), stderr: String(e.stderr ?? "") }; }
}

test("actual combined entry refuses the isolated mode before legacy prerequisites and never echoes input", () => {
  for (const env of [
    { ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "canary-secret" },
    { ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_COMBINED_E2E_AUTOMATIC_DISCOVERY: "false" },
    { ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_CURRENT_DISCOVERY_CONFIG: "/nonexistent/canary-secret" },
  ]) {
    const result = runCombined(env, true);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /^current discovery: (mode-invalid|config-unavailable)\n$/);
    assert.equal(result.stdout, "");
    assert.doesNotMatch(result.stderr, /canary-secret|legacy setup reached|Chrome|postgres| at /);
  }
});

test("entry consumes a bounded read-only process response, writes private refusal evidence and refuses reuse", async t => {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), "discovery-preflight-node-")));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const value = config(); value.evidenceDirectory = dir; value.database.psql = path.join(dir, "psql");
  const file = path.join(dir, "config.json");
  await writeFile(file, JSON.stringify(value), { mode: 0o600 });
  // Controlled process boundary, NOT PostgreSQL, login, provider or discovery
  // evidence. The child checks the consumer's actual isolation arguments.
  await writeFile(value.database.psql, `#!${process.execPath}\nimport assert from 'node:assert/strict';\nassert.equal(process.env.PGPASSWORD,undefined);assert.equal(process.env.PGOPTIONS,undefined);assert.equal(process.env.HOME,undefined);assert.equal(process.env.PGSERVICEFILE,'/approved/libpq/services.conf');assert.match(process.argv.at(-1),/runtime_ready\\(\\)/);assert.match(process.argv.at(-1),/READ ONLY/);assert.ok(process.argv.includes('-X')&&process.argv.includes('-w'));console.log(${JSON.stringify(JSON.stringify(ownerObservation()))});\n`, { mode: 0o700 });
  const env = { ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_CURRENT_DISCOVERY_CONFIG: file, PGPASSWORD: "canary-secret", PGOPTIONS: "-c role=owner" };
  const result = runCombined(env);
  assert.equal(result.code, 1);
  assert.equal(result.stderr, "current discovery: runtime-closed; journey not run\n");
  assert.equal(result.stdout, "");
  const evidence = path.join(dir, "current-discovery-preflight.json");
  const raw = await readFile(evidence, "utf8");
  const record = JSON.parse(raw);
  assert.deepEqual(Object.keys(record).sort(), ["code", "configSHA256", "format", "journey", "observedLogins", "phase", "sourceSHA256"].sort());
  assert.equal(record.code, "runtime-closed"); assert.equal(record.observedLogins, 1);
  assert.equal((await stat(evidence)).mode & 0o777, 0o600);
  assert.doesNotMatch(raw, /approved|canary-secret|password|postgres|https:/);
  assert.equal(runCombined(env).stderr, "current discovery: evidence-unavailable\n");
  assert.equal(await readFile(evidence, "utf8"), raw);
  const link = path.join(dir, "config-link.json"); await symlink(file, link);
  assert.equal(runCombined({ ...env, ZASP_CURRENT_DISCOVERY_CONFIG: link }).stderr, "current discovery: config-unavailable\n");
});

test("actual journey entry reaches authority preflight but never launches browser for mismatched model", async t=>{
  const dir=await realpath(await mkdtemp(path.join(os.tmpdir(),"discovery-connected-entry-")));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const value=connectedConfig();value.evidenceDirectory=dir;value.database.psql=path.join(dir,"psql");
  const validator=`#!${process.execPath}\nlet raw='';for await(const chunk of process.stdin)raw+=chunk;const q=JSON.parse(raw);if(process.argv[2]!=='--validate-config'||q.format!=='zasp-discovery-config-validation-v1')process.exit(1);console.log(JSON.stringify({format:'zasp-discovery-config-validation-v1',valid:true}));\n`;
  value.journey.temporal.executable=path.join(dir,"discovery-observe");value.journey.temporal.sha256=createHash("sha256").update(validator).digest("hex");await writeFile(value.journey.temporal.executable,validator,{mode:0o700});
  const file=path.join(dir,"config.json");await writeFile(file,JSON.stringify(value),{mode:0o600});
  const owner={...ownerObservation(),runtime_ready:true};
  await writeFile(value.database.psql,`#!${process.execPath}\nconst sql=process.argv.at(-1);if(!sql.includes('READ ONLY'))process.exit(1);let v;if(sql.includes('model_bound'))v={model_bound:false,verifiers_bound:true,desired:1,applied:1,generation:1};else if(sql.includes('runtime_ready()'))v=${JSON.stringify(owner)};else{const s=process.argv.find(x=>x.startsWith('service=')).split(' ')[0].slice(8);v={session_user:s,current_user:s,read_only:true,registered:true,login_role:true,superuser:false};}console.log(JSON.stringify(v));\n`,{mode:0o700});
  const result=runCombined({ZASP_COMBINED_E2E_CURRENT_DISCOVERY:"true",ZASP_CURRENT_DISCOVERY_CONFIG:file});
  assert.equal(result.code,1);assert.equal(result.stderr,"current discovery: profile-mismatch; journey not run\n");
  const record=JSON.parse(await readFile(path.join(dir,"current-discovery-journey.json"),"utf8"));
  assert.equal(record.phase,"authority-preflight");assert.equal(record.observedLogins,6);assert.equal(record.sourceStable,true);assert.equal(Object.keys(record.sourcesSHA256).length,5);
});

test("interruption joins the owned read-only client before the harness exits", async t => {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), "discovery-preflight-cancel-")));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const value = config(); value.evidenceDirectory = dir; value.database.psql = path.join(dir, "psql");
  const marker = path.join(dir, "client-state"); const file = path.join(dir, "config.json");
  await writeFile(file, JSON.stringify(value), { mode: 0o600 });
  await writeFile(value.database.psql, `#!${process.execPath}\nconst fs=require('node:fs');const f=${JSON.stringify(marker)};fs.writeFileSync(f,'running');process.on('SIGTERM',()=>{fs.writeFileSync(f,'joined');process.exit(0)});setTimeout(()=>{fs.writeFileSync(f,'unjoined-natural-exit');process.exit(0)},2000);`, { mode: 0o700 });
  const child = spawn(process.execPath, ["scripts/production-combined-e2e.mjs"], { cwd: root, env: { ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_CURRENT_DISCOVERY_CONFIG: file }, stdio: "ignore" });
  const closed = once(child, "close");
  try {
    let state;
    for (let n = 0; n < 150; n++) { state = await readFile(marker, "utf8").catch(() => "absent"); if (state === "running") break; await delay(10); }
    assert.equal(state, "running");
    child.kill("SIGTERM");
    const [code, signal] = await closed;
    // Drain the controlled child even against the pre-fix parent so the RED
    // leaves no detached process or racing temp-directory cleanup.
    for (let n = 0; n < 250 && await readFile(marker, "utf8") === "running"; n++) await delay(10);
    assert.equal(await readFile(marker, "utf8"), "joined");
    assert.equal(code, 143); assert.equal(signal, null);
  } finally { child.kill("SIGTERM"); await closed; }
});

test("database errors, unbounded output and malformed bodies remain fixed refusals without raw diagnostics", async t => {
  for (const body of [
    "process.stderr.write('canary-secret postgres" + "://user:password@host');process.exit(2)",
    "process.stdout.write('canary-secret'.repeat(2000))",
    "console.log('canary-secret not json')",
  ]) {
    const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), "discovery-preflight-error-")));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const value = config(); value.evidenceDirectory = dir; value.database.psql = path.join(dir, "psql");
    const file = path.join(dir, "config.json");
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await writeFile(value.database.psql, `#!${process.execPath}\n${body}\n`, { mode: 0o700 });
    const result = runCombined({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_CURRENT_DISCOVERY_CONFIG: file });
    assert.equal(result.code, 1); assert.equal(result.stdout, "");
    assert.equal(result.stderr, "current discovery: database-unavailable; journey not run\n");
    const raw = await readFile(path.join(dir, "current-discovery-preflight.json"), "utf8");
    assert.equal(JSON.parse(raw).journey, "not-run");
    assert.doesNotMatch(raw + result.stderr, /canary|postgres:|password|approved| at /);
  }
});

test("capture limit bounds retained combined bytes while a TERM-resistant child keeps flooding", async () => {
  const code = `process.on('SIGTERM',()=>{});const send=()=>{process.stdout.write('x'.repeat(32768));process.stderr.write('y'.repeat(32768))};send();setInterval(send,5);setTimeout(()=>process.exit(0),350);`;
  const owned = spawnOwnedCommand(process.execPath, ["-e", code], { maxOutputBytes: 4096, graceMs: 100, killMs: 1000 });
  let observed = 0;
  for (const stream of [owned.child.stdout, owned.child.stderr]) stream.on("data", chunk => { observed += chunk.length; });
  try {
    const result = await owned.completed;
    assert.ok(observed > 65536, "fixture must keep producing through the cleanup grace");
    assert.ok(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <= 4096, "retained capture exceeded the actual combined byte cap");
    assert.equal(result.capturedOutputBytes, 4096);
    assert.equal(result.outputLimitExceeded, true);
    assert.equal(result.signal, "SIGKILL");
    await owned.stop(); await owned.stop();
  } finally { await owned.stop(); }
});

test("bounded capture accepts exact-limit bytes and validates the opt-in before spawning", async () => {
  const owned = spawnOwnedCommand(process.execPath, ["-e", "process.stdout.write('out');process.stderr.write('err')"], { maxOutputBytes: 6 });
  try {
    assert.deepEqual(await owned.completed, { status: 0, signal: null, stdout: "out", stderr: "err", capturedOutputBytes: 6, outputLimitExceeded: false });
  } finally { await owned.stop(); }
  for (const value of [0, -1, 1.5, Infinity, "4096", null]) assert.throws(() => spawnOwnedCommand("/must-not-spawn", [], { maxOutputBytes: value }), /capture limit/);
});

test("a real FIFO config with no writer refuses without blocking open or starting setup", { skip: process.platform === "win32" }, async t => {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), "discovery-preflight-fifo-")));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const fifo = path.join(dir, "config.fifo");
  execFileSync("/usr/bin/mkfifo", [fifo], { stdio: "ignore", timeout: 2000 });
  const result = runCombined({ ZASP_COMBINED_E2E_CURRENT_DISCOVERY: "true", ZASP_CURRENT_DISCOVERY_CONFIG: fifo }, true);
  assert.equal(result.code, 1, "configuration refusal must finish, not rely on the test watchdog");
  assert.equal(result.stderr, "current discovery: config-unavailable\n");
  assert.equal(result.stdout, "");
  assert.equal((await stat(fifo)).isFIFO(), true);
});
