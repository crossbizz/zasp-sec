import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { runLocalSmoke } from "./production-ui-api-smoke.mjs";
import { runSmokeLifecycle, describeSmokeFailure, connectSmokeCDP } from "./ui-api-smoke-support.mjs";
import * as smokeSupport from "./ui-api-smoke-support.mjs";
import { validateSmokeMode, smokeEnvironment, assertSmokeObservation, cookieIsHostSession, createSmokeOwner, runSmokeCommand, reloadSmokePage } from "./ui-api-smoke-support.mjs";
import { identityReply, historyReply, migrationEnvironment, fixtureSeedSQL, smokeAPIEnvironment, proxyRoute, smokeProxyHeaders } from "./ui-api-smoke-fixtures.mjs";

test("trusted TLS proxy supplies exact origin host and port without retaining spoofed forwarding",()=>{
  for(const [origin,host,port] of [["https://zasp.local-smoke.test:49157","zasp.local-smoke.test:49157","49157"],["https://zasp.local-smoke.test","zasp.local-smoke.test","443"]]){
    const input={host,cookie:"opaque-session","content-type":"application/json",origin,"x-zasp-scope":"scope","Forwarded":"for=evil;proto=http","X-FoRwArDeD-HoSt":"evil","x-forwarded-port":"80","x-forwarded-for":"evil","x-forwarded-proto":"http","x-forwarded-unknown":["evil"]};
    const before=structuredClone(input),actual=smokeProxyHeaders(input,origin);
    assert.deepEqual(actual,{host,cookie:"opaque-session","content-type":"application/json",origin,"x-zasp-scope":"scope","x-forwarded-for":"127.0.0.1","x-forwarded-host":host,"x-forwarded-port":port,"x-forwarded-proto":"https"});
    assert.deepEqual(input,before);
  }
});

test("trusted TLS proxy refuses foreign host or malformed local origin and preserves API origin validation",()=>{
  const origin="https://zasp.local-smoke.test:49157",headers={host:"zasp.local-smoke.test:49157"};
  for(const host of [undefined,"foreign.test:49157","zasp.local-smoke.test","zasp.local-smoke.test:49158",[headers.host]])assert.throws(()=>smokeProxyHeaders({...headers,host},origin));
  for(const bad of ["http://zasp.local-smoke.test:49157","https://foreign.test:49157",origin+"/path",origin+"?query",origin+"#fragment","https://user@zasp.local-smoke.test:49157"])assert.throws(()=>smokeProxyHeaders(headers,bad));
  assert.throws(()=>smokeProxyHeaders({...headers,Host:headers.host},origin));
  assert.equal(smokeProxyHeaders({...headers,origin:"https://foreign.test"},origin).origin,"https://foreign.test");
});

const scope = {
  organization_id: "pid_10000001-0000-4000-8000-000000000001",
  workspace_id: "pid_10000002-0000-4000-8000-000000000002",
  environment_id: "pid_10000003-0000-4000-8000-000000000003",
};
const observation = () => ({
  bootstrap: {status:200,noStore:true,body:{...scope,principal:{id:"pid_10000004-0000-4000-8000-000000000004",active:true},fresh_auth_expires_at:new Date(Date.now()+60_000).toISOString()}},
  agents:{status:200,noStore:true,body:{items:[],page_info:{has_more:false,next_cursor:null}}},
  receipts:{status:200,noStore:true,body:{items:[]}},
  text:"Agents\nNo records in this scope.",
});

const finalEvidence=()=>({observedCookie:true,identityStarts:1,callbackCount:1,historyReads:2,browserFailure:false,fixtureFailure:false,activeSessionCount:"1",inventoryCount:"0",sessionCountReadFailed:false,inventoryCountReadFailed:false});

test("final evidence diagnostics preserve every refusal and expose all remaining bounded observations",()=>{
  smokeSupport.assertSmokeFinalEvidence(observation(),scope,finalEvidence());
  for(const [key,bad] of [["observedCookie",false],["identityStarts",2],["callbackCount",0],["browserFailure",true],["fixtureFailure",true],["activeSessionCount","2"],["inventoryCount","1"]]){
    const evidence={...finalEvidence(),[key]:bad,secret:"SECRET_BODY"};
    assert.throws(()=>smokeSupport.assertSmokeFinalEvidence(observation(),scope,evidence),error=>{
      const row=describeSmokeFailure("final-evidence",error,true).errors[0];
      assert.deepEqual(row.finalEvidence,{observedCookie:evidence.observedCookie,identityStarts:evidence.identityStarts,callbackCount:evidence.callbackCount,historyReads:2,browserFailure:evidence.browserFailure,fixtureFailure:evidence.fixtureFailure,activeSessionCount:Number(evidence.activeSessionCount),inventoryCount:Number(evidence.inventoryCount),sessionCountReadFailed:false,inventoryCountReadFailed:false,observationPassed:true});
      assert.equal(JSON.stringify(row).includes("SECRET"),false);return true;
    });
  }
  const bad=observation();bad.agents.status=503;
  assert.throws(()=>smokeSupport.assertSmokeFinalEvidence(bad,scope,finalEvidence()),error=>{const d=describeSmokeFailure("final-evidence",error,true);assert.equal(d.errors[0].finalEvidence.observationPassed,false);assert.equal(d.errors[0].responses.agents.status,503);return true;});
});

test("final evidence diagnostics preserve count query errors and reject unbounded or secret metadata",()=>{
  for(const name of ["session","inventory"]){
    const cause=Object.assign(Error("SECRET_QUERY"),{code:"ETIMEDOUT"}),evidence={...finalEvidence(),[name+"CountReadFailed"]:true};
    assert.throws(()=>smokeSupport.assertSmokeFinalEvidence(observation(),scope,evidence,{[name+"Error"]:cause}),error=>{assert.equal(error,cause);const d=describeSmokeFailure("final-evidence",error,true);assert.equal(d.errors[0].finalEvidence[name+"CountReadFailed"],true);assert.equal(d.errors[0].kind,"system");assert.deepEqual(d.errors[0].countQueryErrors,{[name]:{kind:"system",code:"ETIMEDOUT"}});assert.equal(JSON.stringify(d).includes("SECRET"),false);return true;});
  }
  assert.throws(()=>smokeSupport.assertSmokeFinalEvidence(observation(),scope,{...finalEvidence(),observedCookie:false},{sessionError:Error("smoke command failed (1)"),inventoryError:Error("SECRET_QUERY")}),error=>{const row=describeSmokeFailure("final-evidence",error,true).errors[0];assert.equal(row.kind,"assertion");assert.deepEqual(row.countQueryErrors,{session:{kind:"command-failed",status:1},inventory:{kind:"query-refused"}});assert.equal(JSON.stringify(row).includes("SECRET"),false);return true;});
  const error=Object.assign(Error("SECRET"),{smokeFinalEvidence:{observedCookie:"SECRET",identityStarts:-1,callbackCount:1e9,historyReads:NaN,activeSessionCount:"1 SECRET",inventoryCount:"99999999999999999",browserFailure:true,firstBrowserFailureSource:"SECRET_URL",firstFixtureFailureSource:"SECRET_BODY",extra:"SECRET"}});
  assert.deepEqual(describeSmokeFailure("final-evidence",error,true).errors[0].finalEvidence,{browserFailure:true});
});

test("first failure evidence retains fixed browser and fixture source classes without replacing earlier events",()=>{
  assert.equal(typeof smokeSupport.markSmokeFailure,"function");
  for(const [family,sources] of [["Browser",["blocked-request","runtime-exception","fetch-cdp-rejection"]],["Fixture",["identity-fixture-refused","history-fixture-refused","upstream-error","proxy-refused"]]]){
    for(const source of sources){const evidence={};smokeSupport.markSmokeFailure(evidence,source);smokeSupport.markSmokeFailure(evidence,sources.at(-1));assert.equal(evidence["first"+family+"FailureSource"],source);}
  }
  assert.throws(()=>smokeSupport.markSmokeFailure({},"SECRET_URL"));
});

test("proxy refusal identifies closed substage method and source-known route without raw request data",async()=>{
  const source=await readFile(new URL("../openapi/openapi.yaml",import.meta.url),"utf8");
  const paths=[...source.matchAll(/^ {2}(\/api\/v1\/[^\s{]+):$/gm)].map(m=>m[1]);assert.ok(paths.length>40);
  for(const pathname of paths){
    const evidence={};smokeSupport.markSmokeFailure(evidence,"proxy-refused",{stage:"route",method:"POST",pathname,headers:{cookie:"SECRET"},query:"SECRET"});
    const error=Object.assign(Error("SECRET"),{smokeFinalEvidence:evidence});
    assert.deepEqual(describeSmokeFailure("final-evidence",error,true).errors[0].finalEvidence.firstProxyRefusal,{stage:"route",method:"POST",route:"api-"+pathname.slice(8).replaceAll("/","-")});
  }
  for(const stage of ["host","url","route","headers","request"]){
    const evidence={};smokeSupport.markSmokeFailure(evidence,"proxy-refused",{stage,method:"HEAD",pathname:"/discovery/assets"});smokeSupport.markSmokeFailure(evidence,"proxy-refused",{stage:"request",method:"GET",pathname:"/sign-in"});
    assert.deepEqual(evidence.firstProxyRefusal,{stage,method:"HEAD",route:"web-discovery-assets"});
  }
  for(const [pathname,route] of [["/api/v1/agents/SECRET_ID","other-api"],["/unknown/SECRET","other-web"],[undefined,"unparsed"]]){
    const evidence={};smokeSupport.markSmokeFailure(evidence,"proxy-refused",{stage:"SECRET",method:"SECRET",pathname});
    const result=describeSmokeFailure("final-evidence",Object.assign(Error("SECRET"),{smokeFinalEvidence:evidence}),true);
    assert.deepEqual(result.errors[0].finalEvidence.firstProxyRefusal,{stage:"unknown",method:"other",route});assert.equal(JSON.stringify(result).includes("SECRET"),false);
  }
  const bad=Object.assign(Error("SECRET"),{smokeFinalEvidence:{firstProxyRefusal:{stage:"SECRET",method:"SECRET",route:"SECRET",url:"SECRET"}}});
  assert.deepEqual(describeSmokeFailure("final-evidence",bad,true).errors[0].finalEvidence.firstProxyRefusal,{stage:"unknown",method:"other",route:"unknown"});
  // Diagnostic classification must not turn any refused operation into a permitted route.
  assert.throws(()=>proxyRoute("POST","/api/v1/session/sign-out"));assert.throws(()=>proxyRoute("POST","/discovery/assets"));
});

test("integrated export route labels are diagnostic only and never permit export operations",()=>{
  for(const [pathname,label] of [["/api/v1/audit-exports","api-audit-exports"],["/api/v1/compliance/exports","api-compliance-exports"]]){
    const evidence={};smokeSupport.markSmokeFailure(evidence,"proxy-refused",{stage:"route",method:"POST",pathname});
    const result=describeSmokeFailure("final-evidence",Object.assign(Error("refused"),{smokeFinalEvidence:evidence}),true);
    assert.equal(result.errors[0].finalEvidence.firstProxyRefusal.route,label);
    for(const method of ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"])assert.throws(()=>proxyRoute(method,pathname));
    const dynamic={};smokeSupport.markSmokeFailure(dynamic,"proxy-refused",{stage:"route",method:"GET",pathname:pathname+"/SECRET_ID/download-grants"});
    const safe=describeSmokeFailure("final-evidence",Object.assign(Error("refused"),{smokeFinalEvidence:dynamic}),true);
    assert.equal(safe.errors[0].finalEvidence.firstProxyRefusal.route,"other-api");assert.equal(JSON.stringify(safe).includes("SECRET_ID"),false);
  }
});

test("fixture identity protocol validates callback, token and actual session exchange", () => {
  const origin="https://zasp.local-smoke.test:4443",callback=origin+"/auth/callback?state="+"a".repeat(32);
  const url=new URL("http://127.0.0.1:1001/v1/b2b/public/oauth/google/start");
  for(const [k,v] of Object.entries({public_token:"public-token-test-local",organization_id:"organization-test-local",login_redirect_url:callback,signup_redirect_url:callback}))url.searchParams.set(k,v);
  const result=identityReply({method:"GET",url,headers:{},body:""},origin);
  assert.equal(result.status,302);assert.equal(new URL(result.headers.location).searchParams.get("token"),"local-oauth-token");
  const headers={authorization:"Basic "+Buffer.from("project-test-local:secret-test-local").toString("base64")};
  const oauth={method:"POST",url:new URL("http://127.0.0.1:1001/v1/b2b/oauth/authenticate"),headers,body:JSON.stringify({oauth_token:"local-oauth-token",session_duration_minutes:60})};
  const authenticated=identityReply(oauth,origin);assert.equal(authenticated.body.session_jwt,"header.payload.signature");
  const session=identityReply({...oauth,url:new URL("http://127.0.0.1:1001/v1/b2b/sessions/authenticate"),body:JSON.stringify({session_jwt:authenticated.body.session_jwt})},origin);
  assert.equal(session.body.member_session.member_id,"member-test-local");assert.ok(Date.parse(session.body.member_session.expires_at)>Date.now());
  for(const bad of [{...oauth,headers:{}},{...oauth,body:'{"oauth_token":"other"}'},{...oauth,method:"DELETE"}])assert.throws(()=>identityReply(bad,origin));
  url.searchParams.set("login_redirect_url","https://foreign.test/auth/callback?state="+"a".repeat(32));assert.throws(()=>identityReply({method:"GET",url,headers:{},body:""},origin));
});

test("history fixture serves only signed readiness mapping/marker, never search data", () => {
  const mapping={mappings:{dynamic:"strict"}},digest="a".repeat(64),request={method:"GET",url:new URL("http://127.0.0.1:1002/zasp-runtime-events-v1/_mapping"),headers:{authorization:"AWS4-HMAC-SHA256 fixture"},body:""};
  assert.deepEqual(historyReply(request,mapping,digest).body,{"zasp-runtime-events-v1":mapping});
  const marker=historyReply({...request,url:new URL("http://127.0.0.1:1002/zasp-runtime-events-v1/_doc/_zasp_schema_v1")},mapping,digest);
  assert.equal(marker.body._source.mapping_digest,"sha256:"+digest);
  for(const bad of [{...request,headers:{}},{...request,method:"POST"},{...request,url:new URL("http://127.0.0.1:1002/zasp-runtime-events-v1/_search")}])assert.throws(()=>historyReply(bad,mapping,digest));
});

test("fixed fixture seeds no product sessions, inventory or workflow effects; configuration stays local", () => {
  const seed=fixtureSeedSQL();assert.match(seed,/INSERT INTO zasp_identity_memberships/);assert.match(seed,/session_bootstrap:/);
  assert.doesNotMatch(seed,/INSERT INTO zasp_(?:product_sessions|inventory|security_agent|workflow)/);
  const migrate=migrationEnvironment("postgres://zasp_e2e@127.0.0.1:5439/postgres?sslmode=disable");assert.equal(migrate.ZASP_MIGRATION_TIMEOUT,"20s");assert.equal(Object.keys(migrate).filter(k=>k.endsWith("DB_PRINCIPAL")).length,29);
  const env=smokeAPIEnvironment({postgresPort:5439,identityPort:11001,historyPort:11002,apiPort:11003,healthPort:11004,publicOrigin:"https://zasp.local-smoke.test:4443"});
  assert.equal(env.ZASP_REQUEST_TIMEOUT,"10s");assert.equal(env.ZASP_PROVIDER_TIMEOUT,"5s");assert.equal(env.ZASP_SHUTDOWN_TIMEOUT,"5s");assert.equal(env.ZASP_ENVIRONMENT,"test");
  assert.equal(proxyRoute("GET","/api/v1/agents"),"api");assert.equal(proxyRoute("POST","/api/v1/session/callback"),"api");assert.equal(proxyRoute("GET","/discovery/assets"),"web");
  for(const [m,p] of [["POST","/api/v1/policies"],["GET","/api/v1/integrations"],["DELETE","/api/v1/session/callback"]])assert.throws(()=>proxyRoute(m,p));
});

test("smoke API fixture generates distinct 32-byte secret material for each config invocation", () => {
  const ports = { postgresPort: 5432, identityPort: 5433, historyPort: 5434, apiPort: 5435, healthPort: 5436, publicOrigin: "https://zasp.local-smoke.test:5437" };
  const first = smokeAPIEnvironment(ports);
  const second = smokeAPIEnvironment(ports);
  assert.notEqual(first.ZASP_STYTCH_WEBHOOK_SECRET, second.ZASP_STYTCH_WEBHOOK_SECRET);
  assert.notEqual(first.ZASP_WORKFLOW_SIGNING_KEY, second.ZASP_WORKFLOW_SIGNING_KEY);
  assert.notEqual(first.ZASP_TOKEN_REVEAL_KEY, second.ZASP_TOKEN_REVEAL_KEY);
  assert.match(first.ZASP_STYTCH_WEBHOOK_SECRET, /^whsec_[A-Za-z0-9+/]+={0,2}$/);
  assert.equal(Buffer.from(first.ZASP_STYTCH_WEBHOOK_SECRET.slice("whsec_".length), "base64").length, 32);
  assert.match(first.ZASP_WORKFLOW_SIGNING_KEY, /^[a-f0-9]{64}$/);
  assert.equal(Buffer.from(first.ZASP_WORKFLOW_SIGNING_KEY, "hex").length, 32);
  assert.equal(Buffer.from(first.ZASP_TOKEN_REVEAL_KEY, "base64url").length, 32);
});

test("proxy permits only the exact shell receipt read while keeping receipt mutations and neighboring paths closed",()=>{
  const target=new URL("/api/v1/workflow-mutation-receipts?limit=50","https://zasp.local-smoke.test:49157");
  assert.equal(proxyRoute("GET",target.pathname),"api");assert.equal(target.pathname+target.search,"/api/v1/workflow-mutation-receipts?limit=50");
  for(const method of ["POST","HEAD","PUT","PATCH","DELETE","OPTIONS","TRACE","CONNECT","get"])assert.throws(()=>proxyRoute(method,target.pathname));
  for(const pathname of [target.pathname+"/",target.pathname+"/id",target.pathname+"/id/acknowledge",target.pathname+"-other",target.pathname+"%2Fid","/api/v1/workflow-mutation-receipt","/api/v1/policies","/api/v1/integrations"]){
    assert.throws(()=>proxyRoute("GET",pathname));assert.throws(()=>proxyRoute("POST",pathname));
  }
  const headers=smokeProxyHeaders({host:"zasp.local-smoke.test:49157",cookie:"opaque","x-zasp-expected-scope":"captured-scope"},target.origin);
  assert.equal(headers.cookie,"opaque");assert.equal(headers["x-zasp-expected-scope"],"captured-scope");
});

test("receipt observation requires real successful uncached empty page and exposes only safe status on refusal",()=>{
  for(const change of [v=>delete v.receipts,v=>v.receipts.status=500,v=>v.receipts.noStore=false,v=>v.receipts.body={items:null},v=>v.receipts.body.items.push({id:"SECRET"}),v=>v.receipts.body.extra="SECRET"]){
    const value=observation();change(value);
    assert.throws(()=>assertSmokeObservation(value,scope),error=>{const row=describeSmokeFailure("observation",error,true).errors[0];assert.deepEqual(row.responses.receipts,value.receipts?{status:value.receipts.status,noStore:value.receipts.noStore}:undefined);assert.equal(JSON.stringify(row).includes("SECRET"),false);return true;});
  }
});

test("smoke entry is explicit, closed and incompatible with other harness modes", () => {
  assert.equal(validateSmokeMode({ZASP_LOCAL_UI_API_SMOKE:"fixture48"}),"fixture48");
  for(const value of [undefined,"","true","production","fixture61"]) assert.throws(()=>validateSmokeMode({ZASP_LOCAL_UI_API_SMOKE:value}));
  assert.throws(()=>validateSmokeMode({ZASP_LOCAL_UI_API_SMOKE:"fixture48",ZASP_COMBINED_E2E_CURRENT_DISCOVERY:"1"}));
});

test("actual entry refuses before prerequisites without mode, including in a real child", async () => {
  await assert.rejects(runLocalSmoke({}),/mode required/);
  const result=await runSmokeCommand(process.execPath,[fileURLToPath(new URL("./production-ui-api-smoke.mjs",import.meta.url))],{env:smokeEnvironment(process.env),reject:false});
  assert.equal(result.status,1);assert.equal(result.stdout,"");assert.equal(result.stderr.trim(),"local fixture smoke refused");
});

test("entry invalid environment refuses promptly without leaving signal listeners or its deadline",{timeout:5000},async()=>{
  const entry=new URL("./production-ui-api-smoke.mjs",import.meta.url).href;
  const script=`import assert from 'node:assert/strict';import {runLocalSmoke} from ${JSON.stringify(entry)};const before=['SIGTERM','SIGINT'].map(s=>process.listenerCount(s));await assert.rejects(runLocalSmoke({ZASP_LOCAL_UI_API_SMOKE:'fixture48',PATH:'/usr/bin:/bin'}));assert.deepEqual(['SIGTERM','SIGINT'].map(s=>process.listenerCount(s)),before);console.log('refused-and-disposed');`;
  const result=await runSmokeCommand(process.execPath,["--input-type=module","-e",script],{env:smokeEnvironment(process.env),timeoutMs:1000});
  assert.equal(result.stdout.trim(),"refused-and-disposed");
});

test("lifecycle handles repeated actual signals throughout slow cleanup and refuses success",{timeout:5000},async()=>{
  const supportURL=new URL("./ui-api-smoke-support.mjs",import.meta.url).href;
  const script=`import assert from 'node:assert/strict';import {runSmokeLifecycle} from ${JSON.stringify(supportURL)};const before=['SIGTERM','SIGINT'].map(s=>process.listenerCount(s));const calls=[];await assert.rejects(runSmokeLifecycle(process.env,async({owner})=>{owner.own(async()=>calls.push('last'));owner.own(async()=>{calls.push('slow');setTimeout(()=>process.kill(process.pid,'SIGTERM'),10);setTimeout(()=>process.kill(process.pid,'SIGTERM'),30);setTimeout(()=>process.kill(process.pid,'SIGINT'),50);await new Promise(r=>setTimeout(r,100));calls.push('joined');});}),/cancel/);assert.deepEqual(calls,['slow','joined','last']);assert.deepEqual(['SIGTERM','SIGINT'].map(s=>process.listenerCount(s)),before);console.log('cancelled-after-all-joins');`;
  const result=await runSmokeCommand(process.execPath,["--input-type=module","-e",script],{env:smokeEnvironment(process.env),timeoutMs:2000});
  assert.equal(result.stdout.trim(),"cancelled-after-all-joins");
});

test("completed work followed by cancellation during final disposal cannot return success",async()=>{
  let joined=false,disposed=false;
  await assert.rejects(runSmokeLifecycle(process.env,async({owner,cancel})=>{owner.own(async()=>{joined=true;});return cancel;},async()=>{disposed=true;process.emit('SIGINT');}),/cancel/);
  assert.equal(joined,true);assert.equal(disposed,true);
});

test("failure diagnostics retain only closed phase, error classes and numeric protocol metadata",()=>{
  const cause=Object.assign(Error("SECRET_COOKIE https://secret.invalid?token=secret"),{code:-32000,data:{body:"secret"}});
  const protocol=Object.assign(Error("smoke debugger request failed",{cause}),{smokeMethod:"Runtime.evaluate"});
  const error=new AggregateError([protocol,Object.assign(Error("SECRET_CLEANUP"),{code:"EACCES"})],"SECRET_AGGREGATE");
  assert.deepEqual(describeSmokeFailure("browser-anchor",error,false),{phase:"browser-anchor",errors:[{kind:"aggregate"},{kind:"cdp-request",method:"Runtime.evaluate",protocolCode:-32000},{kind:"system",code:"EACCES"}],cleanupComplete:false});
  const output=JSON.stringify(describeSmokeFailure("SECRET_PHASE",Object.assign(Error("SECRET_ERROR"),{code:"SECRET_CODE",smokeMethod:"SECRET_METHOD"}),"SECRET_FLAG"));
  assert.equal(output.includes("SECRET"),false);assert.deepEqual(JSON.parse(output),{phase:"unknown",errors:[{kind:"unknown"}],cleanupComplete:false});
  const cycle=Error("secret");cycle.cause=cycle;assert.ok(JSON.stringify(describeSmokeFailure("browser-connect",cycle,true)).length<512);
  const typed=Object.assign(Error("secret"),{code:"ERR_ASSERTION",smokeException:"TypeError"});assert.deepEqual(describeSmokeFailure("browser-anchor",typed,true).errors,[{kind:"assertion",exceptionClass:"TypeError"}]);
  protocol.cause.code=32768;assert.equal(Object.hasOwn(describeSmokeFailure("browser-anchor",protocol,true).errors[0],"protocolCode"),false);
  typed.smokeException="SECRET_CLASS";assert.equal(JSON.stringify(describeSmokeFailure("browser-anchor",typed,true)).includes("SECRET"),false);
});

test("existing HTTP oracles still refuse while diagnostics expose only bounded status/cache observations",()=>{
  for(const target of ["bootstrap","agents","receipts"]){
    const value=observation();value[target].status=503;value[target].noStore=false;value[target].body.secret="DO_NOT_LOG";
    assert.throws(()=>assertSmokeObservation(value,scope),error=>{const result=describeSmokeFailure("observation",error,true);assert.deepEqual(result.errors[0].responses,{bootstrap:{status:value.bootstrap.status,noStore:value.bootstrap.noStore},agents:{status:value.agents.status,noStore:value.agents.noStore},receipts:{status:value.receipts.status,noStore:value.receipts.noStore}});assert.equal(JSON.stringify(result).includes("DO_NOT_LOG"),false);return true;});
  }
  for(const name of ["unauthenticatedBootstrap","foreignScope"]){
    const error=Object.assign(Error("SECRET_ERROR"),{code:"ERR_ASSERTION",smokeResponses:{[name]:{status:403,noStore:false,body:"SECRET_BODY",url:"SECRET_URL"},SECRET_TARGET:{status:200,noStore:true}}});
    assert.deepEqual(describeSmokeFailure("browser-unauthenticated",error,false).errors,[{kind:"assertion",responses:{[name]:{status:403,noStore:false}}}]);
    error.smokeResponses[name]={status:"403_SECRET",noStore:"SECRET"};assert.deepEqual(describeSmokeFailure("browser-unauthenticated",error,false).errors,[{kind:"assertion"}]);
    error.smokeResponses[name]={status:600,noStore:true};assert.deepEqual(describeSmokeFailure("browser-unauthenticated",error,false).errors,[{kind:"assertion",responses:{[name]:{noStore:true}}}]);
  }
});

test("actual CDP rejection retains first request method and code but never raw protocol text",async(t)=>{
  class Socket extends EventTarget{
    constructor(){super();queueMicrotask(()=>this.dispatchEvent(new Event("open")));}
    send(raw){const q=JSON.parse(raw);queueMicrotask(()=>this.dispatchEvent(new MessageEvent("message",{data:JSON.stringify({id:q.id,error:{code:-32602,message:"SECRET_PROTOCOL",data:"SECRET_BODY"}})})));}
    close(){this.dispatchEvent(new Event("close"));}
  }
  const original=globalThis.WebSocket;globalThis.WebSocket=Socket;t.after(()=>{globalThis.WebSocket=original;});
  const cdp=await connectSmokeCDP("ws://127.0.0.1:12345",new AbortController().signal);
  try{await assert.rejects(cdp.send("Fetch.enable",{patterns:[]}),error=>{assert.equal(error.cause.message,"SECRET_PROTOCOL");const d=describeSmokeFailure("browser-interception",error,true);assert.deepEqual(d,{phase:"browser-interception",errors:[{kind:"cdp-request",method:"Fetch.enable",protocolCode:-32602}],cleanupComplete:true});assert.equal(JSON.stringify(d).includes("SECRET"),false);return true;});}finally{cdp.close();}
});

test("lifecycle preserves work and cleanup failures and restores handlers after every closer",async()=>{
  const before=["SIGTERM","SIGINT"].map(s=>process.listenerCount(s)),calls=[];
  await assert.rejects(runSmokeLifecycle(process.env,async({owner})=>{owner.own(async()=>calls.push("last"));owner.own(async()=>{calls.push("failed");throw Error("join refused");});throw Error("work refused");}),error=>error instanceof AggregateError&&error.errors[0].message==="work refused"&&error.errors[1] instanceof AggregateError);
  assert.deepEqual(calls,["failed","last"]);assert.deepEqual(["SIGTERM","SIGINT"].map(s=>process.listenerCount(s)),before);
});

test("smoke protocol matches checked-in real sign-in/session/view contracts",async()=>{
  const source=await readFile(new URL("../app/sign-in/page.tsx",import.meta.url),"utf8");assert.match(source,/<a href=\{target\}>Continue to sign in<\/a>/);
  const session=await readFile(new URL("../app/auth/SessionProvider.tsx",import.meta.url),"utf8");assert.ok(session.includes('client.GET("/api/v1/session/scopes"'));assert.equal(proxyRoute("GET","/api/v1/session/scopes"),"api");
  const view=await readFile(new URL("../app/features/agents/AgentSecurityView.tsx",import.meta.url),"utf8");assert.ok(view.includes('values.length === 0 ? <p>No records in this scope.</p>'));
});

test("child environment drops ambient credentials and loader/config injection", () => {
  const env=smokeEnvironment({PATH:"/usr/bin:/bin",HOME:"/home/test",TMPDIR:"/tmp",ZASP_POSTGRES_DSN:"secret",NODE_OPTIONS:"--require /evil",PGOPTIONS:"bad",AWS_SECRET_ACCESS_KEY:"secret",HTTPS_PROXY:"https://evil"});
  assert.deepEqual(env,{PATH:"/usr/bin:/bin",HOME:"/home/test",TMPDIR:"/tmp",LANG:"C.UTF-8",GOENV:"off",GOTOOLCHAIN:"local",GOPROXY:"off",GOSUMDB:"off",GOWORK:"off",GOFLAGS:"-mod=readonly",CGO_ENABLED:"0",GOMAXPROCS:"2",NPM_CONFIG_AUDIT:"false",NPM_CONFIG_FUND:"false",NPM_CONFIG_OFFLINE:"true",NPM_CONFIG_USERCONFIG:"/dev/null",NPM_CONFIG_UPDATE_NOTIFIER:"false"});
  assert.throws(()=>smokeEnvironment({PATH:"/bin"}));
});

test("smoke oracle demands actual fresh scoped bootstrap, exact empty page and UI", () => {
  assertSmokeObservation(observation(),scope);
  for(const change of [v=>v.bootstrap.status=401,v=>v.bootstrap.noStore=false,v=>v.bootstrap.body.environment_id="foreign",v=>v.bootstrap.body.fresh_auth_expires_at="2020-01-01T00:00:00Z",v=>v.bootstrap.body.principal.active=false,v=>v.bootstrap.body.principal.id="foreign",v=>v.agents.status=503,v=>v.agents.body.items.push({id:"fabricated"}),v=>v.agents.body.page_info.has_more=true,v=>v.text="Product API unavailable"]){const v=observation();change(v);assert.throws(()=>assertSmokeObservation(v,scope));}
  assert.equal(cookieIsHostSession("__Host-zasp_session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax"),true);
  for(const cookie of ["other=opaque; Path=/; Secure; HttpOnly","__Host-zasp_session=opaque; Path=/; HttpOnly","__Host-zasp_session=opaque; Path=/; Secure; HttpOnly; Domain=localhost"])assert.equal(cookieIsHostSession(cookie),false);
});

test("reload requires a new document loader, not the still-visible pre-reload DOM",async()=>{
  const calls=[];let reads=0;
  const cdp={async send(method,params){calls.push({method,params});if(method==="Page.getFrameTree")return {frameTree:{frame:{loaderId:++reads>=3?"new":"old"}}};return {};}};
  await reloadSmokePage(cdp,new AbortController().signal);
  assert.equal(reads,3);assert.deepEqual(calls.find(c=>c.method==="Page.reload"),{method:"Page.reload",params:{ignoreCache:true}});
});

test("actual Agents readiness expression tolerates only new-document body absence and loading",async()=>{
  const ready={innerText:"Agents\nNo records in this scope."};
  for(const [pathname,body,expected] of [["/discovery/assets",null,false],["/discovery/assets",undefined,false],["/discovery/assets",{innerText:"Loading"},false],["/sign-in",ready,false],["/discovery/assets",ready,true]]){
    assert.equal(runInNewContext(smokeSupport.smokeAgentsReadyExpression,{location:{pathname},document:{body}}),expected);
  }
  const states=[null,{innerText:"Loading"},ready],signal=new AbortController().signal;let reads=0;
  await smokeSupport.waitForSmokeAgents(expression=>runInNewContext(expression,{location:{pathname:"/discovery/assets"},document:{body:states[reads++]}}),signal);
  assert.equal(reads,3);
});

test("navigation readiness preserves new loader sequencing and propagates real evaluation errors without retry",async()=>{
  const signal=new AbortController().signal,calls=[];let loaderReads=0,bodyReads=0;
  const cdp={async send(method){calls.push(method);if(method==="Page.getFrameTree")return {frameTree:{frame:{loaderId:++loaderReads<3?"old":"new"}}};return {};}};
  await reloadSmokePage(cdp,signal);
  await smokeSupport.waitForSmokeAgents(expression=>{assert.equal(loaderReads,3);bodyReads++;return runInNewContext(expression,{location:{pathname:"/discovery/assets"},document:{body:bodyReads===1?null:{innerText:"Agents\nNo records in this scope."}}});},signal);
  assert.equal(bodyReads,2);assert.equal(calls.filter(m=>m==="Page.reload").length,1);
  const failure=Error("actual evaluation failure");let attempts=0;
  await assert.rejects(smokeSupport.waitForSmokeAgents(()=>{attempts++;throw failure;},signal),error=>error===failure);assert.equal(attempts,1);
  assert.throws(()=>runInNewContext(smokeSupport.smokeAgentsReadyExpression,{location:{pathname:"/discovery/assets"},document:{body:{}}}),error=>error.name==="TypeError");
  const controller=new AbortController();let incomplete=0;
  await assert.rejects(smokeSupport.waitForSmokeAgents(()=>{incomplete++;controller.abort();return false;},controller.signal),/cancel/);assert.equal(incomplete,1);
});

test("cleanup is once-only, reverse-order and joins later resources after refusal", async () => {
  const owner=createSmokeOwner(),calls=[];
  owner.own(async()=>calls.push("first"));owner.own(async()=>{calls.push("second");throw Error("close failure");});owner.own(async()=>calls.push("third"));
  await assert.rejects(owner.close(),/cleanup/);await assert.rejects(owner.close(),/cleanup/);
  assert.deepEqual(calls,["third","second","first"]);
  assert.throws(()=>owner.own(async()=>{}),/closed/);
});

test("owned command preserves nonzero failure without disclosing child output", async () => {
  await assert.rejects(runSmokeCommand(process.execPath,["-e","process.stderr.write('DO_NOT_DISCLOSE');process.exit(7)"],{env:smokeEnvironment(process.env),timeoutMs:2000}),e=>e.message==="smoke command failed (7)"&&!JSON.stringify(e).includes("DO_NOT_DISCLOSE"));
  const result=await runSmokeCommand(process.execPath,["-e","process.stdout.write('ready')"],{env:smokeEnvironment(process.env),timeoutMs:2000});
  assert.equal(result.stdout,"ready");assert.equal(result.status,0);
});

test("cancellation joins an actual owned child without converting interruption to success", {timeout:5000}, async()=>{
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),100);
  try{await assert.rejects(runSmokeCommand(process.execPath,["-e","setInterval(()=>{},1000)"],{env:smokeEnvironment(process.env),signal:controller.signal,timeoutMs:2000}),/cancel/);}finally{clearTimeout(timer);}
});
