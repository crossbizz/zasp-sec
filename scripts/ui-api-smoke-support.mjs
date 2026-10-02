import assert from "node:assert/strict";
import { spawnOwnedCommand } from "./owned-command.mjs";
import { reloadBrowserPage } from "./browser-e2e-helpers.mjs";
import { smokePrincipal } from "./ui-api-smoke-fixtures.mjs";

const diagnosticPhases=new Set(["preflight","build","postgres","migration48","api-ready","web-ready","browser","browser-target","browser-connect","browser-enable","browser-interception","browser-navigate","browser-anchor","browser-unauthenticated","browser-click","browser-authenticated","observation","scope-refusal","reload","final-evidence"]);
const diagnosticMethods=new Set(["Page.enable","Runtime.enable","Fetch.enable","Fetch.continueRequest","Fetch.failRequest","Page.navigate","Runtime.evaluate","Page.getFrameTree","Page.reload"]);
const diagnosticMessages=new Map([["smoke cancelled","cancelled"],["smoke observation timed out","observation-timeout"],["smoke debugger timed out","cdp-connect-timeout"],["smoke debugger failed","cdp-connect-failed"],["smoke debugger refused","cdp-endpoint-refused"],["smoke debugger closed","cdp-closed"],["smoke debugger request timed out","cdp-request-timeout"],["smoke debugger request failed","cdp-request"],["smoke browser request refused","browser-origin-refused"]]);
const diagnosticSystems=new Set(["ENOENT","EACCES","ECONNREFUSED","ECONNRESET","ETIMEDOUT"]);
const diagnosticExceptions=new Set(["Error","TypeError","ReferenceError","SyntaxError","RangeError","EvalError","URIError"]);
const browserFailureSources=new Set(["blocked-request","runtime-exception","fetch-cdp-rejection"]);
const fixtureFailureSources=new Set(["identity-fixture-refused","history-fixture-refused","upstream-error","proxy-refused"]);
const proxyStages=new Set(["host","url","route","headers","request"]);
const proxyMethods=new Set(["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS","CONNECT","TRACE"]);
// Diagnostic labels only: exact parameter-free paths in this candidate's OpenAPI.
// They do not participate in the proxy's separate, unchanged routing allowlist.
const proxyRouteLabels=new Map(["session/start","session/bootstrap","session/callback","session/sign-out","session/scopes","session/scope","organization","workspaces","environments","me","admin/members","admin/group-mappings","admin/roles","admin/sso-connections","admin/scim-connections","admin/api-tokens","admin/api-token-reveal-grants","audit-events","integration-catalog","workflow-mutation-receipts","sensors","integrations","integrations/oauth/callback","agents","tools","identities","runtimes","findings","attack-paths","search","policies","security-agent-templates","security-actions","security-agents","security-agent-execution-controls","security-agent-runs","security-agent-approvals","home/summary","sessions","compliance/controls","compliance/evidence","settings/data-controls","settings/external-data-flows","system/status","system/components","system/version","recovery/backups","recovery/restores","tests","test-runs","attack-lab/preflight","attack-lab/runs"].map(path=>["/api/v1/"+path,"api-"+path.replaceAll("/","-")]));
// Shared-worktree OpenAPI additions; still diagnostic-only, never routing permissions.
proxyRouteLabels.set("/api/v1/audit-exports","api-audit-exports");
proxyRouteLabels.set("/api/v1/compliance/exports","api-compliance-exports");
for(const [path,label] of [["/","web-root"],["/sign-in","web-sign-in"],["/auth/callback","web-auth-callback"],["/discovery/assets","web-discovery-assets"]])proxyRouteLabels.set(path,label);
const proxyRouteClasses=new Set([...proxyRouteLabels.values(),"other-api","other-web","unparsed"]);
function proxyRefusalDiagnostic(value){
  if(!value||typeof value!=="object")return undefined;
  return {stage:proxyStages.has(value.stage)?value.stage:"unknown",method:proxyMethods.has(value.method)?value.method:"other",route:proxyRouteClasses.has(value.route)?value.route:"unknown"};
}
export function markSmokeFailure(evidence,source,request){
  if(browserFailureSources.has(source))evidence.firstBrowserFailureSource??=source;
  else if(fixtureFailureSources.has(source))evidence.firstFixtureFailureSource??=source;
  else throw Error("smoke failure source refused");
  if(source==="proxy-refused"&&request){
    const pathname=request.pathname;
    const route=typeof pathname!=="string"?"unparsed":proxyRouteLabels.get(pathname)??(pathname.startsWith("/api/")?"other-api":"other-web");
    evidence.firstProxyRefusal??=proxyRefusalDiagnostic({...request,route});
  }
}
function finalEvidenceDiagnostic(value){
  if(!value||typeof value!=="object")return undefined;
  const result={};
  for(const key of ["observedCookie","browserFailure","fixtureFailure","observationPassed","sessionCountReadFailed","inventoryCountReadFailed"])if(typeof value[key]==="boolean")result[key]=value[key];
  for(const key of ["identityStarts","callbackCount","historyReads"])if(Number.isInteger(value[key])&&value[key]>=0&&value[key]<=1_000_000)result[key]=value[key];
  for(const key of ["activeSessionCount","inventoryCount"])if(typeof value[key]==="string"&&/^(0|[1-9][0-9]{0,6})$/.test(value[key])&&Number(value[key])<=1_000_000)result[key]=Number(value[key]);
  if(browserFailureSources.has(value.firstBrowserFailureSource))result.firstBrowserFailureSource=value.firstBrowserFailureSource;
  if(fixtureFailureSources.has(value.firstFixtureFailureSource))result.firstFixtureFailureSource=value.firstFixtureFailureSource;
  const proxy=proxyRefusalDiagnostic(value.firstProxyRefusal);if(proxy)result.firstProxyRefusal=proxy;
  return Object.keys(result).length?result:undefined;
}
export function describeSmokeFailure(phase,error,cleanupComplete){
  const errors=[],seen=new Set();
  const visit=value=>{
    if(!value||typeof value!=="object"||seen.has(value)||errors.length>=8)return;
    seen.add(value);let row;
    if(value instanceof AggregateError)row={kind:"aggregate"};
    else if(value.code==="ERR_ASSERTION")row={kind:"assertion"};
    else if(diagnosticSystems.has(value.code))row={kind:"system",code:value.code};
    else row={kind:diagnosticMessages.get(value.message)??"unknown"};
    if(diagnosticMethods.has(value.smokeMethod))row.method=value.smokeMethod;
    if(row.kind==="cdp-request"&&Number.isInteger(value.cause?.code)&&value.cause.code>=-32768&&value.cause.code<=32767)row.protocolCode=value.cause.code;
    if(diagnosticExceptions.has(value.smokeException))row.exceptionClass=value.smokeException;
    const finalEvidence=finalEvidenceDiagnostic(value.smokeFinalEvidence);if(finalEvidence)row.finalEvidence=finalEvidence;
    const countQueryErrors={};
    for(const key of ["session","inventory"]){
      const queryError=value.smokeFinalQueryErrors?.[key];if(!queryError||typeof queryError!=="object")continue;
      const match=typeof queryError.message==="string"?queryError.message.match(/^smoke command failed \(([0-9]{1,3})\)$/):null;
      countQueryErrors[key]=diagnosticSystems.has(queryError.code)?{kind:"system",code:queryError.code}:match&&Number(match[1])<=255?{kind:"command-failed",status:Number(match[1])}:{kind:diagnosticMessages.get(queryError.message)??"query-refused"};
    }
    if(Object.keys(countQueryErrors).length)row.countQueryErrors=countQueryErrors;
    if(row.kind==="assertion"){
      const responses={};
      for(const name of ["unauthenticatedBootstrap","bootstrap","agents","receipts","foreignScope"]){
        const source=value.smokeResponses?.[name];if(!source||typeof source!=="object")continue;
        const observed={};
        if(Number.isInteger(source.status)&&(source.status===0||source.status>=100&&source.status<=599))observed.status=source.status;
        if(typeof source.noStore==="boolean")observed.noStore=source.noStore;
        if(Object.keys(observed).length)responses[name]=observed;
      }
      if(Object.keys(responses).length)row.responses=responses;
    }
    errors.push(row);
    if(value instanceof AggregateError)for(const child of value.errors.slice(0,8))visit(child);
    else if(row.kind!=="cdp-request")visit(value.cause);
  };
  visit(error);if(!errors.length)errors.push({kind:"unknown"});
  return {phase:diagnosticPhases.has(phase)?phase:"unknown",errors,cleanupComplete:cleanupComplete===true};
}
function cdpFailure(method,message,cause){const error=Error(message,{cause});error.smokeMethod=method;return error;}

export function validateSmokeMode(env) {
  if(env.ZASP_LOCAL_UI_API_SMOKE!=="fixture48" || Object.keys(env).some(k=>k.startsWith("ZASP_COMBINED_E2E_")))throw Error("local fixture smoke mode required");
  return "fixture48";
}

export function smokeEnvironment(env) {
  for(const name of ["PATH","HOME"])if(typeof env[name]!=="string"||!env[name]||env[name].includes("\0"))throw Error("smoke environment refused");
  return {PATH:env.PATH,HOME:env.HOME,TMPDIR:env.TMPDIR||"/tmp",LANG:"C.UTF-8",GOENV:"off",GOTOOLCHAIN:"local",GOPROXY:"off",GOSUMDB:"off",GOWORK:"off",GOFLAGS:"-mod=readonly",CGO_ENABLED:"0",GOMAXPROCS:"2",NPM_CONFIG_AUDIT:"false",NPM_CONFIG_FUND:"false",NPM_CONFIG_OFFLINE:"true",NPM_CONFIG_USERCONFIG:"/dev/null",NPM_CONFIG_UPDATE_NOTIFIER:"false"};
}

export function assertSmokeObservation(value,scope) {
  const b=value?.bootstrap,a=value?.agents,r=value?.receipts;
  try{
  assert.equal(b?.status,200);assert.equal(b.noStore,true);
  for(const key of Object.keys(scope))assert.equal(b.body?.[key],scope[key]);
  assert.equal(b.body?.principal?.active,true);
  assert.equal(b.body?.principal?.id,smokePrincipal);
  assert.ok(Date.parse(b.body?.fresh_auth_expires_at)>Date.now());
  assert.equal(a?.status,200);assert.equal(a.noStore,true);
  assert.deepEqual(a.body,{items:[],page_info:{has_more:false,next_cursor:null}});
  assert.match(value.text,/Agents/);assert.match(value.text,/No records in this scope\./);
  assert.doesNotMatch(value.text,/Product API unavailable|Sign-in failed|Agent inventory unavailable/);
  assert.equal(r?.status,200);assert.equal(r.noStore,true);assert.deepEqual(r.body,{items:[]});
  }catch(error){error.smokeResponses={bootstrap:{status:b?.status,noStore:b?.noStore},agents:{status:a?.status,noStore:a?.noStore},receipts:{status:r?.status,noStore:r?.noStore}};throw error;}
}

export function assertSmokeFinalEvidence(observation,scope,evidence,{firstBrowserError,sessionError,inventoryError}={}){
  evidence.observationPassed=false;
  try{
  assertSmokeObservation(observation,scope);
  evidence.observationPassed=true;
  assert.equal(evidence.observedCookie,true);assert.equal(evidence.identityStarts,1);assert.equal(evidence.callbackCount,1);
  try{assert.equal(evidence.browserFailure,false);}catch(error){error.cause=firstBrowserError;throw error;}
  assert.equal(evidence.fixtureFailure,false);
  if(sessionError)throw sessionError;
  assert.equal(evidence.activeSessionCount,"1");
  if(inventoryError)throw inventoryError;
  assert.equal(evidence.inventoryCount,"0");
  }catch(error){error.smokeFinalEvidence=evidence;error.smokeFinalQueryErrors={session:sessionError,inventory:inventoryError};throw error;}
}

export function cookieIsHostSession(header) {
  if(typeof header!=="string")return false;
  const [cookie,...attributes]=header.split(";").map(x=>x.trim());
  const names=attributes.map(x=>x.toLowerCase());
  return /^__Host-zasp_session=[^;\s]+$/.test(cookie)&&names.includes("secure")&&names.includes("httponly")&&names.includes("path=/")&&!names.some(x=>x.startsWith("domain="));
}

export function createSmokeOwner() {
  const closers=[];let closing;
  return {
    own(close){if(closing)throw Error("smoke owner closed");if(typeof close!=="function")throw Error("invalid closer");closers.push(close);},
    close(){return closing??=(async()=>{const errors=[];for(const close of closers.reverse()){try{await close();}catch(error){errors.push(error);}}if(errors.length)throw new AggregateError(errors,"smoke cleanup failed");})();},
  };
}

// Own the entry's existing lifecycle separately from its native/browser work.
export async function runSmokeLifecycle(environment,operation,afterJoined=async()=>{}){
  // Validate before owning a timer or signal handler: refusal must be inert.
  const base=smokeEnvironment(environment);
  const controller=new AbortController(),signal=controller.signal,owner=createSmokeOwner();let closing=false;
  const cancel=()=>controller.abort(),overall=setTimeout(cancel,600000);
  process.on("SIGTERM",cancel);process.on("SIGINT",cancel);
  let result,failure;
  try{result=await operation({base,signal,owner,cancel,isClosing:()=>closing});}catch(error){failure=error;}
  closing=true;
  try{await owner.close();await afterJoined();}
  catch(error){failure=failure?new AggregateError([failure,error],"smoke work and cleanup failed"):error;}
  finally{
    // Repeated signals still cancel rather than killing the owner mid-join.
    clearTimeout(overall);process.removeListener("SIGTERM",cancel);process.removeListener("SIGINT",cancel);
  }
  if(signal.aborted)throw Error("smoke cancelled",{cause:failure});
  if(failure)throw failure;
  return result;
}

export async function runSmokeCommand(executable,args,{env,cwd,input,signal,timeoutMs=10_000,reject=true}={}) {
  if(signal?.aborted)throw Error("smoke cancelled");
  const owned=spawnOwnedCommand(executable,args,{env,cwd,input,maxOutputBytes:1_048_576});
  let expired=false;const abort=()=>{void owned.stop().catch(()=>{});};
  const timer=setTimeout(()=>{expired=true;abort();},timeoutMs);
  signal?.addEventListener("abort",abort,{once:true});
  try{const result=await owned.completed;if(signal?.aborted)throw Error("smoke cancelled");if(expired)throw Error("smoke command timed out");if(result.outputLimitExceeded)throw Error("smoke command output limit");if(reject&&result.status!==0)throw Error(`smoke command failed (${result.status})`);return result;}
  finally{clearTimeout(timer);signal?.removeEventListener("abort",abort);await owned.stop();}
}

export function startSmokeChild(owner,executable,args,{env,cwd,onResult}={}) {
  const owned=spawnOwnedCommand(executable,args,{env,cwd,maxOutputBytes:1_048_576});
  owner.own(async()=>{await owned.stop();const result=await owned.completed;if(result.outputLimitExceeded)throw Error("smoke child output limit");onResult?.(result);});
  return owned;
}

export async function smokeWait(operation,signal,timeoutMs=30_000) {
  const end=Date.now()+timeoutMs;
  while(Date.now()<end){if(signal?.aborted)throw Error("smoke cancelled");const value=await operation();if(value)return value;await new Promise(resolve=>setTimeout(resolve,50));}
  throw Error("smoke observation timed out");
}

export const smokeAgentsReadyExpression="location.pathname==='/discovery/assets'&&document.body!==null&&document.body!==undefined&&document.body.innerText.includes('No records in this scope.')";
export async function waitForSmokeAgents(evaluate,signal){
  await smokeWait(()=>evaluate(smokeAgentsReadyExpression),signal);
}

export async function reloadSmokePage(cdp,signal){
  const prior=(await cdp.send("Page.getFrameTree")).frameTree.frame.loaderId;assert.ok(typeof prior==="string"&&prior.length>0);
  await reloadBrowserPage(cdp);
  await smokeWait(async()=>{const current=(await cdp.send("Page.getFrameTree")).frameTree.frame.loaderId;return typeof current==="string"&&current.length>0&&current!==prior;},signal);
}

export async function connectSmokeCDP(target,signal) {
  const endpoint=new URL(target);if(endpoint.protocol!=="ws:"||endpoint.hostname!=="127.0.0.1")throw Error("smoke debugger refused");
  const socket=new WebSocket(target),pending=new Map();const listeners=new Set();let id=0,closed=false;
  const close=()=>{if(closed)return;closed=true;for(const p of pending.values()){clearTimeout(p.timer);p.reject(cdpFailure(p.method,"smoke debugger closed"));}pending.clear();socket.close();};
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{close();reject(Error("smoke debugger timed out"));},5000);socket.addEventListener("open",()=>{clearTimeout(timer);resolve();},{once:true});socket.addEventListener("error",()=>{clearTimeout(timer);close();reject(Error("smoke debugger failed"));},{once:true});});
  const abort=()=>close();signal?.addEventListener("abort",abort,{once:true});
  socket.addEventListener("close",()=>{signal?.removeEventListener("abort",abort);close();});
  socket.addEventListener("message",event=>{let value;try{value=JSON.parse(event.data);}catch{close();return;}if(!value.id){for(const listener of listeners)listener(value);return;}const p=pending.get(value.id);if(!p)return;clearTimeout(p.timer);pending.delete(value.id);if(value.error)p.reject(cdpFailure(p.method,"smoke debugger request failed",value.error));else p.resolve(value.result);});
  return {on(listener){listeners.add(listener);},close,send(method,params={}){if(closed||signal?.aborted)return Promise.reject(cdpFailure(method,"smoke debugger closed"));const number=++id;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(number);reject(cdpFailure(method,"smoke debugger request timed out"));},10_000);pending.set(number,{resolve,reject,timer,method});socket.send(JSON.stringify({id:number,method,params}));});}};
}
