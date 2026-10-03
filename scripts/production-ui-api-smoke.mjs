// Explicit local migration48 plumbing smoke. No production identity/provider proof.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnOwnedCommand } from "./owned-command.mjs";
import { validateSmokeMode, assertSmokeObservation, assertSmokeFinalEvidence, markSmokeFailure, cookieIsHostSession, runSmokeLifecycle, runSmokeCommand, smokeWait, waitForSmokeAgents, connectSmokeCDP, reloadSmokePage, describeSmokeFailure } from "./ui-api-smoke-support.mjs";
import { smokeScope, smokePrincipal, principalSQL, migrationEnvironment, fixtureSeedSQL, smokeAPIEnvironment, identityReply, historyReply, proxyRoute, smokeProxyHeaders } from "./ui-api-smoke-fixtures.mjs";

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const hostname="zasp.local-smoke.test";
const chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

async function reservePort(){
  const s=net.createServer();await new Promise((resolve,reject)=>{s.once("error",reject);s.listen(0,"127.0.0.1",resolve);});
  const port=s.address().port;await new Promise((resolve,reject)=>s.close(e=>e?reject(e):resolve()));return port;
}
async function listenOwned(owner,server,port){
  server.requestTimeout=5000;server.headersTimeout=5000;server.timeout=5000;
  // Register before listen so startup refusal cannot leak an owned server.
  owner.own(()=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error("smoke server close timed out")),3000);server.close(e=>{clearTimeout(timer);if(e&&e.code!=="ERR_SERVER_NOT_RUNNING")reject(Error("smoke server close failed"));else resolve();});server.closeAllConnections();}));
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
}
async function body(request){
  const chunks=[];let length=0;for await(const chunk of request){length+=chunk.length;if(length>65536)throw Error("smoke body refused");chunks.push(chunk);}return Buffer.concat(chunks).toString("utf8");
}
async function localResponse(url,signal){
  const value=new URL(url);assert.equal(value.hostname,"127.0.0.1");assert.equal(value.protocol,"http:");
  const reply=await fetch(value,{redirect:"error",signal:AbortSignal.any([signal,AbortSignal.timeout(2000)])});
  const chunks=[];let size=0;
  for await(const chunk of reply.body){size+=chunk.length;if(size>1048576)throw Error("smoke response refused");chunks.push(Buffer.from(chunk));}
  return {status:reply.status,text:Buffer.concat(chunks).toString("utf8")};
}

function assertMacSmokeGoIdentity(goVersion, version) {
  assert.ok(goVersion === "go1.26.8\n" || goVersion === "go1.26.8\r\n", "smoke Go identity refused");
  assert.ok(version === "go version go1.26.8 darwin/arm64\n" || version === "go version go1.26.8 darwin/arm64\r\n", "smoke Go architecture refused");
}

export async function runLocalSmoke(environment=process.env){
  validateSmokeMode(environment);assert.equal(process.version,"v22.23.1");
  let temporary,stage="preflight",cleanupComplete=false;
  try{await runSmokeLifecycle(environment,async({base,signal,owner,cancel,isClosing})=>{
  const go=path.join(base.HOME,"go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.darwin-arm64/bin/go");
  base.PATH=path.dirname(process.execPath)+":"+path.dirname(go)+":"+base.PATH;
  const command=(exe,args,options={})=>runSmokeCommand(exe,args,{env:base,cwd:root,signal,...options});
  const child=(exe,args,options={})=>{
    const owned=spawnOwnedCommand(exe,args,{cwd:root,env:base,...options,maxOutputBytes:1048576});
    owned.completed.then(()=>{if(!isClosing())cancel();},()=>{if(!isClosing())cancel();});
    owner.own(async()=>{await owned.stop();const result=await owned.completed;if(result.outputLimitExceeded)throw Error("smoke child output limit");});return owned;
  };
    // Accepted exact-lock build must be staged locally by the run owner; no install/build UI fallback.
    await Promise.all([access(chrome),access(go),access(path.join(root,"node_modules/.bin/vinext")),access(path.join(root,"dist/server/index.js"))]);
    assertMacSmokeGoIdentity((await command(go,["env","GOVERSION"])).stdout, (await command(go,["version"])).stdout);
    const pg=(await command("pg_config",["--bindir"])).stdout.trim();assert.ok(path.isAbsolute(pg)&&!/[\r\n\0]/.test(pg));
    temporary=await mkdtemp(path.join(os.tmpdir(),"zasp-local-ui-api-"));await chmod(temporary,0o700);base.TMPDIR=temporary;
    const migrate=path.join(temporary,"migrate"),apiBinary=path.join(temporary,"api");
    stage="build";for(const [target,pkg] of [[migrate,"./agentsec-migrate"],[apiBinary,"./agentsec-api"]])await command(go,["build","-p=1","-o",target,pkg],{cwd:path.join(root,"services/platform"),timeoutMs:180000});
    const ports=[];while(ports.length<8){const p=await reservePort();if(!ports.includes(p))ports.push(p);}
    const [postgresPort,identityPort,historyPort,apiPort,healthPort,webPort,proxyPort,chromePort]=ports;
    const publicOrigin=`https://${hostname}:${proxyPort}`,identityOrigin=`http://127.0.0.1:${identityPort}`;
    const dsn=`postgres://zasp_e2e@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,data=path.join(temporary,"data");
    const sql=async input=>(await command(path.join(pg,"psql"),[dsn,"-X","-At","-v","ON_ERROR_STOP=1"],{input,timeoutMs:20000})).stdout.trim();
    stage="postgres";await command(path.join(pg,"initdb"),["--no-locale","--encoding=UTF8","--auth-local=trust","--auth-host=trust","--username=zasp_e2e","-D",data],{timeoutMs:30000});
    const postgres=child(path.join(pg,"postgres"),["-D",data,"-h","127.0.0.1","-p",String(postgresPort),"-k",""]);
    owner.own(async()=>{
      const stop=await runSmokeCommand(path.join(pg,"pg_ctl"),["-D",data,"-m","fast","-w","stop"],{env:base,cwd:root,timeoutMs:10000,reject:false});
      await postgres.stop();const joined=await postgres.completed;assert.equal(stop.status,0,"PostgreSQL stop refused");assert.equal(joined.status,0,"PostgreSQL exit refused");
    });
    await smokeWait(async()=>{const result=await command(path.join(pg,"pg_isready"),["-h","127.0.0.1","-p",String(postgresPort),"-U","zasp_e2e","-d","postgres"],{reject:false});return result.status===0;},signal);
    await sql(principalSQL());stage="migration48";
    await command(migrate,["up-to-48"],{env:{...base,...migrationEnvironment(dsn)},timeoutMs:30000});
    assert.equal(await sql("SELECT version||'|'||name FROM zasp_schema_versions ORDER BY version DESC LIMIT 1;"),"48|production_runtime_acceptance");
    await sql(fixtureSeedSQL());assert.equal(await sql("SELECT count(*) FROM zasp_product_sessions;"),"0");
    assert.equal(await sql("SELECT count(*) FROM zasp_inventory_entities;"),"0");
    console.log("local smoke: owned migration48 and empty inventory verified");
    let fixtureFailure=false,identityStarts=0,historyReads=0,observedCookie=false,callbackCount=0;
    const failureEvidence={};
    const fixture=(reply,count,source)=>http.createServer(async(request,response)=>{try{const input={method:request.method,url:new URL(request.url,"http://127.0.0.1"),headers:request.headers,body:await body(request)};const result=reply(input);count(input);response.writeHead(result.status,{"content-type":"application/json","cache-control":"no-store",...result.headers});response.end(result.body?JSON.stringify(result.body):"");}catch{fixtureFailure=true;markSmokeFailure(failureEvidence,source);response.writeHead(500);response.end();}});
    const identity=fixture(input=>identityReply(input,publicOrigin),input=>{if(input.url.pathname.endsWith("/start"))identityStarts++;},"identity-fixture-refused");
    await listenOwned(owner,identity,identityPort);
    const source=await readFile(path.join(root,"services/platform/runtimeindex/opensearchdriver/schema.go"),"utf8"),match=source.match(/indexSchemaJSON = `([^`]+)`/);assert.ok(match);
    const history=fixture(input=>historyReply(input,JSON.parse(match[1]),createHash("sha256").update(match[1]).digest("hex")),()=>historyReads++,"history-fixture-refused");
    await listenOwned(owner,history,historyPort);
    stage="api-ready";child(apiBinary,[],{env:{...base,...smokeAPIEnvironment({postgresPort,identityPort,historyPort,apiPort,healthPort,publicOrigin})}});
    await smokeWait(async()=>{try{return (await localResponse(`http://127.0.0.1:${healthPort}/readyz`,signal)).status===200;}catch{return false;}},signal);
    assert.equal(fixtureFailure,false);assert.ok(historyReads>0);
    stage="web-ready";child(process.execPath,[path.join(root,"node_modules/.bin/vinext"),"start","--port",String(webPort),"--hostname","127.0.0.1"],{env:{...base,NODE_ENV:"production"}});
    await smokeWait(async()=>{try{return (await localResponse(`http://127.0.0.1:${webPort}/sign-in`,signal)).status===200;}catch{return false;}},signal);
    const key=path.join(temporary,"tls.key"),cert=path.join(temporary,"tls.crt");
    await command("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj",`/CN=${hostname}`,"-addext",`subjectAltName=DNS:${hostname}`,"-keyout",key,"-out",cert]);await chmod(key,0o600);
    const upstreams=new Set();
    const proxy=https.createServer({key:await readFile(key),cert:await readFile(cert)},(request,response)=>{
      let proxyStage="host",proxyPath;
      try{
        assert.equal(request.headers.host,`${hostname}:${proxyPort}`);
        proxyStage="url";const target=new URL(request.url,publicOrigin);proxyPath=target.pathname;
        proxyStage="route";const route=proxyRoute(request.method,target.pathname);
        if(target.pathname==="/api/v1/session/callback")callbackCount++;
        proxyStage="headers";const headers=smokeProxyHeaders(request.headers,publicOrigin);
        proxyStage="request";const upstream=http.request({hostname:"127.0.0.1",port:route==="api"?apiPort:webPort,path:target.pathname+target.search,method:request.method,headers,timeout:11000},reply=>{
          for(const cookie of reply.headers["set-cookie"]??[])if(cookieIsHostSession(cookie))observedCookie=true;
          response.writeHead(reply.statusCode??502,{...reply.headers,"referrer-policy":"no-referrer"});reply.pipe(response);
        });
        upstreams.add(upstream);upstream.on("close",()=>upstreams.delete(upstream));response.on("close",()=>upstream.destroy());
        upstream.on("timeout",()=>upstream.destroy());upstream.on("error",()=>{fixtureFailure=true;markSmokeFailure(failureEvidence,"upstream-error");if(!response.headersSent)response.writeHead(502);response.end();});request.on("aborted",()=>upstream.destroy());request.pipe(upstream);
      }catch{fixtureFailure=true;markSmokeFailure(failureEvidence,"proxy-refused",{stage:proxyStage,method:request.method,pathname:proxyPath});response.writeHead(403);response.end();}
    });await listenOwned(owner,proxy,proxyPort);owner.own(async()=>{for(const upstream of upstreams)upstream.destroy();});
    stage="browser";
    child(chrome,["--headless=new","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync","--disable-default-apps","--disable-extensions","--no-proxy-server","--ignore-certificate-errors",`--host-resolver-rules=MAP ${hostname} 127.0.0.1`,`--remote-debugging-port=${chromePort}`,`--user-data-dir=${path.join(temporary,"browser")}`,"about:blank"]);
    stage="browser-target";
    const tab=await smokeWait(async()=>{try{const list=JSON.parse((await localResponse(`http://127.0.0.1:${chromePort}/json/list`,signal)).text);return list.find(t=>t.type==="page"&&t.webSocketDebuggerUrl);}catch{return false;}},signal);
    stage="browser-connect";
    const cdp=await connectSmokeCDP(tab.webSocketDebuggerUrl,signal);owner.own(()=>cdp.close());
    let browserFailure=false,firstBrowserError;
    cdp.on(event=>{
      if(event.method==="Runtime.exceptionThrown"){browserFailure=true;markSmokeFailure(failureEvidence,"runtime-exception");}
      if(event.method==="Fetch.requestPaused"){
        const url=new URL(event.params.request.url),allowed=[publicOrigin,identityOrigin].includes(url.origin);
        if(!allowed){browserFailure=true;markSmokeFailure(failureEvidence,"blocked-request");}
        void cdp.send(allowed?"Fetch.continueRequest":"Fetch.failRequest",allowed?{requestId:event.params.requestId}:{requestId:event.params.requestId,errorReason:"BlockedByClient"}).catch(error=>{browserFailure=true;markSmokeFailure(failureEvidence,"fetch-cdp-rejection");firstBrowserError??=error;});
      }
    });
    stage="browser-enable";for(const method of ["Page.enable","Runtime.enable"])await cdp.send(method);
    stage="browser-interception";
    await cdp.send("Fetch.enable",{patterns:[{urlPattern:"http*",requestStage:"Request"}]});
    const evaluate=async expression=>{const result=await cdp.send("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});try{assert.equal(result.exceptionDetails,undefined,"browser evaluation failed");}catch(error){error.smokeMethod="Runtime.evaluate";error.smokeException=result.exceptionDetails?.exception?.className;throw error;}return result.result.value;};
    stage="browser-navigate";
    await cdp.send("Page.navigate",{url:publicOrigin+"/sign-in?return_to=%2Fdiscovery%2Fassets"});
    stage="browser-anchor";await smokeWait(()=>evaluate(`Boolean([...document.querySelectorAll('a')].find(b=>b.textContent.trim()==='Continue to sign in'))`),signal);
    stage="browser-unauthenticated";
    const unauthenticated=await evaluate(`(async()=>{const r=await fetch('/api/v1/session/bootstrap',{cache:'no-store'});return {status:r.status,noStore:r.headers.get('cache-control')?.includes('no-store')===true};})()`);
    try{assert.deepEqual(unauthenticated,{status:401,noStore:true});}catch(error){error.smokeResponses={unauthenticatedBootstrap:unauthenticated};throw error;}
    stage="browser-click";await evaluate(`[...document.querySelectorAll('a')].find(b=>b.textContent.trim()==='Continue to sign in').click()`);
    stage="browser-authenticated";await waitForSmokeAgents(evaluate,signal);
    const scope=Object.values(smokeScope).join("/");
    const observe=()=>evaluate(`(async()=>{const read=async(p,h)=>{const r=await fetch(p,{credentials:'same-origin',headers:h,cache:'no-store'});return {status:r.status,noStore:r.headers.get('cache-control')?.includes('no-store')===true,body:await r.json()};};return {bootstrap:await read('/api/v1/session/bootstrap'),agents:await read('/api/v1/agents',{'x-zasp-expected-scope':${JSON.stringify(scope)}}),receipts:await read('/api/v1/workflow-mutation-receipts?limit=50',{'x-zasp-expected-scope':${JSON.stringify(scope)}}),text:document.body.innerText};})()`);
    stage="observation";assertSmokeObservation(await observe(),smokeScope);
    stage="scope-refusal";
    const denied=await evaluate(`(async()=>{const r=await fetch('/api/v1/agents',{headers:{'x-zasp-expected-scope':${JSON.stringify(scope.replace(smokeScope.environment_id,"pid_90000003-0000-4000-8000-000000000003"))}}});const b=await r.json();return {status:r.status,noStore:r.headers.get('cache-control')?.includes('no-store'),code:b.code};})()`);
    try{assert.deepEqual(denied,{status:409,noStore:true,code:"scope_stale"});}catch(error){error.smokeResponses={foreignScope:{status:denied.status,noStore:denied.noStore}};throw error;}
    stage="reload";await reloadSmokePage(cdp,signal);await waitForSmokeAgents(evaluate,signal);
    stage="final-evidence";
    const finalObservation=await observe();let activeSessionCount,inventoryCount,sessionError,inventoryError;
    // Read each existing final count once before checking, so an earlier assertion cannot hide it.
    try{activeSessionCount=await sql(`SELECT count(*) FROM zasp_product_sessions WHERE principal_id='${smokePrincipal}' AND revoked_at IS NULL AND expires_at>now();`);}catch(error){sessionError=error;}
    try{inventoryCount=await sql("SELECT count(*) FROM zasp_inventory_entities;");}catch(error){inventoryError=error;}
    assertSmokeFinalEvidence(finalObservation,smokeScope,{...failureEvidence,observedCookie,identityStarts,callbackCount,historyReads,browserFailure,fixtureFailure,activeSessionCount,inventoryCount,sessionCountReadFailed:!!sessionError,inventoryCountReadFailed:!!inventoryError},{firstBrowserError,sessionError,inventoryError});
    console.log("local smoke: fixture identity, real session/API, empty Agents and reload verified; discovery/provider journey not exercised");
  },async()=>{if(temporary)await rm(temporary,{recursive:true,force:true});cleanupComplete=true;});}
  catch(error){const failure=Error(`local fixture smoke refused at ${stage}`,{cause:error});failure.smokeDiagnostic=describeSmokeFailure(stage,error,cleanupComplete);throw failure;}
  console.log("local smoke: all owned children and PostgreSQL joined");
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{await runLocalSmoke();}catch(error){console.error(error.message.startsWith("local fixture smoke refused")?error.message:"local fixture smoke refused");if(error.smokeDiagnostic)console.error(JSON.stringify(error.smokeDiagnostic));process.exitCode=1;}
}
