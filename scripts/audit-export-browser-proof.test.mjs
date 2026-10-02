import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import {spawnOwnedCommand} from "./owned-command.mjs";
import {parseAuditExportProviderReady,validateAuditExportBrowserMode,validateAuditExportPrepareMode,truncateAuditExportCreateResponse} from "./audit-export-browser-proof.mjs";

const root="/private/tmp/zasp-browser-owned";
const ready={schema:"audit-browser-provider-v1",pid:1234,address:"127.0.0.1:14443",control:root+"/control.sock",ca:root+"/ca.pem",token:root+"/token"};
test("lost-create fault sends real status then truncated bytes only after upstream completion",{timeout:5000},async()=>{
 let committed=false,calls=0;
 const upstream=http.createServer((_request,response)=>{calls++;committed=true;response.writeHead(201,{"Content-Type":"application/json"});response.end('{"committed":true}');});
 await new Promise(resolve=>upstream.listen(0,"127.0.0.1",resolve));
 const proxy=http.createServer((_request,response)=>{http.get(`http://127.0.0.1:${upstream.address().port}`,original=>truncateAuditExportCreateResponse(original,response));});
 await new Promise(resolve=>proxy.listen(0,"127.0.0.1",resolve));
 try{
   const response=await fetch(`http://127.0.0.1:${proxy.address().port}`,{method:"POST",body:"{}",signal:AbortSignal.timeout(2000)});
   assert.equal(response.status,201);assert.equal(committed,true);
   await assert.rejects(response.text());assert.equal(calls,1);
 }finally{await Promise.all([proxy,upstream].map(server=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));}));}
});
test("accepts only the spawned provider's owned readiness and rejects foreign authority",()=>{
 assert.deepEqual(parseAuditExportProviderReady(JSON.stringify(ready)+"\n",1234,root),ready);
 for(const changed of [{pid:9999},{address:"example.com:443"},{address:"127.0.0.1:0443"},{control:"/tmp/foreign.sock"},{ca:root+"/../ca.pem"},{token:root+"/other"},{extra:true},{schema:"other"}]) {
  assert.throws(()=>parseAuditExportProviderReady(JSON.stringify({...ready,...changed})+"\n",1234,root));
 }
 for(const raw of [JSON.stringify(ready),JSON.stringify(ready)+"\n{}\n",'{"pid":1,'+JSON.stringify(ready).slice(1)+"\n"," ".repeat(4097)]) assert.throws(()=>parseAuditExportProviderReady(raw,1234,root));
});

test("async fixture assertion retains the failure and joins its owned child before exit",{timeout:10000},async()=>{
 const helper=new URL("./audit-export-browser-proof.mjs",import.meta.url).href;
 const owner=new URL("./owned-command.mjs",import.meta.url).href;
 const source=`import assert from 'node:assert/strict';import {spawnOwnedCommand} from ${JSON.stringify(owner)};import {installAuditBrowserFatalCleanup} from ${JSON.stringify(helper)};
 const resource=spawnOwnedCommand(process.execPath,['--input-type=module','-e',"import net from 'node:net';const server=net.createServer();server.listen(0,'127.0.0.1',()=>console.log('owned-ready'));setTimeout(()=>{server.close();process.exit(0)},1500)"]);
 installAuditBrowserFatalCleanup(async()=>{await resource.stop();await resource.completed;console.error('owned-child-joined')});
 resource.child.stdout.once('data',()=>{void Promise.resolve().then(()=>assert.equal(1,2,'owned async failure'))});`;
 const command=spawnOwnedCommand(process.execPath,["--input-type=module","-e",source]);
 try {const result=await command.completed;assert.equal(result.status,1);assert.match(result.stderr,/owned async failure/);assert.match(result.stderr,/owned-child-joined/);} finally {await command.stop();}
});
test("selected export mode refuses ambiguous or unrelated runtime selections",()=>{
 assert.equal(validateAuditExportBrowserMode({}),false);
 assert.equal(validateAuditExportBrowserMode({ZASP_COMBINED_E2E_AUDIT_EXPORT:"true",ZASP_COMBINED_E2E_AUDIT_BROWSE:"true"}),true);
 for(const env of [{ZASP_COMBINED_E2E_AUDIT_EXPORT:"false"},{ZASP_COMBINED_E2E_AUDIT_EXPORT:"true"},{ZASP_COMBINED_E2E_AUDIT_EXPORT:"true",ZASP_COMBINED_E2E_AUDIT_BROWSE:"true",ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION:"true"}]) assert.throws(()=>validateAuditExportBrowserMode(env));
});
test("preparation-only boundary needs explicit selected mode and refuses misspelled flags",()=>{
 assert.equal(validateAuditExportPrepareMode({},false),false);
 assert.equal(validateAuditExportPrepareMode({ZASP_COMBINED_E2E_AUDIT_EXPORT_PREPARE_ONLY:"true"},true),true);
 for(const [value,selected] of [["true",false],["false",true],["1",true],["TRUE",true]]) assert.throws(()=>validateAuditExportPrepareMode({ZASP_COMBINED_E2E_AUDIT_EXPORT_PREPARE_ONLY:value},selected));
});
