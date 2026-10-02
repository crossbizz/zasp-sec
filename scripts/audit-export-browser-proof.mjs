import assert from "node:assert/strict";
import net from "node:net";
import path from "node:path";
import http from "node:http";

export function auditExportVolumeMetadata() {
  return { payload: "x".repeat(512), padding: "x".repeat(512) };
}

export async function joinAuditExportProvider(provider) {
  const result = await provider.completed;
  assert.ok(result.status === 0 && result.signal === null, "audit provider failed during joined completion");
  return result;
}

export function assertAuditExportVolume(measurements, emit = console.log) {
  const { events, chunkBytes, maximumEnvelopeBytes } = measurements;
  emit(`AUDIT_EXPORT_VOLUME_MEASURED ${JSON.stringify({ events, chunkBytes, maximumEnvelopeBytes })}`);
  assert.ok([events, chunkBytes, maximumEnvelopeBytes].every(Number.isSafeInteger), "finite integer volume measurements required");
  assert.ok(events >= 100001, "large export requires at least100001 events");
  assert.ok(chunkBytes > 64 * 1024 * 1024, "large export must exceed64MiB");
  assert.ok(maximumEnvelopeBytes > 1000000 && maximumEnvelopeBytes <= 1064960, "near-limit envelope must exceed1000000 and not exceed1064960 bytes");
}

export function truncateAuditExportCreateResponse(upstream, response) {
  assert.equal(upstream.statusCode,201);
  let first;
  upstream.on("data",chunk=>{first??=chunk.subarray(0,1);});
  upstream.once("end",()=>{
    assert.equal(first?.length,1);
    // A zero-header disconnect can be transparently replayed by the browser.
    // A committed status plus incomplete body reaches the actual error path.
    response.writeHead(upstream.statusCode,{"Content-Type":upstream.headers["content-type"],"Content-Length":"2","Connection":"close"});
    response.write(first);
    setImmediate(()=>response.destroy());
  });
  upstream.once("error",()=>response.destroy());
}

export function installAuditBrowserFatalCleanup(cleanup) {
  assert.equal(typeof cleanup,"function");
  let pending;
  const fatal=error=>{
    console.error("selected audit browser asynchronous failure",error);
    pending ??= Promise.resolve().then(cleanup).catch(cleanupError=>console.error("owned cleanup failed",cleanupError)).finally(()=>process.exit(1));
  };
  process.once("uncaughtException",fatal);process.once("unhandledRejection",fatal);
  return ()=>{process.removeListener("uncaughtException",fatal);process.removeListener("unhandledRejection",fatal);};
}

export async function auditExportProviderCommand(ready, command) {
  const body=JSON.stringify(command);
  assert.ok(Buffer.byteLength(body)<=4096);
  return new Promise((resolve,reject)=>{
    const request=http.request({socketPath:ready.control,path:"/",method:"POST",headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}},response=>{
      let size=0;const chunks=[];
      response.on("data",chunk=>{size+=chunk.length;if(size>4096)response.destroy(new Error("provider response exceeded bound"));else chunks.push(chunk);});
      response.on("error",reject);
      response.on("end",()=>{try{assert.equal(response.statusCode,200,Buffer.concat(chunks).toString());resolve(JSON.parse(Buffer.concat(chunks).toString()));}catch(error){reject(error);}});
    });
    request.setTimeout(300_000,()=>request.destroy(new Error("owned provider command deadline")));
    request.on("error",reject);request.end(body);
  });
}

export function parseAuditExportProviderReady(raw, pid, ownedRoot) {
  auditExportOwnedRoot(ownedRoot);
  assert.ok(typeof raw==="string" && Buffer.byteLength(raw)<=4096 && raw.endsWith("\n"),"bounded framed readiness required");
  const record=JSON.parse(raw);
  assert.deepEqual(Object.keys(record),["schema","pid","address","control","ca","token"]);
  assert.equal(raw,JSON.stringify(record)+"\n","noncanonical readiness refused");
  assert.equal(record.schema,"audit-browser-provider-v1");
  assert.ok(Number.isSafeInteger(pid) && pid>1);assert.equal(record.pid,pid);
  auditExportOwnedAddress(record.address);
  for(const [key,name] of [["control","control.sock"],["ca","ca.pem"],["token","token"]]) assert.equal(record[key],path.join(ownedRoot,name));
  return record;
}

export function validateAuditExportBrowserMode(environment) {
  if (environment.ZASP_COMBINED_E2E_AUDIT_EXPORT === undefined) return false;
  assert.equal(environment.ZASP_COMBINED_E2E_AUDIT_EXPORT,"true");
  assert.equal(environment.ZASP_COMBINED_E2E_AUDIT_BROWSE,"true");
  for(const key of ["ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION","ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY","ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY"]) assert.notEqual(environment[key],"true");
  return true;
}

export function validateAuditExportPrepareMode(environment, selected) {
  if (environment.ZASP_COMBINED_E2E_AUDIT_EXPORT_PREPARE_ONLY === undefined) return false;
  assert.equal(environment.ZASP_COMBINED_E2E_AUDIT_EXPORT_PREPARE_ONLY,"true");
  assert.equal(selected,true,"preparation requires the selected owned export composition");
  return true;
}

export function auditExportOwnedAddress(address) {
  const match = /^(127\.0\.0\.1):([1-9][0-9]{0,4})$/.exec(address);
  assert.ok(match && net.isIPv4(match[1]) && Number(match[2]) <= 65535,"owned IPv4 listener required");
  return address;
}

export function auditExportOwnedRoot(root) {
  assert.ok(path.isAbsolute(root) && path.resolve(root)===root && !/[\r\n\0]/.test(root),"canonical owned root required");
  return root;
}
