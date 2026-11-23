import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { verifyPilot, profiles } from "./verify-live-pilot.mjs";

const sha = b => createHash("sha256").update(b).digest("hex");
const manifestJSON = x => JSON.stringify(x,null,2)+"\n";
async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(),"pilot-attestation-"));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const environment = "fixture-environment", commit = "d".repeat(40), lane = "fixture", version = "v1.2.3", now = Date.now();
  const folder = path.join(dir,"public/downloads/zaspctl",version);
  await mkdir(folder,{recursive:true});
  await mkdir(path.join(dir,"app/features/tools"),{recursive:true});
  const native = generateKeyPairSync("ed25519");
  const releaseKey = path.join(dir,"release.pub");
  const keyBytes = native.publicKey.export({type:"spki",format:"pem"});
  await writeFile(releaseKey,keyBytes);
  const assets = [];
  for (const name of ["zaspctl-darwin-amd64","zaspctl-darwin-arm64","zaspctl-linux-amd64","zaspctl-windows-amd64.exe"]) {
    const bytes = Buffer.from("fixture bytes for "+name);
    await writeFile(path.join(folder,name),bytes);
    assets.push({name,bytes:bytes.length,sha256:sha(bytes)});
  }
  const manifest = Buffer.from(manifestJSON({schema:"zaspctl-release.v1",version,commit,assets}));
  await writeFile(path.join(folder,"manifest.json"),manifest);
  await writeFile(path.join(folder,"manifest.ed25519"),sign(null,manifest,native.privateKey));
  const pin = {version,commit,manifest_sha256:sha(manifest),assets};
  const pinPath = path.join(dir,"app/features/tools/cli-release-pin.json");
  await writeFile(pinPath,manifestJSON(pin));
  const trust={lane,environment,keys:{},release_key_sha256:sha(keyBytes)}, entries={}, keys={};
  async function put(name,change={}) {
    const value={...entries[name],...change};
    const raw=Buffer.from(JSON.stringify(value)+"\n");
    await writeFile(path.join(dir,name+".json"),raw);
    await writeFile(path.join(dir,name+".sig"),sign(null,Buffer.concat([Buffer.from("zasp.live-pilot.v1\0"),raw]),keys[value.profile]));
  }
  for(const [profile,required] of Object.entries(profiles)){
    const {publicKey,privateKey}=generateKeyPairSync("ed25519");
    trust.keys[profile]=publicKey.export({format:"pem",type:"spki"});keys[profile]=privateKey;
    for(const name of profile==="jamf"?["jamf-1","jamf-2"]:[profile]) {
      const entry={schema:"zasp.live-pilot.v1",lane,profile,environment,commit,observed_at:new Date(now).toISOString(),evidence:Object.fromEntries(required.map(k=>[k,name+"."+k]))};
      if(profile==="native_signing")Object.assign(entry,{version,manifest_sha256:pin.manifest_sha256});
      if(profile==="jamf")Object.assign(entry,{device_ref:name,os_build:"fixture-os",harness_build:"fixture-claude",hook_latency_ms:Array(20).fill(10)});
      if(profile==="archive")Object.assign(entry,{version_id:"v1+/=",deleted_version_id:"v1+/=",created_at:new Date(now-86400_000).toISOString(),deleted_at:new Date(now).toISOString()});
      entries[name]=entry;
      await put(name);
    }
  }
  const trustFile=path.join(dir,"trust.json"),data=JSON.stringify(trust);
  await writeFile(trustFile,data);
  return {args:{commit,environment,now,lane,directory:dir,stagedRoot:dir,releaseKey,trustFile,trustDigest:sha(data)},dir,put,entries,pin,pinPath,folder};
}
test("validates all seven scoped scenarios and executes the offline verifier CLI",async t=>{
  const {args,dir}=await fixture(t);
  const report=await verifyPilot(args);
  assert.equal(report.lane,"fixture");
  assert.equal(new Set(report.receipts.map(x=>x.profile)).size,7);
  assert.equal(report.receipts.length,8);
  assert.equal(report.receipts.filter(r=>r.profile==="jamf"&&r.p95_ms===10).length,2);
  const out=path.join(dir,"new-report.json");
  const cli=[new URL("./verify-live-pilot.mjs",import.meta.url).pathname,args.lane,args.commit,args.environment,args.trustFile,args.trustDigest,dir,dir,args.releaseKey,out];
  const options={encoding:"utf8"};
  assert.equal(spawnSync(process.execPath,cli,options).status,0);
  const recorded=JSON.parse(await readFile(out,"utf8"));
  assert.deepEqual(recorded.receipts,report.receipts);
  assert.equal(spawnSync(process.execPath,cli,options).status,1,"existing output was overwritten");
  await assert.rejects(verifyPilot({...args,lane:"staging"}));
});
test("rejects substituted artifacts, trust, incomplete measurements and stale receipts",async t=>{
  const {args,entries,put,pin,pinPath,folder}=await fixture(t);
  for(const [name,changes] of [
    ["jamf-2",{device_ref:"jamf-1"}],["jamf-1",{hook_latency_ms:Array(20).fill(76)}],
    ["archive",{deleted_version_id:"other"}],["archive",{created_at:new Date(args.now-3600000).toISOString()}],
    ["remote_mcp",{commit:"a".repeat(40)}],["stytch_login",{evidence:{}}],["native_signing",{manifest_sha256:"1".repeat(64)}],
    ["model_gateway",{observed_at:new Date(args.now+1).toISOString()}],["model_gateway",{observed_at:new Date(args.now-8*86400_000).toISOString()}],
    ["model_gateway",{observed_at:"2026-02-30T01:00:00Z"}],["model_gateway",{unexpected:"free text"}],
    ["aws_remediation",{evidence:{...entries.aws_remediation.evidence,rollback_readback:entries.aws_remediation.evidence.change_readback}}],
  ]){
    await put(name,changes);await assert.rejects(verifyPilot(args));await put(name);
  }
  await assert.rejects(verifyPilot({...args,trustDigest:"a".repeat(64)}));
  await writeFile(pinPath,manifestJSON({...pin,assets:pin.assets.slice(1)}));await assert.rejects(verifyPilot(args));
  await writeFile(pinPath,manifestJSON(pin));
  await writeFile(path.join(folder,pin.assets[0].name),"substituted binary");await assert.rejects(verifyPilot(args));
});
test("rejects signature reuse and incomplete device coverage",async t=>{
  const {args,dir,put}=await fixture(t);
  await writeFile(path.join(dir,"remote_mcp.sig"),await readFile(path.join(dir,"model_gateway.sig")));
  await assert.rejects(verifyPilot(args));
  await put("remote_mcp");
  await rm(path.join(dir,"jamf-2.json"));
  await assert.rejects(verifyPilot(args));
});
test("staging workflow is opt-in and checks a signing workflow run for the selected release",async()=>{
  const workflow=await readFile(new URL("../.github/workflows/verify-live-pilot.yml",import.meta.url),"utf8");
  assert.match(workflow,/workflow_dispatch:/);
  assert.doesNotMatch(workflow,/\bpull_request:|\bpush:|\bschedule:/);
  for(const token of ["github.ref_protected","environment: zasp-live-pilot","zaspctl-release-sign.yml","staged-zaspctl-console-","ZASP_PILOT_TRUST_SHA256","scripts/verify-live-pilot.mjs staging"])assert.ok(workflow.includes(token),token);
});
