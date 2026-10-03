import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {buildOrderedCurrentCloudSourceCopyV1} from './ordered-current-cloud-source-copy-v1.mjs';
import {buildOrderedCurrentLinuxRuntimeSourceV1 as build,assertOrderedCurrentLinuxRuntimeSourceV1 as check,assertOrderedCurrentLinuxRuntimeWitnessV1 as checkWitness} from './ordered-current-linux-runtime-source-v1.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const rawWitness=()=>fs.readFileSync(new URL('./ordered-current-linux-runtime-identity-witness-v1.json',import.meta.url));
let original,current;
const load=()=>{original??=buildOrderedCurrentCloudSourceCopyV1();current??=build();return [original,current];};
const manifest=x=>JSON.parse(x);
const canonical=x=>JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
test('fixed approved SOURCE witness requires exact raw pin four identity fields and complete lifecycle',()=>{
 const raw=rawWitness(),w=manifest(raw);assert.equal(sha(raw),'468c02f31c83d0b2dd9bbe4fc2d6138591186ca88d66e967201148f0319d61fd');assert.equal(checkWitness(raw),true);
 for(const group of ['verification','cleanup'])for(const key of Object.keys(w[group]))for(const mode of ['missing','null','changed']){const x=structuredClone(w);if(mode==='missing')delete x[group][key];else x[group][key]=mode==='null'?null:typeof x[group][key]==='boolean'?false:typeof x[group][key]==='number'?1:'invalid';assert.throws(()=>checkWitness(Buffer.from(JSON.stringify(x))),/witness/);}
 for(const group of ['identity','ownership','runtimeAuthority','query'])for(const key of Object.keys(w[group])){const x=structuredClone(w);delete x[group][key];assert.throws(()=>checkWitness(Buffer.from(JSON.stringify(x))),/witness/);}
 for(const x of [null,{},[],Buffer.alloc(16385),Buffer.concat([raw,Buffer.from('{}')]),Buffer.from(raw.toString().replace('{','{"format":"unreviewed",'))])assert.throws(()=>checkWitness(x),/witness/);
 assert.throws(()=>checkWitness(raw,{}),/authority/);assert.throws(()=>build({postgresVersion:w.identity.postgresVersion}),/authority/);
});
test('SOURCE witness consumed substitution is refused before any source build',()=>{
 const filename=new URL('./ordered-current-linux-runtime-identity-witness-v1.json',import.meta.url),read=fs.readFileSync;
 try{fs.readFileSync=function(p,...args){const raw=read.call(this,p,...args);return String(p)===filename.pathname?Buffer.concat([raw,Buffer.from('substitution')]):raw;};assert.throws(()=>build(),/consumed file pin/);}finally{fs.readFileSync=read;}
});
test('runtime source changes only build postgres and module manifest checkpoint hash chain',()=>{
 const [o,r]=load(),old=manifest(o.outputs['services/platform/migrations/ordered_current/development-manifest.json']),fresh=manifest(r.outputs['development-manifest.json']);
 const before=old.facts.find(x=>x.kind==='build').fact,after=fresh.facts.find(x=>x.kind==='build').fact;
 assert.equal(fresh.facts.length,10052);assert.equal(fresh.facts.filter(x=>x.kind!=='build').length,10051);assert.deepEqual(fresh.facts.filter(x=>x.kind!=='build'),old.facts.filter(x=>x.kind!=='build'));
 assert.deepEqual(Object.keys(before).sort(),Object.keys(after).sort());assert.equal(Object.keys(after).length,11);for(const k of Object.keys(before).filter(k=>k!=='postgres'))assert.deepEqual(after[k],before[k]);assert.equal(after.postgres,manifest(rawWitness()).identity.postgresVersion);assert.notEqual(after.postgres,before.postgres);
 const changed=Object.keys(r.outputs).filter(n=>!r.outputs[n].equals(o.outputs['services/platform/migrations/ordered_current/'+n]));assert.deepEqual(changed.sort(),['development-checkpoint.json','development-manifest.json','development-module.sql']);
 const oldModule=o.outputs['services/platform/migrations/ordered_current/development-module.sql'].toString(),newModule=r.outputs['development-module.sql'].toString();const guard="IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;";assert.ok(newModule.includes(guard));
 const literal=x=>canonical(x).replaceAll("'","''");assert.equal(newModule,oldModule.replace("('build','provenance','"+literal(before)+"'::jsonb)","('build','provenance','"+literal(after)+"'::jsonb)").replace("VALUES(true,1,'"+before.profile_checksum+"','"+old.payloadSHA256+"');","VALUES(true,1,'"+before.profile_checksum+"','"+fresh.payloadSHA256+"');"));
 const oldCheckpoint=manifest(o.outputs['services/platform/migrations/ordered_current/development-checkpoint.json']),checkpoint=manifest(r.outputs['development-checkpoint.json']);for(const k of ['payloadSHA256','manifestFileSHA256','moduleFileSHA256']){delete oldCheckpoint[k];delete checkpoint[k];}assert.deepEqual(checkpoint,oldCheckpoint);
 assert.equal(r.receipt.sourceReceipt.inputs.length,171);assert.equal(r.receipt.sourceReceipt.outputs.length,8);assert.equal(r.receipt.sourceWitnessAcceptanceSHA256,'13eda7ab5db5be3ad4d64df3449b18543b0fa12c45450de7c93e234ce9e87f8d');assert.equal(check(r),true);
 for(const key of ['installable','nativeVerified','captureAuthority'])assert.equal(r[key],false);
});
test('runtime source regeneration twice is deterministic and every output pin refusal is closed',()=>{
 const [,left]=load(),right=build();assert.deepEqual(left.receipt,right.receipt);for(const name of Object.keys(left.outputs))assert.ok(left.outputs[name].equals(right.outputs[name]));
 for(const name of Object.keys(left.outputs)){const r={...left,outputs:{...left.outputs,[name]:Buffer.concat([left.outputs[name],Buffer.from('changed')])}};assert.throws(()=>check(r),/pin/);const missing={...left,outputs:{...left.outputs}};delete missing.outputs[name];assert.throws(()=>check(missing),/receipt/);}
 for(const mutate of [x=>x.installable=true,x=>x.receipt.runtimeWitnessSHA256='0'.repeat(64),x=>x.receipt.sourceReceipt.inputs.pop(),x=>x.extra=true]){const x={...left,receipt:structuredClone(left.receipt),outputs:{...left.outputs}};mutate(x);assert.throws(()=>check(x),/receipt/);}
});

test('SOURCE runtime environment overrides are refused before source generation',()=>{
 for(const name of ['ZASP_ORDERED_CURRENT_LINUX_RUNTIME_VERSION','ZASP_ORDERED_CURRENT_LINUX_RUNTIME_WITNESS','ZASP_ORDERED_CURRENT_LINUX_RUNTIME_WITNESS_SHA256','ZASP_ORDERED_CURRENT_LINUX_RUNTIME_PROFILE','ZASP_ORDERED_CURRENT_LINUX_RUNTIME_EXPECTED_POSTGRES']){
  const previous=process.env[name];try{process.env[name]='unreviewed';assert.throws(()=>build(),/caller-selected runtime authority/);}finally{if(previous===undefined)delete process.env[name];else process.env[name]=previous;}
 }
});
