import test from 'node:test';
import assert from 'node:assert/strict';
import {buildOrderedCurrentCloudSourceCopyV1} from './ordered-current-cloud-source-copy-v1.mjs';
import {buildOrderedCurrentNative379EntryFrameV1} from './ordered-current-native379-entry-frame-v1.mjs';
let source;
const fixture=()=>{source??=buildOrderedCurrentCloudSourceCopyV1();return source.outputs;};
const input=()=>Object.fromEntries([['contractRaw','effective-contract4.json'],['moduleRaw','development-module.sql'],['manifestRaw','development-manifest.json'],['admissionRaw','development-admission.sql']].map(([key,name])=>[key,Buffer.from(fixture()['services/platform/migrations/ordered_current/'+name])]));
const api=()=>import('./ordered-current-native379-entry-frame-cloud-v1.mjs');
test('historical authority refuses actual fresh private8 source',()=>assert.throws(()=>buildOrderedCurrentNative379EntryFrameV1(input()),/entry-frame/));
test('cloud entry binds actual private8 source and retains all entry/frame obligations',async()=>{
 const a=await api(),i=input(),v=a.buildOrderedCurrentNative379EntryFrameCloudV1(i);
 assert.equal(v.format,'ordered-current-native379-entry-frame-cloud-v1');assert.equal(v.entry.privateRoutineFacts.length,8);assert.equal(v.controls.length,26);
 assert.deepEqual(v.counts,{controls:26,entry:17,frame:9});assert.equal(v.installable,false);assert.equal(v.nativeVerified,false);assert.equal(v.captureAuthority,false);
 assert.equal(a.assertOrderedCurrentNative379EntryFrameCloudV1(v,i),undefined);
 for(const c of v.controls){assert.equal(c.restoration.beforeNextProbe,true);assert.equal(c.restoration.timeoutIsDenial,false);assert.ok(c.sourceSite.frame);assert.ok(c.program.steps.some(s=>s.id==='assert-restored'));}
});
test('every exact private8 routine has independent source-drift refusal and restoration',async()=>{
 const a=await api(),i=input(),v=a.buildOrderedCurrentNative379EntryFrameCloudV1(i);
 const expected=['canonical(jsonb)','catalog(text)','function_definition_public(oid)','function_identity_arguments_public(oid)','function_identity_public(oid)','function_resolve_public(text)','normalize_rows(jsonb,text)','require(text)'].map(name=>'zasp_authorization80_ordered_current.'+name);
 assert.deepEqual(v.entry.privateRoutineFacts.map(row=>JSON.parse(row.identity)[1]).sort(),expected.sort());
 const controls=v.controls.filter(control=>control.category==='private-source-drift');
 assert.deepEqual(controls.map(control=>control.sourceSite.sourceIdentity).sort(),expected);
 for(const c of controls){
  assert.equal(c.expected.sqlState,'42501');assert.equal(c.expected.firstError.stage,'independent-private-admission');
  assert.ok(c.mutation.sql.startsWith('CREATE OR REPLACE FUNCTION '));
  assert.ok(c.program.steps.some(step=>step.id==='assert-restored'&&step.expected.value===true));
  assert.equal(c.restoration.beforeNextProbe,true);assert.equal(c.restoration.timeoutIsDenial,false);
 }
});
test('cloud entry refuses corrupted/omitted/extra/getter bytes and altered controls',async()=>{
 const a=await api();for(const key of Object.keys(input())){const i=input();i[key][0]^=1;assert.throws(()=>a.buildOrderedCurrentNative379EntryFrameCloudV1(i),/entry-frame/);const missing=input();delete missing[key];assert.throws(()=>a.buildOrderedCurrentNative379EntryFrameCloudV1(missing),/entry-frame/);}
 const i=input();i.extra=Buffer.alloc(0);assert.throws(()=>a.buildOrderedCurrentNative379EntryFrameCloudV1(i),/entry-frame/);
 const getter=input();Object.defineProperty(getter,'moduleRaw',{get(){throw Error('untrusted getter');}});assert.throws(()=>a.buildOrderedCurrentNative379EntryFrameCloudV1(getter),/entry-frame/);
 const v=a.buildOrderedCurrentNative379EntryFrameCloudV1(input());for(const mutate of [x=>x.controls.pop(),x=>x.controls.push(x.controls[0]),x=>x.entry.privateRoutineFacts.pop(),x=>x.controls[0].restoration.beforeNextProbe=false,x=>x.controls[0].sourceSite.frame.owner='forged']){const q=structuredClone(v);mutate(q);assert.throws(()=>a.assertOrderedCurrentNative379EntryFrameCloudV1(q,input()),/entry-frame/);}
 assert.throws(()=>a.buildOrderedCurrentNative379EntryFrameCloudV1(input(),{}),/authority/);
});
