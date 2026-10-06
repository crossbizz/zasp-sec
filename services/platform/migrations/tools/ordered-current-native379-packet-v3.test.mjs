import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as v3 from './ordered-current-native379-packet-v3.mjs';
import {admitOrderedCurrentNative379PacketV2,assertOrderedCurrentNative379PacketV2} from './ordered-current-native379-packet-v2.mjs';
import {readOrderedCurrentNative379LinuxReferenceV3,native379V3Canonical} from './ordered-current-native379-source-schema-v3.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
let draft,baseline;
const load=()=>structuredClone(draft??=v3.compileOrderedCurrentNative379ControlsDraftV3());
const old=()=>structuredClone(baseline??=admitOrderedCurrentNative379PacketV2());
test('actual reference boundary admits exact Linux provenance rather than historical v2 truth',()=>{
 // The retained RED executes the existing v2 compiler, not a missing feature.
 const p=process.env.ZASP_NATIVE379_V3_OFFLINE_BASELINE==='v2'?old():load();
 assert.equal(p.referenceProvenance.postgres,readOrderedCurrentNative379LinuxReferenceV3().identity.postgres);
 assert.deepEqual(p.referenceProvenance,p.expectedFacts.find(f=>f.kind==='build'&&f.identity==='provenance').fact);
});
test('v3 recompiles all original controls and nested preimages without native authority',()=>{
 const p=load(),b=old();assert.equal(p.format,'ordered-current-native379-controls-draft-v3');assert.equal(p.installable,false);assert.equal(p.nativeVerified,false);assert.equal(p.captureAuthority,false);
 assert.deepEqual(p.rules,b.rules);assert.deepEqual(p.sourceInventory,b.sourceInventory);assert.deepEqual(p.limits,b.limits);assert.deepEqual(p.phases,b.phases);
 assert.equal(p.expectedFacts.length,10052);assert.deepEqual(p.expectedFacts.filter(f=>f.kind!=='build'),b.expectedFacts.filter(f=>f.kind!=='build'));
 assert.deepEqual(p.controls.map(c=>c.id),b.controls.map(c=>c.id));assert.equal(p.controls.length,589);assert.equal(p.controls.reduce((n,c)=>n+c.program.steps.length,0),6348);
 let changedSteps=0,changedControls=0;
 const substitute=value=>typeof value==='string'?value.replaceAll(b.entry.manifest,p.entry.manifest):Array.isArray(value)?value.map(substitute):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,substitute(v)])):value;
 for(const [i,c]of p.controls.entries()){
  const before=b.controls[i];assert.equal(c.phase,before.phase);assert.equal(c.program.steps.length,before.program.steps.length);assert.deepEqual(c.ruleIds,before.ruleIds);const afterExpected=substitute(before.expected);
  if(afterExpected.firstError?.sql){afterExpected.firstError.sql=afterExpected.firstError.sql.replaceAll(b.entry.manifest,p.entry.manifest);afterExpected.firstError.siteSHA256=sha(afterExpected.firstError.sql);afterExpected.firstError.end=Buffer.byteLength(afterExpected.firstError.sql);}
  assert.deepEqual(c.expected,afterExpected);
  if(c.mutation)assert.equal(c.mutationSHA256,sha(native379V3Canonical(c.mutation)),c.id);
  let changed=false;
  for(const [j,step]of c.program.steps.entries()){
   const prior=before.program.steps[j];assert.equal(step.id,prior.id);assert.equal(step.role,prior.role);assert.deepEqual(step.expected,substitute(prior.expected));assert.equal(step.sqlSHA256,sha(step.sql));
   if(step.sql!==prior.sql){changed=true;changedSteps++;assert.equal(step.sql,prior.sql.replaceAll(b.entry.manifest,p.entry.manifest),c.id+':'+step.id);}
  }
  if(changed)changedControls++;
 }
 assert.equal(changedSteps,539);assert.equal(changedControls,520);
 assert.equal(p.authority.sourceInventorySHA256,null);assert.equal(p.authority.generatedIdentitiesSHA256,null);assert.equal(p.authority.sourceFactDeltaSHA256,null);
 assert.throws(()=>v3.admitOrderedCurrentNative379PacketV3(),/final source5 push/);assert.throws(()=>v3.serializeOrderedCurrentNative379PacketV3(p),/draft cannot publish/);
 assert.throws(()=>assertOrderedCurrentNative379PacketV2(p),/native379/);
});
test('v3 metadata closure rejects independently forged SQL, mutation, role, fact and caps',()=>{
 const p=load();
 for(const mutate of [q=>q.controls.pop(),q=>q.controls[0].program.steps[7].sql+=' ',q=>q.controls[0].program.steps[7].sqlSHA256='0'.repeat(64),q=>q.controls[0].program.steps[4].role='zasp_security_agent_worker',q=>q.controls[0].mutationSHA256='0'.repeat(64),q=>q.expectedFacts[0].fact={forged:true},q=>q.limits.maxBytes++,q=>q.phases[1].limits.maxMilliseconds++,q=>q.referenceProvenance.postgres=old().referenceProvenance.postgres,q=>q.authority.goPacketAnchorPolicy.excludedSourcePaths.push('extra'),q=>q.nativeVerified=true]){const q=structuredClone(p);mutate(q);assert.throws(()=>v3.assertOrderedCurrentNative379ControlsDraftV3(q),/draft reference/);}
 assert.throws(()=>v3.compileOrderedCurrentNative379ControlsDraftV3({}),/caller-selected/);
});
