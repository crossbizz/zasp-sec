import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import * as api from './ordered-current-native379-packet-v2.mjs';

let packet;
const load=()=>structuredClone(packet??=api.admitOrderedCurrentNative379PacketV2());
test('runtime admission refuses wrong version platform architecture or executable before regeneration',()=>{
 const module=new URL('./ordered-current-native379-packet-v2.mjs',import.meta.url).href;
 for(const [field,value]of [['version','v22.23.0'],['platform','darwin'],['arch','arm64'],['execPath',new URL('./ordered-current-native379-packet-v2.mjs',import.meta.url).pathname]]){
  const script=`Object.defineProperty(process,${JSON.stringify(field)},{value:${JSON.stringify(value)}}); const api=await import(${JSON.stringify(module)}); try {api.admitOrderedCurrentNative379PacketV2(); process.exitCode=2;} catch(e) {if(!/approved executable SHA256/.test(e.message))process.exitCode=3;}`;
  const result=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000,maxBuffer:1048576,env:{TZ:'UTC',LANG:'C'}});
  assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);
 }
});
test('Linux v2 reconciles complete source-derived evaluator, facts and pending trust chain',()=>{
 const p=load();
 assert.equal(p.format,'ordered-current-native379-packet-v2');assert.equal(p.status,'NATIVE-PARITY-PENDING');
 assert.equal(p.installable,false);assert.equal(p.nativeVerified,false);assert.equal(p.captureAuthority,false);
 assert.deepEqual(p.buildRuntime,{version:'v22.23.1',platform:'linux',arch:'x64',executableSHA256:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',executablePolicy:'resolved-process-executable-regular-file-exact-sha256'});
 assert.equal(p.rules.length,379);assert.equal(new Set(p.rules.map(r=>r.id)).size,379);
 assert.equal(p.expectedFacts.length,p.rules.reduce((n,r)=>n+r.expectedFacts,1));
 assert.equal(p.expectedFacts.length,10052);
 assert.equal(p.sourceFactDelta.historicalV1.expectedFacts,10053);
 assert.equal(p.sourceFactDelta.perRule.length,379);
 assert.deepEqual(p.sourceFactDelta.perRule.filter(r=>r.delta!==0).map(r=>[r.ruleId,r.delta]).sort(),[['private-routines',1],['temporal72:trigger',-2]]);
 assert.equal(p.sourceFactDelta.additions.length,1);assert.equal(p.sourceFactDelta.equalExisting.length,2);
 assert.equal(p.sourceFactDelta.sharedPayloadChanges.length,8);
 assert.equal(p.sourceFactDelta.sharedPayloadChanges.filter(r=>r.kind==='constraint').length,5);
 assert.equal(p.sourceFactDelta.sharedPayloadChanges.filter(r=>r.kind==='trigger').length,1);
 assert.equal(p.sourceFactDelta.sharedPayloadChanges.filter(r=>r.kind==='routine').length,1);
 assert.equal(p.sourceFactDelta.sharedPayloadChanges.filter(r=>r.kind==='build').length,1);
 for(const alias of p.sourceFactDelta.equalExisting){assert.ok(p.expectedFacts.some(f=>f.kind===alias.kind&&f.identity===alias.retainedCanonicalIdentity));assert.ok(!p.expectedFacts.some(f=>f.kind===alias.kind&&f.identity===alias.removedAliasIdentity));}
 assert.equal(p.sourceInventory.sites.length,565);assert.equal(p.sourceInventory.unclassified,0);
 assert.match(p.referenceProvenance.postgres,/Homebrew/);
 assert.deepEqual(p.referenceProvenance,p.expectedFacts.find(f=>f.kind==='build').fact);
 assert.match(p.identity.postgres,/PostgreSQL 18\.3 \(Debian 18\.3-1\.pgdg12\+1\)/);
 assert.equal(p.identity.pgcrypto,'1.4');assert.equal(p.identity.serverVersionNum,180003);
 assert.ok(p.pendingGates.includes('independently-reviewed-Go-source-module-test-binary-envelope'));
 assert.equal(p.authority.goPacketAnchorPolicy.implementation,'services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go');
 assert.deepEqual(p.authority.goPacketAnchorPolicy.excludedSourcePaths,['services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go']);
 assert.deepEqual(p.phases.map(s=>s.id),['preflight','pristine-truth','drift','forged-entry','null-error-lazy-demand','frame-restoration','cleanup-result']);
 assert.equal(p.controls.filter(c=>c.category==='expected-key-set').length,379);
 for(const category of ['body','owner','acl','default-acl','config','rls','constraint','index','trigger','saved-definition','registration','addition','missing-dependency','explicit-null','duplicate-bag','scalar-many','lazy-unselected','lazy-selected','first-error','forged-entry','frame'])assert.ok(p.controls.some(c=>c.category===category),category);
 assert.equal(p.controls.length,589);
 for(const c of p.controls){assert.ok(c.program?.steps.length>=3,c.id);assert.equal(c.restoration.beforeNextProbe,true);assert.equal(c.restoration.timeoutIsDenial,false);}
 api.assertOrderedCurrentNative379PacketV2(p);
});

test('v2 packet refuses stale source, missing facts, control loss, platform changes and status promotion',()=>{
 const p=load();
 assert.throws(()=>api.admitOrderedCurrentNative379PacketV2({}),/caller/);
 for(const change of [q=>q.expectedFacts.pop(),q=>q.controls.pop(),q=>q.rules[0].expectedFacts++,q=>q.authority.task4='0'.repeat(64),q=>q.authority.generated['development-module.sql']='0'.repeat(64),q=>q.buildRuntime.platform='darwin',q=>q.identity.postgres=q.referenceProvenance.postgres,q=>q.nativeVerified=true,q=>q.pendingGates=[],q=>q.sourceFactDelta.perRule.pop(),q=>q.sourceFactDelta.equalExisting[0].retainedCanonicalIdentity='forged']){
  const bad=structuredClone(p);change(bad);assert.throws(()=>api.assertOrderedCurrentNative379PacketV2(bad),/native379/);
 }
 const wire=api.serializeOrderedCurrentNative379PacketV2(p);
 assert.deepEqual(api.parseOrderedCurrentNative379PacketV2(wire.raw),p);
 for(const raw of [wire.raw.subarray(0,-2),Buffer.concat([wire.raw,Buffer.from(' ')]),Buffer.from(wire.raw.toString().replace('"installable":false','"installable":true'))])assert.throws(()=>api.parseOrderedCurrentNative379PacketV2(raw),/native379/);
});
