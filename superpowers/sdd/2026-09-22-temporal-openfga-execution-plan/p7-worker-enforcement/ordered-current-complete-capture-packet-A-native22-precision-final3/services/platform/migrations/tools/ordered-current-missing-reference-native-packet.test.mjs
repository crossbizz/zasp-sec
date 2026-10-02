import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
 buildOrderedCurrentMissingReferenceNativePacket,
 materializeOrderedCurrentMissingReferenceNativePacket,
 serializeOrderedCurrentMissingReferenceNativePacket,
} from './ordered-current-missing-reference-native-packet.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const optedIn=process.env.ZASP_ORDERED_CURRENT_MISSING_REFERENCE_NATIVE==='1';
const manifest=optedIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const root=manifest?.packetBytes?.A?.packetDirectory;
const p7=root&&path.join(root,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const files=p7&&{
 compiledReleaseRaw:path.join(p7,'recovery80-worker-compiled-release.json'),
 sourceContractRaw:path.join(p7,'recovery80-effective-contract.json'),
 catalogRaw:path.join(p7,'recovery80-effective-catalog.json'),
};
const available=Boolean(files)&&Object.values(files).every(file=>fs.existsSync(file));
if(optedIn&&!available)test('explicit native packet opt-in refuses absent fixed prerequisites',()=>assert.fail('fixed recovery80 inputs unavailable'));
const artifactTest=(name,fn)=>test(name,{skip:available?false:optedIn?'fixed recovery80 inputs unavailable':'set ZASP_ORDERED_CURRENT_MISSING_REFERENCE_NATIVE=1'},fn);
const fixed=()=>Object.fromEntries(Object.entries(files).map(([key,file])=>[key,fs.readFileSync(file)]));
let cached;
const packet=()=>cached??=buildOrderedCurrentMissingReferenceNativePacket(fixed());

test('packet builder refuses absent or caller-selected source authority',()=>{
 assert.throws(()=>buildOrderedCurrentMissingReferenceNativePacket(),/missing reference native packet/i);
 assert.throws(()=>buildOrderedCurrentMissingReferenceNativePacket({}),/missing reference native packet/i);
});

artifactTest('fixed packet closes twelve rules, 204 rows and frame-separated baseline execution',()=>{
 const value=packet();
 assert.equal(value.format,'ordered-current-missing-reference-native-v1');
 assert.equal(value.status,'NATIVE-UNVERIFIED');
 assert.equal(value.installable,false);
 assert.equal(value.captureStatus,'NOT-CAPTURED');
 assert.deepEqual(value.counts,{rules:12,rows:204,sourceSites:21,witnessFamilies:7});
 assert.equal(value.contract.contractSHA256,'262728237a748a512b98e499a9b0335c13cabcf39a372fd3eaf65261e8f1449d');
 assert.equal(value.sourcePins.contractModuleSHA256,'2a304799618b0ca70b18df1f63f04c7bc450aab83b0bfcc19b779aead5b3af90');
 assert.match(value.sourcePins.contractJSONSHA256,/^[a-f0-9]{64}$/);
 assert.deepEqual(value.baseline.transaction,{isolation:'repeatable-read',access:'read-only',snapshot:'single'});
 assert.equal(value.baseline.rules.length,12);
 assert.equal(value.baseline.rules.reduce((sum,rule)=>sum+rule.exactRows,0),204);
 for(const rule of value.baseline.rules){
  assert.deepEqual(rule.stages.map(stage=>stage.id),['capture-projection','capture-projection-identities','capture-canonical-roster-identities','compare-identity-multisets']);
  assert.equal(rule.stages[0].frame,'projectionFrame');
  assert.equal(rule.stages[1].frame,'projectionFrame');
  assert.equal(rule.stages[2].frame,'canonicalRosterFrame');
  assert.equal(rule.stages[3].frame,'bound-values-only');
  assert.deepEqual(rule.stages[3].inputs.map(input=>input.type),['text[]','text[]']);
  assert.equal(rule.sqlIdentities.every(digest=>/^[a-f0-9]{64}$/.test(digest)),true);
 }
 assert.equal(Object.hasOwn(value,'facts'),false);
 assert.equal(Object.hasOwn(value,'expectedRows'),false);
});

artifactTest('packet includes all seven source-bound witness families and isolated mutation probes',()=>{
 const value=packet(),byId=new Map(value.witnessProgram.families.map(family=>[family.id,family]));
 assert.deepEqual([...byId.keys()],[
  'role-profile:current-profile:aggregate','role-profile:native-roles:aggregate','role-profile:native-roles:membership',
  'routine-config-array-shape','saved-scalar-case-demand','managed-role-current-database','inventory-core-owner-resolution',
 ]);
 for(const id of ['role-profile:current-profile:aggregate','role-profile:native-roles:aggregate','role-profile:native-roles:membership']){
  assert.equal(byId.get(id).baseline.length,1);
  assert.equal(byId.get(id).baseline[0].frame,'sourceDiscoveryPublic');
 }
 const missingRole=byId.get('role-profile:native-roles:membership').probes[0];
 assert.match(missingRole.stages[2].sql,/WITH membership AS MATERIALIZED/);
 assert.match(missingRole.stages[2].sql,/'zasp_temporal_accounting'::pg_catalog\.regrole/);
 assert.deepEqual(byId.get('routine-config-array-shape').baseline.map(item=>item.ruleId),['temporal72:function','inventory-fields:function']);
 assert.ok(byId.get('routine-config-array-shape').baseline.every(item=>/JOIN pg_catalog\.pg_namespace config_namespace ON config_namespace\.oid=(?:p|procedure)\.pronamespace AND config_namespace\.nspname='public'/.test(item.sql)));
 assert.deepEqual(byId.get('managed-role-current-database').baseline.map(item=>item.ruleId),['temporal72:role','inventory-fields:role']);
 const saved=byId.get('saved-scalar-case-demand').probes;
 assert.deepEqual(saved.map(item=>item.id),['temporal-lazy-unselected','temporal-zero-row-null','temporal-multiple-row','temporal-missing-regprocedure','precision-lazy-unselected','precision-zero-row-null','precision-multiple-row','precision-missing-regprocedure']);
 for(const id of ['temporal-zero-row-null','precision-zero-row-null']){
  const setup=saved.find(item=>item.id===id).stages[1].sql;
  assert.match(setup,/ALTER TABLE zasp_temporal72\.predecessor_functions DISABLE TRIGGER immutable/);
  assert.match(setup,/DELETE FROM zasp_temporal72\.predecessor_functions/);
  assert.match(setup,/ALTER TABLE zasp_temporal72\.predecessor_functions ENABLE TRIGGER immutable/);
 }
 const inventory=byId.get('inventory-core-owner-resolution').probes;
 assert.deepEqual(inventory.map(item=>item.id),['inventory-core-shadow-resolution','inventory-core-missing-regclass']);
 for(const probe of [...saved,...inventory]){
  assert.equal(probe.transaction,'separate-read-write-rollback');
  assert.equal(probe.cleanup,'rollback-and-verify-exact-state');
  assert.ok(probe.stages.length>=3,probe.id);
  assert.equal(probe.stages[1].sqlSHA256,crypto.createHash('sha256').update(probe.stages[1].sql).digest('hex'));
  assert.equal(probe.stages[2].sqlSHA256,crypto.createHash('sha256').update(probe.stages[2].sql).digest('hex'));
 }
 assert.deepEqual(value.witnessProgram.limits,{sqlSeconds:10,lockSeconds:3,cleanupSeconds:3});
});

artifactTest('serialization and exclusive owner-only materialization bind the entire packet',()=>{
 const value=packet(),first=serializeOrderedCurrentMissingReferenceNativePacket(value),second=serializeOrderedCurrentMissingReferenceNativePacket(value);
 assert.deepEqual(first,second);
 assert.ok(first.raw.length>0);
 assert.match(first.sha256,/^[a-f0-9]{64}$/);
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-missing-reference-native-packet-'));
 const written=materializeOrderedCurrentMissingReferenceNativePacket(value,directory);
 assert.equal(written.sha256,first.sha256);
 assert.equal(fs.statSync(written.path).mode&0o777,0o600);
 assert.deepEqual(materializeOrderedCurrentMissingReferenceNativePacket(value,directory),written);
 fs.writeFileSync(written.path,Buffer.from('mismatch'));
 assert.throws(()=>materializeOrderedCurrentMissingReferenceNativePacket(value,directory),/overwrite|exists/i);
});

artifactTest('fixed packet refuses any source byte drift',()=>{
 for(const field of ['compiledReleaseRaw','sourceContractRaw','catalogRaw']){
  const input=fixed();input[field]=Buffer.from(input[field]);input[field][0]^=1;
  assert.throws(()=>buildOrderedCurrentMissingReferenceNativePacket(input),/missing reference native packet/i);
 }
});
