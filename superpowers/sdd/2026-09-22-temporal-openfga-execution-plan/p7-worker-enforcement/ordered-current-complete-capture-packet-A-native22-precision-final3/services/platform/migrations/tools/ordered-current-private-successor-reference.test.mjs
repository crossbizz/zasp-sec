import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  admitOrderedCurrentPrivateSuccessorReferenceV1,
  assertOrderedCurrentPrivateSuccessorPacketV1,
  buildOrderedCurrentPrivateSuccessorCaptureV1,
  checkOrderedCurrentPrivateSuccessorReferenceV1,
  materializeOrderedCurrentPrivateSuccessorCaptureV1,
  parseOrderedCurrentPrivateSuccessorReferenceJSONV1,
  serializeOrderedCurrentPrivateSuccessorCaptureV1,
} from './ordered-current-private-successor-reference.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const roots={
  compiler:'/private/tmp/zasp-direct-frame-source-check.pDCNE6/release.json',
  contract:'/private/tmp/zasp-recovery80-native-composition-A.86UE9x/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/recovery80-effective-contract.json',
  catalog:'/private/tmp/zasp-recovery80-native-composition-A.86UE9x/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/recovery80-effective-catalog.json',
};
const exactInputs=()=>({compilerArtifactRaw:fs.readFileSync(roots.compiler),sourceContractRaw:fs.readFileSync(roots.contract),catalogRaw:fs.readFileSync(roots.catalog)});
const sourceAvailable=Object.values(roots).every(path=>fs.existsSync(path));
let packet;

test('builds the exact closed 57-row successor packet from source2ca', {skip:!sourceAvailable}, ()=>{
  packet=buildOrderedCurrentPrivateSuccessorCaptureV1(exactInputs());
  assert.equal(packet.format,'ordered-current-private-successor-capture-v1');
  assert.equal(packet.status,'NATIVE-UNVERIFIED');
  assert.equal(packet.installable,false);
  assert.equal(packet.captureStatus,'NOT-CAPTURED');
  assert.deepEqual(packet.counts,{rules:11,rows:57,routineRows:22,nonroutineRows:35});
  assert.equal(packet.ddl.sha256,'fc7aacc36a9a09fb86c181d531a35c34a06adeabdcd1a1289fdaf2a53bb5b724');
  assert.equal(packet.collector.sha256,'625a5888444ab719a707c4d8acd0b872088feece0cbf4c370af0e7dd416459da');
  assert.equal(packet.sourcePins.compilerArtifactSHA256,'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c');
  assert.equal(packet.expectedRoutineFacts.length,22);
  assert.equal(packet.rules.length,11);
  assert.equal(assertOrderedCurrentPrivateSuccessorPacketV1(packet),true);
  assert.ok(!JSON.stringify(packet).includes('15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607'));
});

test('refuses changed source inputs and semantic packet fields', {skip:!sourceAvailable}, ()=>{
  const inputs=exactInputs();
  for(const key of Object.keys(inputs)){
    const changed={...inputs,[key]:Buffer.concat([inputs[key],Buffer.from(' ')] )};
    assert.throws(()=>buildOrderedCurrentPrivateSuccessorCaptureV1(changed),/source authority/);
  }
  const baseline=buildOrderedCurrentPrivateSuccessorCaptureV1(inputs);
  const mutations=[
    value=>{value.ddl.sql+='\nSELECT 1;';},
    value=>{value.collector.sql+='\nLIMIT 1';},
    value=>{value.expectedRoutineFacts.pop();},
    value=>{value.rules[0].fields.pop();},
    value=>{value.shape.ruleMaxRows['private-routines']=21;},
    value=>{value.helperPins['ordered-current-private.mjs']='0'.repeat(64);},
  ];
  for(const mutate of mutations){
    const changed=structuredClone(baseline);mutate(changed);
    assert.throws(()=>assertOrderedCurrentPrivateSuccessorPacketV1(changed),/packet/);
  }
});

const typedValue=type=>({string:'fixture',boolean:false,number:1,string_array:['fixture'],object:{fixture:true}}[type]??null);
function shapedReference(value){
  const rows=structuredClone(value.expectedRoutineFacts);
  for(const rule of value.rules){
    if(rule.kind==='routine')continue;
    for(let index=0;index<value.shape.ruleMaxRows[rule.id];index++){
      const fact={};for(const field of rule.fields)fact[field]=typedValue(value.shape.fieldTypes[rule.kind][field]);
      rows.push({kind:rule.kind,identity:JSON.stringify([rule.id,`fixture-${index}`]),fact});
    }
  }
  const frame={sessionUser:'zasp_test',role:'zasp_test',searchPath:'public',timeZone:'Etc/UTC',postgres:value.database.postgres,serverVersionNum:'180003',pgcrypto:'1.4',readOnly:false};
  return Buffer.from(JSON.stringify({
    format:'ordered-current-private-successor-reference-v1',status:'LOCAL-REFERENCE-ONLY',installable:false,captureStatus:'CAPTURED-UNBOUND',variant:'A',sessionUser:'zasp_test',packetSHA256:sha(Buffer.from(JSON.stringify(value))),sourcePins:value.sourcePins,helperPins:value.helperPins,ddlSHA256:value.ddl.sha256,querySHA256:value.collector.sha256,postgres:frame.postgres,serverVersionNum:'180003',pgcrypto:'1.4',originalFrame:frame,collectorFrame:{...frame,role:'zasp_discovery_authority',searchPath:'pg_catalog',timeZone:'UTC'},readOnly:false,originalAdmission:true,writeRollback:true,readOnlyPostAdmission:true,postAdmission:true,readRollback:true,namespaceAbsent:true,frameRestored:true,expectedManifestRows:0,registrationRows:0,publication:{mode:'0600',atomicNoOverwrite:true},rows,
  })+'\n');
}

test('checks all 57 rows and witnesses but keeps captured facts unbound', {skip:!sourceAvailable}, ()=>{
  const value=packet??buildOrderedCurrentPrivateSuccessorCaptureV1(exactInputs());
  const raw=shapedReference(value);
  const checked=checkOrderedCurrentPrivateSuccessorReferenceV1(raw,value);
  assert.equal(checked.valid,true);
  assert.equal(checked.validatedRoutineCount,22);
  assert.equal(checked.nonroutineCount,35);
  assert.equal(checked.installable,false);
  assert.equal(checked.captureStatus,'CAPTURED-UNBOUND');
  assert.equal(checked.facts.length,35);
  assert.ok(checked.facts.every(row=>row.kind!=='routine'));
  assert.ok(checked.facts.every(row=>value.rules.some(rule=>rule.id===JSON.parse(row.identity)[0]&&rule.kind!=='routine')));
  assert.throws(()=>admitOrderedCurrentPrivateSuccessorReferenceV1(raw,{referenceFileSHA256:sha(raw)}),/caller input/);
  const admitted=admitOrderedCurrentPrivateSuccessorReferenceV1();
  assert.equal(admitted.nonroutineCount,35);
  assert.equal(admitted.validatedRoutineCount,22);
  const base=JSON.parse(raw);
  const mutations=[
    value=>{value.rows.pop();},
    value=>{value.rows.push(value.rows[0]);},
    value=>{value.rows[0].fact.source+=' changed';},
    value=>{value.rows[22].fact.unknown=true;},
    value=>{value.writeRollback=false;},
    value=>{value.collectorFrame.searchPath='public';},
    value=>{value.packetSHA256='0'.repeat(64);},
    value=>{value.publication.mode='0644';},
  ];
  for(const mutate of mutations){const changed=structuredClone(base);mutate(changed);assert.throws(()=>checkOrderedCurrentPrivateSuccessorReferenceV1(Buffer.from(JSON.stringify(changed)+'\n'),value),/reference/);}
  const duplicate=raw.toString().replace('"format":','"format":"duplicate","format":');
  assert.throws(()=>checkOrderedCurrentPrivateSuccessorReferenceV1(Buffer.from(duplicate),value),/JSON|reference/);
  assert.throws(()=>parseOrderedCurrentPrivateSuccessorReferenceJSONV1(Buffer.from('[1,2]'),{maxContainerItems:1}),/bounded container/);
  assert.throws(()=>parseOrderedCurrentPrivateSuccessorReferenceJSONV1(Buffer.from('{"a":1,"b":2}'),{maxNodes:2}),/bounded structure/);
  const vendored=new URL('./ordered-current-capture-intake-v1-artifacts/private-successor-reference.json',import.meta.url);
  assert.equal(sha(fs.readFileSync(vendored)),'b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80');
});

test('serializes and exclusively materializes the complete packet owner-only', {skip:!sourceAvailable}, ()=>{
  const value=packet??buildOrderedCurrentPrivateSuccessorCaptureV1(exactInputs());
  const serialized=serializeOrderedCurrentPrivateSuccessorCaptureV1(value);
  assert.equal(serialized.sha256,sha(serialized.raw));
  assert.ok(serialized.bytes>65536);
  assert.ok(serialized.bytes<=value.limits.maxBytes);
  assert.equal(serialized.raw.at(-1),10);
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-private-successor-packet-'));
  const written=materializeOrderedCurrentPrivateSuccessorCaptureV1(value,directory);
  assert.equal(written.sha256,serialized.sha256);
  assert.equal(fs.statSync(written.path).mode&0o777,0o600);
  assert.deepEqual(materializeOrderedCurrentPrivateSuccessorCaptureV1(value,directory),written);
  fs.writeFileSync(written.path,Buffer.from('mismatch'));
  assert.throws(()=>materializeOrderedCurrentPrivateSuccessorCaptureV1(value,directory),/overwrite/);
});
