import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {privateObjectRules} from './ordered-current-private.mjs';
const reader=await import('./ordered-current-private-reference.mjs').catch(()=>({}));
const evidence=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const raw=fs.readFileSync(new URL('ordered-current-private-reference-alias1.json',evidence));
const contractRaw=fs.readFileSync(new URL('ordered-current-private-reference-alias-contract.json',evidence));
const templateRaw=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url));
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
const pins=()=>({referenceFileSHA256:'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607',contractRaw,templateRaw,currentRules:privateObjectRules(),variant:'A',sessionUser:'zasp_test'});
const encode=value=>Buffer.from(JSON.stringify(value)+'\n');
const admit=value=>reader.checkOrderedPrivateReferenceContent(encode(value),pins());
test('accepted39 private facts validate completely and only35 explicit nonroutine facts are imported',()=>{
  assert.equal(typeof reader.admitOrderedPrivateReference,'function');
  const result=reader.admitOrderedPrivateReference(raw,pins());
  assert.equal(result.facts.length,35);
  assert.equal(result.validatedRoutineCount,4);
  assert.ok(result.facts.every(row=>row.kind!=='routine'));
  assert.deepEqual(result.categoryCounts,{routine:4,namespace:1,relation:4,column:10,constraint:14,index:2,type:4});
  assert.deepEqual(new Set(result.facts.map(row=>JSON.parse(row.identity)[0])),new Set(['private-namespace','private-relation','private-column','private-constraint','private-index','private-type']));
  const expected=JSON.parse(raw).rows.filter(row=>row.kind!=='routine');
  for(const row of expected)assert.deepEqual(result.facts.find(r=>r.kind===row.kind&&r.identity===row.identity),row);
  assert.equal(result.installable,false);
  assert.equal(result.contractFileSHA256,'59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63');
});
test('missing categories, duplicate keys, altered frozen routine fields and unselected fields refuse before import',()=>{
  assert.equal(typeof reader.admitOrderedPrivateReference,'function');
  for(const mutate of [
    ref=>{ref.rows=ref.rows.filter(row=>row.kind!=='namespace');},
    ref=>{ref.rows.pop();},
    ref=>{ref.rows[1]=structuredClone(ref.rows[0]);},
    ref=>{ref.rows.find(row=>row.kind==='routine').fact.source+=' ';},
    ref=>{ref.rows.find(row=>row.kind==='routine').fact.config=['search_path=pg_catalog, public'];},
    ref=>{ref.rows.find(row=>row.kind==='routine').fact.acl=null;},
    ref=>{ref.rows.find(row=>row.kind==='routine').fact.default_count=1;},
    ref=>{ref.rows.find(row=>row.kind==='routine').fact.result_type='oid';},
    ref=>{ref.rows.find(row=>row.kind==='namespace').fact.extra=true;},
    ref=>{ref.rows.find(row=>row.kind==='relation').fact.row_security='false';},
    ref=>{ref.rows.find(row=>row.kind==='namespace').identity='["other-namespace","zasp_authorization80_ordered_current"]';},
  ]){const ref=JSON.parse(raw);mutate(ref);assert.throws(()=>admit(ref));}
});
test('immutable provenance, exact frame, rollback witnesses and current declaration compatibility refuse changes',()=>{
  assert.equal(typeof reader.admitOrderedPrivateReference,'function');
  for(const mutate of [
    ref=>{ref.contractSHA256='0'.repeat(64);},ref=>{ref.ddlSHA256='0'.repeat(64);},ref=>{ref.querySHA256='0'.repeat(64);},ref=>{ref.snapshotSHA256='0'.repeat(64);},
    ref=>{ref.originalAdmission=false;},ref=>{ref.postAdmission=false;},ref=>{ref.writeRollback=false;},ref=>{ref.readRollback=false;},ref=>{ref.namespaceAbsent=false;},ref=>{ref.frameRestored=false;},
    ref=>{ref.readOnly=true;},ref=>{ref.expectedManifestRows=1;},ref=>{ref.registrationRows=1;},
    ref=>{ref.collectorFrame.searchPath='pg_catalog, public';},ref=>{ref.collectorFrame.role='zasp_test';},ref=>{ref.collectorFrame.readOnly=true;},ref=>{ref.collectorFrame.timeZone='America/Los_Angeles';},
    ref=>{ref.collectorFrame.postgres='PostgreSQL 18.3 other build';},ref=>{ref.serverVersionNum='180002';},ref=>{ref.variant='B';},ref=>{ref.extra=true;},
  ]){const ref=JSON.parse(raw);mutate(ref);assert.throws(()=>admit(ref));}
  assert.throws(()=>reader.admitOrderedPrivateReference(raw,{...pins(),referenceFileSHA256:'0'.repeat(64)}));
  assert.throws(()=>reader.admitOrderedPrivateReference(raw,{...pins(),contractRaw:Buffer.from('{}')}));
  assert.throws(()=>reader.admitOrderedPrivateReference(raw,{...pins(),templateRaw:Buffer.concat([templateRaw,Buffer.from(' ')])}));
  const changed=pins();changed.currentRules[0].fields.push('name');assert.throws(()=>reader.admitOrderedPrivateReference(raw,changed));
});
test('publisher framing and nested duplicate JSON keys refuse despite a caller matching the byte hash',()=>{
  assert.equal(typeof reader.admitOrderedPrivateReference,'function');
  for(const bytes of [raw.subarray(0,-1),Buffer.concat([raw,Buffer.from('\n')]),Buffer.concat([raw.subarray(0,-1),Buffer.from(' \n')]),Buffer.from(raw.toString().replace('"frameRestored":true','"frameRestored":false,"frameRestored":true'))]){
    assert.notDeepEqual(bytes,raw);
    assert.throws(()=>reader.checkOrderedPrivateReferenceContent(bytes,pins()));
  }
});
test('a caller cannot repin modified nonroutine facts into an accepted private reference',()=>{
  const ref=JSON.parse(raw);ref.rows.find(row=>row.kind==='namespace').fact.owner='other_owner';
  const bytes=encode(ref);
  assert.throws(()=>reader.admitOrderedPrivateReference(bytes,{...pins(),referenceFileSHA256:sha(bytes)}),/file pin/);
});
