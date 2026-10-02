import assert from 'node:assert/strict';
import test from 'node:test';
import {compileOrderedCollector,compileOrderedDirectFrameCollectorV1} from './ordered-current-catalog.mjs';
import {directFrameAdaptersV1,directFrameAdmissionSQL,directFrameRulesV1} from './ordered-current-direct-frame-v1.mjs';

const occurrences=(value,needle)=>value.split(needle).length-1;

test('fixed direct-frame compiler gates every per-rule fact projection before adapter invocation',()=>{
 const rules=structuredClone(directFrameRulesV1),compiled=compileOrderedDirectFrameCollectorV1(rules);
 assert.equal(compiled.directFrameVersion,1);
 assert.equal(compiled.installable,false);
 assert.equal(compiled.ruleFieldMatrix.length,50);
 assert.equal(compiled.admissionSQL,directFrameAdmissionSQL);
 assert.equal(occurrences(compiled.sql,'CROSS JOIN direct_frame_admission admission'),50);
 assert.equal(occurrences(compiled.sql,'WHERE admission.admitted IS TRUE'),50);
 assert.equal(occurrences(compiled.sql,'CASE WHEN admission.admitted IS TRUE'),rules.reduce((sum,rule)=>sum+rule.fields.length,0));
 for(const adapter of directFrameAdaptersV1)assert.ok(compiled.sql.includes(adapter.name+'('));
});

test('fixed direct-frame compiler keeps canonical identities and selectors outside framed leaves',()=>{
 const rules=structuredClone(directFrameRulesV1),baseline=compileOrderedCollector(rules),framed=compileOrderedDirectFrameCollectorV1(rules);
 for(const rule of rules){
  const identity="'['||pg_catalog.to_json('"+rule.id+"'::text)::text||','||pg_catalog.to_json(identity)::text||']' AS identity";
  assert.ok(baseline.sql.includes(identity));
  assert.ok(framed.sql.includes(identity));
 }
 for(const cte of framed.sql.split(/direct_frame_\d+ AS MATERIALIZED/).slice(1)){
  const [select,tail]=cte.split(' AS fact FROM ');
  assert.doesNotMatch(select.slice(0,select.indexOf('pg_catalog.jsonb_build_object')),/zasp_authorization80_ordered_current\.[a-z_]+\(/);
  assert.doesNotMatch(tail.split('),\n',1)[0],/zasp_authorization80_ordered_current\.[a-z_]+\(/);
 }
});

test('fixed direct-frame compiler refuses altered or partial universes',()=>{
 const missing=structuredClone(directFrameRulesV1);missing.pop();
 assert.throws(()=>compileOrderedDirectFrameCollectorV1(missing),/direct frame v1 rule coverage/);
 const changed=structuredClone(directFrameRulesV1);changed[0].selector={field:'namespace',equals:'other'};
 assert.throws(()=>compileOrderedDirectFrameCollectorV1(changed),/direct frame v1 rule binding/);
});
