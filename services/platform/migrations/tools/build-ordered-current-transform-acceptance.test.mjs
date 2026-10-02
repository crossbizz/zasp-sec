import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {splitTransformBranch,originalTransformProjection,validateTransformConfigWitnesses,buildOrderedTransformAcceptance} from './build-ordered-current-transform-acceptance.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
const bytes=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(bytes),temporal=lowerOrderedTemporalTransforms(contract),pub=lowerOrderedPublicFunctionTransforms(contract);
const all=[...temporal.recipes,...pub.recipes],sites=[...temporal.sites,...pub.sites];
test('original field splitter retains nested commas, literal commas/quotes and original FROM bytes',()=>{
  const s=" UNION ALL SELECT concat_ws('|','function',p.proname,replace('a,b''c',',',';'),(SELECT value FROM t WHERE a=1)) FROM pg_proc p WHERE p.oid='x()'::regprocedure";
  const out=splitTransformBranch(s);
  assert.deepEqual(out.expressions,['p.proname',"replace('a,b''c',',',';')",'(SELECT value FROM t WHERE a=1)']);
  assert.equal(out.tail," FROM pg_proc p WHERE p.oid='x()'::regprocedure");
  assert.equal(out.line,"concat_ws('|','function',p.proname,replace('a,b''c',',',';'),(SELECT value FROM t WHERE a=1))");
});
test('original projection consumes source fields not recipe ASTs, preserving original helper calls',()=>{
  for(const r of all){const site=sites.find(s=>s.sha256===r.siteSHA256),fields=Object.keys(r.fields),out=originalTransformProjection(site,fields);assert.ok(out.includes('p.oid::text'));assert.ok(out.includes(splitTransformBranch(site.text).tail));assert.equal(splitTransformBranch(site.text).expressions.length,fields.length);if(r.ruleId.startsWith('public:'))assert.ok(out.includes(`public.zasp_${site.family}_function_identity(p.oid)`));assert.ok(!out.includes('transform_inputs'));}
  const r=all.find(r=>r.ruleId==='temporal:74.owner66_fingerprint:function'),s=sites.find(s=>s.sha256===r.siteSHA256);
  assert.ok(originalTransformProjection(s,Object.keys(r.fields)).includes("(SELECT acl FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_temporal66.legacy_visible(text,text,text,text)')"));
});
test('splitter refuses unbalanced, comments, alternate labels, missing FROM or extra statements',()=>{
  for(const s of ["SELECT concat_ws('|','function',p.name FROM pg_proc p", "SELECT concat_ws('|','other',p.name) FROM pg_proc p", "SELECT concat_ws('|','function',p.name)", "SELECT concat_ws('|','function',p.name) FROM pg_proc p;SELECT 1", "SELECT concat_ws('|','function',p.name/*x*/) FROM pg_proc p"] )assert.throws(()=>splitTransformBranch(s));
});
test('projection rejects source tamper and arity changes rather than dropping fields',()=>{
  const r=all[0],s=sites.find(s=>s.sha256===r.siteSHA256),fields=Object.keys(r.fields);
  assert.throws(()=>originalTransformProjection({...s,text:s.text+' '},fields));
  assert.throws(()=>originalTransformProjection(s,fields.slice(1)));
  assert.throws(()=>originalTransformProjection(s,[...fields,'extra']));
  assert.throws(()=>originalTransformProjection(s,['a',...fields.slice(1).map(()=> 'a')]));
});
test('actual witness consumer requires original text equality and distinct verified nonstandard refusal',()=>{
  const normal={objectOID:'42',identity:'public.f()',config:['search_path=pg_catalog, public'],dimensions:1,lowerBound:1,upperBound:1,originalText:'{"search_path=pg_catalog, public"}'};
  assert.deepEqual(validateTransformConfigWitnesses([normal],false),{compared:1,refused:0});
  assert.deepEqual(validateTransformConfigWitnesses([{...normal,lowerBound:0,upperBound:0,originalText:'[0:0]={"search_path=pg_catalog, public"}'}],true),{compared:0,refused:1});
  for(const rows of [[{...normal,originalText:'made-up'}],[{...normal,dimensions:null}],[{...normal,identity:''}],[normal,normal],[{...normal,extra:'hidden'}],[]])assert.throws(()=>validateTransformConfigWitnesses(rows,false));
  assert.throws(()=>validateTransformConfigWitnesses([normal],true));
});
test('connected thirteen packet has actual typed SQL, separate raw query and complete closed fault matrix',()=>{
  const p=buildOrderedTransformAcceptance(contract);assert.equal(p.rules.length,13);assert.equal(p.maxRows,380);assert.equal(p.compiledSHA256,'981a36a06bdb553b32f88243e4f8fdc5e55df2d2d2c70739cb8221c7cf7bea1e');
  assert.deepEqual(p.cases.map(c=>c.id),['pristine','config-null','config-empty','config-quoted','config-nonstandard','owner','acl','replacement','constraint-duplicate','constraint-null','saved-missing','saved-null-definition','saved-null-acl','saved-duplicate-definition','saved-duplicate-acl','saved-unselected-duplicate','saved-missing-column','saved-missing-relation','literal-missing']);
  assert.equal(p.cases.find(c=>c.id==='config-nonstandard').expectNonstandard,true);
  assert.equal(p.cases.find(c=>c.id==='saved-duplicate-definition').sqlState,'21000');
  assert.equal(p.cases.find(c=>c.id==='saved-missing-column').sqlState,'42703');
  assert.equal(p.cases.find(c=>c.id==='constraint-null').sqlState,'23502');
  assert.ok(p.cases.filter(c=>c.id!=='pristine').every(c=>c.write));
  assert.ok(p.cases.every(c=>c.ruleIDs.every(id=>p.rules.some(r=>r.id===id))));
  assert.deepEqual(p.reserved,['temporal77-demand-boundary']);assert.ok(p.rules.every(r=>r.originalSQL.includes('object_oid')&&r.candidateSQL.includes('transform_inputs')));
  for(const r of p.rules){
    assert.equal(r.originalAggregateSQL,"SELECT pg_catalog.string_agg(line,E'\\n' ORDER BY line) FROM ("+r.originalSQL+") original_lines");
    assert.equal(r.candidateAggregateSQL,"SELECT pg_catalog.string_agg(line,E'\\n' ORDER BY line) FROM ("+r.candidateSQL+") candidate_lines");
  }
});
