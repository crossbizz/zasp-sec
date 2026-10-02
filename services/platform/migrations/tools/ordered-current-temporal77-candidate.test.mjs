import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const candidate=await import('./ordered-current-temporal77-candidate.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url)));
test('two77 candidate uses actual catalog OID correlation and selected local materialization only',()=>{
  assert.equal(typeof candidate.compileOrderedTemporal77Candidate,'function');
  const result=candidate.compileOrderedTemporal77Candidate(contract);
  assert.equal(result.installable,false);assert.equal(result.native_unverified,true);assert.equal(result.recipes,2);
  const sql=result.sql;
  assert.match(sql,/SELECT p\.oid AS live_oid/);
  assert.equal((sql.match(/WITH demanded AS MATERIALIZED/g)??[]).length,2);
  assert.equal((sql.match(/CASE WHEN p\.live_oid IS NULL THEN NULL::text\[\] ELSE ARRAY\[/g)??[]).length,2);
  assert.equal((sql.match(/\)::regprocedure\[\]::oid\[\] AS resolved/g)??[]).length,2);
  assert.match(sql,/SELECT p\.live_oid AS value/);
  assert.equal((sql.match(/WHEN p\.live_oid IN\(SELECT signature::regprocedure FROM zasp_temporal78\.predecessor_functions WHERE signature LIKE 'zasp_temporal77\.%'\)/g)??[]).length,2);
  assert.equal((sql.match(/WHEN d\.value = ANY\(d\.resolved\)/g)??[]).length,2);
  assert.doesNotMatch(sql,/ordered_writer_definition\(/);
  assert.doesNotMatch(sql,/\b(?:SET|set_config|EXECUTE)\b/);
  assert.doesNotMatch(sql,/'live_oid'|'oid'|'resolved'/);
  assert.doesNotMatch(sql,/pg_get_functiondef\(p\.oid\)/,'raw deparse is not precomputed before CASE');
  assert.match(sql,/pg_catalog\.pg_get_functiondef\(p\.live_oid\)/);
  assert.equal((sql.match(/pg_catalog\.replace\(/g)??[]).length,4);
  assert.equal(result.helperBindings.length,15);
  assert.ok(result.gates.some(g=>g.includes('first-error')));
});
test('source and frame changes cannot produce an installable or less-correlated candidate',()=>{
  assert.equal(typeof candidate.compileOrderedTemporal77Candidate,'function');
  for(const change of [
    c=>{c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').config=['search_path=public'];},
    c=>{c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').source+=' ';},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal78.predecessor77_fingerprint()').source=c.nodes.find(n=>n.identity==='zasp_temporal78.predecessor77_fingerprint()').source.replace("signature LIKE 'zasp_temporal77.%'","signature LIKE 'zasp_temporal77x%'");},
  ]){const changed=structuredClone(contract);change(changed);assert.throws(()=>candidate.compileOrderedTemporal77Candidate(changed));}
  assert.deepEqual(candidate.compileOrderedTemporal77Candidate(contract),candidate.compileOrderedTemporal77Candidate(contract));
});
