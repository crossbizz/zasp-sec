import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as worker from './ordered-current-worker-selectors.mjs';
import * as catalogTools from './ordered-current-catalog.mjs';
const {compileOrderedCollector,projectOrderedFacts}=catalogTools;
const evidence=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contract=JSON.parse(fs.readFileSync(new URL('ordered-current-effective-contract3.json',evidence)));
const catalog=JSON.parse(fs.readFileSync(new URL('ordered-current-effective-catalog1.json',evidence)));

test('native18 RED source-built test74 successor is required from the pinned 0074 stop source',()=>{
  assert.equal(typeof worker.buildOrderedWorkerTest74StopEvidenceSource,'function');
  const built=worker.buildOrderedWorkerTest74StopEvidenceSource(catalog);
  assert.equal(built.identity,'zasp_authorization80_worker.test74_stop_evidence(text,text,text,text)');
  assert.equal(built.owner,'zasp_discovery_authority');
  assert.match(built.definition,/CREATE OR REPLACE FUNCTION zasp_authorization80_worker\.test74_stop_evidence/);
  assert.match(built.definition,/parent_valid:=true;/);
  assert.equal(worker.buildOrderedWorkerTest74StopEvidenceSource({...catalog,functions:catalog.functions.filter(row=>row.identity!=='zasp_temporal74.stop_evidence(text,text,text,text)')}),null);
});
test('native18 source replay refuses mutated or ambiguous anchors and round-trips the exact body',()=>{
  const base=catalog.functions.find(row=>row.identity==='zasp_temporal74.stop_evidence(text,text,text,text)');
  assert.ok(base);
  assert.throws(()=>worker.buildOrderedWorkerTest74StopEvidenceSource({...catalog,functions:[...catalog.functions,{...base}]}),/cardinality/);
  assert.throws(()=>worker.buildOrderedWorkerTest74StopEvidenceSource({...catalog,functions:catalog.functions.map(row=>row===base?{...row,definition:row.definition.replace(' IF t.run_id IS NULL',' IF t.run_id IS NULL OR false')}:row)}),/anchor/);
  const built=worker.buildOrderedWorkerTest74StopEvidenceSource(catalog);
  assert.equal(built.sourceClosure.transform,'go-authorizationWorkerStopSuccessor-v1');
  const armStart=built.definition.indexOf(' -- A verified late receipt');
  const armEnd=built.definition.indexOf(' IF t.run_id IS NULL',armStart);
  assert.ok(armStart>0&&armEnd>armStart);
  const restored=(built.definition.slice(0,armStart)+built.definition.slice(armEnd))
    .replace('FUNCTION zasp_authorization80_worker.test74_stop_evidence(','FUNCTION zasp_temporal74.stop_evidence(');
  assert.equal(restored,base.definition);
  assert.throws(()=>worker.buildOrderedWorkerTest74StopEvidenceSource({...catalog,functions:catalog.functions.map(row=>row===base?{...row,definition:row.definition.replace('r text)','r integer)')}:row)}),/signature/);
});
test('native18 source closure bridges Go scopes to catalog deparse and refuses incomplete provenance',()=>{
  const built=worker.buildOrderedWorkerTest74StopEvidenceSource(catalog);
  const closure=built.sourceClosure;
  assert.equal(Object.keys(closure.workerSQL).length,41);
  assert.equal(Object.keys(closure.generatorInputs).length,1);
  assert.equal(closure.generatorInputs['0080_authorization_worker_ordered_current_integrity.sql'],'d42d975c4b9cbadf7c5b368d4f14b361cd917c65a114d9629307e73af3021e5f');
  assert.equal(closure.generatorInputRoles['0080_authorization_worker_ordered_current_integrity.sql'],'node-generator-template');
  assert.equal(closure.execution.owner,'zasp_discovery_authority');
  assert.equal(closure.execution.acl,'{zasp_discovery_authority=X/zasp_discovery_authority}');
  assert.equal(closure.deparseBridge.mapping.byteForByte,true);
  assert.equal(closure.deparseBridge.mapping.predecessor.rawBodySHA256,'43dc8b5918df21c0419e4f1f9e0d5f1ecbe8596d02a919d6dee09767f2d4bc8e');
  assert.equal(closure.deparseBridge.mapping.successor.rawBodySHA256,'f6922e090b12778964641be3b3f2491f11c022eb14e9d554c550a5e77d5d849a');
  assert.deepEqual(closure.deparseBridge.successor.insertedArm,[1513,2097]);
  for(const mutate of [
    c=>c.goInputs['production_authorization_worker_profile.go']='0'.repeat(64),
    c=>c.temporal74Inputs['0074_production_temporal_test_executor.up.sql']='0'.repeat(64),
    c=>c.workerSQL['0080_authorization_worker_profile.sql']='0'.repeat(64),
    c=>c.generatorInputs['0080_authorization_worker_ordered_current_integrity.sql']='0'.repeat(64),
    c=>c.generatorInputRoles['0080_authorization_worker_ordered_current_integrity.sql']='go-assembly',
    c=>{const value=c.goInputs['production_authorization_worker_profile.go'];delete c.goInputs['production_authorization_worker_profile.go'];c.goInputs['bogus.go']=value;},
    c=>{const value=c.workerSQL['0080_authorization_worker_profile.sql'];delete c.workerSQL['0080_authorization_worker_profile.sql'];c.workerSQL['0080_authorization_worker_replacement.sql']=value;},
    c=>{const entries=Object.entries(c.workerSQL).reverse();c.workerSQL=Object.fromEntries(entries);}
  ]) {
    const mutant=structuredClone(closure); mutate(mutant);
    assert.throws(()=>worker.assertNative18WorkerClosure(mutant));
  }
  for(const mutate of [
    c=>delete c.goInputs['production_temporal_test_executor.go'],
    c=>delete c.workerSQL['0080_authorization_worker_profile.sql'],
    c=>c.workerSQL['0080_authorization_worker_extra.sql']='0'.repeat(64),
    c=>c.rawScopes.successorBody.span=[1,6825],
    c=>c.execution.frame='wrong-frame',
    c=>c.builder.compiler='wrong-compiler',
    c=>c.deparseBridge.mapping.successor.rawBodySHA256='0'.repeat(64)
  ]) {
    const mutant=structuredClone(closure); mutate(mutant);
    assert.throws(()=>worker.assertNative18WorkerClosure(mutant));
  }
});
test('worker lowering accounts for every original fact branch and exact source identity',()=>{
  assert.equal(typeof worker.lowerOrderedWorkerCatalog,'function');
  const lowered=worker.lowerOrderedWorkerCatalog(contract,catalog);
  assert.deepEqual(lowered.sites.map(s=>s.line),[2,4,5,6,7,8,9,10,11,12,15,16,17,18,19,20,21,22,23,24,25,26,27,31,32,33,34,35,36,37,38,39,40,41]);
  assert.equal(lowered.rules.length,34);
  assert.equal(lowered.obligations.length,2);
  assert.doesNotThrow(()=>compileOrderedCollector(lowered.rules));
  const changed=structuredClone(contract);changed.nodes.find(n=>n.identity===lowered.identity).source+=' ';
  assert.throws(()=>worker.lowerOrderedWorkerCatalog(changed,catalog),/source/);
  const missing=structuredClone(catalog);missing.functions=missing.functions.filter(f=>f.identity!=='public.zasp_runtime_finish_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)');
  assert.throws(()=>worker.lowerOrderedWorkerCatalog(contract,missing),/routine/);
});
test('worker trigger projection retains function facts only at original selected sites',()=>{
  assert.equal(typeof worker.lowerOrderedWorkerCatalog,'function');
  const {rules}=worker.lowerOrderedWorkerCatalog(contract,catalog);
  const input=[{kind:'trigger',identity:'stage',namespace:'public',relation:'public.zasp_runtime_stage_work',name:'zasp_authorization80_runtime_stage_insert',fact:{enabled:'O',definition:'trigger',function_definition:'body',function_owner:'owner',function_acl:null}},{kind:'trigger',identity:'run',namespace:'public',relation:'public.zasp_security_agent_runs',name:'zasp_authorization80_worker_run_capture',fact:{enabled:'O',definition:'trigger',function_definition:'irrelevant',function_owner:'owner',function_acl:null}}];
  const rows=projectOrderedFacts(rules.filter(r=>[23,32,36].includes(Number(r.id.split('-').at(-1)))),input);
  assert.equal(rows.length,3);
  assert.equal(rows.filter(r=>Object.hasOwn(r.fact,'function_definition')).length,2);
  assert.deepEqual(rows.find(r=>r.identity.includes('line-36')).fact,{enabled:'O',definition:'trigger'});
});
test('independent reference descriptors connect all worker branches without inventing values',()=>{
  assert.equal(typeof catalogTools.orderedReferenceInput,'function');
  const {rules}=worker.lowerOrderedWorkerCatalog(contract,catalog);
  const input=catalogTools.orderedReferenceInput(catalog);
  const rows=projectOrderedFacts(rules,input);
  for(const rule of rules)assert.ok(rows.some(row=>JSON.parse(row.identity)[0]===rule.id),'unrepresented '+rule.id);
  assert.ok(rows.length>1168);
  assert.equal(rows.filter(row=>row.kind==='worker_registration').length,1);
  assert.deepEqual(Object.keys(rows.find(row=>row.kind==='worker_registration').fact),['fingerprint']);
  const missing=structuredClone(catalog);missing.functions=missing.functions.filter(f=>f.identity!==catalog.triggers.find(t=>t.name==='zasp_authorization80_runtime_stage_insert').function);
  assert.throws(()=>projectOrderedFacts(rules,catalogTools.orderedReferenceInput(missing)),/missing required/);
});
