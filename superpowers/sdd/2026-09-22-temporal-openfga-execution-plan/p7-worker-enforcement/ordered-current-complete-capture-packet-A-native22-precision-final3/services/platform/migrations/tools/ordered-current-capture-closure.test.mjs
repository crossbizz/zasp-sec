import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {buildOrderedCaptureClosure,assertOrderedCaptureClosure} from './ordered-current-capture-closure.mjs';
import {buildOrderedConsolidationNeeds} from './ordered-current-consolidation-needs.mjs';
import {prepareOrderedCaptureRule,compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';
const base=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const artifactNames=Object.freeze({'ordered-current-effective-contract3.json':'effective-contract3.json','ordered-current-effective-catalog1.json':'effective-catalog1.json','ordered-current-supplementary-reference1.json':'supplementary-reference1.json','ordered-current-remaining-reference1.json':'remaining-reference1.json','ordered-current-private-reference-alias1.json':'private-reference-alias1.json'});
const read=name=>fs.readFileSync(new URL(artifactNames[name],base));
const sourceContract=JSON.parse(read('ordered-current-effective-contract3.json'));
const catalog=JSON.parse(read('ordered-current-effective-catalog1.json'));
const acceptedEvidence=Object.fromEntries(['ordered-current-effective-catalog1.json','ordered-current-supplementary-reference1.json','ordered-current-remaining-reference1.json','ordered-current-private-reference-alias1.json'].map(name=>[name,read(name)]));
const input={sourceContract,catalog,acceptedEvidence};

test('audit none branch requires namespace, cast and trigger observations independently',()=>{
 const c=buildOrderedCaptureClosure(input),identity='zasp_authorization80.runtime_audit_ready()';
 const site=c.requiredIndex.find(s=>s.sourceIdentity===identity&&s.start===230&&s.end===461);
 assert.ok(site,'none branch must have its own required source entry');
 const expected=[['wrapper:runtime-audit:none-namespace','namespace_identity'],['wrapper:runtime-audit:none-relation-resolution','resolvedIdentity'],['wrapper:runtime-audit:none-trigger-inputs','name']];
 for(const [ruleId,field]of expected){
  assert.ok(site.children.some(c=>c.ruleId===ruleId&&c.field===field));
  const broken=structuredClone(c);broken.rawRules=broken.rawRules.filter(r=>r.id!==ruleId);broken.entries=broken.entries.filter(e=>e.evidence.ruleId!==ruleId);
  for(const algebra of broken.runtimeAlgebra)algebra.children=algebra.children?.filter(c=>c.ruleId!==ruleId);
  assert.throws(()=>assertOrderedCaptureClosure(broken),/coverage|source/);
 }
 const namespace=c.rawRules.find(r=>r.id===expected[0][0]),trigger=c.rawRules.find(r=>r.id===expected[2][0]);
 assert.equal(namespace.sqlPhase,'witness');assert.equal(trigger.sqlPhase,'witness');
 assert.match(namespace.projections.at(-1),/CASE WHEN.*count\(\*\).*rp\.singleton.*rp\.audit_mode='none'.*THEN to_regnamespace/s);
 assert.match(trigger.from,/tgrelid=\(CASE WHEN.*THEN 'public\.zasp_admin_audit' ELSE NULL END\)::regclass/s);
 assert.match(trigger.from,/tgname='zasp_authorization80_audit_write_guard'/);
 assert.equal(c.rawRules.some(r=>r.id.startsWith('wrapper:runtime-audit:none-')&&r.fields.includes('ready')),false);
});

// A partial proposal must not pass by deleting the obligations that it cannot
// satisfy. This consumes actual admitted source/evidence, with no mock names.
test('the old fifty plus thirteen proposal is not a complete closure',()=>{
 assert.throws(()=>assertOrderedCaptureClosure(buildOrderedConsolidationNeeds(sourceContract,catalog).contract),/coverage|closure/);
});
test('complete missing-input ledger closes non-P delegates, higher regions and mixed inputs',()=>{
 const c=buildOrderedCaptureClosure(input);
 assert.equal(c.unresolved.length,0,JSON.stringify(c.unresolved.map(x=>({sourceIdentity:x.sourceIdentity,field:x.field,reason:x.reason}))));
 assert.equal(c.retainedOpaque.every(x=>x.sourceIdentity==='zasp_authorization80_worker.projected74()'),true);
 assert.equal(assertOrderedCaptureClosure(c),undefined);
 assert.equal(c.entries.some(x=>x.disposition==='capture'&&/migration_owned|member_result|guard_result/.test(x.field)),false);
});
test('an independent required index detects omitted fields and changed source/frame evidence',()=>{
 const c=buildOrderedCaptureClosure(input);
 for(const change of [x=>x.entries.splice(0,1),x=>x.entries[0].start++,x=>x.entries[0].frame.config=['search_path=public'],x=>x.sourcePins['ordered-current-effective-catalog1.json']='0'.repeat(64),x=>x.rawRules[0].fields.pop()]){
  const broken=structuredClone(c);change(broken);assert.throws(()=>assertOrderedCaptureClosure(broken),/coverage|frame|source|unresolved/);
 }
});
test('caller-supplied matching evidence hashes cannot replace fixed source files',()=>{
 const broken={...input,acceptedEvidence:{...acceptedEvidence,'ordered-current-remaining-reference1.json':Buffer.from('{}\n')}};
 assert.throws(()=>buildOrderedCaptureClosure(broken),/evidence|pin/);
 const altered=structuredClone(sourceContract);altered.higherRegions[0].prefix+=' ';assert.throws(()=>buildOrderedCaptureClosure({...input,sourceContract:altered}),/source|pin/);
});
test('every source entry carries the full original invocation frame and writer casts stay lazy',()=>{
 const c=buildOrderedCaptureClosure(input);
 for(const entry of c.entries){const node=sourceContract.nodes.find(n=>n.identity===entry.sourceIdentity);assert.ok(node);assert.deepEqual(entry.frame.config,node.config);assert.equal(entry.frame.language,node.language);assert.equal(entry.frame.owner,node.owner);}
 const writer=c.rawRules.filter(r=>r.id.includes(':helper-resolution:')&&!r.id.startsWith('materialized:'));
 assert.equal(writer.length,75);assert.ok(writer.every(r=>r.projections.at(-1).startsWith('(CASE WHEN ')));
 assert.ok(c.runtimeAlgebra.some(a=>a.disposition==='runtime-demanded-resolution-required'&&a.observedResolution===false));
});
test('source-child closure indexes every required source disposition and implicit field',()=>{
 const c=buildOrderedCaptureClosure(input);
 assert.ok(Array.isArray(c.sourceIndex),'recursive source index is required');
 const worker=c.sourceIndex.find(n=>n.sourceIdentity==='zasp_authorization80_worker.projected72()');
 assert.ok(worker.requiredSites.length>1);
 assert.ok(worker.sourceChildren.includes('public.zasp_inventory_live_fingerprint()'));
 const config=c.entries.find(e=>e.field==='config_bounds');
 assert.ok(c.sourceIndex.some(n=>n.requiredSites.some(s=>s.children.some(child=>child.ruleId===config.evidence.ruleId&&child.field==='config_bounds'))));
 for(const change of [x=>x.sourceIndex.find(n=>n.sourceIdentity===worker.sourceIdentity).requiredSites.pop(),x=>{const a=x.runtimeAlgebra.find(a=>a.children?.length);a.children[0].field='missing-capture-field';},x=>x.sourceIndex.find(n=>n.sourceIdentity===worker.sourceIdentity).sourceChildren=[]]){
  const broken=structuredClone(c);change(broken);assert.throws(()=>assertOrderedCaptureClosure(broken),/coverage|source|child/);
 }
});
test('worker catalog guard captures its complete nested recipe and original saved selectors',()=>{
 const c=buildOrderedCaptureClosure(input),worker=c.sourceIndex.find(n=>n.sourceIdentity==='zasp_authorization80_worker.catalog_ready()');
 assert.equal(worker.closed,true);
 const selected=c.rawRules.find(r=>r.id==='worker-catalog:line:5');
 assert.ok(selected.from.includes('SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions'));
 assert.ok(c.rawRules.some(r=>r.id==='worker-catalog:line:41'));
 for(const r of c.rawRules)assert.doesNotThrow(()=>compileOrderedCaptureRule(prepareOrderedCaptureRule(r)),r.id);
});
test('copied materialized SELECT branches have independent source and frame accounting',()=>{
 const c=buildOrderedCaptureClosure(input);
 assert.ok(c.materializedIndex?.length>200,'copied SELECT leaves need their own required index');
 assert.ok(c.materializedIndex.every(s=>s.sourceIdentity&&s.siteSHA256&&s.frame&&Array.isArray(s.children)));
 const broken=structuredClone(c);broken.materializedIndex.pop();assert.throws(()=>assertOrderedCaptureClosure(broken),/coverage|source/);
});
test('inlined budget, export and schedule branches bind exact fields and deferred guard children',()=>{
 const c=buildOrderedCaptureClosure(input);
 for(const [identity,start]of [['zasp_temporal68.predecessor_ready(text,text)',82109],['zasp_temporal68.predecessor_ready(text,text)',95647],['zasp_temporal68.predecessor_ready(text,text)',104270],['zasp_temporal77.base67_fingerprint()',70660],['zasp_temporal77.base67_fingerprint()',93510]]){
  const row=c.materializedIndex.find(r=>r.sourceIdentity===identity&&r.start===start);
  assert.equal(row?.disposition,'source-inlined-inputs',identity+':'+start);
  assert.ok(row.children.length>0);assert.ok(row.correspondence.length>0);
  assert.equal(row.evaluatorEquivalence,false);
 }
 const writer=c.sourceIndex.find(n=>n.sourceIdentity==='zasp_authorization80_worker.ordered_writer_definition(oid)');
 assert.ok(writer.requiredSites.length);assert.ok(writer.requiredSites.some(s=>s.children.some(r=>r.ruleId.includes(':helper-resolution:'))));
});
test('ready78 saved-current comparison retains absent bindings and source deparse demand',()=>{
 const c=buildOrderedCaptureClosure(input),r=c.rawRules.find(r=>r.id==='ready78:saved-current:bindings');
 assert.ok(r,'full saved-to-current comparison is required');
 assert.equal(r.bag,true);assert.match(r.from,/LEFT JOIN pg_proc p ON p.oid=to_regprocedure\(s.signature\)/);
 assert.ok(r.fields.includes('present'));assert.match(r.projections[r.fields.indexOf('definition')],/^CASE WHEN s.signature NOT IN/);
 const canonical=compileOrderedCaptureRule(prepareOrderedCaptureRule(c.rawRules.find(r=>r.id==='ready78:saved-current:routines')));
 assert.match(canonical.demand,/to_regprocedure\(signature\)/);assert.doesNotMatch(canonical.keys,/signature/);
 assert.match(canonical.original,/'identity',NULL/);
});
test('authorization conditional guards link static raw inputs without capturing verdicts',()=>{
 const c=buildOrderedCaptureClosure(input);
 for(const identity of ['zasp_authorization80_temporal.fingerprint()','zasp_authorization79.ready(text)','zasp_authorization79.fingerprint()']){
  const node=c.sourceIndex.find(n=>n.sourceIdentity===identity);assert.ok(node?.requiredSites.length,identity);
  assert.ok(node.sourceChildren.includes(identity.includes('ready')?'zasp_authorization79.fingerprint()':'zasp_authorization80_worker.catalog_ready()'));
 }
});
test('authorization80 catalog leaves use semantic object identities for source OID projections',()=>{
 const c=buildOrderedCaptureClosure(input),column=c.rawRules.find(r=>r.id==='authorization80:runtime-profile-column');
 assert.ok(column,'authorization80 raw catalog branches are required');
 assert.ok(column.fields.includes('type_identity'));assert.ok(column.fields.includes('typmod'));
 assert.equal(column.projections.includes('a.atttypid'),false);
 const trigger=c.rawRules.find(r=>r.id==='authorization80:hierarchy-trigger');
 for(const field of ['constraint_present','constraint_identity','constraint_relation_present','constraint_relation_identity','constraint_index_present','constraint_index_identity'])assert.ok(trigger.fields.includes(field));
 assert.equal(trigger.projections.includes('t.tgqual'),false);
 assert.ok(trigger.fields.includes('qual'));
 assert.match(trigger.projections[trigger.fields.indexOf('qual')],/^CASE WHEN t.tgqual IS NULL THEN NULL::text ELSE \(t.tgqual IS NULL\)::text::integer::text END$/);
 assert.doesNotMatch(trigger.from,/tgqual/);
 assert.equal(c.unresolved.some(u=>u.field==='hierarchy-trigger.tgqual'),false);
 assert.ok(c.rawRules.some(r=>r.id==='authorization80:runtime-profile-column:types'&&r.kind==='type'));
});
test('temporal capture-trigger guard binds selected raw trigger and callable inputs',()=>{
 const c=buildOrderedCaptureClosure(input),trigger=c.rawRules.find(r=>r.id==='authorization-temporal:triggers-ready:triggers');
 assert.ok(trigger);assert.match(trigger.from,/zasp_discovery_syncs/);assert.match(trigger.from,/zasp_authorization79_capture/);
 assert.ok(trigger.fields.includes('qual_is_null'));assert.ok(trigger.fields.includes('arguments'));
 const node=c.sourceIndex.find(n=>n.sourceIdentity==='zasp_authorization80_temporal.triggers_ready(boolean)');
 assert.equal(node.closed,true);
});
