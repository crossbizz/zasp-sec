import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {buildOrderedRecursiveCaptureInputs} from './ordered-current-capture-recursive-inputs.mjs';
import {compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contractRaw=fs.readFileSync(new URL('ordered-current-effective-contract3.json',base));
const catalogRaw=fs.readFileSync(new URL('ordered-current-effective-catalog1.json',base));
assert.equal(sha(contractRaw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
assert.equal(sha(catalogRaw),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
const contract=JSON.parse(contractRaw),catalog=JSON.parse(catalogRaw);

const conditionalTargets={
 '65.fingerprint':['zasp_temporal74.fingerprint()','zasp_temporal74.outbox65_fingerprint()'],
 '66.fingerprint':['zasp_temporal74.fingerprint()','zasp_temporal74.owner66_fingerprint()'],
 '67.base_fingerprint':['zasp_temporal77.catalog_ready()','zasp_temporal77.base67_fingerprint()'],
 '67.fingerprint':['zasp_temporal77.catalog_ready()','zasp_temporal77.domain67_fingerprint()'],
 '69.fingerprint':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected69()'],
 '72.fingerprint':['zasp_authorization80_temporal.catalog_ready()','zasp_authorization80_temporal.projected72()'],
 '73.fingerprint':['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor73_fingerprint()'],
 '74.fingerprint':['zasp_temporal76.catalog_ready()','zasp_temporal76.executor74_fingerprint()'],
 '76.executor74_fingerprint':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected74()'],
 '76.fingerprint':['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor76_fingerprint()'],
 '77.fingerprint':['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor77_fingerprint()'],
 '78.fingerprint':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected78()']
};
const publicTargets={
 'public.zasp_recovery_execution_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.gateway_projected27()'],
 'public.zasp_security_agent_session_isolation_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.gateway_projected24()'],
 'public.zasp_policy_deployment_execution_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.ordered_projected28()'],
 'public.zasp_production_runtime_sessions_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.runtime_projected40()']
};
const additionalTargets={
 'zasp_authorization80_temporal.projected68()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected68()'],
 'zasp_ordered_public62.fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected62()'],
 'public.zasp_execution_live_fingerprint()':['zasp_temporal72.fingerprint()','zasp_temporal72.retained_execution_fingerprint()'],
 'public.zasp_production_runtime_precision_live_fingerprint()':['zasp_temporal72.fingerprint()','zasp_temporal72.retained_precision_fingerprint()']
};
const rawIds=[
 'recursive:predecessor68:routine','recursive:ready68:routine','recursive:ready78:routine','recursive:base67:routine',
 'recursive:native-role-shape:roles','recursive:native-role-shape:membership','recursive:schema-metadata:normalization-input',
 'recursive:worker-catalog-ready:routine','recursive:worker-catalog-ready:definition','recursive:worker-catalog-ready:registration',
 'recursive:worker-catalog-ready:literal-resolution','recursive:temporal74:registration',
 'recursive:temporal76:registration','recursive:temporal77:registration','recursive:temporal78:registration',
 'recursive:authorization80-temporal:registration','recursive:roles-ready:roles',
 'recursive:roles-ready:membership','recursive:roles-ready:bindings',
 'recursive:temporal68:registration','recursive:temporal69:registration','recursive:temporal70:registration',
 'recursive:temporal71:registration','recursive:temporal72:registration','recursive:temporal73:registration',
 'recursive:temporal75:registration','recursive:authorization79:registration','recursive:authorization80:registration'
];
const ownRoutineFields=['routine_identity','definition','source_body','owner','raw_acl','language','volatility','security_definer','strict','parallel','leakproof','config_json','config_raw','config_dims','config_ndims','config_bounds','identity_arguments','result','cost','rows'];

test('recursive capture descriptors preserve bounded source descendants without freezing live verdicts',async t=>{
 const out=buildOrderedRecursiveCaptureInputs(contract,catalog);

 await t.test('anchors every owned raw leaf to its exact source and emits compilable bounded rules',()=>{
  assert.deepEqual(out.rawRules.map(rule=>rule.id),rawIds);
  assert.deepEqual(out.unresolved,[]);
  assert.equal(out.entries.length,out.rawRules.reduce((count,rule)=>count+rule.fields.length,0));
  for(const rule of out.rawRules){
   const node=contract.nodes.find(row=>row.identity===rule.sourceSite.sourceIdentity);
   assert.ok(node,rule.id);
   assert.equal(rule.sourceSite.sourceSHA256,node.sourceSHA256);
   assert.equal(rule.sourceSite.definitionSHA256,node.definitionSHA256);
   assert.equal(rule.sourceSite.siteSHA256,sha(Buffer.from(node.source).subarray(rule.sourceSite.start,rule.sourceSite.end)));
   assert.deepEqual(rule.sourceSite.frame,Object.fromEntries(['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].map(key=>[key,node[key]])));
   assert.equal(rule.refusalMaxRows,10000);
   assert.notEqual(rule.sourceMaxRows,10000);
   compileOrderedCaptureRule(rule);
  }
  for(const id of rawIds.slice(0,4)){
   const rule=out.rawRules.find(row=>row.id===id);
   assert.deepEqual(rule.fields,ownRoutineFields);
   assert.equal(rule.sourceMaxRows,1);
   assert.equal(rule.canonicalClass,'pg_proc');
   assert.equal(rule.handleExpression,"'pg_proc:'||p.oid::text||':0'");
   assert.match(rule.from,/^FROM pg_proc p JOIN pg_language l ON l\.oid=p\.prolang WHERE p\.oid='/);
  }
 });

 await t.test('links higher regions, exact structural spans, live spans and the conditional63/64 tail',()=>{
  for(const identity of ['zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)','zasp_temporal77.base67_fingerprint()']){
   const root=out.runtimeAlgebra.find(row=>row.sourceIdentity===identity&&row.disposition==='recursive-source-algebra');
   assert.ok(root,identity);
   const obligation=contract.materializedObligations.find(row=>row.identity===identity);
   assert.deepEqual(root.recipeSegments,obligation.recipeSegments);
   assert.deepEqual(root.sourceChildren.map(row=>[row.sourceIdentity,row.sourceSite.start,row.sourceSite.end]),obligation.retainedLiveCalls.map(call=>[root.targetByCallId[call.id],call.start,call.end]));
   assert.ok(root.children.some(child=>child.ruleId===root.rawRuleId&&child.field==='source_body'));
  }
  const higher=contract.higherRegions;
  for(const region of higher){
   const root=out.runtimeAlgebra.find(row=>row.sourceIdentity===region.identity&&row.disposition==='recursive-source-algebra');
   assert.deepEqual(root.higherRegion,{prefix:region.prefix,prefixSHA256:region.prefixSHA256,originalExpression:region.originalExpression,originalExpressionSHA256:region.originalExpressionSHA256,suffix:region.suffix,suffixSHA256:region.suffixSHA256,tailObligation:region.tailObligation});
  }
  const structural=out.runtimeAlgebra.filter(row=>row.disposition==='structural-inputs-under-live-expression');
  assert.equal(structural.length,11);
  assert.ok(structural.filter(row=>row.kind==='fixed-current-profile').every(row=>row.children.some(child=>child.ruleId==='wrapper:runtime-profile'&&child.field==='singleton')&&row.children.some(child=>child.ruleId==='wrapper:runtime-profile'&&child.field==='name')));
  assert.ok(structural.filter(row=>row.kind==='fixed-native-role-shape-and-membership').every(row=>row.children.some(child=>child.ruleId==='recursive:native-role-shape:membership'&&child.field==='admin_option')));
  const live=out.runtimeAlgebra.filter(row=>row.disposition==='live-witness-only');
  assert.equal(live.filter(row=>row.kind==='saved-export-migration-owner').length,2);
  assert.equal(live.filter(row=>row.kind==='metadata-owner-normalization').length,2);
  assert.ok(live.every(row=>row.expectedFact===false));
  const tail=out.runtimeAlgebra.find(row=>row.ruleId==='recursive:predecessor68:conditional63-64-tail');
  assert.deepEqual(tail.children,[
   {ruleId:'wrapper:retired-authorities',field:'schema_name'},
   {ruleId:'wrapper:retired-authorities',field:'original_fingerprint'},
   {ruleId:'wrapper:retired-authorities',field:'retired_fingerprint'}
  ]);
  assert.equal(tail.start,118841);
  assert.equal(tail.end,119679);
  assert.equal(tail.expectedFact,false);
  assert.match(tail.cardinality,/zero, one, both, duplicates and orphans/);
 });

 await t.test('maps projected and conditional wrappers to both live guards and selected children',()=>{
  const projected=out.runtimeAlgebra.find(row=>row.sourceIdentity==='zasp_authorization80_temporal.projected_domain()'&&row.disposition==='conditional-source-algebra');
  assert.deepEqual(projected.sourceChildren.map(row=>row.sourceIdentity),['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected_domain()']);
  assert.ok(projected.children.some(child=>child.ruleId==='recursive:worker-catalog-ready:routine'&&child.field==='source_body'));
  assert.ok(projected.children.some(child=>child.ruleId==='recursive:worker-catalog-ready:registration'&&child.field==='checksum'));
  assert.equal(projected.liveGuard.expectedFact,false);
  assert.equal(projected.nullElse,'NULL');

  for(const [identity,targets] of Object.entries(publicTargets)){
   const algebra=out.runtimeAlgebra.find(row=>row.sourceIdentity===identity&&row.disposition==='conditional-source-algebra');
   assert.ok(algebra,identity);
   assert.deepEqual(algebra.sourceChildren.map(row=>row.sourceIdentity),targets);
   assert.equal(algebra.liveGuard.expectedFact,false);
   assert.equal(algebra.liveGuard.sourceIdentity,targets[0]);
  }
  for(const [family,targets] of Object.entries(conditionalTargets)){
   const algebra=out.runtimeAlgebra.find(row=>row.ruleId===`recursive:conditional:${family}`);
   assert.ok(algebra,family);
   assert.deepEqual(algebra.sourceChildren.map(row=>row.sourceIdentity),targets);
   assert.equal(algebra.liveGuard.expectedFact,false);
   assert.equal(algebra.siteSHA256,contract.nodes.find(node=>node.identity===algebra.sourceIdentity).sourceSHA256);
  }
  for(const [identity,targets] of Object.entries(additionalTargets)){
   const algebra=out.runtimeAlgebra.find(row=>row.sourceIdentity===identity&&row.disposition==='conditional-source-algebra');
   assert.ok(algebra,identity);
   assert.deepEqual(algebra.sourceChildren.map(row=>row.sourceIdentity),targets);
   assert.equal(algebra.liveGuard.expectedFact,false);
   if(targets[0]==='zasp_temporal72.fingerprint()'){
    assert.ok(algebra.children.some(child=>child.ruleId==='schedule:guard-registration'&&child.field==='checksum'));
    assert.ok(algebra.children.some(child=>child.ruleId==='schedule:guard-registration'&&child.field==='fingerprint'));
   }
  }
  const opaque=out.runtimeAlgebra.find(row=>row.ruleId==='recursive:conditional:76.executor74_fingerprint').sourceChildren[1];
  assert.equal(opaque.sourceIdentity,'zasp_authorization80_worker.projected74()');
  assert.equal(opaque.required,'retained-opaque-P');
  assert.equal(out.runtimeAlgebra.filter(row=>row.sourceChildren?.some(child=>child.required==='retained-opaque-P')).length,3);
  const registrations=out.rawRules.filter(rule=>/registration$/.test(rule.id));
  assert.ok(registrations.every(rule=>rule.sqlPhase==='witness'&&rule.section==='witnesses'&&rule.bag===true));
  assert.deepEqual(out.rawRules.find(rule=>rule.id==='recursive:temporal74:registration').fields,['checksum','fingerprint']);
  assert.deepEqual(out.rawRules.find(rule=>rule.id==='recursive:worker-catalog-ready:registration').fields,['checksum']);
 });

 await t.test('uses exact selectors and refuses source, frame and catalog drift',()=>{
  const roles=out.rawRules.find(rule=>rule.id==='recursive:native-role-shape:roles');
  assert.deepEqual(roles.selector,{roleNames:['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting']});
  assert.equal(roles.sourceMaxRows,3);
  const memberships=out.rawRules.find(rule=>rule.id==='recursive:native-role-shape:membership');
  assert.deepEqual(memberships.selector,{grantedRole:'zasp_temporal_accounting',memberRoles:['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting']});
  assert.equal(memberships.sourceMaxRows,null);
  const metadata=out.rawRules.find(rule=>rule.id==='recursive:schema-metadata:normalization-input');
  assert.deepEqual(metadata.fields,['key','value']);
  assert.match(metadata.from,/^FROM public\.zasp_schema_metadata WHERE key NOT IN\(/);
  assert.equal(metadata.sqlPhase,'witness');
  assert.equal(metadata.section,'witnesses');
  assert.ok(out.entries.filter(entry=>entry.evidence.ruleId===metadata.id).every(entry=>entry.disposition==='live-witness-only'));
  const executableProjections=out.rawRules.map(rule=>rule.projections.join(' ')).join(' ').replace(/'(?:[^']|'')*'/g,'');
  assert.doesNotMatch(executableProjections,/(?:public\.)?zasp_[a-z0-9_.]+\s*\(/i);
  const forbidden=new Set(['guard_result','member_result','binding_result','migration_owned','ready_result']);
  assert.equal(out.rawRules.some(rule=>rule.fields.some(field=>forbidden.has(field))),false);
  assert.equal(out.entries.some(entry=>forbidden.has(entry.field)),false);

  const changedSource=structuredClone(contract);
  changedSource.nodes.find(node=>node.identity==='public.zasp_recovery_execution_live_fingerprint()').source+=' ';
  assert.throws(()=>buildOrderedRecursiveCaptureInputs(changedSource,catalog),/recursive capture source pin/);
  const changedFrame=structuredClone(contract);
  changedFrame.nodes.find(node=>node.identity==='zasp_temporal68.ready(text,text)').config=['search_path=public'];
  assert.throws(()=>buildOrderedRecursiveCaptureInputs(changedFrame,catalog),/recursive capture source frame/);
  const changedCatalog=structuredClone(catalog);
  changedCatalog.columns.find(row=>row.relation==='zasp_temporal74.registration'&&row.name==='fingerprint').type='bytea';
  assert.throws(()=>buildOrderedRecursiveCaptureInputs(contract,changedCatalog),/recursive capture catalog pin/);
  assert.deepEqual(buildOrderedRecursiveCaptureInputs(contract,catalog),out);
 });

 await t.test('expands catalog-ready guards through exact registration leaves and recursive calls',()=>{
  for(const family of ['76','77','78']){
   const identity=`zasp_temporal${family}.catalog_ready()`;
   const algebra=out.runtimeAlgebra.find(row=>row.sourceIdentity===identity&&row.disposition==='catalog-ready-source-algebra');
   assert.ok(algebra,identity);
   assert.deepEqual(algebra.sourceChildren.map(child=>child.sourceIdentity),[`zasp_temporal${family}.fingerprint()`]);
   assert.deepEqual(algebra.children,[
    {ruleId:`recursive:temporal${family}:registration`,field:'checksum'},
    {ruleId:`recursive:temporal${family}:registration`,field:'fingerprint'}
   ]);
   assert.equal(algebra.expectedFact,false);
  }

  const authorization=out.runtimeAlgebra.find(row=>row.sourceIdentity==='zasp_authorization80_temporal.catalog_ready()'&&row.disposition==='catalog-ready-source-algebra');
  assert.deepEqual(authorization.sourceChildren.map(child=>child.sourceIdentity),[
   'zasp_authorization80_temporal.fingerprint()',
   'zasp_authorization79.ready(text)',
   'zasp_authorization80.fingerprint()',
   'zasp_authorization80.runtime_audit_ready()',
   'zasp_authorization80_temporal.triggers_ready(boolean)'
  ]);
  assert.ok(authorization.children.some(child=>child.ruleId==='recursive:authorization80-temporal:registration'&&child.field==='checksum'));
  assert.ok(authorization.children.some(child=>child.ruleId==='wrapper:runtime-profile'&&child.field==='singleton'));
  assert.equal(authorization.expectedFact,false);
  for(const id of ['recursive:temporal76:registration','recursive:temporal77:registration','recursive:temporal78:registration','recursive:authorization80-temporal:registration']){
   const rule=out.rawRules.find(row=>row.id===id);
   assert.deepEqual(rule.fields,['checksum','fingerprint']);
   assert.equal(rule.sqlPhase,'witness');
   assert.equal(rule.section,'witnesses');
  }
 });

 await t.test('maps roles_ready raw universes and projected72 without helper verdict capture',()=>{
  const roles=out.runtimeAlgebra.find(row=>row.ruleId==='recursive:roles-ready:algebra');
  assert.equal(roles.sourceIdentity,'zasp_temporal72.roles_ready()');
  assert.deepEqual(new Set(roles.children.map(child=>child.ruleId)),new Set([
   'wrapper:principals','recursive:roles-ready:roles','recursive:roles-ready:membership','recursive:roles-ready:bindings'
  ]));
  assert.equal(roles.expectedFact,false);
  for(const id of ['recursive:roles-ready:roles','recursive:roles-ready:membership','recursive:roles-ready:bindings']){
   const rule=out.rawRules.find(row=>row.id===id);
   assert.equal(rule.sqlPhase,'witness');
   assert.equal(rule.section,'witnesses');
   assert.equal(rule.bag,true);
  }
  const projected=out.runtimeAlgebra.find(row=>row.sourceIdentity==='zasp_authorization80_temporal.projected72()'&&row.disposition==='conditional-source-algebra');
  assert.deepEqual(projected.sourceChildren.map(child=>child.sourceIdentity),[
   'zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected72()'
  ]);
  assert.ok(projected.children.some(child=>child.ruleId==='recursive:worker-catalog-ready:routine'&&child.field==='source_body'));
  assert.ok(projected.children.some(child=>child.ruleId==='worker:projected72:function'));
  assert.equal(projected.expectedFact,false);
 });

 await t.test('maps ready predicates to full registration bags and normalized worker definition text',()=>{
  const definition=out.rawRules.find(rule=>rule.id==='recursive:worker-catalog-ready:definition');
  assert.deepEqual(definition.fields,['definition']);
  assert.deepEqual(definition.projections,['pg_get_functiondef(p.oid)']);
  assert.equal(definition.sqlPhase,undefined);
  assert.equal(definition.sourceMaxRows,1);
  const registrations=[...['68','69','70','71','72','73','75'].map(family=>`recursive:temporal${family}:registration`),'recursive:authorization79:registration','recursive:authorization80:registration'];
  for(const id of registrations){
   const rule=out.rawRules.find(row=>row.id===id);
   assert.deepEqual(rule.fields,['checksum','fingerprint']);
   assert.equal(rule.sourceMaxRows,null);
   assert.equal(rule.sqlPhase,'witness');
   assert.equal(rule.section,'witnesses');
   assert.doesNotMatch(rule.from,/\bWHERE\b/);
  }
  const ready68=out.runtimeAlgebra.filter(row=>row.sourceIdentity==='zasp_temporal68.ready(text,text)'&&row.disposition==='ready-predicate-live-witness-algebra');
  const ready78=out.runtimeAlgebra.filter(row=>row.sourceIdentity==='zasp_temporal78.ready(text,text)'&&row.disposition==='ready-predicate-live-witness-algebra');
  assert.ok(ready68.some(row=>row.children.some(child=>child.ruleId==='recursive:worker-catalog-ready:definition'&&child.field==='definition')));
  assert.ok(ready78.some(row=>row.children.some(child=>child.ruleId==='recursive:worker-catalog-ready:definition'&&child.field==='definition')));
  assert.deepEqual(new Set(ready68.flatMap(row=>row.children.map(child=>child.ruleId))),new Set(['recursive:worker-catalog-ready:routine','recursive:worker-catalog-ready:definition','recursive:temporal68:registration','recursive:authorization80-temporal:registration','recursive:authorization79:registration','recursive:authorization80:registration']));
  assert.deepEqual(new Set(ready78.flatMap(row=>row.children.map(child=>child.ruleId))),new Set(['recursive:worker-catalog-ready:routine','recursive:worker-catalog-ready:definition','recursive:temporal68:registration','recursive:temporal69:registration','recursive:temporal70:registration','recursive:temporal71:registration','recursive:temporal72:registration','recursive:temporal73:registration','recursive:temporal74:registration','recursive:temporal75:registration','recursive:temporal76:registration','recursive:temporal77:registration','recursive:temporal78:registration','recursive:authorization80-temporal:registration','recursive:authorization79:registration','recursive:authorization80:registration']));
  assert.ok(ready68.some(row=>row.start===131&&row.end===692&&row.siteSHA256==='ea74f616b5fd356dc02efa99ddba46853ad8263ae5cd2a3de9e47b81ac0b558f'));
  assert.ok(ready78.some(row=>row.start===287&&row.end===848&&row.siteSHA256==='ea74f616b5fd356dc02efa99ddba46853ad8263ae5cd2a3de9e47b81ac0b558f'));
  assert.ok([...ready68,...ready78].every(row=>row.expectedFact===false));
 });
});
