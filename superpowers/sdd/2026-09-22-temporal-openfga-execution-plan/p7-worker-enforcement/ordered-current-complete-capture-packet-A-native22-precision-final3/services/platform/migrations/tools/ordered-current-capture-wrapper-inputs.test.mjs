import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {buildOrderedWrapperCaptureInputs} from './ordered-current-capture-wrapper-inputs.mjs';
import {compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contractRaw=fs.readFileSync(new URL('ordered-current-effective-contract3.json',base));
const catalogRaw=fs.readFileSync(new URL('ordered-current-effective-catalog1.json',base));
assert.equal(sha(contractRaw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
assert.equal(sha(catalogRaw),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
const contract=JSON.parse(contractRaw),catalog=JSON.parse(catalogRaw);
const rule=(out,id)=>out.rawRules.find(x=>x.id===id);

const identities={
 scope:'zasp_temporal67.scope_authority_ready()',
 migration:'zasp_temporal72.migration_helper_identity(text,text,text)',
 runtime:'zasp_authorization80.runtime_audit_ready()',
 expected:'public.zasp_audit_export_source_acl_expected(jsonb)',
 sourceReady:'public.zasp_audit_export_source_acl_ready()',
 sourceSnapshot:'public.zasp_audit_export_source_acl_snapshot()',
 catalogACL:'public.zasp_audit_export_source_catalog_acl(aclitem[],oid)',
 catalogRole:'public.zasp_audit_export_source_catalog_role(oid,oid)',
 workflowReady:'public.zasp_audit_export_workflow_acl_ready()',
 workflowSnapshot:'public.zasp_audit_export_workflow_acl_snapshot()'
};

test('the exact contract3 wrapper sources lower anchored raw leaves without taking over saved bags',()=>{
 const out=buildOrderedWrapperCaptureInputs(contract,catalog);
 assert.deepEqual(out.rawRules.map(x=>x.id),[
  'wrapper:scope-authority:relation','wrapper:scope-authority:routines','wrapper:scope-authority:routine-acl','wrapper:scope-authority:relation-resolution','wrapper:scope-authority:routine-resolution',
  'wrapper:migration-helper:relations','wrapper:migration-helper:routines','wrapper:migration-helper:routine-acl','wrapper:migration-helper:relation-resolution','wrapper:migration-helper:routine-resolution',
  'wrapper:runtime-audit:none-namespace','wrapper:runtime-audit:none-relation-resolution','wrapper:runtime-audit:none-trigger-inputs','wrapper:runtime-audit:registration-resolution','wrapper:runtime-audit:catalog-resolution',
  'wrapper:audit-source:relation','wrapper:audit-source:columns','wrapper:audit-source:relation-acl','wrapper:audit-source:column-acl','wrapper:audit-source:snapshot','wrapper:audit-source:ready-relation','wrapper:audit-source:expected',
  'wrapper:audit-workflow:relation','wrapper:audit-workflow:columns','wrapper:audit-workflow:relation-acl','wrapper:audit-workflow:column-acl','wrapper:audit-workflow:snapshot'
 ]);
 assert.deepEqual(out.unresolved,[]);
 assert.equal(out.entries.length,out.rawRules.reduce((n,x)=>n+x.fields.length,0));
 assert.ok(!out.rawRules.some(x=>['wrapper:runtime-profile','wrapper:audit-source-acl','wrapper:principals','wrapper:retired-authorities'].includes(x.id)));

 for(const raw of out.rawRules){
  const node=contract.nodes.find(x=>x.identity===raw.sourceSite.sourceIdentity);
  assert.ok(node,raw.id);
  assert.equal(raw.sourceSite.sourceSHA256,node.sourceSHA256);
  assert.equal(raw.sourceSite.definitionSHA256,node.definitionSHA256);
  assert.equal(raw.sourceSite.siteSHA256,sha(Buffer.from(node.source).subarray(raw.sourceSite.start,raw.sourceSite.end)));
  assert.deepEqual(raw.sourceSite.frame,Object.fromEntries(['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].map(k=>[k,node[k]])));
  const entries=out.entries.filter(x=>x.evidence.ruleId===raw.id);
  assert.equal(entries.length,raw.fields.length,raw.id);
  entries.forEach((entry,index)=>assert.deepEqual(entry,{
   ...raw.sourceSite,expressionOrdinal:index,field:raw.fields[index],sourceExpression:raw.projections[index],selector:raw.selector,
   demandPath:raw.demandPath,disposition:'capture',evidence:{phase:raw.sqlPhase??'original',ruleId:raw.id,field:raw.fields[index]}
  }));
  compileOrderedCaptureRule(raw);
 }
});

test('scope authority and migration helper retain owners, raw ACLs, tuple bags and gated resolutions',()=>{
 const out=buildOrderedWrapperCaptureInputs(contract,catalog);
 const scopeRelation=rule(out,'wrapper:scope-authority:relation');
 assert.deepEqual(scopeRelation.fields,['relation_identity','owner']);
 assert.equal(scopeRelation.canonicalClass,'pg_class');
 assert.equal(scopeRelation.handleExpression,"'pg_class:'||c.oid::text||':0'");
 assert.equal(scopeRelation.sourceMaxRows,1);
 assert.match(scopeRelation.from,/c\.oid='public\.zasp_authorized_scopes'::regclass/);

 const scopeRoutines=rule(out,'wrapper:scope-authority:routines');
 assert.deepEqual(scopeRoutines.fields,['routine_identity','owner','raw_acl']);
 assert.equal(scopeRoutines.canonicalClass,'pg_proc');
 assert.equal(scopeRoutines.sourceMaxRows,2);
 assert.match(scopeRoutines.from,/lock_scope\(text,text,text,text\).*pricing_lock_scope\(text,text,text,text\)/s);
 const scopeACL=rule(out,'wrapper:scope-authority:routine-acl');
 assert.equal(scopeACL.bag,true);
 assert.equal(scopeACL.sourceMaxRows,null);
 assert.deepEqual(scopeACL.fields,['routine_identity','owner','grantor','grantee','privilege','grantable']);
 assert.match(scopeACL.from,/aclexplode\(p\.proacl\)/);

 for(const id of ['wrapper:scope-authority:relation-resolution','wrapper:scope-authority:routine-resolution']){
  const resolution=rule(out,id);
  assert.equal(resolution.sqlPhase,'resolution');
  assert.equal(resolution.section,'resolutions');
  assert.equal(resolution.bag,true);
  assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
 }
 assert.equal(rule(out,'wrapper:scope-authority:relation-resolution').fieldTypes.resolvedIdentity,'text');
 assert.equal(rule(out,'wrapper:scope-authority:routine-resolution').fieldTypes.resolvedIdentity,'text');

 const migrationRelations=rule(out,'wrapper:migration-helper:relations');
 assert.equal(migrationRelations.sourceMaxRows,2);
 assert.match(migrationRelations.from,/zasp_core_payloads.*zasp_authorized_scopes/s);
 assert.match(migrationRelations.from,/CASE WHEN EXISTS\(SELECT 1 FROM zasp_temporal72\.predecessor_functions/);
 const migrationRoutines=rule(out,'wrapper:migration-helper:routines');
 assert.equal(migrationRoutines.sourceMaxRows,2);
 assert.match(migrationRoutines.from,/CASE WHEN s\.signature IN\(/);
 assert.match(migrationRoutines.from,/to_regprocedure\('public\.'\|\|s\.signature\)/);
 const migrationACL=rule(out,'wrapper:migration-helper:routine-acl');
 assert.equal(migrationACL.bag,true);
 assert.match(migrationACL.from,/aclexplode\(p\.proacl\)/);

 for(const id of ['wrapper:migration-helper:relation-resolution','wrapper:migration-helper:routine-resolution']){
  const resolution=rule(out,id);
  assert.equal(resolution.sqlPhase,'resolution');
  assert.equal(resolution.bag,true);
  assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
  assert.deepEqual(resolution.demandPath,['saved-input:zasp_temporal72.predecessor_functions',identities.migration]);
  assert.match(resolution.projections.at(-1),/^CASE WHEN s\.signature IN\(/);
  assert.match(resolution.from,/WHERE s\.signature IN\(/);
 }
 assert.equal(rule(out,'wrapper:migration-helper:routine-resolution').fieldTypes.resolvedIdentity,'text?');
});

test('runtime audit resolution follows the count guard and non-STRICT SELECT INTO source semantics',()=>{
 const node=contract.nodes.find(x=>x.identity===identities.runtime);
 assert.match(node.source,/count\(\*\).*<>1 THEN RETURN false/s);
 assert.match(node.source,/SELECT audit_mode INTO selected/);
 assert.doesNotMatch(node.source,/SELECT audit_mode INTO STRICT/);

 const out=buildOrderedWrapperCaptureInputs(contract,catalog);
 for(const id of ['wrapper:runtime-audit:registration-resolution','wrapper:runtime-audit:catalog-resolution']){
  const resolution=rule(out,id);
  assert.equal(resolution.sqlPhase,'resolution');
  assert.equal(resolution.section,'resolutions');
  assert.equal(resolution.sourceMaxRows,1);
  assert.deepEqual(resolution.demandPath,['wrapper:runtime-profile',identities.runtime]);
  assert.match(resolution.from,/\(SELECT count\(\*\) FROM zasp_authorization80\.runtime_profile\)=1/);
  assert.match(resolution.from,/rp\.singleton AND rp\.audit_mode='source52-canonical61-audit-v1'/);
  assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
  assert.equal(resolution.fieldTypes.resolvedIdentity,'text?');
  assert.ok(resolution.projections.at(-1).startsWith("CASE WHEN rp.audit_mode='source52-canonical61-audit-v1' THEN to_reg"));
 }

 const algebra=out.runtimeAlgebra.find(x=>x.ruleId==='wrapper-algebra:'+identities.runtime);
 assert.ok(algebra);
 assert.ok(algebra.children.some(x=>x.ruleId==='wrapper:runtime-profile'&&x.field==='audit_mode'));
 assert.ok(algebra.children.some(x=>x.ruleId==='wrapper:runtime-audit:catalog-resolution'&&x.field==='resolvedIdentity'));
 const none=out.runtimeAlgebra.find(x=>x.ruleId==='wrapper:runtime-audit:none-branch');
 assert.ok(none.children.some(x=>x.ruleId==='wrapper:runtime-audit:none-namespace'&&x.field==='namespace_identity'));
 assert.ok(none.children.some(x=>x.ruleId==='wrapper:runtime-audit:none-trigger-inputs'&&x.field==='name'));
 assert.ok(!out.rawRules.some(x=>/runtime-profile/.test(x.id)));
});

test('audit export keeps raw ACL NULLs, expanded multiplicity and pure source normalization observations',()=>{
 const out=buildOrderedWrapperCaptureInputs(contract,catalog);
 for(const [prefix,relation,expectedColumns] of [
  ['audit-source','public.zasp_admin_audit',10],
  ['audit-workflow','public.zasp_workflow_audit',11]
 ]){
  const relationRule=rule(out,`wrapper:${prefix}:relation`);
  assert.deepEqual(relationRule.fields,['relation_identity','owner','raw_acl']);
  assert.equal(relationRule.fieldTypes.raw_acl,'text?');
  assert.equal(relationRule.sourceMaxRows,1);
  assert.match(relationRule.from,new RegExp(relation.replaceAll('.','\\.')));
  const columns=rule(out,`wrapper:${prefix}:columns`);
  assert.deepEqual(columns.fields,['relation_identity','number','name','raw_acl']);
  assert.equal(columns.fieldTypes.raw_acl,'text?');
  assert.equal(columns.canonicalClass,'pg_attribute');
  assert.equal(columns.handleExpression,"'pg_attribute:'||a.attrelid::text||':'||a.attnum::text");
  assert.equal(columns.selector.catalog1ColumnCount,expectedColumns);
  assert.equal(columns.sourceMaxRows,null);
  const relationACL=rule(out,`wrapper:${prefix}:relation-acl`);
  assert.equal(relationACL.bag,true);
  assert.equal(relationACL.sourceMaxRows,null);
  assert.deepEqual(relationACL.fields,['relation_identity','owner','acl_defaulted','grantor','grantee','privilege','grantable']);
  assert.match(relationACL.from,/aclexplode\(COALESCE\(c\.relacl,acldefault\('r',c\.relowner\)\)\)/);
  const columnACL=rule(out,`wrapper:${prefix}:column-acl`);
  assert.equal(columnACL.bag,true);
  assert.deepEqual(columnACL.fields,['relation_identity','number','name','owner','grantor','grantee','privilege','grantable']);
  assert.match(columnACL.from,/aclexplode\(a\.attacl\)/);
  const snapshot=rule(out,`wrapper:${prefix}:snapshot`);
  assert.equal(snapshot.section,'normalizationObservations');
  assert.equal(snapshot.sqlPhase,'witness');
  assert.equal(snapshot.bag,true);
  assert.deepEqual(snapshot.fields,['normalized_acl']);
  assert.match(snapshot.projections[0],/jsonb_build_object/);
  assert.doesNotMatch(snapshot.projections[0],/public\.zasp_[a-z0-9_]+\s*\(/i);
 }

 const ready=rule(out,'wrapper:audit-source:ready-relation');
 assert.deepEqual(ready.fields,['relation_identity','kind','row_security','forced_row_security']);
 assert.match(ready.from,/public\.zasp_admin_audit/);
 const expected=rule(out,'wrapper:audit-source:expected');
 assert.equal(expected.section,'normalizationObservations');
 assert.equal(expected.sqlPhase,'witness');
 assert.deepEqual(expected.demandPath,['wrapper:audit-source-acl',identities.expected]);
 assert.match(expected.projections[0],/jsonb_array_elements\(s\.before_state->'grants'\)/);
 assert.doesNotMatch(expected.projections[0],/public\.zasp_[a-z0-9_]+\s*\(/i);

 const allFields=new Set(out.rawRules.flatMap(x=>x.fields));
 for(const forbidden of ['ready','ready_result','binding','binding_exists','login','member','member_result','effective_privilege','migration_owned','guard_result'])assert.equal(allFields.has(forbidden),false,forbidden);
 for(const id of [identities.sourceReady,identities.catalogACL,identities.catalogRole,identities.workflowReady]){
  assert.ok(out.runtimeAlgebra.some(x=>x.sourceIdentity===id),id);
 }
});

test('source and catalog drift refuse, inputs stay untouched and output is deterministic',()=>{
 const beforeSource=JSON.stringify(contract),beforeCatalog=JSON.stringify(catalog);
 const first=buildOrderedWrapperCaptureInputs(contract,catalog);
 assert.deepEqual(first,buildOrderedWrapperCaptureInputs(contract,catalog));
 assert.equal(JSON.stringify(contract),beforeSource);
 assert.equal(JSON.stringify(catalog),beforeCatalog);

 const changes=[
  ([source])=>source.nodes.find(x=>x.identity===identities.scope).source+=' ',
  ([source])=>source.nodes.find(x=>x.identity===identities.migration).owner='other',
  ([source])=>source.nodes=source.nodes.filter(x=>x.identity!==identities.workflowSnapshot),
  (([,cat])=>{cat.relations.find(x=>x.identity==='public.zasp_admin_audit').owner='other';}),
  (([,cat])=>{cat.columns=cat.columns.filter(x=>!(x.relation==='public.zasp_workflow_audit'&&x.position===11));})
 ];
 for(const change of changes){const inputs=[structuredClone(contract),structuredClone(catalog)];change(inputs);assert.throws(()=>buildOrderedWrapperCaptureInputs(...inputs),/wrapper capture (?:source|catalog) pin/);}
 assert.throws(()=>buildOrderedWrapperCaptureInputs(null,catalog),/wrapper capture source pin/);
 assert.throws(()=>buildOrderedWrapperCaptureInputs(contract,null),/wrapper capture catalog pin/);
});
