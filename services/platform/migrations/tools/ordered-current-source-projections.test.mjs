import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {compileOrderedCollector,orderedReferenceInput,projectOrderedFacts} from './ordered-current-catalog.mjs';
import * as catalogCompiler from './ordered-current-catalog.mjs';
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
const evidence=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const read=name=>JSON.parse(fs.readFileSync(new URL(name,evidence)));
const contract=read('ordered-current-effective-contract3.json');
const simple=(kind,fields)=>({id:'source-'+kind,kind,namespaces:['public'],identities:[],fields});
test('all accepted temporal static rules compile without dropping requested source fields',()=>{
  const lowering=lowerOrderedTemporalCatalog(contract);
  assert.equal(lowering.rules.length,92);
  const sql=compileOrderedCollector(lowering.rules).sql;
  assert.match(sql,/pg_get_expr\(d.adbin,d.adrelid,true\)/);
  assert.match(sql,/pg_get_indexdef\(i.indexrelid,0,true\)/);
  assert.match(sql,/trigger_proc.proname::text/);
  assert.match(sql,/pg_get_function_identity_arguments\(t.tgfoid\)/);
  assert.equal(lowering.obligations.filter(o=>o.type==='original-transformation').length,17);
});
test('source-specific class indexes and type identities preserve changed-kind and typmod distinctions',()=>{
  assert.equal(lowerOrderedPublicCatalog(contract).rules.length,59);
  assert.doesNotThrow(()=>compileOrderedCollector(lowerOrderedPublicCatalog(contract).rules));
  const sql=compileOrderedCollector([simple('class_index',['name','definition']),simple('column_name',['type_identity','namespace_name','relation_name']),simple('trigger',['namespace_name','relation_name']),simple('role',['name'])]).sql;
  assert.match(sql,/pg_get_indexdef\(c.oid\)/);
  assert.doesNotMatch(sql,/pg_catalog.pg_index /);
  assert.match(sql,/a.atttypid::regtype::text/);
  assert.match(sql,/n.nspname::text/);
  const rule={...simple('class_index',['name','definition']),namespaces:[],selector:{all:[{field:'namespace',equals:'public'},{field:'name',equals:'selected'}]}};
  const rows=['i','r'].map((relation_kind,i)=>({kind:'class_index',identity:'public.row'+i,namespace:'public',name:'selected',relation_kind,fact:{name:'selected',definition:'deparse'+i}}));
  assert.equal(projectOrderedFacts([rule],rows).length,2);
});

test('column collation preserves semantic NULL for PostgreSQL no-collation marker',()=>{
 const sql=compileOrderedCollector([simple('column',['collation'])]).sql;
 assert.match(sql,/NULLIF\(a\.attcollation::regcollation::text,'-'\)/);
 assert.doesNotMatch(sql,/a\.attcollation::regcollation::text(?!,'-')/);
});
test('new source projections leave the immutable 57-rule capture query byte-identical',()=>{
  const frozen=read('ordered-current-supplementary-query-contract2.json');
  const actual=crypto.createHash('sha256').update(compileOrderedCollector(frozen.rules).sql+'\n').digest('hex');
  assert.equal(actual,frozen.sqlSHA256);
});
test('captured saved signatures retain their original values and table keys',()=>{
  const catalog=read('ordered-current-effective-catalog1.json');
  const rules=lowerOrderedTemporalCatalog(contract).rules.filter(r=>['saved_function','saved_constraint'].includes(r.kind));
  const facts=projectOrderedFacts(rules,orderedReferenceInput(catalog));
  assert.ok(facts.length>0);
  const row=facts.find(r=>r.kind==='saved_constraint');
  assert.equal(row.fact.signature,'zasp_temporal74.run_owners.run_owners_source_kind_check');
  assert.match(row.identity,/zasp_temporal76.predecessor_constraints/);
});
test('offline source projections use captured raw values and mark absent universes or fields as pending',()=>{
  const catalog=read('ordered-current-effective-catalog1.json'),input=orderedReferenceInput(catalog);
  const schema=input.find(r=>r.kind==='namespace'&&r.identity==='zasp_temporal70');
  assert.equal(schema.fact.acl_text_or_empty,catalog.schemas.find(r=>r.name==='zasp_temporal70').acl??'');
  const column=input.find(r=>r.kind==='column_name'&&r.fact.default===null);
  assert.ok(column);
  assert.equal(column.fact.default_text_or_empty,'');
  assert.ok(!Object.hasOwn(column.fact,'default_pretty_text_or_empty'));
  assert.equal(typeof catalogCompiler.inspectOrderedReferenceRules,'function');
  const availability=catalogCompiler.inspectOrderedReferenceRules(lowerOrderedTemporalCatalog(contract).rules,input,new Set(['namespace','relation','column','column_name','constraint','global_constraint','index','policy','trigger','saved_function','saved_constraint']));
  assert.ok(availability.pending.some(r=>r.kind==='foreign_key_trigger'&&r.reason==='uncaptured descriptor universe'));
  assert.ok(availability.pending.some(r=>r.missingFields?.includes('persistence')));
  assert.ok(availability.pending.some(r=>r.id==='temporal:72.retained_execution_fingerprint:index'&&r.candidates>0&&r.missingFields.includes('definition_pretty')));
  assert.ok(availability.resolved.some(r=>r.id==='temporal:70.fingerprint:schema'));
  assert.ok(availability.resolved.some(r=>r.id==='temporal:70.fingerprint:saved'));
  const multistep=lowerOrderedPublicCatalog(contract).rules.find(r=>r.id==='public:sa_multistep:column');
  assert.ok(projectOrderedFacts([multistep],input).length>0,'r/p relation kind selects the existing multistep columns');
});
test('execution72 source-derived fields retain nullable markers and ordered JSON ACL values',()=>{
  const rules=[simple('relation',['execution_acl_text']),simple('routine',['execution_acl_text','execution_config_text','execution_body','namespace_name','precision_definition']),simple('policy',['execution_roles_text']),simple('role',['execution_v1_managed_here']),simple('trigger',['execution_definition'])];
  const sql=compileOrderedCollector(rules).sql;
  assert.match(sql,/aclexplode\(COALESCE\(c.relacl,pg_catalog.acldefault\('r',c.relowner\)\)\)/);
  assert.match(sql,/aclexplode\(COALESCE\(p.proacl,pg_catalog.acldefault\('f',p.proowner\)\)\)/);
  assert.match(sql,/shobj_description\(r.oid,'pg_authid'\)=ANY/);
  assert.match(sql,/production-discovery-execution-v1:database:%s:created/);
  assert.match(sql,/production-discovery-execution-v1:database:%s:bound/);
  assert.match(sql,/to_regprocedure\(signature\)=p.oid/);
  const role={...simple('role',['execution_v1_managed_here']),namespaces:[],identities:['zasp_discovery_scheduler']};
  for(const value of [null,false,true])assert.equal(projectOrderedFacts([role],[{kind:'role',identity:'zasp_discovery_scheduler',namespace:'',fact:{execution_v1_managed_here:value}}])[0].fact.execution_v1_managed_here,value);
});
test('inventory normalization keeps its exact three-function owner relation and separate marker',()=>{
  const sql=compileOrderedCollector([simple('routine',['inventory_owner','inventory_acl_text','inventory_body']),simple('role',['inventory_v1_managed_here'])]).sql;
  assert.match(sql,/p.proname IN\('zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence'\)/);
  assert.match(sql,/WHERE oid='public.zasp_core_payloads'::regclass/);
  assert.doesNotMatch(sql,/oid='zasp_core_payloads'::regclass/);
  assert.match(sql,/typed-inventory-cutover-v1:database:%s:created/);
  assert.match(sql,/typed-inventory-cutover-v1:database:%s:bound/);
  assert.doesNotMatch(sql,/production-discovery-execution-v1/);
});
