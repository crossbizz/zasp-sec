import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as catalog from './ordered-current-catalog.mjs';
import {lowerOrderedRuntimeCatalog} from './ordered-current-runtime-selectors.mjs';
import {lowerOrderedProductCatalog} from './ordered-current-product-selectors.mjs';
import {lowerOrderedRoleProfileCatalog} from './ordered-current-role-profile.mjs';
test('finite capture bounds count selector metadata without inventing missing fact values',()=>{
  assert.equal(typeof catalog.countOrderedReferenceCandidates,'function');
  const rules=[{id:'columns',kind:'information_column',namespaces:[],identities:[],fields:['data_type'],selector:{field:'relation_name',equals:'wanted'}}];
  assert.deepEqual(catalog.countOrderedReferenceCandidates(rules,[{kind:'information_column',relation_name:'wanted'},{kind:'information_column',relation_name:'other'}]),{columns:1});
});
test('all source-reviewed runtime and product projection rules compile together',()=>{
  const contract=JSON.parse(fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url)));
  const runtime=lowerOrderedRuntimeCatalog(contract),product=lowerOrderedProductCatalog(contract),role=lowerOrderedRoleProfileCatalog(contract);
  assert.equal(runtime.rules.length,33);assert.equal(product.rules.length,22);
  const compiled=catalog.compileOrderedCollector([...runtime.rules,...product.rules,...role.rules]);
  assert.ok(compiled.sql.includes('pg_catalog.pg_policies'));
  assert.ok(compiled.sql.includes('information_schema.columns'));
  assert.equal(runtime.unsupported.length,13);
  assert.match(compiled.sql,/FROM zasp_authorization80\.runtime_profile s/);
});
