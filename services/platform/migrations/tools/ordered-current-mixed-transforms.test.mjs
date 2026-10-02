import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {compileOrderedTransformAST} from './ordered-current-transform-compiler.mjs';
const mixed=await import('./ordered-current-mixed-transforms.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url)));
test('schedule representation preserves selected guard, nullable scalar and ordered replacements without a new primitive exception',()=>{
  assert.equal(typeof mixed.lowerOrderedMixedTransforms,'function');
  const out=mixed.lowerOrderedMixedTransforms(contract),recipe=out.recipes.find(r=>r.ruleId==='public:discovery_schedule_replay:function');
  assert.ok(recipe);assert.equal(Object.keys(recipe.fields).length,12);
  assert.equal(recipe.selector.op,'saved-signature-universe');
  assert.equal(recipe.selector.schema,'zasp_schedule_replay_prior');assert.equal(recipe.selector.cast,'regprocedure');
  const demand=recipe.fields.definition;
  assert.equal(demand.op,'original-helper-demand');
  const outer=demand.expression;
  assert.equal(outer.op,'replace');assert.equal(outer.from,'1ed52fb5f9a83384e1d3fecbc3bc116d3981a36479e9b3b1f6ec04b5cd4f3b36');assert.equal(outer.to,'<compiled-fingerprint>');
  const inner=outer.input;assert.equal(inner.from,'37956023196757f30a7ecb415e9d7d7e6f76cfa32a3ffa2d45445c172f6313ab');assert.equal(inner.to,'<compiled-checksum>');
  const branch=inner.input;
  assert.deepEqual(branch.identities,['public.zasp_execution_live_fingerprint()','public.zasp_discovery_schedule_replay_function_identity(oid)']);
  assert.deepEqual(branch.else,{op:'field',field:'definition'});
  assert.equal(branch.then.op,'original72-guard');
  assert.equal(branch.then.condition,"EXISTS(SELECT 1 FROM zasp_temporal72.registration WHERE checksum='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940' AND fingerprint='b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e') AND zasp_temporal72.fingerprint()='b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e'");
  assert.deepEqual(branch.then.else,{op:'literal',value:null});
  assert.deepEqual(branch.then.then,{op:'saved-oid-scalar',schema:'zasp_temporal72',table:'predecessor_functions',field:'definition',signatureResolution:'to_regprocedure',argument:'original-helper-value'});
  assert.equal(branch.then.primitiveException,false);assert.equal(branch.then.outsideCollectorAuthorized,false);
  assert.throws(()=>compileOrderedTransformAST(demand),/unknown transform op/);
  assert.equal(out.installable,false);assert.equal(out.unsupported.length,2);
});
test('export representation keeps two exact signatures, fresh MEMBER predicate and ACL tags outside entries',()=>{
  assert.equal(typeof mixed.lowerOrderedMixedTransforms,'function');
  const out=mixed.lowerOrderedMixedTransforms(contract),recipe=out.recipes.find(r=>r.ruleId==='public:sa_export:saved');
  assert.ok(recipe);assert.equal(recipe.sourceTable,'zasp_sa_export_prior.functions');
  const condition=recipe.bindings.migration_owned;
  assert.deepEqual(condition.signatures,['public.zasp_workflow_mutate_v3(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)','public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)']);
  assert.equal(condition.bindingTable,'public.zasp_discovery_principal_bindings');assert.equal(condition.role,'zasp_discovery_authority');assert.equal(condition.roleTest,'MEMBER');assert.equal(condition.ownerField,'owner_name');
  assert.match(condition.source,/b.principal_name=s.owner_name/);assert.match(condition.source,/pg_has_role\(r.oid,'zasp_discovery_authority','MEMBER'\)/);
  assert.deepEqual(recipe.fields.owner,{op:'registered-owner-case',condition:'migration_owned',registered:'<registered-migration-principal>',literalPrefix:'owner:',field:'owner_name'});
  assert.deepEqual(recipe.fields.acl,{op:'registered-acl-case',condition:'migration_owned',field:'acl',ownerField:'owner_name',registeredTag:'registered-migration-principal',literalTag:'literal',removeOnly:'grantee',order:'original-ordinality',result:'original-jsonb-text',emptyAggregate:null});
  assert.equal(recipe.fields.definition.field,'definition');assert.equal(recipe.fields.signature.field,'signature');
  assert.throws(()=>compileOrderedTransformAST(recipe.fields.owner),/unknown transform op/);
  assert.throws(()=>compileOrderedTransformAST(recipe.fields.acl),/unknown transform op/);
  assert.equal(out.sites.length,4);assert.equal(out.guardInputs.length,4);
});
test('mixed source, definition and original frame changes fail closed without narrowing full branch coverage',()=>{
  assert.equal(typeof mixed.lowerOrderedMixedTransforms,'function');
  for(const identity of ['public.zasp_discovery_schedule_replay_function_identity(oid)','public.zasp_discovery_schedule_replay_live_fingerprint()','public.zasp_sa_export_live_fingerprint()','zasp_temporal72.fingerprint()','zasp_authorization80_temporal.catalog_ready()','zasp_authorization80_temporal.projected72()','zasp_authorization80_worker.projected72()']){
    for(const field of ['source','definition','config']){
      const changed=structuredClone(contract),node=changed.nodes.find(n=>n.identity===identity);
      node[field]=field==='config'?['search_path=public']:node[field]+' ';
      assert.throws(()=>mixed.lowerOrderedMixedTransforms(changed),identity+' '+field);
    }
  }
  assert.deepEqual(mixed.lowerOrderedMixedTransforms(contract),mixed.lowerOrderedMixedTransforms(contract));
});
