import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {buildOrderedPriorCaptureInputs} from './ordered-current-capture-prior-inputs.mjs';
import {prepareOrderedCaptureRule,compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contractRaw=fs.readFileSync(new URL('ordered-current-effective-contract3.json',base));
const catalogRaw=fs.readFileSync(new URL('ordered-current-effective-catalog1.json',base));
assert.equal(sha(contractRaw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
assert.equal(sha(catalogRaw),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
const contract=JSON.parse(contractRaw),catalog=JSON.parse(catalogRaw);
const rule=(out,id)=>out.rawRules.find(row=>row.id===id);
const branchCounts={compliance:4,existing:10,'run-context':4,budget:9,audit:13};

test('the exact five predecessor sources lower every anchored concat branch into compilable raw inputs',()=>{
 const out=buildOrderedPriorCaptureInputs(contract,catalog);
 assert.deepEqual(out.unresolved,[]);
 const branches=out.runtimeAlgebra.filter(row=>row.disposition==='prior-branch-algebra');
 assert.equal(branches.length,40);
 for(const [family,count] of Object.entries(branchCounts))assert.equal(branches.filter(row=>row.family===family).length,count,family);
 for(const branch of branches){
  const node=contract.nodes.find(row=>row.identity===branch.sourceIdentity);
  assert.ok(node,branch.ruleId);
  assert.equal(branch.sourceSHA256,node.sourceSHA256);
  assert.equal(branch.definitionSHA256,node.definitionSHA256);
  assert.equal(branch.siteSHA256,sha(Buffer.from(node.source).subarray(branch.start,branch.end)));
  assert.equal(branch.expectedFact,false);
  for(const child of branch.children){
   assert.equal(typeof child.ruleId,'string');
   assert.equal(typeof child.field,'string');
  }
 }
 assert.equal(out.rawRules.length,51);
 assert.equal(out.entries.length,out.rawRules.reduce((sum,row)=>sum+row.fields.length,0));
 for(const raw of out.rawRules){
  assert.equal(raw.refusalMaxRows,10000,raw.id);
  const compiled=compileOrderedCaptureRule(prepareOrderedCaptureRule(raw));
  assert.ok(compiled.original,raw.id);
  const entries=out.entries.filter(entry=>entry.evidence.ruleId===raw.id);
  assert.equal(entries.length,raw.fields.length,raw.id);
 }
 const genuineBags=new Set(['acl_bag','saved_bag','resolution','live_role_witness_bag']);
 for(const raw of out.rawRules){
  if(genuineBags.has(raw.kind)){assert.equal(raw.bag,true,raw.id);continue;}
  assert.equal(raw.bag,undefined,raw.id);
  assert.equal(typeof raw.canonicalClass,'string',raw.id);
  assert.equal(typeof raw.handleExpression,'string',raw.id);
 }
});

test('function branches retain raw routine bytes, array dimensions, helper constants and live child semantics',()=>{
 const out=buildOrderedPriorCaptureInputs(contract,catalog);
 for(const family of ['compliance','existing','run-context','budget','audit']){
  const raw=rule(out,`prior:${family}:function`);
  assert.ok(raw,family);
  for(const field of ['namespace_name','name','definition','source_body','owner','raw_acl','config_json','config_raw','config_dims','config_ndims','config_bounds'])assert.ok(raw.fields.includes(field),`${family}.${field}`);
  assert.equal(raw.projections[raw.fields.indexOf('namespace_name')],'n.nspname::text');
  assert.equal(raw.projections[raw.fields.indexOf('name')],'p.proname::text');
  assert.equal(raw.projections[raw.fields.indexOf('owner')],'r.rolname::text');
  assert.match(raw.from,/JOIN pg_roles r ON r\.oid=p\.proowner/);
  assert.match(raw.from,/JOIN pg_language l ON l\.oid=p\.prolang/);
  assert.equal(raw.bag,undefined);
  assert.equal(raw.canonicalClass,'pg_proc');
  assert.equal(raw.sourceMaxRows,null);
 }
 for(const family of ['compliance','existing','run-context']){
  const helper=out.runtimeAlgebra.find(row=>row.ruleId===`prior:${family}:function-identity-helper`);
  assert.equal(helper.pattern,"expected_(checksum|fingerprint) = '[a-f0-9]{64}'");
  assert.equal(helper.replacement,"expected_\\1 = '<compiled-pin>'");
  assert.equal(helper.flags,'g');
  assert.equal(helper.expectedFact,false);
  const resolution=rule(out,`prior:${family}:function-identity-readiness-resolution`);
  assert.equal(resolution.sqlPhase,'resolution');
  assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
  assert.equal(resolution.sourceMaxRows,null);
  assert.equal(resolution.selector.outerRuleId,`prior:${family}:function`);
  assert.equal(resolution.selector.literalBindings.length,1);
  assert.match(resolution.from,/FROM pg_proc selected JOIN pg_namespace selected_ns/);
  assert.match(resolution.projections.at(-1),/^CASE WHEN selected\.oid IS NOT NULL THEN d\.literal::regprocedure::text ELSE NULL END$/);
  assert.ok(helper.children.some(row=>row.ruleId===resolution.id&&row.field==='resolvedIdentity'));
 }
 const budget=out.runtimeAlgebra.find(row=>row.ruleId==='prior:budget:function-identity-helper');
 assert.deepEqual(budget.specialIdentities,[
  'public.zasp_security_agent_live_fingerprint()',
  'public.zasp_security_agent_session_isolation_live_fingerprint()',
  'public.zasp_security_agent_budgets_function_identity(oid)'
 ]);
 assert.ok(budget.sourceChildren.some(row=>row.sourceIdentity==='zasp_authorization80_worker.catalog_ready()'));
 assert.ok(budget.children.some(row=>row.ruleId==='saved-input:zasp_authorization80_worker.predecessor_functions'&&row.field==='definition'));
 const fixed=rule(out,'prior:budget:function-identity-fixed-resolution');
 assert.equal(fixed.selector.literalBindings.length,3);
 assert.equal(fixed.sourceMaxRows,null);
 assert.equal(fixed.selector.outerRuleId,'prior:budget:function');
 assert.equal(fixed.selector.sourceCastKind,'regprocedure');
 assert.match(fixed.from,/FROM pg_proc selected JOIN pg_namespace selected_ns/);
 assert.match(fixed.from,/JOIN pg_roles selected_owner/);
 assert.match(fixed.from,/CROSS JOIN \(VALUES/);
 assert.equal(fixed.projections.at(-1),'CASE WHEN selected.oid IS NOT NULL THEN d.literal::regprocedure::text ELSE NULL END');
 const readiness=rule(out,'prior:budget:function-identity-readiness-resolution');
 assert.deepEqual(readiness.selector.literalBindings,[{literal:'public.zasp_production_security_agent_budgets_readiness(text,text)',cast:'to_regprocedure'}]);
 assert.equal(readiness.sourceMaxRows,null);
 assert.equal(readiness.fieldTypes.resolvedIdentity,'text?');
 assert.match(readiness.projections.at(-1),/^CASE WHEN selected\.oid IN\(/);
 assert.match(readiness.projections.at(-1),/THEN NULL ELSE to_regprocedure\(d\.literal\)::text END$/);
 assert.match(readiness.from,/AND CASE WHEN selected\.oid IN\([\s\S]+::regprocedure\) THEN false/);
 assert.match(readiness.from,/THEN false ELSE true END$/);
 const writer=rule(out,'prior:budget:ordered-writer-resolution');
 assert.equal(writer.selector.literalBindings.length,15);
 assert.equal(writer.sourceMaxRows,null);
 assert.match(writer.from,/selected\.oid IN\(/);
 assert.match(writer.projections.at(-1),/^CASE WHEN selected\.oid IN\(/);
 assert.match(writer.projections.at(-1),/WHEN selected\.oid=to_regprocedure\('public\.zasp_production_security_agent_budgets_readiness\(text,text\)'\) THEN NULL ELSE d\.literal::regprocedure::text END$/);
 assert.match(writer.from,/AND CASE WHEN selected\.oid IN\(/);
 assert.match(writer.from,/WHEN selected\.oid=to_regprocedure\('public\.zasp_production_security_agent_budgets_readiness\(text,text\)'\) THEN false ELSE true END$/);
 for(const id of [fixed.id,readiness.id,writer.id])assert.ok(budget.children.some(row=>row.ruleId===id&&row.field==='resolvedIdentity'),id);
 for(const id of ['prior:existing:table','prior:run-context:activity-index','prior:budget:table','prior:budget:column','prior:budget:constraint','prior:budget:index','prior:budget:policy','prior:budget:trigger','prior:audit:table','prior:audit:view','prior:audit:source-shape','prior:audit:column','prior:audit:source-columns-shape','prior:audit:constraint','prior:audit:index','prior:audit:policy','prior:audit:trigger']){
  const raw=rule(out,id);assert.ok(raw.fields.includes('relation_name'),id);assert.match(raw.projections[raw.fields.indexOf('relation_name')],/\.relname::text$/,id);
 }
});

test('the prior chain, jobs and full-spelling global call use explicit source children and resolution proof',()=>{
 const out=buildOrderedPriorCaptureInputs(contract,catalog);
 const child=(family,label)=>out.runtimeAlgebra.find(row=>row.ruleId===`prior:${family}:${label}`)?.sourceChildren?.map(row=>row.sourceIdentity)??[];
 assert.deepEqual(child('compliance','prior'),['zasp_sa_attack_lab_prior.existing_tests_fingerprint()']);
 assert.deepEqual(child('compliance','jobs'),['public.zasp_compliance_jobs_catalog()']);
 assert.deepEqual(child('existing','prior'),['zasp_sa_attack_lab_prior.run_context_fingerprint()']);
 assert.deepEqual(child('run-context','prior'),['zasp_sa_attack_lab_prior.budget_fingerprint()']);
 assert.deepEqual(child('budget','prior'),['zasp_sa_attack_lab_prior.audit_fingerprint()']);
 assert.deepEqual(child('audit','prior'),['public.zasp_production_runtime_precision_live_fingerprint()']);

 const resolution=rule(out,'prior:existing:global-resolution');
 assert.equal(resolution.sqlPhase,'resolution');
 assert.equal(resolution.section,'resolutions');
 assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
 assert.match(resolution.from,/public\.zasp_production_security_agent_existing_tests_global_fingerprint\(\)/);
 assert.match(resolution.projections.at(-1),/::regprocedure::text/);
 const global=out.runtimeAlgebra.find(row=>row.ruleId==='prior:existing:global');
 assert.deepEqual(global.sourceChildren.map(row=>row.sourceIdentity),['public.zasp_production_security_agent_existing_tests_global_fingerprin()']);
 assert.ok(global.children.some(row=>row.ruleId==='prior:existing:global-resolution'&&row.field==='resolvedIdentity'));
});

test('owner and ACL normalization stays live while audit metadata remains witness-only',()=>{
 const out=buildOrderedPriorCaptureInputs(contract,catalog);
 for(const [family,relation] of [['compliance','public.zasp_data_controls'],['run-context','public.zasp_environments']]){
  const owner=rule(out,`prior:${family}:normalization-relation`);
  assert.equal(owner.selector.relation,relation);
  assert.deepEqual(owner.fields,['relation_identity','owner','raw_acl']);
  const acl=rule(out,`prior:${family}:routine-acl`);
  assert.equal(acl.bag,true);
  assert.match(acl.from,/aclexplode\(COALESCE\(p\.proacl,acldefault\('f',p\.proowner\)\)\)/);
  const algebra=out.runtimeAlgebra.find(row=>row.ruleId===`prior:${family}:function`);
  assert.equal(algebra.expectedFact,false);
  assert.ok(algebra.sourceChildren.some(row=>row.sourceIdentity==='public.zasp_audit_export_source_catalog_role(oid,oid)'));
  assert.ok(algebra.sourceChildren.some(row=>row.sourceIdentity==='public.zasp_audit_export_source_catalog_acl(aclitem[],oid)'));
 }

 const metadata=rule(out,'prior:audit:metadata');
 assert.equal(metadata.sqlPhase,'witness');
 assert.equal(metadata.section,'witnesses');
 assert.equal(metadata.bag,true);
 const principals=rule(out,'prior:audit:metadata-principals');
 assert.deepEqual(principals.fields,['principal_name','authority_role']);
 assert.match(principals.from,/public\.zasp_discovery_principal_bindings/);
 const metadataAlgebra=out.runtimeAlgebra.find(row=>row.ruleId==='prior:audit:metadata');
 assert.ok(metadataAlgebra.children.some(row=>row.ruleId==='prior:audit:metadata-principals'));
 assert.ok(!metadataAlgebra.children.some(row=>row.ruleId==='wrapper:principals'));
 const principalLogin=rule(out,'prior:audit:metadata-principal-login');
 assert.equal(principalLogin.sqlPhase,'witness');
 assert.equal(principalLogin.section,'witnesses');
 assert.equal(principalLogin.bag,true);
 const source=out.runtimeAlgebra.find(row=>row.ruleId==='prior:audit:source-table');
 assert.equal(source.expectedFact,false);
 for(const id of ['wrapper:audit-source:relation','wrapper:audit-workflow:relation','prior:audit:red-team-relation'])assert.ok(source.children.some(row=>row.ruleId===id),id);
 assert.ok(source.sourceChildren.some(row=>row.sourceIdentity==='public.zasp_audit_export_source_catalog_role(oid,oid)'));
 assert.ok(source.sourceChildren.some(row=>row.sourceIdentity==='public.zasp_audit_export_source_acl_ready()'));
 assert.ok(!out.rawRules.some(row=>['wrapper:audit-source-acl','wrapper:runtime-profile','wrapper:principals','wrapper:retired-authorities'].includes(row.id)));
});

test('pin drift and caller mutation refuse deterministically',()=>{
 const first=buildOrderedPriorCaptureInputs(contract,catalog),second=buildOrderedPriorCaptureInputs(contract,catalog);
 assert.deepEqual(second,first);
 assert.deepEqual(contract,JSON.parse(contractRaw));
 assert.deepEqual(catalog,JSON.parse(catalogRaw));
 const changed=structuredClone(contract),node=changed.nodes.find(row=>row.identity==='zasp_sa_attack_lab_prior.compliance_fingerprint()');node.source+=' ';
 assert.throws(()=>buildOrderedPriorCaptureInputs(changed,catalog),/prior capture source pin/);
 const broken=structuredClone(catalog);broken.relations=broken.relations.filter(row=>row.identity!=='public.zasp_data_controls');
 assert.throws(()=>buildOrderedPriorCaptureInputs(contract,broken),/prior capture catalog pin/);
});
