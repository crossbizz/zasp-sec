import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {buildOrderedMaterializedCaptureInputs} from './ordered-current-capture-materialized-inputs.mjs';
import {prepareOrderedCaptureRule,compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const base=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contractRaw=fs.readFileSync(new URL('ordered-current-effective-contract3.json',base));
const catalogRaw=fs.readFileSync(new URL('ordered-current-effective-catalog1.json',base));
assert.equal(sha(contractRaw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
assert.equal(sha(catalogRaw),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
const contract=JSON.parse(contractRaw),catalog=JSON.parse(catalogRaw);
const labels=['saved','legacy-approval-fence','legacy-action-fence','schema','function','table','column','constraint','index','trigger','foreign-key-trigger','policy'];
const baseRawIds=[
 'saved-input:zasp_sa_multistep_prior.functions',
 ...labels.slice(1).map(label=>`materialized:sa-multistep-prior:${label}`),
 'materialized:sa-multistep-prior:deployment-compile-saved',
 'materialized:ordered-writer-definition:routine',
 'materialized:ordered-writer-normalized-identity:routine'
];
const fullRoutineFields=['routine_identity','definition','source_body','owner','raw_acl','language','volatility','security_definer','strict','parallel','leakproof','config_json','config_raw','config_dims','config_ndims','config_bounds','identity_arguments','result','cost','rows'];
const branchPins={
 saved:'896cf4c6ca461438efdc8d2072732648daa97d5639bd61a80ca266e5c1d4413f',
 'legacy-approval-fence':'51eb24269fc9ed1657a6f3020e24f5364f6eff1bf876cd19862e289bd3ed39e7',
 'legacy-action-fence':'4b5e628134405d0deb24cc7d5372ce4c87e784c75c2ad285b2b15ef2e4ff44a0',
 schema:'be3549b7d4044edfb648c11846e0125fd8dbbea0038b546706b68469d92f3faf',
 function:'6d018f1ceb22996f8a4120e661b71d90a8089cbb59cb0155d06cf20a23a45161',
 table:'eaee4a4e227826501bdd7843c878ac9a4abcb0ed67b259bf0235f2ad4e7672bf',
 column:'2ff1e3bfbf3fc934d4c8d66968f53b07cb9d92ea07c2917af0973914dafcaea0',
 constraint:'fb33f6f11807f8c5158ea69a1b4147e844204a2d04117332b39b704f8bf661fd',
 index:'7ff0ae2ab21cb7fb9a053e125d2150c8a0eaaf129c02d63864a757de790937f6',
 trigger:'b6f57c516be7ce586f73a7b273fad525f901d8dfe5b67c3c5375fa756a6ddc95',
 'foreign-key-trigger':'eee5ba05bff4fff480c63e73ecc24aec142d68777d2c5302fd563f6bc3e206d0',
 policy:'5e172040ea207cd381fc610778a20a04634ab360af73620fed3c5629844c6de7'
};

test('materialized legacy multistep descriptors preserve all copied source branches',async t=>{
 const out=buildOrderedMaterializedCaptureInputs(contract,catalog);

 await t.test('finds exact lexical recipes and compiles one raw descriptor per label',()=>{
  assert.deepEqual(out.rawRules.slice(0,baseRawIds.length).map(rule=>rule.id),baseRawIds);
  assert.equal(out.rawRules.length,247);
  assert.equal(out.entries.length,out.rawRules.reduce((sum,rule)=>sum+rule.fields.length,0));
  const branches=out.runtimeAlgebra.filter(row=>row.disposition==='materialized-legacy-branch-algebra');
  assert.equal(branches.length,48);
  for(const label of labels){
   const selected=branches.filter(row=>row.branch===label);
   assert.equal(selected.length,4,label);
   assert.ok(selected.every(row=>row.siteSHA256===branchPins[label]));
  }
  assert.deepEqual(branches.filter(row=>row.branch==='saved').map(row=>row.start),[108454,96716,103627,110542]);
  assert.deepEqual(branches.filter(row=>row.branch==='policy').map(row=>row.end),[115016,103278,110189,117104]);
  for(const branch of branches){
   const node=contract.nodes.find(row=>row.identity===branch.sourceIdentity);
   assert.equal(branch.siteSHA256,sha(Buffer.from(node.source).subarray(branch.start,branch.end)));
   assert.equal(branch.expectedFact,false);
  }
  for(const rule of out.rawRules){
   assert.equal(rule.refusalMaxRows,10000);
   assert.notEqual(rule.sourceMaxRows,10000);
   const compiled=compileOrderedCaptureRule(prepareOrderedCaptureRule(rule));
   assert.ok(compiled.original,rule.id);
  }
 });

 await t.test('keeps private selectors, raw owner ACL and exact saved bags',()=>{
  const rule=id=>out.rawRules.find(row=>row.id===id);
  assert.deepEqual(rule('saved-input:zasp_sa_multistep_prior.functions').fields,['signature','definition','owner_name','acl']);
  assert.equal(rule('saved-input:zasp_sa_multistep_prior.functions').bag,true);
  assert.equal(rule('saved-input:zasp_sa_multistep_prior.functions').from,'FROM zasp_sa_multistep_prior.functions');
  for(const label of ['legacy-approval-fence','legacy-action-fence','function']){
   const routine=rule(`materialized:sa-multistep-prior:${label}`);
   for(const field of ['name','identity_arguments','raw_owner','raw_acl','definition'])assert.ok(routine.fields.includes(field),`${label}.${field}`);
   assert.equal(routine.canonicalClass,'pg_proc');
   assert.equal(routine.handleExpression,"'pg_proc:'||p.oid::text||':0'");
   assert.doesNotMatch(routine.projections.join(' '),/ordered_writer_(?:definition|normalized_identity)\s*\(/);
  }
  assert.match(rule('materialized:sa-multistep-prior:legacy-approval-fence').from,/p\.pronamespace='public'::regnamespace AND p\.proname IN\('zasp_security_agent_decide_approval'/);
  assert.match(rule('materialized:sa-multistep-prior:legacy-action-fence').from,/p\.pronamespace='public'::regnamespace AND p\.proname IN\('zasp_security_agent_claim_temporary_policy_effects'/);
  assert.equal(rule('materialized:sa-multistep-prior:function').from,"FROM pg_proc p WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace");
  assert.match(rule('materialized:sa-multistep-prior:table').from,/c\.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c\.relkind IN\('r','v','m','p','S'\)/);
  assert.match(rule('materialized:sa-multistep-prior:column').from,/c\.relkind IN\('r','p'\) AND a\.attnum>0 AND NOT a\.attisdropped/);
  assert.match(rule('materialized:sa-multistep-prior:foreign-key-trigger').from,/t\.tgisinternal AND k\.contype='f'/);
  const executable=out.rawRules.flatMap(rule=>[...rule.projections,rule.from]).join(' ').replace(/'(?:[^']|'')*'/g,'');
  assert.doesNotMatch(executable,/(?:public\.)?zasp_[a-z0-9_.]+\s*\(/i);
  assert.equal(out.rawRules.some(rule=>rule.id.startsWith('public:sa_multistep:')),false);
 });

 await t.test('retains source-specific helper demand without capturing helper truth',()=>{
  const branches=out.runtimeAlgebra.filter(row=>['legacy-approval-fence','legacy-action-fence','function'].includes(row.branch));
  assert.equal(branches.length,12);
  assert.equal(branches.filter(row=>row.sourceChildren[0].sourceIdentity==='zasp_authorization80_worker.ordered_writer_definition(oid)').length,8);
  assert.equal(branches.filter(row=>row.sourceChildren[0].sourceIdentity==='zasp_authorization80_worker.ordered_writer_normalized_identity(oid)').length,4);
  assert.ok(branches.every(row=>row.sourceChildren[0].execution==='selected original row only; helper result is not an expected fact'));
  assert.ok(branches.every(row=>row.children.some(child=>child.field==='raw_owner')&&row.children.some(child=>child.field==='raw_acl')));
  assert.deepEqual(out.unresolved,[]);
  const helperResolutions=out.rawRules.filter(row=>row.id.includes(':helper-resolution:'));
  const scopeResolutions=out.rawRules.filter(row=>row.id.includes(':scope-resolution:'));
  const branchResolutions=out.rawRules.filter(row=>row.id.includes(':branch-resolution:'));
  const callerPaths=[
   'zasp_temporal68.predecessor_ready(text,text):108775:legacy-approval-fence',
   'zasp_temporal68.predecessor_ready(text,text):109903:legacy-action-fence',
   'zasp_temporal68.predecessor_ready(text,text):111455:function',
   'zasp_temporal77.base67_fingerprint():97037:legacy-approval-fence',
   'zasp_temporal77.base67_fingerprint():98165:legacy-action-fence',
   'zasp_temporal77.base67_fingerprint():99717:function',
   'zasp_temporal77.base67_fingerprint():103948:legacy-approval-fence',
   'zasp_temporal77.base67_fingerprint():105076:legacy-action-fence',
   'zasp_temporal77.base67_fingerprint():106628:function',
   'zasp_temporal77.base67_fingerprint():110863:legacy-approval-fence',
   'zasp_temporal77.base67_fingerprint():111991:legacy-action-fence',
   'zasp_temporal77.base67_fingerprint():113543:function'
  ];
  assert.equal(helperResolutions.length,180);
  assert.equal(scopeResolutions.length,48);
  assert.equal(branchResolutions.length,4);
  assert.equal(new Set(out.rawRules.map(row=>row.id)).size,out.rawRules.length,'duplicate raw rule ID');
  assert.deepEqual([...new Set(helperResolutions.map(row=>row.selector.callerDemandPath))],callerPaths);
  assert.deepEqual([...new Set(scopeResolutions.map(row=>row.selector.callerDemandPath))],callerPaths);
  for(const resolution of [...helperResolutions,...scopeResolutions,...branchResolutions]){
   assert.equal(resolution.kind,'resolution');
   assert.equal(resolution.bag,true);
   assert.equal(resolution.sqlPhase,'resolution');
   assert.equal(resolution.section,'resolutions');
   assert.deepEqual(resolution.fields,['literal','cast','sourceSite','demandPath','resolvedIdentity']);
   assert.match(resolution.projections[4],/CASE WHEN .+ THEN '[^']+' ELSE NULL END/);
   assert.match(resolution.from,/FROM pg_proc p WHERE/);
  }
  for(const branch of branches){
   assert.equal(new Set(branch.children.filter(child=>child.ruleId.includes(':helper-resolution:')).map(child=>child.ruleId)).size,15);
   assert.equal(new Set(branch.children.filter(child=>child.ruleId.includes(':scope-resolution:')).map(child=>child.ruleId)).size,4);
   assert.equal(new Set(branch.children.filter(child=>child.ruleId.includes(':branch-resolution:')).map(child=>child.ruleId)).size,branch.branch==='function'?1:0);
  }
  for(const callerDemandPath of callerPaths){
   const selectedHelpers=helperResolutions.filter(row=>row.selector.callerDemandPath===callerDemandPath);
   const selectedScopes=scopeResolutions.filter(row=>row.selector.callerDemandPath===callerDemandPath);
   assert.equal(selectedHelpers.length,15,`missed or duplicate helper path ${callerDemandPath}`);
   assert.equal(new Set(selectedHelpers.map(row=>row.selector.literal)).size,15,`helper literal duplication ${callerDemandPath}`);
   assert.equal(selectedScopes.length,4,`missed or duplicate scope path ${callerDemandPath}`);
   assert.equal(new Set(selectedScopes.map(row=>`${row.sourceSite.sourceIdentity}:${row.sourceSite.start}`)).size,4,`scope occurrence duplication ${callerDemandPath}`);
  }
  for(const callerDemandPath of callerPaths.filter(path=>path.endsWith(':function'))){
   const selectedHelpers=helperResolutions.filter(row=>row.selector.callerDemandPath===callerDemandPath);
   assert.ok(selectedHelpers.every(row=>row.selector.selectedRowDemand==="p.oid<>'zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure"));
   assert.ok(selectedHelpers.every(row=>row.from.endsWith("AND (p.oid<>'zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure)")));
  }
  assert.ok(branchResolutions.every(row=>row.selector.literal==='zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'));
  assert.equal(new Set(scopeResolutions.map(row=>`${row.sourceSite.sourceIdentity}:${row.sourceSite.start}`)).size,48);
  const writer=out.runtimeAlgebra.find(row=>row.ruleId==='materialized:ordered-writer-definition:algebra');
  assert.equal(writer.sourceIdentity,'zasp_authorization80_worker.ordered_writer_definition(oid)');
  assert.equal(writer.helperBindings.length,15);
  assert.ok(writer.children.some(child=>child.ruleId==='saved-input:zasp_authorization80_worker.predecessor_functions'&&child.field==='definition'));
  const normalized=out.runtimeAlgebra.find(row=>row.ruleId==='materialized:ordered-writer-normalized-identity:algebra');
  assert.deepEqual(normalized.sourceChildren.map(child=>child.sourceIdentity),['zasp_authorization80_worker.ordered_writer_definition(oid)']);
  assert.deepEqual(normalized.replacements.map(row=>row.to),['<compiled-checksum>','<compiled-fingerprint>','<registered-fingerprint>']);
  for(const id of ['materialized:ordered-writer-definition:routine','materialized:ordered-writer-normalized-identity:routine']){
   const helper=out.rawRules.find(row=>row.id===id);
   assert.deepEqual(helper.fields,fullRoutineFields);
   assert.equal(helper.canonicalClass,'pg_proc');
   assert.equal(helper.sourceMaxRows,1);
  }
  const privateFunction=out.runtimeAlgebra.find(row=>row.branch==='function');
  assert.ok(privateFunction.children.some(child=>child.ruleId==='materialized:sa-multistep-prior:deployment-compile-saved'&&child.field==='definition'));
  assert.equal(out.rawRules.some(rule=>rule.fields.some(field=>/^(?:helper_result|guard_result|ready_result|verdict)$/.test(field))),false);
 });

 await t.test('refuses source, frame, branch and catalog-shape drift deterministically',()=>{
  const changedSource=structuredClone(contract);
  changedSource.nodes.find(node=>node.identity==='zasp_temporal77.base67_fingerprint()').source+=' ';
  assert.throws(()=>buildOrderedMaterializedCaptureInputs(changedSource,catalog),/materialized source pin/);
  const changedFrame=structuredClone(contract);
  changedFrame.nodes.find(node=>node.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').config=['search_path=public'];
  assert.throws(()=>buildOrderedMaterializedCaptureInputs(changedFrame,catalog),/materialized source frame/);
  const changedBranch=structuredClone(contract);
  const predecessor=changedBranch.nodes.find(node=>node.identity==='zasp_temporal68.predecessor_ready(text,text)');
  predecessor.source=predecessor.source.replace("concat_ws('|','legacy-action-fence'","concat_ws('|','legacy-action-fences'");
  predecessor.sourceSHA256=sha(predecessor.source);
  assert.throws(()=>buildOrderedMaterializedCaptureInputs(changedBranch,catalog),/materialized source pin|materialized recipe/);
  const changedCatalog=structuredClone(catalog);
  changedCatalog.columns.find(row=>row.relation==='zasp_sa_multistep_prior.functions'&&row.name==='acl').type='text';
  assert.throws(()=>buildOrderedMaterializedCaptureInputs(contract,changedCatalog),/materialized catalog pin/);
  assert.deepEqual(buildOrderedMaterializedCaptureInputs(contract,catalog),out);
 });
});
