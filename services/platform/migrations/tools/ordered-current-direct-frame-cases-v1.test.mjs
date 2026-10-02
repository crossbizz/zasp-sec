import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {directFrameAdaptersV1,directFrameRuleFieldMatrixV1} from './ordered-current-direct-frame-v1.mjs';
import {assertOrderedCurrentDirectFrameCasesV1,buildOrderedCurrentDirectFrameCasesV1} from './ordered-current-direct-frame-cases-v1.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const manifest=fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const root=manifest?.packetBytes.A.packetDirectory;
const p7=root&&path.join(root,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const paths=root&&{
 compiledReleaseRaw:path.join(p7,'recovery80-worker-compiled-release.json'),
 sourceContractRaw:path.join(p7,'recovery80-effective-contract.json'),
 coverageRaw:path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json'),
 catalogRaw:path.join(p7,'recovery80-effective-catalog.json'),
};
const available=Boolean(paths)&&Object.values(paths).every(file=>fs.existsSync(file));
if(artifactOptIn&&!available)test('fixed source input opt-in refuses missing fixture',()=>assert.fail('ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED=1 but fixed source inputs are unavailable'));
const artifactTest=(name,fn)=>test(name,{skip:available?false:'fixed source inputs unavailable; set ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED=1 to require them'},fn);
const input=()=>Object.fromEntries(Object.entries(paths).map(([key,file])=>[key,fs.readFileSync(file)]));
const signature=adapter=>`${adapter.name}(${adapter.args.map(argument=>argument[1]).join(',')})`;
let built;
const program=()=>built??=buildOrderedCurrentDirectFrameCasesV1(input());

test('builder and validator refuse absent or open-ended programs',()=>{
 assert.throws(()=>buildOrderedCurrentDirectFrameCasesV1(),/fixed input/);
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1({}),/program envelope/);
});

artifactTest('each exact adapter gets an executable isolated poison case and both gated collectors',()=>{
 const value=program(),expected=directFrameAdaptersV1.map(signature);
 assert.equal(value.installable,false);
 assert.deepEqual(value.poisonCases.map(item=>item.target.signature),expected);
 assert.equal(new Set(value.poisonCases.map(item=>item.id)).size,18);
 for(const item of value.poisonCases){
  assert.ok(item.mutation.sql.startsWith(`CREATE OR REPLACE FUNCTION ${item.target.name}(`));
  for(const type of item.target.argumentTypes)assert.ok(item.mutation.sql.includes(type));
  assert.match(item.mutation.sql,/RAISE EXCEPTION USING ERRCODE='ZX001'/);
  assert.deepEqual(item.stages.map(stage=>stage.id),['capture-pre-state','mutate','positive-invocation','rollback-positive-invocation','admission-probe','selector-reachability-probe','direct-gated-collector','transform-gated-collector','assert-noninvocation','rollback-case','verify-restoration']);
  assert.equal(item.stages[4].expectedAdmission,false);
  assert.equal(item.stages[5].minimumRows,1);
  assert.equal(item.stages[5].selectedKeyAuthority,'requiredAcceptance.directExpectedRows');
  assert.deepEqual(item.stages.slice(6,8).map(stage=>[stage.expectedOutcome,stage.expectedRows,stage.frame,stage.forbiddenSQLState]),[['success',0,'canonicalCollector','ZX001'],['success',0,'canonicalCollector','ZX001']]);
  assert.equal(item.stages[2].expectedSQLState,'ZX001');
  assert.equal(item.nonInvocation.mode,'reachable-poison-no-error');
  assert.equal(item.nonInvocation.forbiddenSQLState,'ZX001');
  assert.equal(item.nonInvocation.affectedCollector,'direct');
  assert.equal(item.reachability.minimumRows,1);
  assert.equal(item.reachability.selectedKeyAuthority,'requiredAcceptance.directExpectedRows');
  assert.equal(item.reachability.expectedKeyComparison,'exact-rule-canonical-key-set');
  assert.match(item.reachability.callBindingSHA256,/^[a-f0-9]{64}$/);
  assert.match(item.reachability.selectorWitnessSQL,/^SELECT identity FROM \(/);
  assert.equal(crypto.createHash('sha256').update(item.reachability.selectorWitnessSQL).digest('hex'),item.reachability.selectorWitnessSQLSHA256);
  const matrix=directFrameRuleFieldMatrixV1.find(rule=>rule.id===item.reachability.ruleId);
  const leaf=matrix?.fields.find(field=>field.name===item.reachability.field);
  assert.equal(leaf?.adapter,item.target.name.split('.').at(-1));
  assert.equal(leaf?.source,item.reachability.sourceExpression);
  assert.equal(item.limits.caseSeconds,10);
  assert.equal(item.limits.cleanupSeconds,3);
  assert.equal(Object.hasOwn(item,'restoreSQL'),false);
 }
});

artifactTest('property controls isolate owner ACL config body signature arity and overload changes',()=>{
 const value=program(),byId=new Map(value.propertyCases.map(item=>[item.id,item]));
 assert.deepEqual([...byId.keys()],['adapter-owner','adapter-acl','adapter-config','adapter-body-signature','adapter-exact-arity','adapter-extra-overload']);
 assert.match(byId.get('adapter-owner').mutation.sql,/ALTER FUNCTION .* OWNER TO zasp_test/);
 assert.match(byId.get('adapter-owner').mutation.sql,/GRANT EXECUTE ON FUNCTION .* TO zasp_discovery_authority/);
 assert.doesNotMatch(byId.get('adapter-owner').mutation.sql,/REVOKE|SET search_path|CREATE/);
 assert.match(byId.get('adapter-acl').mutation.sql,/REVOKE ALL .* zasp_discovery_authority/);
 assert.doesNotMatch(byId.get('adapter-acl').mutation.sql,/OWNER TO|SET search_path|CREATE/);
 assert.match(byId.get('adapter-config').mutation.sql,/SET search_path TO public/);
 assert.match(byId.get('adapter-body-signature').mutation.sql,/RETURN 'altered-body'/);
 assert.match(byId.get('adapter-exact-arity').mutation.sql,/DROP FUNCTION/);
 assert.match(byId.get('adapter-exact-arity').mutation.sql,/value pg_catalog\.oid, extra pg_catalog\.oid/);
 assert.match(byId.get('adapter-extra-overload').mutation.sql,/value pg_catalog\.text/);
 for(const item of value.propertyCases.filter(item=>!['adapter-acl','adapter-exact-arity'].includes(item.id))){
  assert.equal(item.expectedAdmission,false);
  assert.deepEqual(item.collectorOutcomes.map(outcome=>[outcome.collector,outcome.rows]),[['direct',0],['transform',0]]);
  assert.equal(item.reachability.minimumRows,1);
  assert.ok(item.stages.some(stage=>stage.id==='admission-probe'&&stage.expectedAdmission===false));
  assert.ok(item.stages.some(stage=>stage.id==='selector-reachability-probe'&&stage.minimumRows===1&&stage.selectedKeyAuthority==='requiredAcceptance.directExpectedRows'));
 }
 assert.deepEqual(byId.get('adapter-acl').collectorOutcomes,[{collector:'direct',outcome:'error',expectedSQLState:'42501'},{collector:'transform',outcome:'success',rows:0}]);
 assert.deepEqual(byId.get('adapter-exact-arity').collectorOutcomes,[{collector:'direct',outcome:'error',expectedSQLState:'42883'},{collector:'transform',outcome:'success',rows:0}]);
 for(const id of ['adapter-acl','adapter-exact-arity']){
  const stages=byId.get(id).stages.map(stage=>stage.id),begin=stages.indexOf('begin-direct-savepoint');
  assert.deepEqual(stages.slice(begin,begin+4),['begin-direct-savepoint','direct-gated-collector','rollback-direct-savepoint','transform-gated-collector']);
 }
});

artifactTest('semantic probes contain original and adapter expressions with exact error and lazy controls',()=>{
 const value=program(),byId=new Map(value.semanticProbes.map(item=>[item.id,item]));
 for(const id of ['routine-definition','routine-identity-arguments','routine-identity','null-regclass','missing-column-default','regclass-selected-error','regclass-unselected-lazy','constraint-pretty-false','constraint-pretty-true','index-core-definition','trigger-pretty-false','trigger-pretty-true','policy-view-computed-text','index-view-computed-text'])assert.ok(byId.has(id),id);
 assert.equal(byId.get('null-regclass').expectedOutcome,'equal-null');
 assert.equal(byId.get('regclass-selected-error').expectedSQLState,'42P01');
 assert.equal(byId.get('regclass-unselected-lazy').expectedOutcome,'equal-text');
 assert.match(byId.get('constraint-pretty-true').originalSQL,/pg_get_constraintdef\([^,]+,true\)/);
 assert.match(byId.get('trigger-pretty-true').adapterSQL,/trigger_definition_pretty_public/);
 assert.equal(byId.get('trigger-when-null-and-value').expectedSQLState,'22023');
 assert.match(byId.get('policy-view-computed-text').originalSQL,/pg_catalog\.pg_policies/);
 assert.match(byId.get('index-view-computed-text').originalSQL,/pg_catalog\.pg_indexes/);
 assert.match(byId.get('index-view-computed-text').originalSQL,/__ordered_frame_probe_index_idx/);
 assert.doesNotMatch(byId.get('regclass-unselected-lazy').originalSQL,/'public\.__ordered_missing_frame_relation'::pg_catalog\.regclass/);
 assert.match(byId.get('regclass-unselected-lazy').originalSQL,/CURRENT_USER/);
 for(const id of ['constraint-pretty-false','trigger-pretty-false','policy-view-computed-text','index-view-computed-text'])assert.ok(byId.get(id).setupSQL.some(sql=>/GRANT (SELECT|EXECUTE).*zasp_discovery_authority/.test(sql)),`fixture grant ${id}`);
 for(const probe of value.semanticProbes){
  assert.equal(probe.originalFrame,'sourceDiscoveryPublic');
  assert.equal(probe.adapterFrame,'canonicalCollector');
  assert.equal(probe.rollback,'required');
 }
 for(const adapter of directFrameAdaptersV1)assert.ok(value.semanticProbes.some(probe=>probe.adapterSQL.includes(adapter.name+'(')),`semantic probe ${adapter.name}`);
});

artifactTest('successor source independently compiles every transform rule and preserves original controls',()=>{
 const value=program(),transform=value.successorTransform;
 assert.equal(transform.rules.length,13);
 assert.equal(new Set(transform.rules.map(rule=>rule.id)).size,13);
 assert.equal(transform.compiled.recipes,13);
 assert.equal(transform.compiled.sourceSHA256,transform.compiledSQLSHA256);
 assert.match(transform.compiled.sql,/definition_frame_admission AS MATERIALIZED/);
 for(const rule of transform.rules){
  assert.equal(rule.executionFrame,'sourceDiscoveryPublic');
  assert.match(rule.originalSQL,/^SELECT p\.oid::text AS object_oid/);
  assert.match(rule.candidateSQL,/definition_frame_admission AS MATERIALIZED/);
  assert.match(rule.rosterSQL,/p\.oid::regprocedure::text AS identity/);
  assert.equal(rule.fields.length,Object.keys(rule.fieldTypes).length);
  const aggregateProjection=rule.candidateAggregateSQL.split(' AS line FROM (')[0];
  for(const [field,type] of Object.entries(rule.fieldTypes))if(type==='boolean')assert.match(aggregateProjection,new RegExp(`fact->>'${field.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}'\\)::boolean`));
 }
 assert.deepEqual(transform.cases.map(item=>item.id),['pristine','config-null','config-empty','config-quoted','config-nonstandard','owner','acl','replacement','constraint-duplicate','constraint-null','saved-missing','saved-null-definition','saved-null-acl','saved-duplicate-definition','saved-duplicate-acl','saved-unselected-duplicate','saved-missing-column','saved-missing-relation','literal-missing']);
 assert.equal(transform.cases.find(item=>item.id==='saved-duplicate-definition').expectedSQLState,'21000');
 assert.equal(transform.cases.find(item=>item.id==='saved-missing-column').expectedSQLState,'42703');
 assert.equal(transform.cases.find(item=>item.id==='literal-missing').expectedSQLState,'42883');
 for(const item of transform.cases){
  const ids=item.stages.map(stage=>stage.id);
  assert.equal(ids[0],'capture-pre-state');
  assert.ok(ids.includes('apply-mutations'));
  assert.ok(ids.includes('run-roster-probes'));
  assert.equal(item.stages.find(stage=>stage.id==='run-roster-probes').frame,'canonicalCollector');
  assert.equal(ids.at(-2),'rollback-case');
  assert.equal(ids.at(-1),'verify-restoration');
  assert.ok(item.stages.filter(stage=>!stage.id.startsWith('rollback-')&&stage.id!=='verify-restoration').every(stage=>stage.timeoutSeconds===10));
  assert.ok(item.stages.filter(stage=>stage.id.startsWith('rollback-')||stage.id==='verify-restoration').every(stage=>stage.timeoutSeconds===3));
  if(item.probeSQL){
   assert.ok(ids.includes('begin-probe-error-savepoint'));
   assert.ok(ids.includes('run-expected-error-probe'));
   assert.ok(ids.includes('rollback-probe-error-savepoint'));
   assert.ok(ids.includes('compare-exact-aggregates'));
  }else if(item.expectedSQLState){
   assert.ok(ids.includes('begin-original-error-savepoint'));
   assert.ok(ids.includes('rollback-original-error-savepoint'));
   assert.ok(ids.includes('begin-candidate-error-savepoint'));
   assert.ok(ids.includes('rollback-candidate-error-savepoint'));
   assert.ok(ids.includes('compare-error-sqlstates'));
  }else{
   assert.ok(ids.includes('run-original-aggregates'));
   assert.ok(ids.includes('run-candidate-aggregates'));
   assert.ok(ids.includes('compare-exact-aggregates'));
  }
 }
});

artifactTest('program pins complete acceptance and rejects byte or schema drift',()=>{
 const value=program();
 assert.deepEqual(value.requiredAcceptance,{rules:63,rows:1600,directRules:50,directRows:1220,transformRules:13,transformRows:380,comparison:'exact-unnormalized-facts-and-canonical-keys',oldUniverse:'byte-identical-before-and-after-all-cases'});
 assert.deepEqual(value.blockingDependencies.map(item=>item.id),['independent-expected-rows','original-universe-query','successor-installation-proof','native-execution']);
 const changed=structuredClone(value);changed.poisonCases[0].stages[4].expectedRows=1;
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(changed),/poison case/);
 const unknownStage=structuredClone(value);unknownStage.poisonCases[0].stages[0].callerSQL='SELECT true';
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(unknownStage),/poison case/);
 const unknownProperty=structuredClone(value);unknownProperty.propertyCases[0].extra=true;
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(unknownProperty),/property cases/);
 const unknownProbe=structuredClone(value);unknownProbe.semanticProbes[0].callback='run-anything';
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(unknownProbe),/semantic probes/);
 const rehashedDirect=structuredClone(value);rehashedDirect.directCollector.sql+=' SELECT 1';rehashedDirect.directCollector.sqlSHA256=crypto.createHash('sha256').update(rehashedDirect.directCollector.sql).digest('hex');
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(rehashedDirect),/direct collector/);
 const rehashedTransform=structuredClone(value);rehashedTransform.successorTransform.rules[0].originalSQL+=' ';
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(rehashedTransform),/successor transform authority/);
 const sameCountWrongWitness=structuredClone(value);sameCountWrongWitness.poisonCases[0].reachability.ruleId=sameCountWrongWitness.poisonCases[2].reachability.ruleId;
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(sameCountWrongWitness),/poison case/);
 const missingTransformStage=structuredClone(value);missingTransformStage.successorTransform.cases[0].stages.splice(3,1);
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(missingTransformStage),/successor transform authority|successor transform case/);
 const unknownTransformStage=structuredClone(value);unknownTransformStage.successorTransform.cases[0].stages[0].arbitrarySQL='SELECT true';
 assert.throws(()=>assertOrderedCurrentDirectFrameCasesV1(unknownTransformStage),/successor transform authority|successor transform case/);
 const drift=input();drift.catalogRaw=Buffer.from(drift.catalogRaw);drift.catalogRaw[10]^=1;
 assert.throws(()=>buildOrderedCurrentDirectFrameCasesV1(drift),/catalog identity/);
});
