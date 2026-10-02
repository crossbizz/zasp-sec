import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  assertOrderedCurrentDirectReferenceV2,
  projectOrderedCurrentDirectReferenceV2,
  resolveOrderedCurrentForeignKeyEdge,
  mergeOrderedCurrentCanonicalCaptureFacts,
  canonicalizeOrderedCurrentSourceQualificationV2,
  canonicalizeOrderedCurrentDirectReferenceIdentityV2,
  testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2,
} from './ordered-current-direct-reference-v2.mjs';

test('native16 qualification proof canonicalizes pinned trigger and constraint deparse only',()=>{
 const catalog={
  relations:[{identity:'public.source_table'},{identity:'public.target_table'}],
  functions:[{identity:'public.guard_fn()'}],
  constraints:[{relation:'public.source_table',name:'source_fk',definition:'FOREIGN KEY (target_id) REFERENCES public.target_table(id)'}],
  triggers:[{relation:'public.source_table',name:'source_trigger',function:'public.guard_fn()',definition:'CREATE TRIGGER source_trigger BEFORE INSERT ON public.source_table FOR EACH ROW EXECUTE FUNCTION public.guard_fn()'}],
 };
 const constraint=canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-rule',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','source_fk']),fact:{definition:'FOREIGN KEY (target_id) REFERENCES target_table(id)'}},catalog);
 assert.equal(constraint.fact.definition,catalog.constraints[0].definition);
 assert.equal(constraint.source.qualificationProof,'pinned-catalog-qualification-only');
 const trigger=canonicalizeOrderedCurrentSourceQualificationV2({id:'worker-edge:runtime_projected50_search:1',kind:'trigger'},
  {identity:JSON.stringify(['public.source_table','source_trigger']),fact:{definition:'CREATE TRIGGER source_trigger BEFORE INSERT ON source_table FOR EACH ROW EXECUTE FUNCTION guard_fn()'}},catalog);
 assert.equal(trigger.fact.definition,catalog.triggers[0].definition);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-rule',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','source_fk']),fact:{definition:'FOREIGN KEY (target_id) REFERENCES other_table(id)'}},catalog),/semantic difference|qualification/i);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'worker-edge:runtime_projected50_search:1',kind:'trigger'},
  {identity:JSON.stringify(['public.source_table','source_trigger']),fact:{definition:'CREATE TRIGGER source_trigger BEFORE INSERT ON source_table FOR EACH ROW EXECUTE FUNCTION overloaded()'}},
  {...catalog,functions:[{identity:'public.overloaded(text)'}],triggers:[{...catalog.triggers[0],function:'public.overloaded()',definition:'CREATE TRIGGER source_trigger BEFORE INSERT ON public.source_table FOR EACH ROW EXECUTE FUNCTION public.overloaded()'}]}),/function.*join|ambiguous/i);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-rule',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','source_fk']),fact:{definition:'FOREIGN KEY ((target_id)) REFERENCES target_table(id)'}},catalog),/semantic difference|qualification/i);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-rule',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','source_fk']),fact:{definition:'FOREIGN KEY (target_id)  REFERENCES target_table(id)'}},catalog),/semantic difference|qualification/i);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-rule',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','source_fk']),fact:{definition:'FOREIGN KEY (target_id) REFERENCES target_table::text(id)'}},catalog),/semantic difference|qualification/i);
 assert.throws(()=>canonicalizeOrderedCurrentSourceQualificationV2({id:'worker-edge:runtime_projected50_search:1',kind:'trigger'},
  {identity:JSON.stringify(['public.source_table','source_trigger']),fact:{definition:'CREATE TRIGGER source_trigger BEFORE INSERT ON source_table FOR EACH ROW WHEN (OLD.id = NEW.id) EXECUTE FUNCTION guard_fn()'}},catalog),/semantic difference|qualification/i);
 const checkCatalog={...catalog,functions:[...catalog.functions,{identity:'public.zasp_valid_product_id(uuid)'}],constraints:[{relation:'public.source_table',name:'check_constraint',definition:'CHECK (public.zasp_valid_product_id(id))'}]};
 const check=canonicalizeOrderedCurrentSourceQualificationV2({id:'constraint-check',kind:'constraint'},
  {identity:JSON.stringify(['public.source_table','check_constraint']),fact:{definition:'CHECK (zasp_valid_product_id(id))'}},checkCatalog);
 assert.equal(check.fact.definition,'CHECK (public.zasp_valid_product_id(id))');
 assert.equal(check.source.qualificationLedger.catalogRegprocedure,'public.zasp_valid_product_id(uuid)');
 assert.equal(check.source.qualificationTokenSpans[0].spans[0].grammar,'check-function');
});

test('native16 runtime search qualifies all five relation fields and trigger routines',()=>{
 const catalog=JSON.parse(fs.readFileSync('services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json'));
 const packet=JSON.parse(fs.readFileSync('services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json'));
 const rule={id:'worker-edge:runtime_projected50_search:9',kind:'trigger'};
 const rows=packet.directFrame.expectedRows.filter(row=>JSON.parse(row.identity)[0]===rule.id);
 assert.equal(rows.length,5);
 for(const row of rows){
  const normalized=canonicalizeOrderedCurrentSourceQualificationV2(rule,row,catalog);
  assert.match(normalized.fact.relation,/^public\./);
  assert.match(normalized.fact.definition,/EXECUTE FUNCTION public\./);
  assert.equal(normalized.fact.name,row.fact.name);assert.equal(normalized.fact.enabled,row.fact.enabled);
  assert.deepEqual(normalized.source.qualificationFields.sort(),['definition','relation']);
 }
});

test('native17 preserves raw collector relation_name while retaining qualified trigger identity and definition',()=>{
 const catalog={
  relations:[{identity:'public.zasp_red_team_audit'},{identity:'public.zasp_gateway_devices'},{identity:'public.zasp_security_agent_temporary_policy_targets'}],
  functions:[{identity:'public.zasp_recovery_guard_scope_mutation()'}],
  triggers:[
   {relation:'public.zasp_red_team_audit',name:'zasp_red_team_audit_recovery_hold',function:'public.zasp_recovery_guard_scope_mutation()',definition:'CREATE TRIGGER zasp_red_team_audit_recovery_hold BEFORE INSERT ON public.zasp_red_team_audit FOR EACH ROW EXECUTE FUNCTION public.zasp_recovery_guard_scope_mutation()'},
   {relation:'public.zasp_gateway_devices',name:'zasp_gateway_devices_policy_sequence',function:'public.zasp_recovery_guard_scope_mutation()',definition:'CREATE TRIGGER zasp_gateway_devices_policy_sequence BEFORE INSERT ON public.zasp_gateway_devices FOR EACH ROW EXECUTE FUNCTION public.zasp_recovery_guard_scope_mutation()'},
  ],
 };
 for(const [ruleId,relation,name] of [
  ['worker-edge:gateway_projected27:12','public.zasp_red_team_audit','zasp_red_team_audit_recovery_hold'],
  ['worker-edge:ordered_projected28:9','public.zasp_gateway_devices','zasp_gateway_devices_policy_sequence'],
 ]){
  const row=canonicalizeOrderedCurrentSourceQualificationV2({id:ruleId,kind:'trigger'},
   {identity:JSON.stringify([relation,name]),fact:{relation_name:relation.slice(relation.indexOf('.')+1),definition_pretty:catalog.triggers.find(item=>item.relation===relation).definition.replaceAll('public.','')}},catalog);
  assert.equal(row.fact.relation_name,relation.slice(relation.indexOf('.')+1));
  assert.equal(JSON.parse(row.identity)[0],relation);
  assert.match(row.fact.definition_pretty,/ON public\./);
  assert.deepEqual(row.source.qualificationFields,['definition_pretty']);
 }
 const policyRelation='public.zasp_security_agent_temporary_policy_targets';
 const policyName='zasp_security_agent_targets_policy_sequence';
 const policyFact={relation_name:'zasp_security_agent_temporary_policy_targets',definition_pretty:"CREATE TRIGGER zasp_security_agent_targets_policy_sequence BEFORE INSERT ON zasp_security_agent_temporary_policy_targets FOR EACH ROW WHEN (new.state = 'planned'::text) EXECUTE FUNCTION zasp_policy_deployment_target_sequence_guard()"};
 const policy=canonicalizeOrderedCurrentSourceQualificationV2({id:'worker-edge:ordered_projected28:9',kind:'trigger'},
  {identity:JSON.stringify([policyRelation,policyName]),fact:policyFact},
  {...catalog,triggers:[...catalog.triggers,{relation:policyRelation,name:policyName,function:'public.zasp_policy_deployment_target_sequence_guard()',definition:'CREATE TRIGGER zasp_security_agent_targets_policy_sequence BEFORE INSERT ON public.zasp_security_agent_temporary_policy_targets FOR EACH ROW WHEN ((new.state = \'planned\'::text)) EXECUTE FUNCTION public.zasp_policy_deployment_target_sequence_guard()'}],functions:[...catalog.functions,{identity:'public.zasp_policy_deployment_target_sequence_guard()'}]});
 assert.deepEqual(policy.fact,policyFact);assert.equal(policy.source.qualificationLedger.status,'refused');assert.equal(policy.source.qualificationFields,undefined);
 const bindingRelation='public.zasp_security_agent_temporary_policy_targets',bindingName='zasp_security_agent_targets_policy_verify';
 const binding=canonicalizeOrderedCurrentSourceQualificationV2({id:'worker-edge:runtime_projected50_binding:4',kind:'trigger'},
  {identity:JSON.stringify([bindingRelation,bindingName]),fact:{name:bindingName,enabled:'O',definition_pretty:'CREATE TRIGGER zasp_security_agent_targets_policy_verify BEFORE UPDATE ON zasp_security_agent_temporary_policy_targets FOR EACH ROW EXECUTE FUNCTION zasp_policy_deployment_target_verify_guard()'}},
  {...catalog,triggers:[...catalog.triggers,{relation:bindingRelation,name:bindingName,function:'public.zasp_policy_deployment_target_verify_guard()',definition:'CREATE TRIGGER zasp_security_agent_targets_policy_verify BEFORE UPDATE ON public.zasp_security_agent_temporary_policy_targets FOR EACH ROW EXECUTE FUNCTION public.zasp_policy_deployment_target_verify_guard()'}],functions:[...catalog.functions,{identity:'public.zasp_policy_deployment_target_verify_guard()'}]});
 assert.equal(binding.fact.name,bindingName);assert.equal(binding.fact.enabled,'O');assert.equal(binding.fact.relation,undefined);assert.equal(binding.fact.relation_name,undefined);assert.match(binding.fact.definition_pretty,/ON public\./);assert.deepEqual(binding.source.qualificationFields,['definition_pretty']);
});

test('canonical capture merge is source-bound, byte-identical, and provenance retaining',()=>{
 const rows=[
  {kind:'relation',identity:'["inventory-fields:table","zasp_table"]',fact:{name:'zasp_table',owner:'owner'}},
  {kind:'relation',identity:'["inventory-fields:table","public.zasp_table"]',fact:{name:'zasp_table',owner:'owner'}},
 ];
 const canonical=rows.map(row=>({...row,identity:JSON.stringify(['inventory-fields:table','public.zasp_table'])}));
 const merged=mergeOrderedCurrentCanonicalCaptureFacts(rows,canonical);
 assert.equal(merged.facts.length,1);assert.equal(merged.merges.length,1);
 assert.deepEqual(merged.merges[0].captureIdentities.sort(),rows.map(row=>row.identity).sort());
 assert.throws(()=>mergeOrderedCurrentCanonicalCaptureFacts(rows,canonical.map((row,index)=>index?({...row,fact:{name:'different',owner:'owner'}}):row)),/canonical identity collision/);
 const crossRule=canonical.map((row,index)=>({...row,identity:JSON.stringify([index?'temporal72:table':'inventory-fields:table','public.zasp_table'])}));
 assert.equal(mergeOrderedCurrentCanonicalCaptureFacts(rows,crossRule).facts.length,2);
});

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const accepted=artifactOptIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const aPacketRoot=accepted?.packetBytes.A.packetDirectory,bPacketRoot=accepted?.packetBytes.B.packetDirectory;
const p7=aPacketRoot&&path.join(aPacketRoot,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const coveragePath=aPacketRoot&&path.join(aPacketRoot,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json');
const catalogPath=p7&&path.join(p7,'recovery80-effective-catalog.json');
function packetAvailable(root){
 const contractPath=root&&path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json'),required=root&&[path.join(root,'snapshot-manifest.json'),contractPath,path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json')];
 if(!required||!required.every(file=>fs.existsSync(file)))return false;
 try{return JSON.parse(fs.readFileSync(contractPath)).phases.flatMap(phase=>phase.batches).every(batch=>fs.existsSync(path.join(root,batch.file)));}catch{return false;}
}
const artifactsAvailable=Boolean(accepted)&&[accepted.packetBytes.A.capturePath,accepted.packetBytes.B.capturePath,path.join(p7,'recovery80-worker-compiled-release.json'),path.join(p7,'recovery80-effective-contract.json'),coveragePath,catalogPath].every(file=>fs.existsSync(file))&&packetAvailable(aPacketRoot)&&packetAvailable(bPacketRoot);
const artifactSkip=artifactOptIn?'fixed private frame-v2 artifact prerequisites unavailable':'set ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED=1 to run fixed private evidence tests';
const artifactTest=(name,fn)=>test(name,{skip:artifactsAvailable?false:artifactSkip},fn);
const fixed=()=>({
 aRaw:fs.readFileSync(accepted.packetBytes.A.capturePath),
 bRaw:fs.readFileSync(accepted.packetBytes.B.capturePath),
 aPacketRoot,bPacketRoot,
 compiledReleaseRaw:fs.readFileSync(path.join(p7,'recovery80-worker-compiled-release.json')),
 sourceContractRaw:fs.readFileSync(path.join(p7,'recovery80-effective-contract.json')),
 coverageRaw:fs.readFileSync(coveragePath),
 catalogRaw:fs.readFileSync(catalogPath),
});

test('FK edge helper binds all relation fields to the pinned constraint definition',()=>{
 const rule={id:'fk',kind:'foreign_key_trigger',selector:{field:'namespace',equals:'s'}};
 const catalog={
  relations:[{identity:'public.target'},{identity:'public.other'}],
  constraints:[{relation:'s.table',name:'constraint',definition:'FOREIGN KEY (id) REFERENCES public.target(id)'}],
  triggers:[{relation:'s.table',name:'trigger',function:'s.function()'},{relation:'public.target',name:'trigger',function:'s.function()'}],
 };
 const row={identity:JSON.stringify(['s.table','trigger']),fact:{name:'constraint'}};
 assert.deepEqual(resolveOrderedCurrentForeignKeyEdge(rule,row,catalog),{constraintRelation:'s.table',triggerRelation:'s.table',referencedRelation:'public.target',constraintPeerRelation:'public.target'});
 const opposite={identity:JSON.stringify(['public.target','trigger']),fact:{name:'constraint'}};
 assert.deepEqual(resolveOrderedCurrentForeignKeyEdge(rule,opposite,catalog),{constraintRelation:'s.table',triggerRelation:'public.target',referencedRelation:'public.target',constraintPeerRelation:'s.table'});
 assert.throws(()=>resolveOrderedCurrentForeignKeyEdge(rule,row,{...catalog,constraints:[{...catalog.constraints[0],definition:'CHECK (id > 0)'}]}),/FK definition form/);
 assert.throws(()=>resolveOrderedCurrentForeignKeyEdge(rule,row,{...catalog,constraints:[{...catalog.constraints[0],definition:'FOREIGN KEY (id) REFERENCES public.missing(id)'}]}),/referenced relation catalog join/);
 assert.throws(()=>resolveOrderedCurrentForeignKeyEdge(rule,row,{...catalog,relations:[...catalog.relations,{identity:'public.target'}]}),/referenced relation catalog join/);
});

test('direct reference refuses absent fixed intake authority',()=>{
 assert.throws(()=>projectOrderedCurrentDirectReferenceV2({}),/direct reference.*input/i);
});

test('component key joins use exact catalog atoms and reject missing or ambiguous matches',()=>{
 const catalog={
  columns:[{relation:'s.table',position:2,name:'column'}],
  constraints:[{relation:'s.table',name:'constraint'},{relation:'other.table',name:'constraint'}],
  indexes:[{identity:'s.index',relation:'s.table'}],
  policies:[{relation:'s.table',name:'policy'}],
  triggers:[{relation:'s.table',name:'trigger',function:'s.function()'}],
 };
 const key=(rule,identity,fact={})=>testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(rule,{identity,fact},catalog);
 assert.equal(key({id:'column',kind:'column_name'},JSON.stringify(['s.table',2,'column'])),JSON.stringify(['s.table','column']));
 assert.equal(key({id:'constraint',kind:'constraint'},JSON.stringify(['s','s.table',null,'constraint'])),JSON.stringify(['s.table','constraint']));
 assert.equal(key({id:'policy-view',kind:'policy_view',selector:{all:[{field:'namespace',equals:'s'},{field:'table_name',equals:'table'}]}},JSON.stringify(['s.table','policy']),{name:'policy'}),JSON.stringify(['s','table','policy']));
 assert.equal(key({id:'index-view',kind:'index_view',selector:{all:[{field:'namespace',equals:'s'},{field:'table_name',equals:'table'}]}},'s.index',{name:'index'}),JSON.stringify(['s','table','index']));
 const fk={id:'fk',kind:'foreign_key_trigger',selector:{field:'namespace',equals:'s'}};
 assert.equal(key(fk,JSON.stringify(['s.table','trigger']),{name:'constraint',event_bits:9}),JSON.stringify(['s.table','constraint','s.table','s.function()',9]));
 assert.throws(()=>key({id:'missing',kind:'column_name'},JSON.stringify(['s.table',3,'column'])),/catalog join \(0\)/);
 const ambiguous=structuredClone(catalog);ambiguous.constraints.push({relation:'s.other',name:'constraint'});
 assert.throws(()=>testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(fk,{identity:JSON.stringify(['s.table','trigger']),fact:{name:'constraint',event_bits:9}},ambiguous),/catalog join \(2\)/);
});

test('routine alias matching requires exact complete ordered type tokens',()=>{
 const rule={id:'temporal72:function',kind:'routine',selector:{field:'namespace',equals:'public'}};
 const accepted={identity:JSON.stringify('custom_function(value text)'),fact:{name:'custom_function',identity_arguments:'value text'}};
 assert.equal(testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(rule,accepted,{functions:[{identity:'public.custom_function(text)'}]}),'public.custom_function(text)');
 const malicious={identity:JSON.stringify('custom_function(value text)'),fact:{name:'custom_function',identity_arguments:'value text'}};
 assert.throws(()=>testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(rule,malicious,{functions:[{identity:'public.custom_function(malicioustext)'}]}),/routine alias catalog join \(0\)/);
 const suffix={identity:JSON.stringify('custom_function(collected_at timestamp with time zone)'),fact:{name:'custom_function',identity_arguments:'collected_at timestamp with time zone'}};
 assert.throws(()=>testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(rule,suffix,{functions:[{identity:'public.custom_function(with time zone)'}]}),/routine alias catalog join \(0\)|unsupported argument syntax/);
});

const aliasRule={id:'temporal72:function',kind:'routine',selector:{field:'namespace',equals:'public'}};
const aliasKey=(argumentsText,sourceType,factArguments,sourceArguments)=>canonicalizeOrderedCurrentDirectReferenceIdentityV2(aliasRule,
 {identity:JSON.stringify(`overload(${argumentsText})`),fact:factArguments===undefined?{name:'overload'}:{name:'overload',identity_arguments:factArguments}},
 {functions:[{identity:`public.overload(${sourceType})`,...(sourceArguments===undefined?{}:{arguments:sourceArguments})}]});

// These cases catch label/type confusion, the missing-fact regression and mode erasure.
for(const [argument,type] of [
 ['arg text','text'],['IN arg text','text'],['text','text'],['',''],
 ['at timestamp with time zone','timestamp with time zone'],
 ['timestamp with time zone','timestamp with time zone'],
 ['arg double precision[]','double precision[]'],['double precision[]','double precision[]'],
 ['arg public.custom_type[]','public.custom_type[]'],
 ['"argument with spaces" "Schema"."Type with spaces"[]','"Schema"."Type with spaces"[]'],
 ['arg numeric(10,2)','numeric(10,2)'],
])test(`shared alias preserves complete type ${argument||'no arguments'}`,()=>{
 assert.equal(aliasKey(argument,type),`public.overload(${type})`);
});

for(const [argument,type,fact] of [
 ['zone','timestamp with time zone','zone'],
 ['timestamp with time zone','zone','timestamp with time zone'],
 ['arg timestamp with time zone','zone','arg timestamp with time zone'],
 ['OUT arg text','text','OUT arg text'],['INOUT arg text','text','INOUT arg text'],
 ['VARIADIC arg text','text','VARIADIC arg text'],
 ['arg text','text','OUT arg text'],['arg text','text','INOUT arg text'],
 ['arg text','text','VARIADIC arg text'],['arg text','text','arg bytea'],
 ['arg text, other integer','text,integer','other integer, arg text'],
])test(`shared alias refuses changed mode/type ${argument} / ${fact}`,()=>{
 assert.throws(()=>aliasKey(argument,type,fact),/routine alias|argument/);
});

for(const mode of ['OUT','INOUT','VARIADIC'])test(`shared alias binds source-declared ${mode} mode`,()=>{
 assert.equal(aliasKey(`${mode} arg text`,'text',`${mode} arg text`,`${mode} arg text`),'public.overload(text)');
 assert.throws(()=>aliasKey('arg text','text','arg text',`${mode} arg text`),/routine alias|argument/);
});

test('shared alias checks explicit fact arguments without coercion',()=>{
 assert.equal(aliasKey('IN arg text','text','arg text'),'public.overload(text)');
 for(const value of [null,[],{},['arg text']])assert.throws(()=>aliasKey('arg text','text',value),/argument|routine alias/);
});

artifactTest('fixed intake projects all eleven worker and thirty-nine edge rules with canonical catalog keys',()=>{
 const result=projectOrderedCurrentDirectReferenceV2(fixed());
 assert.equal(result.status,'SOURCE-BOUND-DIRECT-EXPECTED-PROJECTION');
 assert.equal(result.installable,false);
 assert.equal(result.descriptorRules.length,50);
 assert.equal(result.descriptorRules.filter(rule=>rule.family==='worker').length,11);
 assert.equal(result.descriptorRules.filter(rule=>rule.family==='edge').length,39);
 assert.equal(result.expectedRows.length,1220);
 assert.equal(new Set(result.expectedRows.map(row=>row.identity)).size,1220);
 assert.deepEqual(result.provenance.frameComparison,{mode:'exact-unnormalized-selected-fact-multisets',rules:50,rows:1220,normalizationApplied:false});
 assert.equal(result.provenance.canonicalKeySource,'admitted-A-pinned-catalog-join');
 const routineRows=result.expectedRows.filter(row=>row.kind==='routine');
 assert.equal(routineRows.length,14);
 for(const row of routineRows)assert.deepEqual(Object.keys(row.source.fieldWitnesses),['config_json','config_raw','config_dims','config_ndims','config_bounds']);
 assert.equal(Object.hasOwn(result,'facts'),false);
 assert.equal(Object.hasOwn(result,'releaseFacts'),false);
 assert.doesNotThrow(()=>assertOrderedCurrentDirectReferenceV2(result));
});

artifactTest('foreign-key, column, constraint and view keys come from exact catalog joins',()=>{
 const result=projectOrderedCurrentDirectReferenceV2(fixed());
 const rows=kind=>result.expectedRows.filter(row=>row.kind===kind);
 assert.equal(rows('foreign_key_trigger').length,288);
 for(const row of rows('foreign_key_trigger')){
  assert.equal(JSON.parse(JSON.parse(row.identity)[1]).length,5);
  assert.equal(JSON.parse(row.source.captureIdentity).length,2);
  assert.equal(row.source.relationshipProof,'pinned-source-k.oid=t.tgconstraint');
 }
 for(const row of [...rows('column_name'),...rows('column_all')]){
  assert.equal(JSON.parse(JSON.parse(row.identity)[1]).length,2);
  assert.equal(JSON.parse(row.source.captureIdentity).length,3);
 }
 for(const row of rows('constraint')){
  assert.equal(JSON.parse(JSON.parse(row.identity)[1]).length,2);
  assert.equal(JSON.parse(row.source.captureIdentity).length,4);
 }
 for(const row of [...rows('policy_view'),...rows('index_view')])assert.equal(JSON.parse(JSON.parse(row.identity)[1]).length,3);
});

artifactTest('projection refuses altered source, coverage and catalog bytes',()=>{
 for(const field of ['sourceContractRaw','coverageRaw','catalogRaw']){
  const input=fixed();input[field]=Buffer.from(input[field]);input[field][0]^=1;
  assert.throws(()=>projectOrderedCurrentDirectReferenceV2(input),new RegExp(field==='catalogRaw'?'catalog identity':'source contract identity|coverage identity'));
 }
});

artifactTest('fixed intake pins refuse missing additional duplicate and selected-field drift',()=>{
 for(const mutate of [
  value=>{const at=value.aRaw.indexOf(Buffer.from('worker:projected_domain:table'));value.aRaw[at]^=1;},
  value=>{value.aRaw=Buffer.concat([value.aRaw.subarray(0,-1),Buffer.from(' '),value.aRaw.subarray(-1)]);},
  value=>{const at=value.aRaw.indexOf(Buffer.from('acl_text_or_empty'));value.aRaw[at]^=1;},
 ]){const input=fixed();input.aRaw=Buffer.from(input.aRaw);mutate(input);assert.throws(()=>projectOrderedCurrentDirectReferenceV2(input),/fixed A capture/);}
});

artifactTest('projection self-check refuses row count, field, type, frame and key drift',()=>{
 const original=projectOrderedCurrentDirectReferenceV2(fixed());
 const mutations=[
  value=>value.expectedRows.pop(),
  value=>value.expectedRows.push(structuredClone(value.expectedRows[0])),
  value=>{value.expectedRows[0].fact.unselected=true;},
  value=>{const row=value.expectedRows.find(candidate=>Object.values(candidate.fact).some(item=>typeof item==='boolean'));const field=Object.keys(row.fact).find(key=>typeof row.fact[key]==='boolean');row.fact[field]='false';},
  value=>{value.expectedRows[0].source.siteSHA256='0'.repeat(64);},
  value=>{value.expectedRows[0].identity=JSON.stringify(['wrong',JSON.parse(value.expectedRows[0].identity)[1]]);},
  value=>{delete value.expectedRows.find(row=>row.kind==='routine').source.fieldWitnesses;},
 ];
 for(const mutate of mutations){const value=structuredClone(original);mutate(value);assert.throws(()=>assertOrderedCurrentDirectReferenceV2(value),/direct reference/);}
});
