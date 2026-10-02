import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  assertOrderedCurrentMissingReferenceContractV1,
  buildOrderedCurrentMissingReferenceContractV1,
} from './ordered-current-missing-reference-contract-v1.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_MISSING_REFERENCE_ACCEPTED==='1';
const accepted=artifactOptIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const packetRoot=accepted?.packetBytes?.A?.packetDirectory;
const p7=packetRoot&&path.join(packetRoot,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const files=p7&&{
 compiledRelease:path.join(p7,'recovery80-worker-compiled-release.json'),
 sourceContract:path.join(p7,'recovery80-effective-contract.json'),
 catalog:path.join(p7,'recovery80-effective-catalog.json'),
};
const artifactsAvailable=Boolean(files)&&Object.values(files).every(file=>fs.existsSync(file));
const artifactSkip=artifactOptIn?'fixed accepted source artifacts unavailable':'set ZASP_ORDERED_CURRENT_MISSING_REFERENCE_ACCEPTED=1 to run fixed private evidence tests';
const artifactTest=(name,fn)=>test(name,{skip:artifactsAvailable?false:artifactSkip},fn);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const rehash=value=>{delete value.contractSHA256;value.contractSHA256=sha(JSON.stringify(value));return value;};
const fixed=()=>({
 compiledReleaseRaw:fs.readFileSync(files.compiledRelease),
 sourceContractRaw:fs.readFileSync(files.sourceContract),
 catalogRaw:fs.readFileSync(files.catalog),
});
const ids=[
 'role-profile:current-profile','role-profile:native-roles',
 'temporal72:table','temporal72:function','temporal72:policy','temporal72:trigger','temporal72:role','temporal72:precision-function',
 'inventory-fields:table','inventory-fields:policy','inventory-fields:function','inventory-fields:role',
];
const bounds=[1,3,18,56,17,2,4,51,9,8,34,1];
const fields={
 'role-profile:current-profile':['singleton','name'],
 'role-profile:native-roles':['login','superuser','create_db','create_role','replication','bypass_rls'],
 'temporal72:table':['name','owner','row_security','forced_row_security','execution_acl_text'],
 'temporal72:function':['name','identity_arguments','owner','security_definer','execution_config_text','execution_acl_text','execution_body'],
 'temporal72:policy':['relation_name','name','permissive','command','execution_roles_text','using','check'],
 'temporal72:trigger':['relation_name','name','execution_definition','enabled','function'],
 'temporal72:role':['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','execution_v1_managed_here'],
 'temporal72:precision-function':['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','precision_definition'],
 'inventory-fields:table':['name','owner','row_security','forced_row_security','execution_acl_text'],
 'inventory-fields:policy':['relation_name','name','permissive','command','execution_roles_text','using','check'],
 'inventory-fields:function':['name','identity_arguments','inventory_owner','security_definer','execution_config_text','inventory_acl_text','inventory_body'],
 'inventory-fields:role':['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','inventory_v1_managed_here'],
};

test('missing-reference contract refuses absent fixed source authority',()=>{
 assert.throws(()=>buildOrderedCurrentMissingReferenceContractV1({}),/missing reference contract.*input/i);
});

artifactTest('fixed accepted source builds the complete twelve-rule 204-row noninstallable capture contract',()=>{
 const value=buildOrderedCurrentMissingReferenceContractV1(fixed());
 assert.equal(value.status,'SOURCE-BOUND-MISSING-REFERENCE-CAPTURE-CONTRACT-V1');
 assert.equal(value.installable,false);
 assert.equal(value.captureStatus,'NOT-CAPTURED');
 assert.equal(Object.hasOwn(value,'expectedRows'),false);
 assert.equal(Object.hasOwn(value,'facts'),false);
 assert.deepEqual(value.rules.map(rule=>rule.id),ids);
 assert.deepEqual(value.rules.map(rule=>rule.maxRows),bounds);
 assert.equal(value.maxRows,204);
 assert.deepEqual(Object.fromEntries(value.rules.map(rule=>[rule.id,rule.fields])),fields);
 assert.deepEqual(value.sourceAuthority,{
  compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
  compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
  compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
  sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
  catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',
 });
 assert.equal(value.rules.find(rule=>rule.id==='role-profile:current-profile').sourceSites.length,7);
 assert.equal(value.rules.find(rule=>rule.id==='role-profile:native-roles').sourceSites.length,4);
 assert.equal(value.rules.slice(2).every(rule=>rule.sourceSites.length===1),true);
 for(const rule of value.rules){
  assert.match(rule.projectionSQL,/^SELECT /);
  assert.match(rule.canonicalRosterSQL,/^SELECT /);
  assert.equal(rule.canonicalRosterFrame.searchPath,'pg_catalog');
  assert.equal(rule.fieldProjections.length,rule.fields.length);
  assert.deepEqual(rule.fieldProjections.map(field=>field.name),rule.fields);
  for(const field of rule.fields)assert.match(rule.projectionSQL,new RegExp(` AS "${field}"(?:,| )`));
  assert.equal(rule.sourceSites.every(site=>site.frame.searchPath.join(', ')==='pg_catalog, public'),true);
  const executableSQL=rule.projectionSQL.replace(/'(?:[^']|'')*'/g,'');
  assert.doesNotMatch(executableSQL,/\.([a-z0-9_]*fingerprint|[a-z0-9_]*readiness)\s*\(/i);
 }
 const inventoryFunction=value.rules.find(rule=>rule.id==='inventory-fields:function');
 assert.match(inventoryFunction.projectionSQL,/ELSE grantor\.rolname END\) FROM aclexplode/);
 assert.match(value.rules.find(rule=>rule.id==='role-profile:current-profile').projectionSQL,/zasp_authorization80\.runtime_profile/);
 assert.doesNotMatch(value.rules.find(rule=>rule.id==='role-profile:current-profile').projectionSQL,/registration/i);
 assert.equal(value.witnesses.some(row=>row.id==='role-profile:current-profile:aggregate'&&row.sql.includes('count(*)=1 AND bool_and')),true);
 assert.equal(value.witnesses.some(row=>row.id==='role-profile:native-roles:membership'&&row.sql.includes('roleid=')&&row.sql.includes(' OR member IN')),true);
 assert.equal(value.unresolved.some(row=>row.kind==='runtime-profile-direct-capture'),true);
 assert.equal(value.unresolved.some(row=>row.kind==='installation-dependent-managed-marker'),true);
 assert.doesNotThrow(()=>assertOrderedCurrentMissingReferenceContractV1(value));
});

artifactTest('fixed authority rejects altered compiler, source, catalog, source anchor, frame and profile-table substitution',()=>{
 for(const field of ['compiledReleaseRaw','sourceContractRaw','catalogRaw']){
  const input=fixed();input[field]=Buffer.from(input[field]);input[field][0]^=1;
  assert.throws(()=>buildOrderedCurrentMissingReferenceContractV1(input),/missing reference contract/);
 }
 for(const replacement of [
  ['zasp_authorization80.runtime_profile','zasp_authorization80.registration'],
  ['"owner": "zasp_discovery_authority"','"owner": "zasp_inventory_authority"'],
  ["count(*)=1 AND bool_and","count(*)=2 AND bool_and"],
 ]){
  const input=fixed(),text=input.sourceContractRaw.toString(),at=text.indexOf(replacement[0]);assert.ok(at>=0,replacement[0]);
  input.sourceContractRaw=Buffer.from(text.slice(0,at)+replacement[1]+text.slice(at+replacement[0].length));
  assert.throws(()=>buildOrderedCurrentMissingReferenceContractV1(input),/source contract identity/);
 }
});

artifactTest('schema check refuses missing, extra and duplicate rules and profile-registration substitution',()=>{
 const original=buildOrderedCurrentMissingReferenceContractV1(fixed()),mutations=[
  value=>value.rules.pop(),
  value=>value.rules.push(structuredClone(value.rules[0])),
  value=>{value.rules[0].id='extra:rule';},
  value=>{value.rules[0].projectionSQL=value.rules[0].projectionSQL.replace('zasp_authorization80.runtime_profile','zasp_authorization80.registration');},
  value=>{value.rules[3].maxRows=55;},
  value=>{value.rules[4].selector={field:'namespace',equals:'public'};},
 ];
 for(const mutate of mutations){const value=structuredClone(original);mutate(value);assert.throws(()=>assertOrderedCurrentMissingReferenceContractV1(value),/missing reference contract/);}
});

artifactTest('every emitted projection expression is bound to an exact source span and frame-separated identity membership program',()=>{
 const value=buildOrderedCurrentMissingReferenceContractV1(fixed());
 for(const rule of value.rules){
  assert.equal(rule.projectionRecipe.length,rule.fields.length+1,rule.id);
  assert.equal(rule.projectionRecipe[0].role,'capture-identity',rule.id);
  assert.deepEqual(rule.projectionRecipe.slice(1).map(entry=>entry.name),rule.fields,rule.id);
  for(const entry of rule.projectionRecipe){
   assert.equal(entry.expressionSHA256,sha(entry.expression),`${rule.id}:${entry.name}`);
   assert.ok(entry.sourceBindings.length>0,`${rule.id}:${entry.name}`);
   for(const binding of entry.sourceBindings){
    const site=rule.sourceSites.find(candidate=>candidate.siteSHA256===binding.siteSHA256&&candidate.sourceIdentity===binding.sourceIdentity&&candidate.start===binding.siteStart);
    assert.ok(site,`${rule.id}:${entry.name}:site`);
    assert.equal(site.sourceExpression.slice(binding.start-site.start,binding.end-site.start),binding.text,`${rule.id}:${entry.name}:span`);
    assert.equal(binding.sha256,sha(binding.text),`${rule.id}:${entry.name}:hash`);
   }
  }
  assert.match(rule.outputControlSQL,/count\(DISTINCT capture_identity\)/i,rule.id);
  assert.match(rule.rosterControlSQL,/count\(DISTINCT identity\)/i,rule.id);
  assert.equal(Object.hasOwn(rule,'membershipControlSQL'),false,rule.id);
  assert.deepEqual(rule.membershipProgram.transaction,{boundary:'single-fixed-transaction',snapshot:'same-snapshot',readOnly:true},rule.id);
  assert.deepEqual(rule.membershipProgram.steps.map(step=>step.id),['capture-projection-identities','capture-canonical-roster-identities','compare-identity-multisets'],rule.id);
  const [projectionCapture,rosterCapture,comparison]=rule.membershipProgram.steps;
  assert.equal(projectionCapture.frame,'projectionFrame',rule.id);
  assert.equal(projectionCapture.output.name,'projectionIdentities',rule.id);
  assert.equal(projectionCapture.output.type,'text[]',rule.id);
  assert.match(projectionCapture.sql,/array_agg\(capture_identity ORDER BY capture_identity\)/,rule.id);
  assert.ok(projectionCapture.sql.includes(rule.projectionSQL),rule.id);
  assert.equal(rosterCapture.frame,'canonicalRosterFrame',rule.id);
  assert.equal(rosterCapture.output.name,'canonicalRosterIdentities',rule.id);
  assert.equal(rosterCapture.output.type,'text[]',rule.id);
  assert.match(rosterCapture.sql,/array_agg\(identity ORDER BY identity\)/,rule.id);
  assert.ok(rosterCapture.sql.includes(rule.canonicalRosterSQL),rule.id);
  assert.equal(comparison.frame,'bound-values-only',rule.id);
  assert.deepEqual(comparison.inputs,[{name:'projectionIdentities',type:'text[]',parameter:1},{name:'canonicalRosterIdentities',type:'text[]',parameter:2}],rule.id);
  assert.match(comparison.sql,/\$1::text\[\]/,rule.id);
  assert.match(comparison.sql,/\$2::text\[\]/,rule.id);
  assert.equal((comparison.sql.match(/EXCEPT ALL/g)??[]).length,2,rule.id);
  assert.equal((comparison.sql.match(/count\(DISTINCT identity\)/g)??[]).length,2,rule.id);
  assert.equal(comparison.sql.includes(rule.projectionSQL),false,rule.id);
  assert.equal(comparison.sql.includes(rule.canonicalRosterSQL),false,rule.id);
  assert.deepEqual(rule.keyProjection.fields,rule.keyFields,rule.id);
  assert.equal(rule.keyProjection.expression,rule.projectionRecipe[0].expression,rule.id);
 }
 const inventoryFunction=value.rules.find(rule=>rule.id==='inventory-fields:function');
 assert.match(inventoryFunction.membershipProgram.steps[0].sql,/'zasp_core_payloads'::regclass/);
 assert.doesNotMatch(inventoryFunction.membershipProgram.steps[1].sql,/zasp_core_payloads/);
 assert.doesNotMatch(inventoryFunction.membershipProgram.steps[2].sql,/zasp_core_payloads|pg_proc|projection/i);
});

artifactTest('closed semantic assertion rejects recomputed-digest expression, span, selector, type, frame, witness, membership and helper drift',()=>{
 const original=buildOrderedCurrentMissingReferenceContractV1(fixed());
 const mutations=[
  value=>{value.rules[2].fieldProjections[0].expression+=' ';},
  value=>{value.rules[2].projectionRecipe[1].sourceBindings[0].start++;value.rules[2].projectionRecipe[1].sourceBindings[0].end++;},
  value=>{value.rules[4].selector={field:'namespace',equals:'public'};},
  value=>{value.rules[3].fieldTypes.owner='boolean';},
  value=>{value.rules[8].projectionFrame.owner='zasp_discovery_authority';},
  value=>{value.witnesses[0].sql='SELECT true';},
  value=>{value.rules[9].canonicalRosterSQL+=' ';},
  value=>{const target=value.rules[10].membershipProgram?.steps?.[2]??value.rules[10];const field=target===value.rules[10]?'membershipControlSQL':'sql';target[field]=target[field].replace('EXCEPT ALL','EXCEPT');},
  value=>{value.helperAuthority['ordered-current-catalog.mjs']='0'.repeat(64);},
  value=>{value.rules[11].keyFields=['missing'];},
  value=>{value.rules[0].unexpectedSemanticField=true;},
 ];
 for(const mutate of mutations){const value=structuredClone(original);mutate(value);rehash(value);assert.throws(()=>assertOrderedCurrentMissingReferenceContractV1(value),/missing reference contract/);}
});
