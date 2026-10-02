import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {canonicalOrderedJSON,compileOrderedCollector} from './build-ordered-current-integrity.mjs';
import {buildOrderedReferenceNeeds} from './ordered-current-reference-needs.mjs';
import {reconcileOrderedCurrentFactCollectionsV1} from './ordered-current-capture-reconciliation-v1.mjs';
import {canonicalizeOrderedCurrentDevelopmentFacts} from './ordered-current-catalog.mjs';
let api={};try{api=await import('./ordered-current-remaining-projection-witness-v1.mjs');}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}
const read=name=>fs.readFileSync(new URL(name,import.meta.url));
const inputs=()=>({catalogRaw:read('ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json'),contractRaw:read('ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json'),directRaw:read('ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json'),missingRaw:read('ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json'),remainingRaw:read('ordered-current-worker-source-closure-v1-artifacts/remaining-reference1.json')});
// Assemble real pinned source rows without the unrelated private-packet helper
// admission, whose resolver pins are pending the root-owned combined cascade.
const sourceBundle=()=>{const raw=inputs();prove(raw);const direct=JSON.parse(raw.directRaw),missing=JSON.parse(raw.missingRaw);return {directFacts:[...direct.directFrame.expectedRows,...direct.transform.expectedRows].map(row=>({kind:row.kind,identity:canonicalOrderedJSON([JSON.parse(row.identity)[0],row.source.captureIdentity]),fact:row.fact})),missingFacts:missing.observations.flatMap(observation=>observation.rows.map(row=>({kind:observation.ruleId==='role-profile:current-profile'?'fixed_runtime_profile':observation.ruleId==='role-profile:native-roles'?'role':observation.ruleId.split(':').at(-1)==='precision-function'?'routine':observation.ruleId.split(':').at(-1)==='function'?'routine':observation.ruleId.split(':').at(-1)==='table'?'relation':observation.ruleId.split(':').at(-1),identity:canonicalOrderedJSON([observation.ruleId,row.identity]),fact:row.fields})))};};
const prove=input=>{assert.equal(typeof api.proveRemainingProjectionV1,'function','source-only proof API is missing');return api.proveRemainingProjectionV1(input??inputs());};
const apply=(proof,directFacts,missingFacts)=>{assert.equal(typeof api.applyRemainingProjectionV1,'function','bounded in-memory application is missing');return api.applyRemainingProjectionV1({proof,directFacts,missingFacts});};
const key=(rule,relation,name)=>canonicalOrderedJSON([rule,canonicalOrderedJSON([relation,name])]);
const temporalKeys=[key('temporal72:trigger','public.zasp_connector_credentials','zasp_execution_bind_oauth_subject'),key('temporal72:trigger','public.zasp_discovery_syncs','zasp_execution_sync_version')];
// Catches missing proof, accidental roster expansion, and changes beyond pretty qualification.
test('fixed inputs prove exactly six pretty rows and two temporal rows without copying source bytes',()=>{
 const input=inputs(),before=Object.values(input).map(b=>b.toString('hex')),proof=prove(input);
 assert.equal(proof.records.length,8);assert.equal(proof.records.filter(r=>r.disposition==='source-pretty-qualified').length,6);
 assert.deepEqual(proof.records.filter(r=>r.disposition==='equalExisting').map(r=>r.canonicalIdentity).sort(),temporalKeys.sort());
 assert.equal(proof.installable,false);assert.equal(proof.nativeVerified,false);assert.equal(proof.executableReplacementVerified,false);
 assert.deepEqual(Object.values(input).map(b=>b.toString('hex')),before);
 const pretty=proof.records.find(r=>r.canonicalIdentity===key('worker-edge:gateway_projected27:7','public.zasp_recovery_backups','zasp_recovery_backups_check'));
 assert.equal(pretty.canonicalFact.definition_pretty,'CHECK (public.zasp_valid_product_id(backup_id) AND public.zasp_valid_product_id(actor_id))');
 assert.equal(pretty.spans.length,2);assert.deepEqual(pretty.changedFields,['definition_pretty']);
 const ordered=proof.records.find(r=>r.kind==='trigger'&&r.collection==='direct');
 assert.equal(ordered.canonicalFact.definition_pretty,"CREATE TRIGGER zasp_security_agent_targets_policy_sequence BEFORE INSERT OR UPDATE OF credential_id ON public.zasp_security_agent_temporary_policy_targets FOR EACH ROW WHEN (new.state = 'planned'::text) EXECUTE FUNCTION public.zasp_policy_deployment_target_sequence_guard()");
 assert.deepEqual(proof.records.filter(r=>r.collection==='missing').map(r=>Object.keys(r.fieldProofs).sort()),[...Array(2)].map(()=>['enabled','execution_definition','function','name','relation_name']));
});
// Each mutation must be refused by the whole-file admission before any fact copies.
for(const field of ['catalogRaw','contractRaw','directRaw','missingRaw','remainingRaw'])test('refuses changed whole-file authority '+field,()=>{const input=inputs();input[field]=Buffer.concat([input[field],Buffer.from(' ')]);assert.throws(()=>prove(input),/remaining projection.*authority/);});
const mutations=[
 ['helper owner','contractRaw',x=>x.nodes.find(n=>n.identity==='zasp_authorization80_worker.gateway_projected27()').owner='other'],
 ['helper config','contractRaw',x=>x.nodes.find(n=>n.identity==='zasp_temporal72.retained_execution_fingerprint()').config=[]],
 ['helper security','contractRaw',x=>x.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_projected28()').security_definer=true],
 ['source expression','contractRaw',x=>x.nodes.find(n=>n.identity==='zasp_temporal72.retained_execution_fingerprint()').source+=' '],
 ['missing join','catalogRaw',x=>x.functions=x.functions.filter(f=>f.identity!=='public.zasp_valid_product_id(text)')],
 ['overloaded function','catalogRaw',x=>x.functions.push({...x.functions.find(f=>f.identity==='public.zasp_valid_product_id(text)'),identity:'public.zasp_valid_product_id(integer)'})],
 ['duplicate join','catalogRaw',x=>x.triggers.push(x.triggers.find(t=>t.name==='zasp_execution_sync_version'))],
 ['wrong namespace','catalogRaw',x=>x.triggers.find(t=>t.name==='zasp_execution_sync_version').relation='other.zasp_discovery_syncs'],
 ['internal trigger','catalogRaw',x=>x.triggers.find(t=>t.name==='zasp_execution_sync_version').internal=true],
 ['malformed alias','missingRaw',x=>x.observations.find(o=>o.ruleId==='temporal72:trigger').rows[0].identity='not-json'],
 ['duplicate temporal','missingRaw',x=>x.observations.find(o=>o.ruleId==='temporal72:trigger').rows.push(x.observations.find(o=>o.ruleId==='temporal72:trigger').rows[0])],
 ['missing temporal','remainingRaw',x=>x.rows=x.rows.filter(r=>!r.identity.includes('zasp_execution_sync_version'))],
];
for(const [name,field,mutate] of mutations)test('refuses source mutation '+name,()=>{const input=inputs(),value=JSON.parse(input[field]);mutate(value);input[field]=Buffer.from(JSON.stringify(value));assert.throws(()=>prove(input),/remaining projection.*authority/);});
for(const field of ['relation_name','name','enabled','function','execution_definition'])for(const collection of ['missingRaw','remainingRaw'])test('refuses every temporal field '+collection+'.'+field,()=>{const input=inputs(),value=JSON.parse(input[collection]);const row=collection==='missingRaw'?value.observations.find(o=>o.ruleId==='temporal72:trigger').rows[0].fields:value.rows.find(r=>r.identity.includes('temporal72:trigger')).fact;row[field]+=' ';input[collection]=Buffer.from(JSON.stringify(value));assert.throws(()=>prove(input),/remaining projection.*authority/);});
for(const text of ['/*zasp_valid_product_id*/','"zasp_valid_product_id"','zasp_valid_product_id(x) AND ','CHECK ((',' ON extra ',' EXECUTE FUNCTION extra ',' WHEN ((new.state','zasp_valid_product_id(backup_id )'])test('refuses pretty text lookalikes/grammar drift '+text,()=>{const input=inputs(),value=JSON.parse(input.directRaw);const row=value.directFrame.expectedRows.find(r=>r.fact.definition_pretty?.startsWith('CHECK (zasp_valid_product_id(backup_id)'));row.fact.definition_pretty=text+row.fact.definition_pretty;input.directRaw=Buffer.from(JSON.stringify(value));assert.throws(()=>prove(input),/remaining projection.*authority/);});
// Catches dropping/reordering, bypassing provenance, or treating temporal aliases as new rows.
test('application preserves indexes, identities, all unrelated rows and historical refusal evidence',()=>{
 const proof=prove(),bundle=sourceBundle();
 const direct=structuredClone(bundle.directFacts),missing=structuredClone(bundle.missingFacts);
 for(const r of direct)r.source={qualificationLedger:{status:'refused',captureIdentity:r.identity},sentinel:'retain'};
 const before=structuredClone({direct,missing}),result=apply(proof,direct,missing);
 assert.equal(result.directFacts.length,1600);assert.equal(result.missingFacts.length,204);assert.deepEqual({direct,missing},before);
 for(const [collection,rows] of [['direct',result.directFacts],['missing',result.missingFacts]])for(const [index,row] of rows.entries()){
  const old=before[collection][index],record=proof.records.find(r=>r.collection===collection&&r.sourceIdentity===old.identity);
  if(!record){assert.deepEqual(row,old);continue;}
  assert.equal(row.identity,record.canonicalIdentity);assert.deepEqual(row.fact,record.canonicalFact);
  assert.equal(row.source.remainingProjection.sourceIdentity,old.identity);
  if(collection==='direct'){assert.deepEqual(row.source.qualificationLedger,old.source.qualificationLedger);assert.equal(row.source.sentinel,'retain');}
 }
 const incoming=result.missingFacts.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger').map(({kind,identity,fact})=>({kind,identity,fact}));
 const existing=JSON.parse(inputs().remainingRaw).rows.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger');
 const reconciled=reconcileOrderedCurrentFactCollectionsV1({existingFacts:existing,collections:{direct:[],missing:incoming,private:[]},declarations:{direct:[],missing:[{id:'temporal72:trigger',kind:'trigger',fields:['relation_name','name','enabled','function','execution_definition']}],private:[]},settlements:[]});
 assert.equal(reconciled.equalExisting.length,2);assert.equal(reconciled.newlySupplied.length,0);assert.equal(reconciled.facts.length,2);
 assert.deepEqual(reconciled.equalExisting.map(r=>r.identity).sort(),temporalKeys.sort());
});
test('application refuses forged proof, duplicate/missing/conflicting facts and mutation of any admitted field',()=>{
 const proof=prove(),bundle=sourceBundle();
 assert.throws(()=>apply(structuredClone(proof),bundle.directFacts,bundle.missingFacts),/remaining projection/);
 for(const field of ['relation_name','name','enabled','function','execution_definition']){const direct=structuredClone(bundle.directFacts),missing=structuredClone(bundle.missingFacts);missing.find(r=>JSON.parse(r.identity)[0]==='temporal72:trigger').fact[field]+=' ';assert.throws(()=>apply(proof,direct,missing),/remaining projection/);}
 for(const edit of [rows=>rows.push(rows[0]),rows=>rows.splice(rows.findIndex(r=>JSON.parse(r.identity)[0]==='temporal72:trigger'),1),rows=>rows.find(r=>JSON.parse(r.identity)[0]==='temporal72:trigger').identity='["temporal72:trigger","malformed"]']){const missing=structuredClone(bundle.missingFacts);edit(missing);assert.throws(()=>apply(proof,bundle.directFacts,missing),/remaining projection/);}
});
test('application refuses a witness row shifted away from its original source index or oversized arrays',()=>{
 const proof=prove(),bundle=sourceBundle(),direct=structuredClone(bundle.directFacts),missing=structuredClone(bundle.missingFacts);
 const index=direct.findIndex(r=>r.identity===proof.records.find(r=>r.collection==='direct').sourceIdentity);
 [direct[index],direct[index+1]]=[direct[index+1],direct[index]];
 assert.throws(()=>apply(proof,direct,missing),/remaining projection.*index/);
 const huge=structuredClone(bundle.directFacts);huge[0].fact.excess='x'.repeat(16777217);
 assert.throws(()=>apply(proof,huge,missing),/remaining projection.*byte bound/);
});
test('canonical temporal keys use the real collector descriptor and pg_catalog frame',()=>{
 const proof=prove(),raw=inputs(),rule=buildOrderedReferenceNeeds(JSON.parse(raw.contractRaw),JSON.parse(raw.catalogRaw)).rules.find(r=>r.id==='temporal72:trigger'),sql=compileOrderedCollector([rule]).sql;
 assert.match(sql,/c\.oid::regclass::text/);assert.match(sql,/c\.oid=t\.tgrelid/);assert.match(sql,/t\.tgname/);
 for(const r of proof.records.filter(r=>r.collection==='missing')){assert.equal(r.keyProof.expression,'jsonb_build_array(c.oid::regclass::text,t.tgname)');assert.equal(r.keyProof.frame,'pg_catalog');assert.equal(r.canonicalIdentity,key('temporal72:trigger',r.keyProof.relationIdentity,r.canonicalFact.name));}
});
test('historical canonicalizer still does not rewrite non-worker temporal aliases',()=>{
 const proof=prove(),bundle=sourceBundle(),rows=bundle.missingFacts.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger');
 const result=canonicalizeOrderedCurrentDevelopmentFacts(rows,[{id:'temporal72:trigger',kind:'trigger',selector:{field:'namespace',equals:'public'}}],JSON.parse(inputs().catalogRaw));
 assert.deepEqual(result,rows);assert.equal(proof.records.filter(r=>r.collection==='missing').length,2);
});
