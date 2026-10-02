import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {admitOrderedCurrentCaptureBundleV1} from './ordered-current-capture-intake-v1.mjs';
import {reconcileOrderedCurrentFactCollectionsV1} from './ordered-current-capture-reconciliation-v1.mjs';
import {checkOrderedCurrentPrecisionSettlementPacketV1,orderedCurrentPrecisionConflictSettlementsV1} from './ordered-current-precision-conflict-settlement-v1.mjs';

const p7=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const tools=new URL('./',import.meta.url);
const packetURL=new URL('ordered-current-capture-intake-v1-artifacts/missing-reference-native-packet.json',tools);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const identities=[
 ['public.zasp_runtime_precision_batch_insert_guard()','6995a08960cdc3786a2d6621413f7342011741c87f533e9bcb70d03934857f5c','ff4000d37a58344a7b72c23c78ff890298764f2292c9d73e4688088e2d20e8bd'],
 ['public.zasp_runtime_precision_batch_update_guard()','9692d7549ce1a8f2e04383c3bdd1fbbfd7bd1a6e9ed27161743420a763f99c59','b9f7753907841c191ed5021bc7dd01c8afcb0bca5c30ea650932ac1d7d0cb774'],
 ['public.zasp_runtime_precision_claim_version_guard()','4500dcc5bfbbcef0918d1b449aac83340f7316c8c1b23821e1e4d9e5a8af8953','0d16bcef45abfa2367fa59c7ce0053dc4bc31d8d809aa92411c15c3ee5c1dc92'],
 ['public.zasp_runtime_precision_delivery_guard()','51ca6a37a97912492a020a171f9563f5acbe2481023a31a7f52881cfd12fe73f','5cf10f5e4865cdcbbd181689cf1df89bf29b769a6f65aa69c3d01558c33e606c'],
 ['public.zasp_runtime_precision_outbox_guard()','a32d9f753325a2aa3fdaca4abbeb92679acbc3b8ada3610219888541c5296fe3','0c70ceb8a32fbc3fedc50de28aaf4d77ab3642ba0184690ca72b1e77df859702'],
 ['public.zasp_runtime_precision_reconciliation_guard()','b1171c67b8a135f5634463727f96ec4569b107df3731b945e108dc3b882e7843','1679447234ae39ad07bbcb9bd43075905eae85b65de42455627acdbb7770dfbd'],
 ['public.zasp_runtime_precision_stage_insert_guard()','c57b17caac5b5f7491417fa107c9875eee1fda7bc5c3493f7fbdf66dcdba43d3','90f4cea15fc373971d40eebd1436ec04880aa7c7768c56df447513f81d28053c'],
];
const fields=['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','precision_definition'];
const oldFacts=()=>{
 const raw=fs.readFileSync(new URL('ordered-current-remaining-reference1.json',p7));
 assert.equal(sha(raw),'db00d660b9927cc4c5651bcffe3af576881e4d14afbd027e4bfc6abd328022d3');
 const wanted=new Set(identities.map(([signature])=>JSON.stringify(['temporal72:precision-function',signature])));
 return JSON.parse(raw).rows.filter(row=>wanted.has(row.identity));
};
const newFacts=()=>{
 const wanted=new Set(identities.map(([signature])=>JSON.stringify(['temporal72:precision-function',signature])));
 return admitOrderedCurrentCaptureBundleV1().missingFacts.filter(row=>wanted.has(row.identity));
};
const declarations={direct:[],missing:[{id:'temporal72:precision-function',kind:'routine',fields}],private:[]};
const reconcile=settlements=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:oldFacts(),collections:{direct:[],missing:newFacts(),private:[]},declarations,settlements});
const clone=value=>structuredClone(value);

test('seven settlements bind exact incomplete old facts to source-authorized accepted replacements',()=>{
 const settlements=orderedCurrentPrecisionConflictSettlementsV1();
 assert.equal(settlements.length,7);
 assert.deepEqual(settlements.map(row=>[JSON.parse(row.identity)[1],row.existingFactSHA256,row.incomingFactSHA256]),identities);
 for(const row of settlements){
  assert.equal(row.collection,'missing');
  assert.equal(row.kind,'routine');
  assert.equal(row.ruleId,'temporal72:precision-function');
  assert.deepEqual(row.fieldSchema,fields);
  assert.equal(row.sourcePacketSHA256,'23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287');
  assert.equal(row.captureContractSHA256,'262728237a748a512b98e499a9b0335c13cabcf39a372fd3eaf65261e8f1449d');
  assert.equal(row.captureContractJSONSHA256,'ae63b0e31dd6ee7d7855d302184acb116e28fb081b2b17facae6c6be4de70d29');
  assert.equal(row.sourceContractSHA256,'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb');
  assert.equal(row.compiledSourceSHA256,'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e');
  assert.equal(row.compilerChecksum,'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214');
  assert.equal(row.compilerArtifactSHA256,'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c');
  assert.equal(row.catalogSHA256,'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df');
  assert.equal(row.contractModuleSHA256,'2a304799618b0ca70b18df1f63f04c7bc450aab83b0bfcc19b779aead5b3af90');
  assert.equal(row.sourceFile,'sql/0072_production_temporal_discovery.up.sql');
  assert.equal(row.sourceFileSHA256,'e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940');
  assert.equal(row.sourceIdentity,'zasp_temporal72.retained_precision_fingerprint()');
  assert.equal(row.sourceBodySHA256,'65c56d5deaa809f9e751bec5878243569750653902d47ab299e98c504649d8b1');
  assert.equal(row.sourceDefinitionSHA256,'d818de30fd18ecfaf7901678f209a497686f7299aee204d33c39a4e3ed896cba');
  assert.equal(row.sourceSiteSHA256,'524cfacb06cd93d4c6884a33db32a1d25a6804eae2ad057faf0077c3820b2765');
  assert.equal(row.sourceRuleSHA256,'ec063cfc5b316df8a931ee8c143f7a178e8a6b0961a68a4c1f5552e15c28e388');
  assert.equal(row.sourceSitesSHA256,'d60cf2bf6919bfa2388f147c1a9cc3551919badf824abe455107e2553a5d1100');
  assert.equal(row.sourceStart,118);
  assert.equal(row.sourceEnd,1663);
  assert.deepEqual(row.sourceFrame,{owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],result:'text',arguments:'',language:'sql',securityDefiner:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,searchPath:['pg_catalog','public']});
  assert.equal(row.disposition,'supersede-incomplete-null-precision-definition-with-source-selected-predecessor-definition');
 }
 const old=oldFacts(),incoming=newFacts();
 assert.equal(old.length,7);assert.equal(incoming.length,7);
 for(const [signature,oldHash,newHash] of identities){
  const identity=JSON.stringify(['temporal72:precision-function',signature]);
  const before=old.find(row=>row.identity===identity),after=incoming.find(row=>row.identity===identity);
  assert.equal(before.fact.precision_definition,null);
  assert.equal(typeof after.fact.precision_definition,'string');assert.ok(after.fact.precision_definition.length>0);
  assert.equal(sha(canonicalOrderedJSON(before.fact)),oldHash);assert.equal(sha(canonicalOrderedJSON(after.fact)),newHash);
  assert.deepEqual(Object.fromEntries(Object.entries(before.fact).filter(([field])=>field!=='precision_definition')),Object.fromEntries(Object.entries(after.fact).filter(([field])=>field!=='precision_definition')));
 }
 const value=reconcile(settlements);
 assert.deepEqual(value.counts,{admitted:7,equalExisting:0,newlySupplied:0,settledConflicts:7,unresolvedConflicts:0});
 assert.deepEqual(value.collections.missing,{admitted:7,equalExisting:0,newlySupplied:0,settledConflicts:7,unresolvedConflicts:0});
 assert.equal(value.settledConflicts.length,7);assert.deepEqual(value.unresolvedConflicts,[]);
 for(const row of incoming)assert.deepEqual(value.facts.find(fact=>fact.kind===row.kind&&fact.identity===row.identity),row);
});

test('settlement authority is clean-checkout vendored and refuses changed packet metadata',()=>{
 const source=fs.readFileSync(new URL('ordered-current-precision-conflict-settlement-v1.mjs',tools),'utf8');
 assert.doesNotMatch(source,/\.superpowers|\/private\/tmp/);
 const raw=fs.readFileSync(packetURL);assert.doesNotThrow(()=>checkOrderedCurrentPrecisionSettlementPacketV1(raw));
 const changed=JSON.parse(raw);const rule=changed.contract.rules.find(row=>row.id==='temporal72:precision-function');rule.fields=[...rule.fields].reverse();
 assert.throws(()=>checkOrderedCurrentPrecisionSettlementPacketV1(Buffer.from(JSON.stringify(changed)+'\n')),/packet|rule|schema|authority/);
 const duplicate=Buffer.from(raw.toString().replace('{"format":','{"format":1,"format":'));
 assert.throws(()=>checkOrderedCurrentPrecisionSettlementPacketV1(duplicate),/duplicate key/);
});

test('every settlement field and every nested frame field fails closed when changed',()=>{
 const original=orderedCurrentPrecisionConflictSettlementsV1();
 const topLevel=Object.keys(original[0]);
 for(const field of topLevel){
  const changed=clone(original);
  if(field==='fieldSchema')changed[0][field]=[...changed[0][field],'owner'];
  else if(field==='sourceFrame')changed[0][field]={...changed[0][field],language:'plpgsql'};
  else if(typeof changed[0][field]==='number')changed[0][field]++;
  else changed[0][field]=changed[0][field]+'-changed';
  assert.throws(()=>reconcile(changed),/settlement/,field);
 }
 for(const field of Object.keys(original[0].sourceFrame)){
  const changed=clone(original),frame=changed[0].sourceFrame;
  if(Array.isArray(frame[field]))frame[field]=['search_path=public'];
  else if(typeof frame[field]==='boolean')frame[field]=!frame[field];
  else frame[field]=frame[field]+'-changed';
  assert.throws(()=>reconcile(changed),/settlement/,`sourceFrame.${field}`);
 }
});

test('wrong, unused, duplicate, extra and unrelated settlements fail closed',()=>{
 const settlements=orderedCurrentPrecisionConflictSettlementsV1();
 assert.throws(()=>reconcile(settlements.slice(0,-1)),/conflicting capture fact/);
 assert.throws(()=>reconcile([...settlements,settlements[0]]),/duplicate settlement/);
 const extra=clone(settlements[0]);extra.identity=JSON.stringify(['temporal72:precision-function','public.unrelated()']);
 assert.throws(()=>reconcile([...settlements,extra]),/settlement/);
 const oneOld=oldFacts().slice(1),oneNew=newFacts().slice(1);
 assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:oneOld,collections:{direct:[],missing:oneNew,private:[]},declarations,settlements}),/unused settlement/);
 const role=id=>({kind:'role',identity:JSON.stringify(['role-rule',id]),fact:{login:id==='new'}});
 assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[role('old')],collections:{direct:[{...role('old'),fact:{login:true}}],missing:[],private:[]},declarations:{direct:[{id:'role-rule',kind:'role',fields:['login']}],missing:[],private:[]},settlements:[]}),/conflicting capture fact/);
});
