import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
 assertOrderedCurrentTransformReferenceV2,
 projectOrderedCurrentTransformReferenceV2,
} from './ordered-current-transform-reference-v2.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const accepted=artifactOptIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const aPacketRoot=accepted?.packetBytes.A.packetDirectory,bPacketRoot=accepted?.packetBytes.B.packetDirectory;
const p7=aPacketRoot&&path.join(aPacketRoot,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const coveragePath=aPacketRoot&&path.join(aPacketRoot,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json');
function packetAvailable(root){
 const contractPath=root&&path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json'),required=root&&[path.join(root,'snapshot-manifest.json'),contractPath,path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json')];
 if(!required||!required.every(file=>fs.existsSync(file)))return false;
 try{return JSON.parse(fs.readFileSync(contractPath)).phases.flatMap(phase=>phase.batches).every(batch=>fs.existsSync(path.join(root,batch.file)));}catch{return false;}
}
const artifactsAvailable=Boolean(accepted)&&[accepted.packetBytes.A.capturePath,accepted.packetBytes.B.capturePath,path.join(p7,'recovery80-worker-compiled-release.json'),path.join(p7,'recovery80-effective-contract.json'),coveragePath].every(file=>fs.existsSync(file))&&packetAvailable(aPacketRoot)&&packetAvailable(bPacketRoot);
const artifactSkip=artifactOptIn?'fixed private frame-v2 artifact prerequisites unavailable':'set ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED=1 to run fixed private evidence tests';
const artifactTest=(name,fn)=>test(name,{skip:artifactsAvailable?false:artifactSkip},fn);
const fixed=()=>({
 aRaw:fs.readFileSync(accepted.packetBytes.A.capturePath),
 bRaw:fs.readFileSync(accepted.packetBytes.B.capturePath),
 aPacketRoot,bPacketRoot,
 compiledReleaseRaw:fs.readFileSync(path.join(p7,'recovery80-worker-compiled-release.json')),
 sourceContractRaw:fs.readFileSync(path.join(p7,'recovery80-effective-contract.json')),
 coverageRaw:fs.readFileSync(coveragePath),
});
let projected;
const projection=()=>projected??=projectOrderedCurrentTransformReferenceV2(fixed());
const counts={
 'temporal:70.fingerprint:function':91,
 'temporal:71.fingerprint:function':47,
 'temporal:74.outbox65_fingerprint:function':6,
 'temporal:74.owner66_fingerprint:function':10,
 'temporal:75.fingerprint:function':15,
 'temporal:77.domain67_fingerprint:function':9,
 'temporal:78.predecessor73_fingerprint:function':10,
 'temporal:78.predecessor76_fingerprint:function':12,
 'temporal:78.predecessor76_fingerprint:executor-function':4,
 'public:sa_attack_lab:function':46,
 'public:sa_export:function':79,
 'public:sa_multistep:function':7,
 'public:sa_webhook:function':44,
};
const expectedResiduals={
 'temporal:70.fingerprint:function':[
  ['64e6bae3878ee548084f91f5ef2a6cf866105d2973594d8fe7d0a45cff032988','<checksum>'],
  ['d15a4b32b9b528fc3913db76097f18d93c74461b31758a19c87142b972f03c99','<fingerprint>'],
  ['c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a','<base-fingerprint>'],
  ['499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf','<domain-fingerprint>'],
 ],
 'temporal:71.fingerprint:function':[
  ['4ab3a167a76f1296c385b36330f83180fe2eedb7233f49377073248bac3f1ec8','<checksum>'],
  ['1bfbd14f6f2a23fd3dd2be171473f646cc3c5b0b4b0b36de4dd2f12cec5f07b3','<fingerprint>'],
  ['c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a','<base-fingerprint>'],
  ['499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf','<domain-fingerprint>'],
 ],
 'temporal:74.outbox65_fingerprint:function':[
  ['2cb65040d3be0f7a08722691c5c1fe38b93b4d036cec6b74b4b2ec83c3a2d56a','<checksum>'],
  ['8c64101128b0b31cd4d12575480035ab1e30f157d92fa96c236babc7620de3f8','<fingerprint>'],
 ],
 'temporal:74.owner66_fingerprint:function':[
  ['6e2fbdef64421286476be12a02188d7936e81db3126764bf2ab55e099fcb12cb','<checksum>'],
  ['422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a','<fingerprint>'],
 ],
 'temporal:75.fingerprint:function':[
  ['27c65026b98f6c7d68620eea2d174db0eebf68cea40c49094350878e185b5371','<checksum>'],
  ['507b909dd0a59c2ffe8c664d8e70c40d120f63ad215a96fc002141c22687b873','<fingerprint>'],
  ['c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a','<base-fingerprint>'],
  ['499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf','<domain-fingerprint>'],
 ],
 'temporal:77.domain67_fingerprint:function':[
  ['b0ce6cf26b4b5f7e909f2e8e8ba5fdc987318efb21878c503117b4583b1544a8','<checksum>'],
  ['3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92','<fingerprint>'],
  ['b8b6e336ec72fa1b056c5e8a2f65cdd8275e9bbaee498ef1064d5f90133cf191','<base-fingerprint>'],
 ],
 'temporal:78.predecessor73_fingerprint:function':[
  ['d2b10f7a97ee8cbc23ccacce852845ce20625851a93428013b0c83f799838556','<checksum>'],
  ['09895c8411beabd971e2425c3382a1152df3d224334ded17433fa80ae243b115','<fingerprint>'],
  ['c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a','<base-fingerprint>'],
  ['499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf','<domain-fingerprint>'],
 ],
 'temporal:78.predecessor76_fingerprint:function':[
  ['57cc7f96f487b7f172502c7dea30eccd0244ad14437a747c32a6d05ecdb3b107','<checksum>'],
  ['606fefa6b41a7627fa6c58687a837b9dc3d0185cabeb761cc420f9933026b079','<fingerprint>'],
  ['c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a','<base-fingerprint>'],
  ['499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf','<domain-fingerprint>'],
 ],
 'temporal:78.predecessor76_fingerprint:executor-function':[],
 'public:sa_attack_lab:function':[
  ['e0f037ec8948a4d574ae33f37e9554d9ff6539785b7d601d7c96685a66c01776','<compiled-checksum>'],
  ['f44bc966ef77ab523a80ace71b59defbe709c1fdbefd69ccfc40cacaf16d7ba8','<compiled-fingerprint>'],
 ],
 'public:sa_export:function':[
  ['5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985','<compiled-checksum>'],
  ['8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f','<compiled-fingerprint>'],
 ],
 'public:sa_multistep:function':[
  ['033bf2ffa9d4a60121d4f20436ff7de36d1421b62f849254a09048caf75998e6','<compiled-checksum>'],
  ['2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98','<compiled-fingerprint>'],
  ['6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92','<registered-fingerprint>'],
 ],
 'public:sa_webhook:function':[
  ['f5021eaf0e9954cba9ab16b4ae1e0ee57e9ea85d909b44eeffe6ac853d0073f4','<compiled-checksum>'],
  ['e89317deca2aabbeb6e35bbe303d8245ba8ea0dbda6351c2d1b2e458e79842f1','<compiled-fingerprint>'],
 ],
};
function expectedDefinition(value,replacements){
 if(value===null)return null;
 return replacements.reduce((text,[from,to])=>text.split(from).join(to),value);
}
function assertIndependentDefinitions(result,rawInputs){
 const actual=new Map(result.expectedRows.map(row=>[row.identity,row.fact.definition]));
 const selected=rawInputs.filter(row=>Object.hasOwn(expectedResiduals,row.ruleId));
 assert.equal(selected.length,380);
 assert.deepEqual([...new Set(selected.map(row=>row.ruleId))].sort(),Object.keys(expectedResiduals).sort());
 for(const row of selected){
  const key=JSON.stringify([row.ruleId,row.identity]);
  assert.equal(actual.get(key),expectedDefinition(row.fact.definition,expectedResiduals[row.ruleId]),`independent transformed definition ${key}`);
 }
}

test('transform reference refuses absent fixed intake authority',()=>{
 assert.throws(()=>projectOrderedCurrentTransformReferenceV2({}),/transform reference input fields/);
});

artifactTest('fixed pair projects all thirteen residual recipes from exact original observations',()=>{
 const result=projection();
 assert.equal(result.status,'SOURCE-BOUND-TRANSFORM-EXPECTED-PROJECTION');
 assert.equal(result.installable,false);
 assert.equal(result.transformRules.length,13);
 assert.equal(result.expectedRows.length,380);
 assert.deepEqual(Object.fromEntries(result.transformRules.map(rule=>[rule.id,rule.expectedRows])),counts);
 assert.deepEqual(result.provenance.frameComparison,{mode:'exact-unnormalized-independent-A-B-transform-rows',rules:13,rows:380,normalizationApplied:false});
 assert.equal(result.provenance.residualBoundary,'captured-original-expression-results-plus-ordered-definition-replacements');
 assert.equal(new Set(result.expectedRows.map(row=>row.identity)).size,380);
 for(const row of result.expectedRows){
  const [ruleId,identity]=JSON.parse(row.identity);
  assert.equal(ruleId,row.source.ruleId);
  assert.equal(identity,row.source.captureIdentity);
  assert.equal(Object.hasOwn(row.fact,'routine_oid'),false);
  for(const witness of ['config_json','config_raw','config_dims','config_ndims','config_bounds'])assert.equal(Object.hasOwn(row.fact,witness),false);
 }
 assert.doesNotThrow(()=>assertOrderedCurrentTransformReferenceV2(result));
});

artifactTest('residual plans prove exact source terminals, ordered pairs, frames and lazy boundary',()=>{
 const result=projection();
 assert.deepEqual(result.transformRules.map(rule=>rule.residual.replacements.length),[4,4,2,2,4,3,4,4,0,2,2,3,2]);
 for(const rule of result.transformRules){
  assert.equal(rule.executionFrameId,'sourceDiscoveryPublic');
  assert.equal(rule.sourceSite.frame.config[0],'search_path=pg_catalog, public');
  assert.equal(rule.residual.terminalDisposition,'already-evaluated-original-source-expression');
  assert.equal(rule.residual.savedRowsRead,0);
  for(const pair of rule.residual.replacements){
   assert.match(pair.from,/^[a-f0-9]{64}$/);
   assert.match(pair.to,/^<[a-z-]+>$/);
  }
 }
 assert.equal(result.provenance.savedInputDisposition,'never-read; original CASE and scalar behavior completed during fixed capture');
});

artifactTest('independent pinned oracle proves every transformed definition and rejects a no-op residual mutant',()=>{
 const result=projection(),rawInputs=JSON.parse(fixed().aRaw).rawInputs;
 assertIndependentDefinitions(result,rawInputs);
 assert.equal(expectedDefinition(null,expectedResiduals['temporal:70.fingerprint:function']),null);
 assert.equal(expectedDefinition('abc',[['a','ab'],['ab','<ordered>']]),'<ordered>bc');
 const noOp=structuredClone(result),captured=new Map(rawInputs.map(row=>[JSON.stringify([row.ruleId,row.identity]),row.fact.definition]));
 for(const row of noOp.expectedRows)if(captured.has(row.identity))row.fact.definition=captured.get(row.identity);
 assert.throws(()=>assertIndependentDefinitions(noOp,rawInputs),/independent transformed definition/);
});

artifactTest('public config witnesses are validation-only and nullable definitions remain lossless',()=>{
 const result=projection();
 const publicRows=result.expectedRows.filter(row=>row.source.ruleId.startsWith('public:'));
 assert.equal(publicRows.length,176);
 assert.ok(publicRows.some(row=>row.fact.config_text_or_empty===''));
 assert.ok(publicRows.some(row=>row.fact.config_text_or_empty==='{"search_path=pg_catalog, public"}'));
 for(const row of publicRows)assert.equal(typeof row.fact.config_text_or_empty,'string');
});

artifactTest('fixed authority and result self-check refuse byte, count, type, frame and key drift',()=>{
 for(const field of ['sourceContractRaw','coverageRaw','aRaw']){
  const input=fixed();input[field]=Buffer.from(input[field]);input[field][100]^=1;
  assert.throws(()=>projectOrderedCurrentTransformReferenceV2(input),/source contract identity|coverage identity|fixed A capture/);
 }
 const original=projection();
 const mutations=[
  value=>value.expectedRows.pop(),
  value=>value.expectedRows.push(structuredClone(value.expectedRows[0])),
  value=>{value.expectedRows[0].fact.unselected=true;},
  value=>{value.expectedRows[0].source.siteSHA256='0'.repeat(64);},
  value=>{value.expectedRows[0].identity=JSON.stringify(['wrong',JSON.parse(value.expectedRows[0].identity)[1]]);},
  value=>{const row=value.expectedRows.find(candidate=>Object.values(candidate.fact).some(item=>typeof item==='boolean'));const field=Object.keys(row.fact).find(key=>typeof row.fact[key]==='boolean');row.fact[field]='false';},
  value=>{value.transformRules[0].frame.searchPath='pg_catalog';},
  value=>{value.transformRules[0].residual.replacements.reverse();},
 ];
 for(const mutate of mutations){const value=structuredClone(original);mutate(value);assert.throws(()=>assertOrderedCurrentTransformReferenceV2(value),/transform reference/);}
});
