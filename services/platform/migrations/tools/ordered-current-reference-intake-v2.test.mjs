import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {admitOrderedCurrentReferenceIntakeV2} from './ordered-current-reference-intake-v2.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const acceptedManifestAvailable=fs.existsSync(manifestPath);
const accepted=artifactOptIn&&acceptedManifestAvailable?JSON.parse(fs.readFileSync(manifestPath)):null;
const aPacketRoot=accepted?.packetBytes.A.packetDirectory;
const bPacketRoot=accepted?.packetBytes.B.packetDirectory;
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
 aPacketRoot,
 bPacketRoot,
 compiledReleaseRaw:fs.readFileSync(path.join(p7,'recovery80-worker-compiled-release.json')),
 sourceContractRaw:fs.readFileSync(path.join(p7,'recovery80-effective-contract.json')),
 coverageRaw:fs.readFileSync(coveragePath),
});
const locate=(result,variant,section,ruleId)=>result.observations[variant][section].find(row=>row.ruleId===ruleId);

test('intake refuses absent authority before reading packet paths',()=>{
 assert.throws(()=>admitOrderedCurrentReferenceIntakeV2({}),/input fields/);
});

artifactTest('fixed frame-v2 pair yields source-bound original typed observations only',()=>{
 const result=admitOrderedCurrentReferenceIntakeV2(fixed());
 assert.equal(result.status,'SOURCE-BOUND-TYPED-OBSERVATIONS');
 assert.equal(result.installable,false);
 assert.deepEqual(result.source,{
  compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
  compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
  compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
  sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
  coverageSHA256:'67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4',
 });
 assert.equal(result.comparison.status,'APPLICATION-FACT-EQUIVALENT');
 assert.equal(result.allowances.disposition,'comparison-only-not-applied-to-observations');
 assert.equal(locate(result,'A','rawInputs','authorization80:data-controls-relation').fact.owner,'zasp_test');
 assert.equal(locate(result,'B','rawInputs','authorization80:data-controls-relation').fact.owner,'zasp_e2e');
 assert.equal(Object.hasOwn(result,'facts'),false);
 assert.equal(Object.hasOwn(result,'releaseFacts'),false);
 assert.equal(result.observations.A.status,'REFERENCE-CAPTURE-ONLY');
 assert.equal(result.observations.B.status,'REFERENCE-CAPTURE-ONLY');
});

artifactTest('source authority must be the captured release rather than old development source',()=>{
 const input=fixed();
 input.compiledReleaseRaw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-inventory-compiled.json',import.meta.url));
 assert.throws(()=>admitOrderedCurrentReferenceIntakeV2(input),/compiled release identity/);
});

artifactTest('source contract and coverage mismatches refuse before returning observations',()=>{
 for(const field of ['sourceContractRaw','coverageRaw']){
  const input=fixed();input[field]=Buffer.from(input[field]);input[field][0]^=1;
  assert.throws(()=>admitOrderedCurrentReferenceIntakeV2(input),new RegExp(field==='sourceContractRaw'?'source contract identity':'coverage identity'));
 }
});

artifactTest('altered captures, unsupported packets and missing pair proof refuse',()=>{
 const altered=fixed();altered.aRaw=Buffer.from(altered.aRaw);altered.aRaw[100]^=1;
 assert.throws(()=>admitOrderedCurrentReferenceIntakeV2(altered),/fixed A capture/);
 const unsupported=fixed();unsupported.bPacketRoot=unsupported.aPacketRoot;
 assert.throws(()=>admitOrderedCurrentReferenceIntakeV2(unsupported),/fixed B packet|fixed B capture/);
 const missing=fixed();delete missing.bRaw;
 assert.throws(()=>admitOrderedCurrentReferenceIntakeV2(missing),/fixed B capture|input fields/);
});
