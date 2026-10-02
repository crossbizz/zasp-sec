import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {native19WorkerSourceReplay} from './ordered-current-worker-source-replay-v1.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
let integration={};
try{integration=await import('./ordered-current-worker-higher-integration-v1.mjs');}
catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}
const api=name=>{assert.equal(typeof integration[name],'function',`missing higher integration ${name}`);return integration[name];};
const issue=()=>api('issueWorkerHigherIntegrationContextV1')();
const sourceInventory=api('readWorkerHigherSourceInputsV1')().inventory;
const identities=[
 'zasp_temporal68.predecessor_ready(text,text)',
 'zasp_temporal68.ready(text,text)',
 'zasp_temporal77.base67_fingerprint()',
 'zasp_temporal78.ready(text,text)',
];
const replacementFactSHA256=[
 'f69d53153704f9db99433c99909932a56cfd898d5f599708f43d61144e609eae',
 'affd9e4337b9951645ed022e541ddbb61fed7fd0e0c6c9e30d48621cbbca742b',
 '7c1b4d64ebb5698e57cd8b501849f6fadb219bae0aca45760c29f6f33ea0774a',
 'd175c6068f32418d3dd3e44c6994976a407012e75afd613c9159d8dcd473f309',
];
const sourcePins={
 contractRaw:'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',
 catalogRaw:'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',
 releaseRaw:'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 graphRaw:'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6',
 compilerRaw:'fb66f8649b5fea1cf54dbaa7776665b5375fd64bb6808c2b7c75036812a56da7',
 regionsRaw:'d72a3e431dd7fd2abfd15612a03a7d0d8c2b6dca1b064f37536d4151d4f83309',
 captureSourceRaw:'60be84a43d564c9c7da3999a22155a7734a1163f258d58206f8bcfabbabc43f6',
};
const artifact=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const inputs={
 optIn:true,
 contractRaw:fs.readFileSync(new URL('effective-contract3.json',artifact)),
 catalogRaw:fs.readFileSync(new URL('effective-catalog1.json',artifact)),
 releaseRaw:fs.readFileSync(new URL('native19-worker-release.json',artifact)),
 graphRaw:fs.readFileSync(new URL('../sql/0080_authorization_worker_readiness_graph.sql',import.meta.url)),
 compilerRaw:fs.readFileSync(new URL('./build-worker-readiness-graph.mjs',import.meta.url)),
 regionsRaw:fs.readFileSync(new URL('./worker-readiness-regions.mjs',import.meta.url)),
 captureSourceRaw:fs.readFileSync(new URL('../../apiserver/authorization_worker_ordered_readiness_capture_test.go',import.meta.url)),
};
for(const [key,digest]of Object.entries(sourcePins))assert.equal(sha(inputs[key]),digest,key);
const higherProof=(()=>{
 // The actual source replay is deliberately required; no native/installed row
 // or generated packet is used as a replacement expectation.
 return import('./ordered-current-worker-higher-source-replay-v1.mjs').then(module=>module.workerHigherSourceReplay(inputs));
})();
const historical=(()=>{
 const replay=native19WorkerSourceReplay();
 const catalog=JSON.parse(inputs.catalogRaw).functions;
 const entries=[...replay.accepted,...replay.refused].map(entry=>{
  const rows=catalog.filter(row=>row?.identity===entry.identity);
  assert.equal(rows.length,1,`historical catalog row ${entry.identity}`);
  const row=rows[0],fact={acl:row.acl,definition:row.definition,owner:row.owner};
  return {...entry,ruleId:'worker-line-5',rawFactSHA256:sha(canonicalOrderedJSON(fact))};
 });
 return {version:replay.version,accepted:replay.accepted.length,refused:replay.refused.length,
  sourceReplay:{accepted:replay.accepted.length,refused:replay.refused.length},
  entries,registration:{...replay.registration,ruleId:'worker-line-2',identity:'historical-registration'}};
})();

function sourceRows(proof){
 const catalog=JSON.parse(inputs.catalogRaw).functions;
 return proof.accepted.map((candidate,index)=>{
  const rows=catalog.filter(row=>row.identity===candidate.identity);
  assert.equal(rows.length,1,candidate.identity);
  const row=rows[0];
  const fact={acl:row.acl,definition:row.definition,owner:row.owner};
  assert.equal(sha(canonicalOrderedJSON(fact)),replacementFactSHA256[index],candidate.identity);
  return {kind:'routine',identity:JSON.stringify(['worker-line-5',candidate.identity]),fact};
 });
}
const splice=(facts,proof,historicalLedger,{issued=issue(),extra={}}={})=>api('applyWorkerHigherSuccessorV1')({facts,proof,historicalLedger,canonicalJSON:canonicalOrderedJSON,context:issued.context,...extra});

test('higher successor splice consumes the reviewed proof and replaces exactly four typed raw facts',async()=>{
 const loaded=api('readWorkerHigherSourceInputsV1')();
 for(const key of Object.keys(sourcePins))assert.deepEqual(loaded.inputs[key],inputs[key],key);
 const expectedInventory={
  'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json':sourcePins.contractRaw,
  'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json':sourcePins.catalogRaw,
  'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json':sourcePins.releaseRaw,
  'services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql':sourcePins.graphRaw,
  'services/platform/migrations/tools/build-worker-readiness-graph.mjs':sourcePins.compilerRaw,
  'services/platform/migrations/tools/worker-readiness-regions.mjs':sourcePins.regionsRaw,
  'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go':sourcePins.captureSourceRaw,
  'services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.mjs':'0a59ac714b861758fc2579de81cda60415b3d2f6b1f1db8a4aa2a73c55739de3',
  'services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.test.mjs':'010a2c0537ffa97afdceeb9fa78b890be4307cd35546e96d9ced9a2a101f6e16',
 };
 assert.deepEqual(loaded.inventory,expectedInventory);
 const proof=await higherProof,facts=[{kind:'role',identity:'unrelated-role',fact:{name:'read-only'}},...sourceRows(proof)];
 const before=structuredClone(facts),historicalBefore=structuredClone(historical);
 const result=splice(facts,proof,historical);
 assert.equal(result.facts.length,5);
 assert.deepEqual(result.facts[0],before[0]);
 assert.strictEqual(result.facts[0],facts[0]);
 assert.notStrictEqual(result.facts[1],facts[1]);
 assert.deepEqual(result.facts.slice(1),before.slice(1));
 assert.deepEqual(result.currentSuccessor.accepted.map(row=>row.identity),identities);
 assert.deepEqual(result.currentSuccessor.accepted.map(row=>row.replacementFactSHA256),replacementFactSHA256);
 assert.equal(result.currentSuccessor.sourceClosed,true);
 assert.equal(result.currentSuccessor.native,false);
 assert.equal(result.currentSuccessor.installable,false);
 assert.equal(result.currentSuccessor.executable,false);
 assert.deepEqual(result.currentSuccessor.inputLedger,Object.fromEntries(Object.entries(sourcePins).map(([key,value])=>[key.replace(/Raw$/,'SHA256'),value])));
 assert.deepEqual(result.currentSuccessor.sourceInventory,expectedInventory);
 assert.equal(result.currentSuccessor.registration.status,'refused');
 assert.equal(result.currentSuccessor.registration.identity,historical.registration.identity);
 assert.equal(result.currentSuccessor.higherRegistrationRefusal.status,'refused');
 assert.equal(Object.hasOwn(result.currentSuccessor.higherRegistrationRefusal,'identity'),false);
 assert.equal(result.historicalLedger,historical);
 assert.deepEqual(historical,historicalBefore);
 assert.equal(historical.accepted,13);
 assert.equal(historical.refused,4);
 assert.equal(historical.entries.length,17);
 assert.equal(historical.entries.filter(row=>row.status==='accepted').length,13);
 assert.equal(historical.entries.filter(row=>row.status==='refused').length,4);
 assert.equal(historical.registration.status,'refused');
});

test('higher successor splice rejects missing, duplicate, reordered, or extra source candidates before changing facts',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const mutate=[
  value=>{value.accepted.pop();},
  value=>{value.accepted[1]=structuredClone(value.accepted[0]);},
  value=>{[value.accepted[0],value.accepted[1]]=[value.accepted[1],value.accepted[0]];},
  value=>{value.accepted.push(structuredClone(value.accepted[0]));},
 ];
 for(const change of mutate){
  const changed=structuredClone(proof);change(changed);
  assert.throws(()=>splice(facts,changed,historical),/higher successor/);
  assert.deepEqual(facts,before);
 }
});

test('higher successor splice rejects raw-fact, typed-frame, identity, and historical-ledger drift atomically',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const changedProofs=[
  value=>{value.accepted[0].replacementFactSHA256='f'.repeat(64);},
  value=>{value.accepted[0].frame.owner='attacker';},
  value=>{value.accepted[0].identity='zasp_temporal68.attacker()';},
  value=>{value.accepted[0].replacementDefinition+=' ';},
 ];
 for(const change of changedProofs){
  const changed=structuredClone(proof);change(changed);
  assert.throws(()=>splice(facts,changed,historical),/higher successor/);
  assert.deepEqual(facts,before);
 }
 for(const mutate of [value=>{value.accepted=12;},value=>{value.refused=5;},value=>{value.entries.pop();},value=>{value.registration.status='accepted';}]){
  const changed=structuredClone(historical);mutate(changed);
  assert.throws(()=>splice(facts,proof,changed),/historical worker replay/);
  assert.deepEqual(facts,before);
 }
});

test('higher successor splice rejects non-three-field captured rows and ambiguous source identities',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const extra=structuredClone(facts);extra[0].fact.extra=true;
 assert.throws(()=>splice(extra,proof,historical),/higher successor/);
 const duplicate=[...facts,structuredClone(facts[0])];
 assert.throws(()=>splice(duplicate,proof,historical),/higher successor/);
 assert.deepEqual(facts,before);
});

test('higher successor splice rejects caller-supplied source inventory and catalog overrides',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const incomplete={...sourceInventory};delete incomplete['services/platform/migrations/tools/worker-readiness-regions.mjs'];
 const substituted={...sourceInventory,'services/platform/migrations/tools/worker-readiness-regions.mjs':'0'.repeat(64)};
 assert.throws(()=>splice(facts,proof,historical,{extra:{sourceInventory:incomplete}}),/higher successor input shape/);
 assert.throws(()=>splice(facts,proof,historical,{extra:{sourceInventory:substituted}}),/higher successor input shape/);
 assert.throws(()=>splice(facts,proof,historical,{extra:{catalogRaw:Buffer.from(inputs.catalogRaw).subarray(1)}}),/higher successor input shape/);
 assert.deepEqual(facts,before);
});

test('higher successor splice rejects target identity collisions across fact kinds',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const collision=[...facts,{kind:'relation',identity:facts[0].identity,fact:{sentinel:'must remain unchanged'}}];
 assert.throws(()=>splice(collision,proof,historical),/higher successor/);
 assert.deepEqual(facts,before);
});

test('higher successor splice rejects current-definition drift even when its ledger is recomputed',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),changed=structuredClone(facts),ledger=structuredClone(historical);
 changed[0].fact.definition='SELECT attacker-controlled stale bytes';
 ledger.entries.find(row=>row.identity===proof.accepted[0].identity).rawFactSHA256=sha(canonicalOrderedJSON(changed[0].fact));
 assert.throws(()=>splice(changed,proof,ledger),/higher successor/);
});

test('higher successor splice authenticates complete source provenance, not caller assertions',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),before=structuredClone(facts);
 const mutations=[
  value=>{delete value.inputLedger.originalFrames;},
  value=>{value.accepted[0].originalDefinitionSHA256='0'.repeat(64);},
  value=>{value.accepted[0].originalSourceSHA256='1'.repeat(64);},
  value=>{value.accepted[0].origin='fabricated-without-graph-proof';},
  value=>{value.baseReplay={};},
 ];
 for(const mutate of mutations){
  const changed=structuredClone(proof);mutate(changed);
  assert.throws(()=>splice(facts,changed,historical),/higher successor/);
  assert.deepEqual(facts,before);
 }
});

test('higher successor splice rejects a second application of its output',async()=>{
 const proof=await higherProof,facts=sourceRows(proof),issued=issue();
 const first=splice(facts,issued.proof,historical,{issued});
 assert.throws(()=>splice(first.facts,issued.proof,historical,{issued}),/higher successor/);
 assert.throws(()=>splice(first.facts,proof,historical),/higher successor/);
});
