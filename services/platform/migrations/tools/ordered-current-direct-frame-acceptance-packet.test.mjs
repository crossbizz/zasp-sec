import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {buildOrderedCurrentDirectFrameAcceptancePacket,orderedCurrentDirectFrameSourcePins,serializeOrderedCurrentDirectFrameAcceptancePacket} from './ordered-current-direct-frame-acceptance-packet.mjs';

const manifestPath='/private/tmp/zasp-recovery80-native-driver-metadata-fix.rumZaA/capture-manifest-accepted-v2.json';
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
const manifest=artifactOptIn&&fs.existsSync(manifestPath)?JSON.parse(fs.readFileSync(manifestPath)):null;
const aPacketRoot=manifest?.packetBytes.A.packetDirectory,bPacketRoot=manifest?.packetBytes.B.packetDirectory;
const p7=aPacketRoot&&path.join(aPacketRoot,'.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement');
const coveragePath=aPacketRoot&&path.join(aPacketRoot,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json');
const catalogPath=p7&&path.join(p7,'recovery80-effective-catalog.json');
const required=[manifest?.packetBytes.A.capturePath,manifest?.packetBytes.B.capturePath,p7&&path.join(p7,'recovery80-worker-compiled-release.json'),p7&&path.join(p7,'recovery80-effective-contract.json'),coveragePath,catalogPath];
const artifactsAvailable=Boolean(manifest)&&required.every(file=>file&&fs.existsSync(file));
const artifactTest=(name,fn)=>test(name,{skip:artifactsAvailable?false:'fixed frame-v2 artifacts unavailable or not opted in'},fn);

function fixedInput(){
 const input={
  aRaw:fs.readFileSync(manifest.packetBytes.A.capturePath),
  bRaw:fs.readFileSync(manifest.packetBytes.B.capturePath),
  aPacketRoot,bPacketRoot,
  compiledReleaseRaw:fs.readFileSync(path.join(p7,'recovery80-worker-compiled-release.json')),
  sourceContractRaw:fs.readFileSync(path.join(p7,'recovery80-effective-contract.json')),
  coverageRaw:fs.readFileSync(coveragePath),
  catalogRaw:fs.readFileSync(catalogPath),
 };
 return input;
}
let packet;
function fixedPacket(){return packet??=buildOrderedCurrentDirectFrameAcceptancePacket(fixedInput());}

test('packet builder refuses absent or caller-selected authority',()=>{
 assert.throws(()=>buildOrderedCurrentDirectFrameAcceptancePacket(),/fixed direct\/transform input/);
 assert.throws(()=>buildOrderedCurrentDirectFrameAcceptancePacket({}),/fixed direct\/transform input/);
});

artifactTest('fixed packet closes fifty direct and thirteen routine rules',()=>{
 const value=fixedPacket();
 assert.equal(value.format,'ordered-current-direct-frame-acceptance-v1');
 assert.equal(value.status,'NATIVE-UNVERIFIED');
 assert.equal(value.installable,false);
 assert.deepEqual(value.counts,{directRules:50,transformRules:13,totalRules:63,directRows:1220,transformRows:380,totalRows:1600});
 assert.equal(value.directFrame.rules.length,50);
 assert.equal(value.directFrame.expectedRows.length,1220);
 assert.equal(value.directFrame.descriptorRules.length,50);
 assert.equal(value.directFrame.adapters.length,18);
  assert.equal(value.transform.expectedRows.length,380);
  assert.equal(value.originalUniverse.rules,50);
  assert.equal(value.originalUniverse.queries.length,50);
  assert.equal(value.originalUniverse.transformRules.length,13);
  assert.equal(value.originalUniverse.comparison,'exact-unnormalized-source-and-roster-multiset-before-and-after-each-case');
  assert.ok(value.originalUniverse.queries.every(query=>query.originalSQL&&query.demandSQL&&query.keysSQL&&query.originalFrame==='sourceDiscoveryPublic'&&query.keyFrame==='pg_catalog'));
  assert.ok(value.originalUniverse.queries.every(query=>Number.isInteger(query.rowCap)&&query.rowCap>0&&Number.isInteger(query.byteCap)&&query.byteCap>0&&query.rowCap<=value.limits.maxRows&&query.byteCap<=value.limits.maxBytes));
  assert.ok(value.originalUniverse.transformRules.every(rule=>rule.originalSQL&&rule.rosterSQL&&rule.originalFrame==='sourceDiscoveryPublic'&&rule.keyFrame==='canonicalCollector'));
  assert.ok(value.originalUniverse.transformRules.every(rule=>Number.isInteger(rule.byteCap)&&rule.byteCap>0&&rule.byteCap<=value.limits.maxBytes));
  assert.deepEqual(value.originalUniverse.transformRules.map(rule=>rule.rowCap),[91,47,6,10,15,9,10,12,4,46,79,7,44]);
  const expectedByteCap=(rows,id)=>Math.max(4096,rows.filter(row=>row?.source?.ruleId===id).reduce((total,row)=>total+Buffer.byteLength(JSON.stringify(row)),0)*2);
  assert.deepEqual(value.originalUniverse.queries.map(query=>query.byteCap),value.originalUniverse.queries.map(query=>expectedByteCap(value.directFrame.expectedRows,query.id)));
  assert.deepEqual(value.originalUniverse.transformRules.map(rule=>rule.byteCap),value.originalUniverse.transformRules.map(rule=>expectedByteCap(value.transform.expectedRows,rule.id)));
  assert.ok(/^[0-9a-f]{64}$/.test(value.originalUniverse.querySHA256));
  assert.equal(value.caseProgram.format,'ordered-current-direct-frame-cases-v1');
  assert.equal(value.caseProgram.status,'NATIVE-UNVERIFIED');
  assert.equal(value.caseProgram.installable,false);
  assert.deepEqual(value.caseProgram.blockingDependencies.map(item=>item.id),[
   'independent-expected-rows',
   'original-universe-query',
   'successor-installation-proof',
   'native-execution',
  ]);
  assert.equal(Object.hasOwn(value,'manifestSHA256'),false);
 assert.equal(Object.hasOwn(value,'outputPath'),false);
  assert.equal(value.sourcePins.sourceContractSHA256,'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb');
  assert.equal(value.sourcePins.transformReferenceModuleSHA256,'9fdc86ef3e6df47f3668ec49474b288a34f44d3c0f0a8b995989dfa60b29898a');
  assert.equal(value.sourcePins.captureSQLModuleSHA256,'30909caf252a6dfad8a48b0673f782a1a6f07253613f0b847c142ef1aefce3d2');
  assert.equal(value.sourcePins.caseProgramModuleSHA256,'e95a1858b8e04473bc80d0d57b3c1f945728d4b223151563b1f206ef90905b8c');
  assert.equal(value.transformCorrespondence.rules.length,13);
  assert.ok(value.transformCorrespondence.rules.every(rule=>rule.kind==='routine'&&Array.isArray(rule.captureFields)&&rule.captureFields.length>=rule.fields.length&&rule.residual&&rule.sql.original&&rule.sql.candidate&&rule.sql.roster&&rule.sql.originalAggregate&&rule.sql.candidateAggregate));
});

test('packet pins every imported transform helper',()=>{
 assert.deepEqual(Object.keys(orderedCurrentDirectFrameSourcePins).filter(key=>key.endsWith('ModuleSHA256')).sort(),[
  'captureSQLModuleSHA256','caseProgramModuleSHA256','catalogModuleSHA256','directFrameModuleSHA256','directReferenceModuleSHA256','transformReferenceModuleSHA256',
 ]);
});

artifactTest('packet serialization is deterministic and binds the full payload',()=>{
 const value=fixedPacket();
 const first=serializeOrderedCurrentDirectFrameAcceptancePacket(value),second=serializeOrderedCurrentDirectFrameAcceptancePacket(value);
 assert.deepEqual(first.raw,second.raw);
 assert.equal(first.sha256,second.sha256);
 assert.ok(first.raw.length>0);
});

artifactTest('packet case program inventory is fixed and bounded',()=>{
 const value=fixedPacket();
 assert.equal(value.caseProgram.poisonCases.length,18);
 assert.equal(value.caseProgram.propertyCases.length,6);
 assert.equal(value.caseProgram.semanticProbes.length,22);
 assert.equal(value.caseProgram.successorTransform.rules.length,13);
 assert.equal(value.caseProgram.successorTransform.cases.length,19);
 assert.ok(value.caseProgram.poisonCases.every(c=>c.stages.map(stage=>stage.id).join(',')==='capture-pre-state,mutate,positive-invocation,rollback-positive-invocation,admission-probe,selector-reachability-probe,direct-gated-collector,transform-gated-collector,assert-noninvocation,rollback-case,verify-restoration'));
});

artifactTest('packet rejects transformed projection drift before emission',()=>{
 const input=fixedInput();
 input.coverageRaw=Buffer.from(input.coverageRaw);
 input.coverageRaw[100]^=1;
 assert.throws(()=>buildOrderedCurrentDirectFrameAcceptancePacket(input),/transform projection/);
});

artifactTest('packet rejects direct catalog drift before emission',()=>{
 const input=fixedInput();
 input.catalogRaw=Buffer.from(input.catalogRaw);
 input.catalogRaw[100]^=1;
 assert.throws(()=>buildOrderedCurrentDirectFrameAcceptancePacket(input),/direct projection/);
});
