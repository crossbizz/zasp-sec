import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {projectOrderedCurrentTransformReferenceV2} from './ordered-current-transform-reference-v2.mjs';
import {projectOrderedCurrentDirectReferenceV2} from './ordered-current-direct-reference-v2.mjs';
import {
  admitOrderedDirectFrameSourceV1,
  directFrameAdaptersV1,
  directFrameRuleFieldMatrixV1,
  directFrameRulesV1,
} from './ordered-current-direct-frame-v1.mjs';
import {compileOrderedDirectFrameCollectorV1} from './ordered-current-catalog.mjs';
import {compileOrderedCaptureRule,prepareOrderedCaptureRule} from './ordered-current-capture-sql.mjs';
import {
  assertOrderedCurrentDirectFrameCasesV1,
  buildOrderedCurrentDirectFrameCasesV1,
} from './ordered-current-direct-frame-cases-v1.mjs';

const fail=message=>{throw Error(`ordered-current direct-frame acceptance packet ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const freeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};

// These are the accepted recovery80 source identities. They are deliberately
// constants: callers cannot select a manifest, SQL packet, or output authority.
export const orderedCurrentDirectFrameSourcePins=freeze({
  compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
  compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
  compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
  sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
  coverageSHA256:'67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4',
  catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',
  directFrameModuleSHA256:'4c15aee77f9a6d00d8c63a969487dbe9f2d024db0b0f3814aab76424fc9a533b',
  directReferenceModuleSHA256:'427ee5fa8fda3e92805caca4e36d6afbf08c8c3cc7b09db48935dda38414dfa2',
  catalogModuleSHA256:'0901442f9885352359aae1065f12c5457a16176b2e13b487efea39719ccab840',
  transformReferenceModuleSHA256:'9fdc86ef3e6df47f3668ec49474b288a34f44d3c0f0a8b995989dfa60b29898a',
  captureSQLModuleSHA256:'30909caf252a6dfad8a48b0673f782a1a6f07253613f0b847c142ef1aefce3d2',
  caseProgramModuleSHA256:'e95a1858b8e04473bc80d0d57b3c1f945728d4b223151563b1f206ef90905b8c',
});

const limits=freeze({maxRows:1600,maxBytes:33554432,observerSeconds:30,sqlSeconds:10,lockSeconds:3,cleanupSeconds:3});
function validProjection(projection){
  if(!projection||typeof projection!=='object')fail('transform projection required');
  // The builder derives the projection itself from the fixed admitted bytes;
  // callers cannot supply an expected-row object as authority.
  const source=projection.provenance?.source;
  for(const [key,value] of Object.entries(orderedCurrentDirectFrameSourcePins)){
    if(key==='catalogSHA256'||key.endsWith('ModuleSHA256'))continue;
    if(source?.[key]!==value)fail(`transform source pin ${key}`);
  }
  if(projection.installable!==false||projection.transformRules.length!==13||projection.expectedRows.length!==380)fail('transform projection bounds');
  return projection;
}

function verifyModuleBytes(){
  const files={
    directFrameModuleSHA256:new URL('./ordered-current-direct-frame-v1.mjs',import.meta.url),
    directReferenceModuleSHA256:new URL('./ordered-current-direct-reference-v2.mjs',import.meta.url),
    catalogModuleSHA256:new URL('./ordered-current-catalog.mjs',import.meta.url),
    transformReferenceModuleSHA256:new URL('./ordered-current-transform-reference-v2.mjs',import.meta.url),
    captureSQLModuleSHA256:new URL('./ordered-current-capture-sql.mjs',import.meta.url),
    caseProgramModuleSHA256:new URL('./ordered-current-direct-frame-cases-v1.mjs',import.meta.url),
  };
  for(const [pin,url] of Object.entries(files))if(sha(fs.readFileSync(url))!==orderedCurrentDirectFrameSourcePins[pin])fail(`module pin ${pin}`);
}

function directFrame(){
  const compiled=compileOrderedDirectFrameCollectorV1(directFrameRulesV1);
  if(compiled.installable!==false||compiled.ruleFieldMatrix.length!==50||compiled.sql.length>limits.maxBytes)fail('direct frame compiler bounds');
  try{admitOrderedDirectFrameSourceV1(compiled.sql);}catch(error){fail(`direct frame compiler admission (${error.message})`);}
  const adapters=directFrameAdaptersV1.map(adapter=>({
    name:adapter.name,
    args:adapter.args,
    body:adapter.body,
    bodySHA256:sha(adapter.body),
  }));
  return {
    version:1,
    installable:false,
    rules:directFrameRulesV1,
    ruleFieldMatrix:directFrameRuleFieldMatrixV1,
    adapters,
    installSQL:compiled.installSQL,
    admissionSQL:compiled.admissionSQL,
    sql:compiled.sql,
    sqlSHA256:compiled.sourceSHA256,
  };
}

const transformRuleRowCaps=Object.freeze([91,47,6,10,15,9,10,12,4,46,79,7,44]);
function derivedQueryCap(rows,ruleID,sourceMaxRows){
  const selected=rows.filter(row=>row?.source?.ruleId===ruleID),rowCap=Number.isInteger(sourceMaxRows)&&sourceMaxRows>0?sourceMaxRows:Math.max(1,selected.length);
  const bytes=Math.max(1,selected.reduce((total,row)=>total+Buffer.byteLength(JSON.stringify(row)) ,0));
  const byteCap=Math.max(4096,bytes*2);
  if(rowCap>limits.maxRows||byteCap>limits.maxBytes)fail(`original universe cap ${ruleID}`);
  return {rowCap,byteCap};
}
function originalUniverse(coverage,caseProgram,directExpectedRows,transformExpectedRows){
  if(!Array.isArray(coverage.rawRules))fail('original universe coverage');
  const queries=directFrameRulesV1.map(rule=>{
    const matches=coverage.rawRules.filter(candidate=>candidate?.id===rule.id);
    if(matches.length!==1)fail(`original universe rule ${rule.id}`);
    const compiled=compileOrderedCaptureRule(prepareOrderedCaptureRule(matches[0]));
    if(typeof compiled.original!=='string'||compiled.original.trim()==='')fail(`original universe SQL ${rule.id}`);
    const cap=derivedQueryCap(directExpectedRows,rule.id,matches[0].sourceMaxRows);
    return {id:rule.id,originalSQL:compiled.original,demandSQL:compiled.demand,keysSQL:compiled.keys,originalFrame:'sourceDiscoveryPublic',keyFrame:'pg_catalog',rowCap:cap.rowCap,byteCap:cap.byteCap};
  });
  const transformRules=caseProgram.successorTransform.rules.map((rule,index)=>{const cap=derivedQueryCap(transformExpectedRows,rule.id,transformRuleRowCaps[index]);return {id:rule.id,originalSQL:rule.originalSQL,rosterSQL:rule.rosterSQL,originalFrame:rule.executionFrame,keyFrame:rule.candidateFrame,rowCap:cap.rowCap,byteCap:cap.byteCap};});
  if(transformRules.length!==13||transformRules.some(rule=>!rule.originalSQL||!rule.rosterSQL))fail('original universe transform rules');
  return {rules:50,queries,transformRules,querySHA256:sha(JSON.stringify({queries,transformRules})),comparison:'exact-unnormalized-source-and-roster-multiset-before-and-after-each-case'};
}

function assertTransformCorrespondence(projectedRules,projectedRows,caseRules){
  if(!Array.isArray(projectedRules)||!Array.isArray(caseRules)||projectedRules.length!==13||caseRules.length!==13)fail('transform correspondence bounds');
  const byID=new Map(caseRules.map(rule=>[rule.id,rule])),counts=new Map(),seen=new Set(),records=[];
  if(byID.size!==13)fail('transform correspondence duplicate case rule');
  for(const row of projectedRows)counts.set(row.source?.ruleId,(counts.get(row.source?.ruleId)??0)+1);
  for(const rule of projectedRules){
    const candidate=byID.get(rule.id);
    if(!candidate||seen.has(rule.id)||rule.kind!=='routine'||candidate.kind!==rule.kind||!same(rule.fields,candidate.fields)||!same(rule.sourceSite,candidate.sourceSite)||rule.executionFrameId!=='sourceDiscoveryPublic'||candidate.executionFrame!=='sourceDiscoveryPublic'||candidate.candidateFrame!=='canonicalCollector'||!same(Object.keys(rule.fieldTypes),rule.fields)||!same(Object.keys(candidate.fieldTypes),candidate.fields)||!same(rule.captureFields.slice(0,rule.fields.length),rule.fields)||!rule.residual||counts.get(rule.id)!==rule.expectedRows)fail(`transform correspondence ${rule.id}`);
    for(const field of rule.fields)if(typeof rule.fieldTypes[field]!=='string'||typeof candidate.fieldTypes[field]!=='string'||!candidate.originalSQL||!candidate.candidateSQL||!candidate.rosterSQL||!candidate.originalAggregateSQL||!candidate.candidateAggregateSQL||sha(candidate.candidateSQL)!==candidate.compiledSQLSHA256)fail(`transform correspondence field ${rule.id}/${field}`);
    seen.add(rule.id);
    records.push({id:rule.id,kind:rule.kind,fields:rule.fields,fieldTypes:{captured:rule.fieldTypes,candidate:candidate.fieldTypes},captureFields:rule.captureFields,residual:rule.residual,sourceSite:rule.sourceSite,executionFrame:rule.executionFrameId,candidateFrame:candidate.candidateFrame,expectedRows:rule.expectedRows,sql:{original:sha(candidate.originalSQL),candidate:sha(candidate.candidateSQL),roster:sha(candidate.rosterSQL),originalAggregate:sha(candidate.originalAggregateSQL),candidateAggregate:sha(candidate.candidateAggregateSQL)}});
  }
  if(seen.size!==13||projectedRules.some(rule=>!byID.has(rule.id)))fail('transform correspondence bidirectional ids');
  return freeze({rules:records});
}

export function buildOrderedCurrentDirectFrameAcceptancePacket(input){
  verifyModuleBytes();
  if(!input||typeof input!=='object'||JSON.stringify(Object.keys(input).sort())!==JSON.stringify(['aPacketRoot','aRaw','bPacketRoot','bRaw','catalogRaw','compiledReleaseRaw','coverageRaw','sourceContractRaw']))fail('fixed direct/transform input required');
  let transform;
  let direct;
  try{transform=projectOrderedCurrentTransformReferenceV2(Object.fromEntries(['aPacketRoot','aRaw','bPacketRoot','bRaw','compiledReleaseRaw','coverageRaw','sourceContractRaw'].map(key=>[key,input[key]])));}catch(error){fail(`transform projection (${error.message})`);}
  validProjection(transform);
  try{direct=projectOrderedCurrentDirectReferenceV2(input);}catch(error){fail(`direct projection (${error.message})`);}
  if(direct.expectedRows.length!==1220||direct.descriptorRules.length!==50)fail('direct projection bounds');
  let caseProgram;
  try {
    caseProgram=buildOrderedCurrentDirectFrameCasesV1({
      compiledReleaseRaw:input.compiledReleaseRaw,
      sourceContractRaw:input.sourceContractRaw,
      coverageRaw:input.coverageRaw,
      catalogRaw:input.catalogRaw,
    });
    assertOrderedCurrentDirectFrameCasesV1(caseProgram);
  } catch(error) { fail(`case program (${error.message})`); }
  const frame=directFrame();
  const successorCompiledSQL=caseProgram.successorTransform.compiled.sql;
  const successorCompiledSQLSHA256=caseProgram.successorTransform.compiledSQLSHA256;
  if(typeof successorCompiledSQL!=='string'||sha(successorCompiledSQL)!==successorCompiledSQLSHA256)fail('successor transform compiler closure');
  const transformCorrespondence=assertTransformCorrespondence(transform.transformRules,transform.expectedRows,caseProgram.successorTransform.rules);
  const packet={
    format:'ordered-current-direct-frame-acceptance-v1',
    status:'NATIVE-UNVERIFIED',
    installable:false,
    sourceAuthority:'accepted-recovery80-source-2ca-local-parity-only',
    sourcePins:orderedCurrentDirectFrameSourcePins,
    limits,
    counts:{directRules:50,transformRules:13,totalRules:63,directRows:1220,transformRows:380,totalRows:1600},
    directFrame:{...frame,expectedRows:direct.expectedRows,descriptorRules:direct.descriptorRules,provenance:direct.provenance},
    originalUniverse:originalUniverse(JSON.parse(input.coverageRaw.toString('utf8')),caseProgram,direct.expectedRows,transform.expectedRows),
    transform:{rules:transform.transformRules,expectedRows:transform.expectedRows,provenance:transform.provenance,compiledSQL:successorCompiledSQL,compiledSQLSHA256:successorCompiledSQLSHA256},
    transformCorrespondence,
    // The case program is the reviewed successor execution contract. Its
    // explicit blocking dependencies remain authoritative until independent
    // expected facts and the native run are separately admitted.
    caseProgram,
  };
  if(packet.directFrame.rules.length+packet.transform.rules.length!==packet.counts.totalRules)fail('rule total');
  if(packet.directFrame.ruleFieldMatrix.length!==50||packet.directFrame.adapters.length!==18)fail('direct frame closure');
  if(packet.transform.expectedRows.length!==packet.counts.transformRows)fail('transform row total');
  return freeze(packet);
}

export function serializeOrderedCurrentDirectFrameAcceptancePacket(packet){
  if(!packet||typeof packet!=='object')fail('packet object required for serialization');
  const raw=Buffer.from(JSON.stringify(packet)+'\n');
  return {raw,sha256:sha(raw)};
}

export function materializeOrderedCurrentDirectFrameAcceptancePacket(packet,directory){
  if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory)fail('materializer directory must be absolute');
  const output=path.join(directory,'direct-frame-acceptance.json');
  if(fs.existsSync(output))fail('materializer refuses overwrite');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const serialized=serializeOrderedCurrentDirectFrameAcceptancePacket(packet);
  fs.writeFileSync(output,serialized.raw,{flag:'wx',mode:0o600});
  return {path:output,sha256:serialized.sha256,bytes:serialized.raw.length};
}
