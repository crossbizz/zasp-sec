import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {admitOrderedCurrentCaptureBundleV1,parseOrderedCurrentCaptureJSONV1} from './ordered-current-capture-intake-v1.mjs';
import {assertOrderedCurrentMissingReferenceNativePacketV1} from './ordered-current-missing-reference-native-packet.mjs';

const fail=message=>{throw Error(`ordered-current precision conflict settlement: ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const sourcePacketSHA256='23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287';
const captureContractSHA256='262728237a748a512b98e499a9b0335c13cabcf39a372fd3eaf65261e8f1449d';
const sourcePins={compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',contractModuleSHA256:'2a304799618b0ca70b18df1f63f04c7bc450aab83b0bfcc19b779aead5b3af90',contractJSONSHA256:'ae63b0e31dd6ee7d7855d302184acb116e28fb081b2b17facae6c6be4de70d29'};
const sourceFile='sql/0072_production_temporal_discovery.up.sql';
const sourceFileSHA256='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940';
const ruleId='temporal72:precision-function';
const fieldSchema=['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','precision_definition'];
const disposition='supersede-incomplete-null-precision-definition-with-source-selected-predecessor-definition';
const conflicts=[
 ['public.zasp_runtime_precision_batch_insert_guard()','6995a08960cdc3786a2d6621413f7342011741c87f533e9bcb70d03934857f5c','ff4000d37a58344a7b72c23c78ff890298764f2292c9d73e4688088e2d20e8bd'],
 ['public.zasp_runtime_precision_batch_update_guard()','9692d7549ce1a8f2e04383c3bdd1fbbfd7bd1a6e9ed27161743420a763f99c59','b9f7753907841c191ed5021bc7dd01c8afcb0bca5c30ea650932ac1d7d0cb774'],
 ['public.zasp_runtime_precision_claim_version_guard()','4500dcc5bfbbcef0918d1b449aac83340f7316c8c1b23821e1e4d9e5a8af8953','0d16bcef45abfa2367fa59c7ce0053dc4bc31d8d809aa92411c15c3ee5c1dc92'],
 ['public.zasp_runtime_precision_delivery_guard()','51ca6a37a97912492a020a171f9563f5acbe2481023a31a7f52881cfd12fe73f','5cf10f5e4865cdcbbd181689cf1df89bf29b769a6f65aa69c3d01558c33e606c'],
 ['public.zasp_runtime_precision_outbox_guard()','a32d9f753325a2aa3fdaca4abbeb92679acbc3b8ada3610219888541c5296fe3','0c70ceb8a32fbc3fedc50de28aaf4d77ab3642ba0184690ca72b1e77df859702'],
 ['public.zasp_runtime_precision_reconciliation_guard()','b1171c67b8a135f5634463727f96ec4569b107df3731b945e108dc3b882e7843','1679447234ae39ad07bbcb9bd43075905eae85b65de42455627acdbb7770dfbd'],
 ['public.zasp_runtime_precision_stage_insert_guard()','c57b17caac5b5f7491417fa107c9875eee1fda7bc5c3493f7fbdf66dcdba43d3','90f4cea15fc373971d40eebd1436ec04880aa7c7768c56df447513f81d28053c'],
];

function packetAuthority(raw){
 const packet=parseOrderedCurrentCaptureJSONV1(raw,{maxBytes:16777216});
 if(sha(raw)!==sourcePacketSHA256)fail('source packet bytes');
 assertOrderedCurrentMissingReferenceNativePacketV1(packet);
 if(packet.sourceAuthority!=='accepted-recovery80-source-2ca-missing-reference-capture-only'||packet.contract.contractSHA256!==captureContractSHA256||canonicalOrderedJSON(packet.sourcePins)!==canonicalOrderedJSON(sourcePins))fail('source packet authority');
 const rules=packet.contract.rules.filter(row=>row.id===ruleId),baselines=packet.baseline.rules.filter(row=>row.id===ruleId);
 if(rules.length!==1||baselines.length!==1)fail('source rule cardinality');
 const rule=rules[0],baseline=baselines[0];
 const fieldTypes={namespace_name:'string',name:'string',identity_arguments:'string',owner:'string',security_definer:'boolean',config_text_or_empty:'string',acl_text_or_empty:'string',precision_definition:'string'};
 if(rule.kind!=='routine'||rule.exactRows!==51||rule.maxRows!==51||canonicalOrderedJSON(rule.fields)!==canonicalOrderedJSON(fieldSchema)||canonicalOrderedJSON(rule.fieldTypes)!==canonicalOrderedJSON(fieldTypes)||rule.sourceSites.length!==1)fail('source rule schema');
 const selected=rule.sourceSites[0],frame={owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',config:['search_path=pg_catalog, public'],result:'text',arguments:'',language:'sql',securityDefiner:false,volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,searchPath:['pg_catalog','public']};
 if(selected.sourceIdentity!=='zasp_temporal72.retained_precision_fingerprint()'||selected.siteSHA256!=='524cfacb06cd93d4c6884a33db32a1d25a6804eae2ad057faf0077c3820b2765'||sha(selected.sourceExpression)!==selected.siteSHA256||selected.sourceExpressionSHA256!==selected.siteSHA256||selected.sourceSHA256!=='65c56d5deaa809f9e751bec5878243569750653902d47ab299e98c504649d8b1'||selected.definitionSHA256!=='d818de30fd18ecfaf7901678f209a497686f7299aee204d33c39a4e3ed896cba'||selected.start!==118||selected.end!==1663||canonicalOrderedJSON(selected.frame)!==canonicalOrderedJSON(frame))fail('source site');
 if(sha(JSON.stringify(rule))!=='ec063cfc5b316df8a931ee8c143f7a178e8a6b0961a68a4c1f5552e15c28e388'||baseline.ruleSHA256!=='ec063cfc5b316df8a931ee8c143f7a178e8a6b0961a68a4c1f5552e15c28e388'||baseline.sourceSitesSHA256!=='d60cf2bf6919bfa2388f147c1a9cc3551919badf824abe455107e2553a5d1100'||canonicalOrderedJSON(baseline.fields)!==canonicalOrderedJSON(fieldSchema)||canonicalOrderedJSON(baseline.fieldTypes)!==canonicalOrderedJSON(fieldTypes)||canonicalOrderedJSON(baseline.projectionFrame)!==canonicalOrderedJSON({owner:frame.owner,searchPath:frame.searchPath}))fail('source rule identity');
 const migrationRaw=fs.readFileSync(new URL('../'+sourceFile,import.meta.url));
 if(sha(migrationRaw)!==sourceFileSHA256)fail('source migration bytes');
 return {selected,frame,baseline};
}

export function checkOrderedCurrentPrecisionSettlementPacketV1(raw){packetAuthority(raw);}

function build(){
 const packetRaw=fs.readFileSync(new URL('./ordered-current-capture-intake-v1-artifacts/missing-reference-native-packet.json',import.meta.url));
 const {selected,frame,baseline}=packetAuthority(packetRaw),capture=admitOrderedCurrentCaptureBundleV1(),incoming=new Map(capture.missingFacts.map(row=>[row.identity,row]));
 const rows=conflicts.map(([signature,existingFactSHA256,incomingFactSHA256])=>{
  const identity=canonicalOrderedJSON([ruleId,signature]),fact=incoming.get(identity);
  if(!fact||fact.kind!=='routine'||sha(canonicalOrderedJSON(fact.fact))!==incomingFactSHA256||typeof fact.fact.precision_definition!=='string'||!fact.fact.precision_definition)fail('accepted replacement '+signature);
  return {collection:'missing',kind:'routine',identity,ruleId,fieldSchema:[...fieldSchema],existingFactSHA256,incomingFactSHA256,
   sourcePacketSHA256,captureContractSHA256,captureContractJSONSHA256:sourcePins.contractJSONSHA256,sourceContractSHA256:sourcePins.sourceContractSHA256,compiledSourceSHA256:sourcePins.compiledSourceSHA256,compilerArtifactSHA256:sourcePins.compilerArtifactSHA256,compilerChecksum:sourcePins.compilerChecksum,catalogSHA256:sourcePins.catalogSHA256,contractModuleSHA256:sourcePins.contractModuleSHA256,
   sourceFile,sourceFileSHA256,sourceIdentity:selected.sourceIdentity,sourceBodySHA256:selected.sourceSHA256,sourceDefinitionSHA256:selected.definitionSHA256,sourceSiteSHA256:selected.siteSHA256,sourceRuleSHA256:baseline.ruleSHA256,sourceSitesSHA256:baseline.sourceSitesSHA256,sourceStart:selected.start,sourceEnd:selected.end,sourceFrame:structuredClone(frame),disposition};
 });
 return freeze(rows);
}

let fixed;
export function orderedCurrentPrecisionConflictSettlementsV1(){
 fixed??=build();
 return structuredClone(fixed);
}

export function assertOrderedCurrentPrecisionConflictSettlementV1(value){
 const expected=(fixed??=build()).find(row=>row.kind===value?.kind&&row.identity===value?.identity);
 if(!expected||canonicalOrderedJSON(value)!==canonicalOrderedJSON(expected))fail('settlement authority');
}
