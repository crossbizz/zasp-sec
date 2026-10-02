import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {checkOrderedConsolidatedReferenceEnvelopeV2,admitOrderedConsolidatedReferenceV2} from './ordered-current-consolidated-reference-v2.mjs';
import {readAdmittedOrderedConsolidatedReferenceObservationV2} from './ordered-current-consolidated-reference-v2-ab.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const pin='a'.repeat(64),packet='services/platform/migrations/ordered_current/';
const wire=value=>Array.isArray(value)?`[${value.map(wire).join(',')}]`:value&&typeof value==='object'?`{${Object.keys(value).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(key=>`${wire(key)}:${wire(value[key])}`).join(',')}}`:JSON.stringify(value).replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029');
const encode=value=>Buffer.from(wire(value)+'\n');
const frame=(role,path)=>({sessionUser:'zasp_test',role,searchPath:path,timeZone:'UTC',readOnly:true});
function fixture(){
 const executionFrames={
  collectorDiscoveryCatalog:{role:'zasp_discovery_authority',searchPath:'pg_catalog',timeZone:'UTC',derivation:'collector',sourceFrameProofSHA256:null},
  sourceDiscoveryPublic:{role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC',derivation:'source-proof',sourceFrameProofSHA256:pin},
  sourceInventoryPublic:{role:'zasp_inventory_authority',searchPath:'pg_catalog, public',timeZone:'UTC',derivation:'source-proof',sourceFrameProofSHA256:pin}
 };
 const batchSpecs=[['demand','sourceInventoryPublic','d'],['keys','collectorDiscoveryCatalog','k'],['original','sourceInventoryPublic','o'],['resolution','sourceDiscoveryPublic','r'],['witness','sourceDiscoveryPublic','w']];
 const batchFiles={};
 const phases=batchSpecs.map(([id,executionFrameId,ruleId])=>{
  const file=`${packet}consolidated-capture-${id}-${executionFrameId.replace(/([a-z])([A-Z])/g,'$1-$2').toLowerCase()}.sql`,raw=Buffer.from(`SELECT '${id}'\n`);batchFiles[file]=raw;
  return {id,batches:[{id:`${id}:${executionFrameId}`,executionFrameId,file,sqlSHA256:sha(raw),ruleIds:[ruleId]}]};
 });
 const rule=(kind,section,phase,executionFrameId,fields=[],bag=false)=>({kind,section,phase,executionFrameId,fields,fieldTypes:Object.fromEntries(fields.map(field=>[field,'text'])),sourceMaxRows:null,refusalMaxRows:10000,bag,rosterRuleId:null,demandRuleId:null});
 const rules={
  d:rule('routine','demand','demand','sourceInventoryPublic'),
  k:{...rule('routine','roster','keys','collectorDiscoveryCatalog'),demandRuleId:'d'},
  o:{...rule('routine','rawInputs','original','sourceInventoryPublic',['value']),rosterRuleId:'k'},
  r:rule('resolution','resolutions','resolution','sourceDiscoveryPublic',['value'],true),
  w:rule('membership','witnesses','witness','sourceDiscoveryPublic',['value'],true)
 };
 const contextPrerequisiteIds=['exact-source-and-query','effective-user-and-session','same-inherited-settings','private-fixture-quiescence','no-unsupported-observers','closed-v2-lifecycle'];
 const contract={format:'ordered-current-complete-capture-contract-v2',status:'REFERENCE-CAPTURE-ONLY',installable:false,captureReady:true,sourceFrameVersion:2,compilerArtifactSHA256:pin,compilerChecksum:pin,compiledSourceSHA256:pin,sourceContractSHA256:pin,closureSHA256:pin,catalog1FileSHA256:pin,frameEvidenceSHA256:pin,contextPrerequisiteIds,requiredPostgres:'PostgreSQL 18.3 test build',requiredServerVersionNum:'180003',pgcrypto:'1.4',variant:'A',sessionUser:'zasp_test',entryFrameId:'collectorDiscoveryCatalog',roleEntryPrecondition:{sessionUser:'zasp_test',superuser:true},maxRows:65536,maxBytes:33554432,executionFrames,phases,rules,reusedEvidence:[],sourcePins:{'source.mjs':pin}};
 const contractRaw=encode(contract),manifest={format:2,source:'offline-v2-control',files:{[`${packet}consolidated-capture-contract-v2.json`]:sha(contractRaw),'source.mjs':pin,...Object.fromEntries(Object.entries(batchFiles).map(([path,raw])=>[path,sha(raw)]))}},manifestRaw=encode(manifest);
 const observations=phases.map(phase=>{const batch=phase.batches[0],definition=executionFrames[batch.executionFrameId],target=frame(definition.role,definition.searchPath);return {id:phase.id,batches:[{id:batch.id,executionFrameId:batch.executionFrameId,sqlSHA256:batch.sqlSHA256,beforeFrame:target,afterFrame:target,restoredFrame:frame('zasp_discovery_authority','pg_catalog'),rowCount:1,expandedRows:1,streamBytes:10}],rowCount:1,expandedRows:1,streamBytes:10};});
 const row=id=>({ruleId:id,identity:`identity:${id}`,multiplicity:1,fact:{value:id}});
 const envelope={format:'ordered-current-complete-reference-v2',status:'REFERENCE-CAPTURE-ONLY',installable:false,sourceFrameVersion:2,packetManifestSHA256:sha(manifestRaw),contractSHA256:sha(contractRaw),closureSHA256:pin,compilerArtifactSHA256:pin,compilerChecksum:pin,compiledSourceSHA256:pin,sourceContractSHA256:pin,catalog1FileSHA256:pin,frameEvidenceSHA256:pin,contextPrerequisiteIds,sourcePins:{'source.mjs':pin},variant:'A',sessionUser:'zasp_test',entryFrame:frame('zasp_discovery_authority','pg_catalog'),postgres:'PostgreSQL 18.3 test build',serverVersionNum:'180003',pgcrypto:'1.4',readOnly:true,preAdmission:true,postAdmission:true,rolledBack:true,frameRestored:true,phases:observations,counts:{streamRows:5,expandedRows:5,streamBytes:50,demandRows:1,rosterRows:1,ruleRows:{d:1,k:1,o:1,r:1,w:1}},rawInputs:[row('o')],normalizationObservations:[],resolutions:[row('r')],witnesses:[row('w')],reusedEvidence:[]};
 return {contract,contractRaw,manifest,manifestRaw,batchFiles,envelope};
}
function repin(value){value.contractRaw=encode(value.contract);value.manifest.files[`${packet}consolidated-capture-contract-v2.json`]=sha(value.contractRaw);value.manifestRaw=encode(value.manifest);value.envelope.contractSHA256=sha(value.contractRaw);value.envelope.packetManifestSHA256=sha(value.manifestRaw);}

function measuredEnvelope(){
 const value=fixture(),witnessBatch=value.contract.phases[4].batches[0],witnessPhase=value.envelope.phases[4],counts=[6952,6952,6952,6952,6953];
 value.envelope.resolutions[0].multiplicity=9000;value.envelope.counts.ruleRows.r=9000;value.envelope.phases[3].batches[0].expandedRows=9000;value.envelope.phases[3].expandedRows=9000;
 value.envelope.witnesses[0].multiplicity=9000;value.envelope.counts.ruleRows.w=9000;
 counts.forEach((multiplicity,index)=>{const id=`w${index+2}`;value.contract.rules[id]={...structuredClone(value.contract.rules.w)};witnessBatch.ruleIds.push(id);value.envelope.counts.ruleRows[id]=multiplicity;value.envelope.witnesses.push({ruleId:id,identity:`identity:${id}`,multiplicity,fact:{value:id}});});
 witnessPhase.batches[0].rowCount=6;witnessPhase.rowCount=6;witnessPhase.batches[0].expandedRows=43761;witnessPhase.expandedRows=43761;
 value.envelope.counts.streamRows=10;value.envelope.counts.expandedRows=52764;value.envelope.counts.streamBytes=27711124;
 value.envelope.phases[0].batches[0].streamBytes=value.envelope.phases[0].streamBytes=10;
 value.envelope.phases[1].batches[0].streamBytes=value.envelope.phases[1].streamBytes=10;
 value.envelope.phases[2].batches[0].streamBytes=value.envelope.phases[2].streamBytes=10;
 value.envelope.phases[3].batches[0].streamBytes=value.envelope.phases[3].streamBytes=10;
 value.envelope.phases[4].batches[0].streamBytes=value.envelope.phases[4].streamBytes=27711084;
 value.envelope.rawInputs[0].fact.value='x'.repeat(23000000);
 repin(value);return value;
}

test('v2 intake accepts exact fixed batches but never opens file admission',()=>{
 const value=fixture();
 assert.equal(checkOrderedConsolidatedReferenceEnvelopeV2(encode(value.envelope),value),undefined);
 assert.throws(()=>admitOrderedConsolidatedReferenceV2(),/closed|not accepted/);
});

test('comparator observation path preserves an unsafe numeric lexeme for intake',()=>{
 const value=fixture();
 value.contract.rules.r.fieldTypes.value='number';
 repin(value);
 const raw=encode(value.envelope),needle=Buffer.from('"value":"r"'),at=raw.indexOf(needle);
 assert.notEqual(at,-1);
 const numeric=Buffer.concat([raw.subarray(0,at),Buffer.from('"value":9007199254740993'),raw.subarray(at+needle.length)]);
 const result=readAdmittedOrderedConsolidatedReferenceObservationV2(numeric,value);
 assert.equal(result.resolutions[0].fact.value.token,'9007199254740993');
});

test('v2 intake refuses frame and batch authority drift',()=>{
 const mutations=[
  value=>value.contract.executionFrames.sourceInventoryPublic.role='zasp_discovery_authority',
  value=>value.contract.executionFrames.sourceInventoryPublic.sourceFrameProofSHA256='b'.repeat(64),
  value=>value.contract.executionFrames.extra={...value.contract.executionFrames.sourceDiscoveryPublic},
  value=>value.contract.contextPrerequisiteIds.pop(),
  value=>value.contract.phases[2].batches[0].executionFrameId='sourceDiscoveryPublic',
  value=>value.contract.phases[2].batches[0].ruleIds.push('w'),
  value=>value.envelope.phases[2].batches[0].beforeFrame.role='zasp_discovery_authority',
  value=>value.envelope.phases[2].batches[0].afterFrame.searchPath='pg_catalog',
  value=>value.envelope.phases[2].batches[0].restoredFrame.role='zasp_inventory_authority',
  value=>value.envelope.entryFrame.searchPath='public',
  value=>value.envelope.frameRestored=false
 ];
 for(const mutate of mutations){const value=fixture();mutate(value);repin(value);assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(encode(value.envelope),value));}
});

test('v2 intake refuses batch, phase, rule and byte accounting drift',()=>{
 const mutations=[
  value=>value.envelope.phases[0].batches[0].rowCount=0,
  value=>value.envelope.phases[0].rowCount=0,
  value=>value.envelope.counts.streamRows=4,
  value=>value.envelope.counts.ruleRows.d=0,
  value=>value.contract.rules.o.executionFrameId='sourceDiscoveryPublic',
  value=>value.batchFiles[value.contract.phases[0].batches[0].file]=Buffer.from('changed\n'),
  value=>delete value.manifest.files[value.contract.phases[0].batches[0].file]
 ];
 for(const mutate of mutations){const value=fixture();mutate(value);repin(value);assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(encode(value.envelope),value));}
});

test('v2 intake rejects caller-selected frame SQL and old wire formats',()=>{
 const value=fixture();value.contract.phases[0].batches[0].setRoleSQL='SET ROLE attacker';repin(value);assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(encode(value.envelope),value));
 const old=fixture();old.contract.format='ordered-current-complete-capture-contract-v1';repin(old);assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(encode(old.envelope),old));
});

test('v2 intake constants match the shared frame wire vectors',()=>{
 const vectors={
  contextPrerequisiteIds:['exact-source-and-query','effective-user-and-session','same-inherited-settings','private-fixture-quiescence','no-unsupported-observers','closed-v2-lifecycle'],
  executionFrames:{
   collectorDiscoveryCatalog:{role:'zasp_discovery_authority',searchPath:'pg_catalog',timeZone:'UTC'},
   sourceDiscoveryPublic:{role:'zasp_discovery_authority',searchPath:'pg_catalog, public',timeZone:'UTC'},
   sourceInventoryPublic:{role:'zasp_inventory_authority',searchPath:'pg_catalog, public',timeZone:'UTC'},
  },
  batchFilenameVectors:[
   ['keys','collectorDiscoveryCatalog','services/platform/migrations/ordered_current/consolidated-capture-keys-collector-discovery-catalog.sql'],
   ['original','sourceDiscoveryPublic','services/platform/migrations/ordered_current/consolidated-capture-original-source-discovery-public.sql'],
   ['witness','sourceInventoryPublic','services/platform/migrations/ordered_current/consolidated-capture-witness-source-inventory-public.sql'],
  ],
 };
 const value=fixture();
 assert.deepEqual(value.contract.contextPrerequisiteIds,vectors.contextPrerequisiteIds);
 for(const [id,expected] of Object.entries(vectors.executionFrames))assert.deepEqual({role:value.contract.executionFrames[id].role,searchPath:value.contract.executionFrames[id].searchPath,timeZone:value.contract.executionFrames[id].timeZone},expected);
 for(const [phase,frameId,file] of vectors.batchFilenameVectors)assert.equal(`services/platform/migrations/ordered_current/consolidated-capture-${phase}-${frameId.replace(/([a-z])([A-Z])/g,'$1-$2').toLowerCase()}.sql`,file);
});

test('v2 intake accepts the measured row and byte range but refuses either new ceiling',()=>{
 const measured=measuredEnvelope(),raw=encode(measured.envelope);
 assert.ok(raw.length>16777216&&raw.length<33554432,raw.length);
 assert.equal(checkOrderedConsolidatedReferenceEnvelopeV2(raw,measured),undefined);

 const rows=fixture(),witnessBatch=rows.contract.phases[4].batches[0],witnessPhase=rows.envelope.phases[4];
 const ids=['w','w2','w3','w4','w5','w6','w7'];
 for(const id of ids.slice(1)){rows.contract.rules[id]={...structuredClone(rows.contract.rules.w)};witnessBatch.ruleIds.push(id);rows.envelope.witnesses.push({ruleId:id,identity:`identity:${id}`,multiplicity:9362,fact:{value:id}});}
 rows.envelope.witnesses[0].multiplicity=9362;for(const id of ids)rows.envelope.counts.ruleRows[id]=9362;
 witnessPhase.batches[0].rowCount=7;witnessPhase.rowCount=7;witnessPhase.batches[0].expandedRows=65534;witnessPhase.expandedRows=65534;
 rows.envelope.counts.streamRows=11;rows.envelope.counts.expandedRows=65537;repin(rows);
 assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(encode(rows.envelope),rows),/global ceiling/);

 const bytes=measuredEnvelope();assert.throws(()=>checkOrderedConsolidatedReferenceEnvelopeV2(Buffer.alloc(33554433,0x20),bytes),/byte/);
});
