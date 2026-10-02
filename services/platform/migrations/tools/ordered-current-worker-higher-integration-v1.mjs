import crypto from 'node:crypto';
import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {workerHigherSourceReplay} from './ordered-current-worker-higher-source-replay-v1.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=message=>{throw Error('higher successor '+message);};
const sourceFields=['owner','acl','language','volatility','strict','parallel','security_definer','config','arguments','result','cost','rows','leakproof'];
const factFields=['acl','definition','owner'];
const roots=Object.freeze([
 'zasp_temporal68.predecessor_ready(text,text)',
 'zasp_temporal68.ready(text,text)',
 'zasp_temporal77.base67_fingerprint()',
 'zasp_temporal78.ready(text,text)',
]);
const issuedContexts=new WeakMap();
const appliedFactArrays=new WeakSet();
const rawInputs=Object.freeze({
 contractRaw:{path:'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',url:'./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',sha256:'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6'},
 catalogRaw:{path:'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',url:'./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',sha256:'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077'},
 releaseRaw:{path:'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',url:'./ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',sha256:'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425'},
 graphRaw:{path:'services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql',url:'../sql/0080_authorization_worker_readiness_graph.sql',sha256:'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6'},
 compilerRaw:{path:'services/platform/migrations/tools/build-worker-readiness-graph.mjs',url:'./build-worker-readiness-graph.mjs',sha256:'fb66f8649b5fea1cf54dbaa7776665b5375fd64bb6808c2b7c75036812a56da7'},
 regionsRaw:{path:'services/platform/migrations/tools/worker-readiness-regions.mjs',url:'./worker-readiness-regions.mjs',sha256:'d72a3e431dd7fd2abfd15612a03a7d0d8c2b6dca1b064f37536d4151d4f83309'},
 captureSourceRaw:{path:'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go',url:'../../apiserver/authorization_worker_ordered_readiness_capture_test.go',sha256:'60be84a43d564c9c7da3999a22155a7734a1163f258d58206f8bcfabbabc43f6'},
});
const moduleInputs=Object.freeze({
 'services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.mjs':{url:'./ordered-current-worker-higher-source-replay-v1.mjs',sha256:'0a59ac714b861758fc2579de81cda60415b3d2f6b1f1db8a4aa2a73c55739de3'},
 'services/platform/migrations/tools/ordered-current-worker-higher-source-replay-v1.test.mjs':{url:'./ordered-current-worker-higher-source-replay-v1.test.mjs',sha256:'010a2c0537ffa97afdceeb9fa78b890be4307cd35546e96d9ced9a2a101f6e16'},
});

export function readWorkerHigherSourceInputsV1(){
 if(arguments.length!==0)fail('source inputs are fixed');
 const inputs={},inventory={};
 for(const [key,spec] of Object.entries(rawInputs)){
  const bytes=fs.readFileSync(new URL(spec.url,import.meta.url));
  if(sha(bytes)!==spec.sha256)fail('source input '+spec.path);
  inputs[key]=bytes;inventory[spec.path]=spec.sha256;
 }
 for(const [path,spec] of Object.entries(moduleInputs)){
  const bytes=fs.readFileSync(new URL(spec.url,import.meta.url));
  if(sha(bytes)!==spec.sha256)fail('source module '+path);
  inventory[path]=spec.sha256;
 }
 return {inputs,inventory};
}

export function issueWorkerHigherIntegrationContextV1(){
 if(arguments.length!==0)fail('integration context issuance arguments');
 const source=readWorkerHigherSourceInputsV1();
 const proof=workerHigherSourceReplay({optIn:true,...source.inputs});
 const context=Object.freeze(Object.create(null));
 issuedContexts.set(context,{source,proof:structuredClone(proof),consumed:false});
 return Object.freeze({context,proof:structuredClone(proof),sourceInventory:Object.freeze({...source.inventory})});
}

function historicalReplayIsPredecessor(ledger){
 if(!ledger||ledger.version!=='native19-worker-definition-replay-v1'||ledger.accepted!==13||ledger.refused!==4||
    ledger.sourceReplay?.accepted!==13||ledger.sourceReplay?.refused!==4||!Array.isArray(ledger.entries)||ledger.entries.length!==17)fail('historical worker replay shape');
 const accepted=ledger.entries.filter(row=>row?.status==='accepted').length;
 const refused=ledger.entries.filter(row=>row?.status==='refused').length;
 if(accepted!==13||refused!==4||accepted+refused!==ledger.entries.length||ledger.registration?.ruleId!=='worker-line-2'||ledger.registration?.status!=='refused'||typeof ledger.registration.identity!=='string')fail('historical worker replay counts or registration');
 return {version:ledger.version,accepted:ledger.accepted,refused:ledger.refused,entries:ledger.entries.length,rawFacts:'pre-successor'};
}

function verifyProof(proof,canonicalJSON){
 if(typeof canonicalJSON!=='function'||proof?.version!=='worker-higher-source-replay-v1'||proof.status!=='sourceClosed'||proof.sourceClosed!==true||proof.native!==false||proof.installable!==false||proof.executable!==false||!Array.isArray(proof.accepted)||proof.accepted.length!==roots.length)fail('proof status or cardinality');
 const expectedPins={contractSHA256:rawInputs.contractRaw.sha256,catalogSHA256:rawInputs.catalogRaw.sha256,releaseSHA256:rawInputs.releaseRaw.sha256,graphSHA256:rawInputs.graphRaw.sha256,compilerSHA256:rawInputs.compilerRaw.sha256,regionsSHA256:rawInputs.regionsRaw.sha256,captureSourceSHA256:rawInputs.captureSourceRaw.sha256};
 for(const [key,value]of Object.entries(expectedPins))if(proof.inputLedger?.[key]!==value)fail('proof input '+key);
 for(const [index,row]of proof.accepted.entries()){
  if(row?.ruleId!=='worker-line-5'||row.kind!=='routine'||row.identity!==roots[index]||row.status!=='sourceClosed'||row.sourceClosed!==true||row.native!==false||row.installable!==false||row.executable!==false)fail('candidate identity/status '+index);
  if(typeof row.replacementDefinition!=='string'||sha(row.replacementDefinition)!==row.definitionSHA256||typeof row.body!=='string'||sha(row.body)!==row.sourceSHA256||!row.replacementDefinition.includes(row.body))fail('candidate source/body '+row.identity);
  if(!row.frame||Object.keys(row.frame).length!==sourceFields.length||sourceFields.some(field=>!Object.hasOwn(row.frame,field)))fail('candidate typed frame '+row.identity);
  for(const field of ['owner','acl','language','volatility','arguments','result'])if(typeof row.frame[field]!=='string')fail('candidate typed frame field '+field);
  if(typeof row.frame.strict!=='boolean'||typeof row.frame.security_definer!=='boolean'||typeof row.frame.leakproof!=='boolean'||!Array.isArray(row.frame.config)||typeof row.frame.cost!=='number'||typeof row.frame.rows!=='number')fail('candidate typed frame values '+row.identity);
 }
 if(proof.registration?.ruleId!=='worker-line-2'||proof.registration.kind!=='worker_registration'||proof.registration.status!=='refused'||proof.registration.sourceClosed!==false||Object.hasOwn(proof.registration,'identity')||!proof.registration.reason)fail('registration refusal');
 return expectedPins;
}

export function applyWorkerHigherSuccessorV1(input){
 const fields=['facts','proof','historicalLedger','canonicalJSON','context'];
 if(arguments.length!==1||!input||Object.keys(input).length!==fields.length||fields.some(field=>!Object.hasOwn(input,field)))fail('input shape');
 const {facts,proof,historicalLedger,canonicalJSON,context}=input;
 const phase=issuedContexts.get(context);
 if(!phase||phase.consumed||!Array.isArray(facts)||appliedFactArrays.has(facts))fail('issued single-use integration context');
 if(!isDeepStrictEqual(proof,phase.proof))fail('authoritative source proof equality');
 const historicalSummary=historicalReplayIsPredecessor(historicalLedger);
 const inputPins=verifyProof(proof,canonicalJSON);
 if(!isDeepStrictEqual(phase.source.inventory,{...Object.fromEntries(Object.values(rawInputs).map(spec=>[spec.path,spec.sha256])),...Object.fromEntries(Object.entries(moduleInputs).map(([path,spec])=>[path,spec.sha256]))}))fail('fixed source inventory');
 const catalogRaw=phase.source.inputs.catalogRaw;
 if(sha(catalogRaw)!==inputPins.catalogSHA256)fail('fixed catalog source bytes');
 if(proof.registration.ruleId!==historicalLedger.registration.ruleId||proof.registration.kind!==historicalLedger.registration.kind||proof.registration.status!==historicalLedger.registration.status)fail('registration refusal continuity');
 const catalog=JSON.parse(Buffer.from(catalogRaw).toString('utf8'));
 const targetRows=new Map;
 for(const [position,row] of facts.entries()){
  if(typeof row?.identity!=='string')continue;
  let identity;try{identity=JSON.parse(row.identity);}catch{continue;}
  if(!Array.isArray(identity)||identity.length!==2||identity[0]!=='worker-line-5'||!roots.includes(identity[1]))continue;
  const signature=identity[1];
  if(row.identity!==JSON.stringify(['worker-line-5',signature]))fail('fact identity ambiguity');
  const rows=targetRows.get(signature)??[];
  rows.push({position,row});targetRows.set(signature,rows);
 }
 const replacements=[];
 for(const [index,candidate] of proof.accepted.entries()){
  const currentRows=targetRows.get(candidate.identity);
  if(!currentRows||currentRows.length!==1||currentRows[0].row.kind!=='routine')fail('fact identity uniqueness or kind '+candidate.identity);
  const {position,row:current}=currentRows[0];
  if(!current||!current.fact||Object.keys(current.fact).length!==factFields.length||factFields.some(field=>!Object.hasOwn(current.fact,field)))fail('fact cardinality or raw shape '+candidate.identity);
  if(factFields.some(field=>typeof current.fact[field]!=='string'))fail('fact raw types '+candidate.identity);
  const matches=catalog.functions.filter(row=>row?.identity===candidate.identity);
  if(matches.length!==1)fail('catalog identity uniqueness '+candidate.identity);
  const source=matches[0];
  const pieces=source.definition.split('$function$');
  if(candidate.replacementDefinition!==source.definition||candidate.definitionSHA256!==sha(source.definition)||pieces.length!==3||candidate.body!==pieces[1])fail('source definition equality '+candidate.identity);
  if(candidate.frame.owner!==source.owner||candidate.frame.acl!==source.acl||sourceFields.some(field=>!isDeepStrictEqual(candidate.frame[field],source[field])))fail('source typed frame equality '+candidate.identity);
  const replacement={acl:source.acl,definition:source.definition,owner:source.owner};
  const replacementSHA256=sha(canonicalJSON(replacement));
  if(candidate.replacementFactSHA256!==replacementSHA256||candidate.replacementFactSHA256!==sha(JSON.stringify(replacement)))fail('rawFact equality '+candidate.identity);
  if(current.fact.owner!==source.owner||current.fact.acl!==source.acl)fail('captured fact owner/ACL '+candidate.identity);
  const beforeRawFactSHA256=sha(canonicalJSON(current.fact));
  if(beforeRawFactSHA256!==replacementSHA256)fail('source-authorized predecessor fact '+candidate.identity);
  const historicalEntries=historicalLedger.entries.filter(entry=>entry?.identity===candidate.identity&&entry.ruleId==='worker-line-5');
  if(historicalEntries.length!==1||historicalEntries[0].status!=='refused'||historicalEntries[0].rawFactSHA256!==beforeRawFactSHA256)fail('historical pre-successor rawFact '+candidate.identity);
  replacements.push({index,position,candidate,current,replacement,replacementSHA256,beforeRawFactSHA256});
 }
 if(replacements.length!==roots.length||targetRows.size!==roots.length)fail('fact roster incomplete');
 const replacementByPosition=new Map(replacements.map(row=>[row.position,row]));
 const projected=facts.map((row,position)=>{
  const replacement=replacementByPosition.get(position);
  return replacement?{...row,fact:replacement.replacement}:row;
 });
 const currentSuccessor={
  version:'worker-higher-current-successor-v1',status:'SOURCE-CLOSED-COMPONENT-ONLY',sourceClosed:true,native:false,installable:false,executable:false,
  historicalReplay:historicalSummary,
  inputLedger:inputPins,
  sourceInventory:phase.source.inventory,
  accepted:replacements.map(({candidate,replacementSHA256,beforeRawFactSHA256})=>({
   ruleId:candidate.ruleId,kind:candidate.kind,identity:candidate.identity,status:candidate.status,sourceClosed:true,native:false,installable:false,executable:false,
   definitionSHA256:candidate.definitionSHA256,sourceSHA256:candidate.sourceSHA256,originalDefinitionSHA256:candidate.originalDefinitionSHA256,
   originalSourceSHA256:candidate.originalSourceSHA256,origin:candidate.origin,beforeRawFactSHA256,replacementFactSHA256:replacementSHA256,
  })),
  registration:{...historicalLedger.registration},
  higherRegistrationRefusal:{...proof.registration},
 };
 phase.consumed=true;
 appliedFactArrays.add(facts);
 appliedFactArrays.add(projected);
 return {facts:projected,historicalLedger,currentSuccessor};
}
