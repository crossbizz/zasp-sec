import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {assertOrderedCurrentMissingReferenceNativePacketV1} from './ordered-current-missing-reference-native-packet.mjs';
import {assertOrderedCurrentPrivateSuccessorPacketV1,checkOrderedCurrentPrivateSuccessorReferenceV1} from './ordered-current-private-successor-reference.mjs';

const fail=message=>{throw Error(`ordered-current capture intake ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
const fixed={
 direct:new URL('./ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json',import.meta.url),
 missingPacket:new URL('./ordered-current-capture-intake-v1-artifacts/missing-reference-native-packet.json',import.meta.url),
 missingCapture:new URL('./ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json',import.meta.url),
 privatePacket:new URL('./ordered-current-capture-intake-v1-artifacts/private-successor-packet.json',import.meta.url),
 privateCapture:new URL('./ordered-current-capture-intake-v1-artifacts/private-successor-reference.json',import.meta.url),
 manifest:new URL('./ordered-current-capture-intake-v1-artifacts/native-composition-manifest.json',import.meta.url),
};
const pins=Object.freeze({
 direct:'c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab',
 missingPacket:'23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287',
 missingCapture:'76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39',
 privatePacket:'6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0',
 privateCapture:'b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80',
 manifest:'742061cb79130a9e866daa63babe914cf1052e4958ba40c798b8e030c1dd7899',
 compositionLog:'2a875ddd77d36971fa5f66921d45b69ae3f8f9165be95c070fc159327948100a',
});
const freeze=value=>{if(value&&typeof value==='object'&&!ArrayBuffer.isView(value)&&!Object.isFrozen(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const closed=(value,keys,description)=>{if(!value||typeof value!=='object'||Array.isArray(value)||!same(Object.keys(value).sort(),[...keys].sort()))fail(description);};
const plain=value=>value&&typeof value==='object'&&!Array.isArray(value);

export function parseOrderedCurrentCaptureJSONV1(raw,limits={}){
 if(!Buffer.isBuffer(raw))fail('JSON bytes');
 const maxBytes=limits.maxBytes??16777216,maxDepth=limits.maxDepth??64,maxNodes=limits.maxNodes??1000000,maxContainerItems=limits.maxContainerItems??1000000;
 if(!Number.isSafeInteger(maxBytes)||!Number.isSafeInteger(maxDepth)||!Number.isSafeInteger(maxNodes)||!Number.isSafeInteger(maxContainerItems)||raw.length>maxBytes)fail('JSON byte bound');
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(raw);}catch{fail('JSON UTF-8');}
 let offset=0,nodes=0;
 const whitespace=()=>{while(/[ \r\n\t]/.test(text[offset]??''))offset++;};
 const string=()=>{const start=offset++;let escaped=false;for(;offset<text.length;offset++){const character=text[offset];if(character==='"'&&!escaped){offset++;try{return JSON.parse(text.slice(start,offset));}catch{fail('JSON string');}}if(character==='\\'&&!escaped)escaped=true;else escaped=false;}fail('JSON string');};
 const value=(depth=0)=>{
  if(depth>maxDepth||++nodes>maxNodes)fail('JSON bounded structure');whitespace();
  if(text[offset]==='"')return string();
  if(text[offset]==='{'){
   offset++;const object={},seen=new Set();whitespace();if(text[offset]==='}'){offset++;return object;}
   while(true){if(seen.size>=maxContainerItems)fail('JSON bounded container');whitespace();if(text[offset]!=='"')fail('JSON key');const key=string();if(seen.has(key))fail('JSON duplicate key');seen.add(key);whitespace();if(text[offset++]!==':')fail('JSON colon');Object.defineProperty(object,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});whitespace();const end=text[offset++];if(end==='}')return object;if(end!==',')fail('JSON object');}
  }
  if(text[offset]==='['){offset++;const array=[];whitespace();if(text[offset]===']'){offset++;return array;}while(true){if(array.length>=maxContainerItems)fail('JSON bounded container');array.push(value(depth+1));whitespace();const end=text[offset++];if(end===']')return array;if(end!==',')fail('JSON array');}}
  const token=text.slice(offset).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];
  if(!token)fail('JSON value');offset+=token.length;const parsed=JSON.parse(token);if(typeof parsed==='number'&&(!Number.isFinite(parsed)||Number.isInteger(parsed)&&!Number.isSafeInteger(parsed)))fail('JSON unsafe integer');return parsed;
 };
 const result=value();whitespace();if(offset!==text.length)fail('JSON trailing bytes');return result;
}

function exactInputs(input){
 closed(input,['directRaw','missingCaptureRaw','missingPacketRaw','privateCaptureRaw','privatePacketRaw'],'artifact input envelope');
 for(const raw of Object.values(input))if(!Buffer.isBuffer(raw))fail('artifact input bytes');
 for(const [name,pin] of Object.entries(pins))if(name!=='manifest'&&name!=='compositionLog'&&sha(input[`${name}Raw`])!==pin)fail(`${name} authority`);
}
function validateDirect(raw){
 const packet=parseOrderedCurrentCaptureJSONV1(raw,{maxBytes:16777216});
 closed(packet,['caseProgram','counts','directFrame','format','installable','limits','originalUniverse','sourceAuthority','sourcePins','status','transform','transformCorrespondence'],'direct envelope');
 if(packet.format!=='ordered-current-direct-frame-acceptance-v1'||packet.status!=='NATIVE-UNVERIFIED'||packet.installable!==false||packet.sourceAuthority!=='accepted-recovery80-source-2ca-local-parity-only'||!same(packet.counts,{directRules:50,transformRules:13,totalRules:63,directRows:1220,transformRows:380,totalRows:1600}))fail('direct controls');
 if(!Array.isArray(packet.directFrame?.expectedRows)||packet.directFrame.expectedRows.length!==1220||!Array.isArray(packet.transform?.expectedRows)||packet.transform.expectedRows.length!==380||!Array.isArray(packet.directFrame.descriptorRules)||packet.directFrame.descriptorRules.length!==50||!Array.isArray(packet.transform.rules)||packet.transform.rules.length!==13)fail('direct rows');
 const rules=new Map([...packet.directFrame.descriptorRules,...packet.transform.rules].map(rule=>[rule.id,rule]));
 const counts=new Map(),facts=[];
 for(const [index,row] of [...packet.directFrame.expectedRows,...packet.transform.expectedRows].entries()){
  closed(row,['fact','identity','kind','source'],`direct row ${index}`);
  if(typeof row.kind!=='string'||typeof row.identity!=='string'||!plain(row.fact)||!plain(row.source))fail(`direct row ${index} shape`);
  let identity;try{identity=parseOrderedCurrentCaptureJSONV1(Buffer.from(row.identity),{maxBytes:65536,maxNodes:32});}catch{fail(`direct row ${index} identity`);}
  if(!Array.isArray(identity)||identity.length!==2||typeof identity[0]!=='string'||typeof identity[1]!=='string'||JSON.stringify(identity)!==row.identity)fail(`direct row ${index} identity`);
  const rule=rules.get(row.source.ruleId);
  if(!rule||row.kind!==rule.kind||identity[0]!==rule.id||!same(Object.keys(row.fact).sort(),[...rule.fields].sort()))fail(`direct row ${index} rule`);
  for(const field of rule.fields)if(!typed(row.fact[field],rule.fieldTypes[field]))fail(`direct row ${index} type`);
  const source=row.source,transform=Array.isArray(rule.captureFields),base=transform?['captureFrame','captureIdentity','definitionSHA256','executionFrameId','factIdentityDisposition','keyFrame','ruleId','siteSHA256','sourceIdentity','sourceSHA256']:['captureFrame','captureIdentity','definitionSHA256','descriptorIdentity','executionFrameId','keyFrame','ruleId','siteSHA256','sourceIdentity','sourceSHA256'],sourceKeys=transform?base:source.fieldWitnesses?[...base,'fieldWitnesses']:source.relationshipProof?[...base,'relationshipProof']:base;
  if(!plain(source)||!same(Object.keys(source).sort(),sourceKeys.sort())||typeof source.captureIdentity!=='string'||source.ruleId!==rule.id||source.sourceIdentity!==rule.sourceSite.sourceIdentity||source.sourceSHA256!==rule.sourceSite.sourceSHA256||source.definitionSHA256!==rule.sourceSite.definitionSHA256||source.siteSHA256!==rule.sourceSite.siteSHA256||source.executionFrameId!==rule.executionFrameId||source.captureFrame!==(transform?'sourceDiscoveryPublic':'original-source-frame')||typeof source.keyFrame!=='string'||!source.keyFrame||transform&&source.factIdentityDisposition!==(rule.fields.includes('identity')?'captured-original-source-frame-field':'not-projected')||!transform&&(source.keyFrame!==rule.keyFrame||typeof source.descriptorIdentity!=='string'||identity[1]!==source.descriptorIdentity))fail(`direct row ${index} source`);
  counts.set(rule.id,(counts.get(rule.id)??0)+1);facts.push({kind:row.kind,identity:JSON.stringify([rule.id,source.captureIdentity]),fact:row.fact});
 }
 for(const rule of rules.values())if(counts.get(rule.id)!==rule.expectedRows)fail(`direct rule cardinality ${rule.id}`);
 return facts;
}
function typed(value,type){
 if(value===null)return true;
 if(type==='string')return typeof value==='string';
 if(type==='boolean')return typeof value==='boolean';
 if(type==='number')return typeof value==='number'&&Number.isFinite(value);
 if(type==='integer')return Number.isSafeInteger(value);
 if(type==='text?')return value===null||typeof value==='string';
 if(type==='array'||type==='acl')return Array.isArray(value)||type==='acl'&&typeof value==='string';
 return false;
}
function expectedControls(packet){
 return packet.witnessProgram.families.flatMap(family=>[
  ...family.baseline.map(item=>({id:item.id,family:family.id,outcome:item.expected,expected:item.expected})),
  ...family.probes.map(item=>({id:item.id,family:family.id,outcome:item.stages[2].expected.outcome,expected:item.stages[2].expected})),
 ]);
}
function nativeJSONArrayBytes(raw,ruleId,field){
 const text=raw.toString('utf8'),needle=`"ruleId":${JSON.stringify(ruleId)}`,section=text.indexOf(field==='rows'?'"observations"':'"canonicalIdentities"'),from=text.indexOf(needle,section);
 if(from<0)fail('missing native digest rule');const arrayAt=text.indexOf(`"${field}":`,from),start=arrayAt+field.length+3;
 if(arrayAt<0||text[start]!=='[')fail('missing native digest field');
 let depth=0,quoted=false,escaped=false;
 for(let index=start;index<text.length;index++){
  const character=text[index];if(quoted){if(character==='\\'&&!escaped)escaped=true;else{if(character==='"'&&!escaped)quoted=false;escaped=false;}continue;}
  if(character==='"'){quoted=true;continue;}if(character==='[')depth++;if(character===']'&&!--depth)return Buffer.from(text.slice(start,index+1));
 }
 fail('missing native digest array');
}
function validateMissing(packetRaw,captureRaw){
 const packet=parseOrderedCurrentCaptureJSONV1(packetRaw,{maxBytes:16777216});assertOrderedCurrentMissingReferenceNativePacketV1(packet);
 const capture=parseOrderedCurrentCaptureJSONV1(captureRaw,{maxBytes:packet.limits.maxBytes});
 closed(capture,['canonicalIdentities','controls','format','installable','observations','provenance','status'],'missing capture envelope');
 if(capture.format!=='ordered-current-missing-reference-capture-v1'||capture.status!=='NATIVE-OBSERVED-NOT-ACCEPTED'||capture.installable!==false||!same(capture.provenance,{packetSHA256:pins.missingPacket,contractSHA256:packet.contract.contractSHA256,sourceAuthority:packet.sourceAuthority}))fail('missing capture provenance');
 if(!Array.isArray(capture.observations)||capture.observations.length!==12||!Array.isArray(capture.canonicalIdentities)||capture.canonicalIdentities.length!==12||!Array.isArray(capture.controls)||capture.controls.length!==18)fail('missing capture counts');
 const identities=new Map(capture.canonicalIdentities.map(item=>{closed(item,['identities','ruleId'],'missing canonical envelope');return [item.ruleId,item.identities];}));
 if(identities.size!==12)fail('missing canonical duplicate rule');
 const rules=new Map(packet.contract.rules.map(rule=>[rule.id,rule]));const facts=[];
 for(const observation of capture.observations){
  closed(observation,['canonicalKeysSHA256','projectionRowsSHA256','rows','ruleId'],'missing observation envelope');
  const rule=rules.get(observation.ruleId),canonical=identities.get(observation.ruleId);
  if(!rule||!Array.isArray(observation.rows)||observation.rows.length!==rule.exactRows||!Array.isArray(canonical)||canonical.length!==rule.exactRows)fail('missing observation rows');
  const seen=new Set();
  for(const row of observation.rows){
   closed(row,['fields','identity'],'missing observation row');
   if(typeof row.identity!=='string'||seen.has(row.identity)||!same(Object.keys(row.fields).sort(),[...rule.fields].sort()))fail('missing observation identity');seen.add(row.identity);
   for(const field of rule.fields)if(!typed(row.fields[field],rule.fieldTypes[field]))fail('missing observation type');
   facts.push({kind:rule.kind,identity:JSON.stringify([rule.id,row.identity]),fact:row.fields});
  }
  if(!same(canonical,[...seen].sort())||observation.projectionRowsSHA256!==sha(nativeJSONArrayBytes(captureRaw,observation.ruleId,'rows'))||observation.canonicalKeysSHA256!==sha(nativeJSONArrayBytes(captureRaw,observation.ruleId,'identities'))||!/^([a-f0-9]{64})$/.test(observation.projectionRowsSHA256)||!/^([a-f0-9]{64})$/.test(observation.canonicalKeysSHA256))fail('missing canonical identities');
 }
 if(facts.length!==204||new Set(facts.map(row=>row.identity)).size!==204)fail('missing fact cardinality');
 const controls=new Map(expectedControls(packet).map(item=>[item.id,item]));
 if(new Set(capture.controls.map(item=>item.id)).size!==18)fail('missing controls duplicate');
 for(const control of capture.controls){
  const expected=controls.get(control.id);if(!expected||control.family!==expected.family||control.outcome!==expected.outcome)fail('missing controls');
  if(control.outcome==='error'){closed(control,['family','id','outcome','sqlState'],'missing error control');if(control.sqlState!==expected.expected.sqlState)fail('missing error semantics');continue;}
  closed(control,['evidence','family','id','outcome'],'missing value control');
  if(!Array.isArray(control.evidence))fail('missing value evidence');
  if(control.outcome==='capture-boolean-or-null'&&(control.evidence.length!==1||!control.evidence.every(value=>value===null||typeof value==='boolean')))fail('missing boolean control');
  if(control.outcome==='capture-jsonb-rows'&&(!control.evidence.length||!control.evidence.every(plain)))fail('missing JSON control');
  if(control.outcome==='one-json-row'&&(control.evidence.length!==1||!plain(control.evidence[0])))fail('missing JSON control');
  if(control.outcome==='one-null-row'&&(control.evidence.length!==1||control.evidence[0]!==null))fail('missing null control');
  if(control.outcome==='one-non-null-row'&&(control.evidence.length!==1||control.evidence[0]===null))fail('missing non-null control');
 }
 if(controls.size!==18)fail('missing control program');
 return facts;
}
export function compareOrderedCurrentCaptureFactSetsV1(namedSets){
 const seen=new Map(),equal=[];
 for(const [name,rows] of Object.entries(namedSets))for(const row of rows){
  closed(row,['fact','identity','kind'],'comparison fact');const key=`${row.kind}\u0000${row.identity}`,bytes=canonicalOrderedJSON(row.fact),prior=seen.get(key);
  if(prior){if(prior.bytes!==bytes)fail(`conflicting duplicate ${key}`);equal.push({key,sets:[prior.name,name]});}else seen.set(key,{name,bytes});
 }
 return equal;
}
function validated(input){
 exactInputs(input);
 const directFacts=validateDirect(input.directRaw);
 const missingFacts=validateMissing(input.missingPacketRaw,input.missingCaptureRaw);
 const privatePacket=parseOrderedCurrentCaptureJSONV1(input.privatePacketRaw);assertOrderedCurrentPrivateSuccessorPacketV1(privatePacket);
 const privateChecked=checkOrderedCurrentPrivateSuccessorReferenceV1(input.privateCaptureRaw,privatePacket);
 if(privateChecked.validatedRoutineCount!==22||privateChecked.nonroutineCount!==35||privateChecked.facts.length!==35||privateChecked.installable!==false)fail('private capture result');
 const privateFacts=privateChecked.facts.map(row=>({kind:row.kind,identity:row.identity,fact:row.fact}));
 return {directFacts,missingFacts,privateFacts,privateChecked,equalOverlaps:compareOrderedCurrentCaptureFactSetsV1({direct:directFacts,missing:missingFacts,private:privateFacts})};
}

export function validateOrderedCurrentCaptureArtifactsV1(input){
 const value=validated(input);
 return freeze({directFacts:value.directFacts,missingFacts:value.missingFacts,privateFacts:value.privateFacts,validatedRoutineRows:value.privateChecked.validatedRoutineCount,equalOverlaps:value.equalOverlaps});
}

function readFixed(name){try{return fs.readFileSync(fixed[name]);}catch(error){fail(`${name} read (${error.message})`);}}
function preserveOwnerOnly(directory,name,raw){
 const output=path.join(directory,name);
 try{fs.writeFileSync(output,raw,{flag:'wx',mode:0o600});}catch(error){
  if(error?.code!=='EEXIST')fail(`capture materializer write (${error.message})`);
  let existing;try{existing=fs.readFileSync(output);}catch(readError){fail(`capture materializer read (${readError.message})`);}
  if(!existing.equals(raw))fail('capture materializer refuses mismatch');
 }
 try{fs.chmodSync(output,0o600);const stat=fs.statSync(output);if(stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600)fail('capture materializer owner-only mode');}catch(error){if(String(error.message).includes('ordered-current capture intake'))throw error;fail(`capture materializer mode (${error.message})`);}
 return freeze({path:output,sha256:sha(raw),bytes:raw.length,mode:'0600',ownerOnly:true});
}
export function materializeOrderedCurrentCaptureEvidenceV1(directory){
 if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory)fail('capture materializer directory');
 const input={directRaw:readFixed('direct'),missingPacketRaw:readFixed('missingPacket'),missingCaptureRaw:readFixed('missingCapture'),privatePacketRaw:readFixed('privatePacket'),privateCaptureRaw:readFixed('privateCapture')};
 exactInputs(input);
 const missingPacket=parseOrderedCurrentCaptureJSONV1(input.missingPacketRaw,{maxBytes:16777216});
 if(missingPacket.output?.mode!=='0600')fail('missing capture publication mode');
 const privateCapture=parseOrderedCurrentCaptureJSONV1(input.privateCaptureRaw,{maxBytes:16777216});
 if(privateCapture.publication?.mode!=='0600')fail('private capture publication mode');
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 return freeze({missingCapture:preserveOwnerOnly(directory,'ordered-current-missing-reference-capture-v1.json',input.missingCaptureRaw),privateCapture:preserveOwnerOnly(directory,'ordered-current-private-successor-reference-v1.json',input.privateCaptureRaw)});
}
function readManifest(){
 const raw=readFixed('manifest');if(sha(raw)!==pins.manifest)fail('manifest authority');
 const manifest=parseOrderedCurrentCaptureJSONV1(raw);
 closed(manifest,['captures','compositionLogSHA256','controls','counts','format','installable','packets','provenance','sourceAuthority','status'],'manifest envelope');
 if(manifest.format!=='ordered-current-native-composition-manifest-v1'||manifest.status!=='LOCAL-NATIVE-VERIFIED-UNBOUND'||manifest.installable!==false||manifest.compositionLogSHA256!==pins.compositionLog||!same(manifest.packets,{directSHA256:pins.direct,missingSHA256:pins.missingPacket,privateSHA256:pins.privatePacket})||!same(manifest.captures,{missingSHA256:pins.missingCapture,privateSHA256:pins.privateCapture})||!same(manifest.counts,{directFacts:1600,missingRules:12,missingFacts:204,missingControls:18,privateRows:57,privateRoutineRows:22,privateFacts:35}))fail('manifest controls');
 return manifest;
}
export function assertOrderedCurrentCaptureBundleV1(value){
 closed(value,['captureStatus','directFacts','installable','missingFacts','privateFacts','provenance'],'bundle envelope');
 if(value.installable!==false||value.captureStatus!=='LOCAL-NATIVE-VERIFIED-UNBOUND'||!Array.isArray(value.directFacts)||value.directFacts.length!==1600||!Array.isArray(value.missingFacts)||value.missingFacts.length!==204||!Array.isArray(value.privateFacts)||value.privateFacts.length!==35||value.provenance?.private?.validatedRoutineRows!==22)fail('bundle controls');
 for(const [set,rows] of Object.entries({direct:value.directFacts,missing:value.missingFacts,private:value.privateFacts})){
  const identities=new Set();for(const row of rows){closed(row,['fact','identity','kind'],`bundle ${set} row`);if(typeof row.kind!=='string'||typeof row.identity!=='string'||!plain(row.fact)||identities.has(`${row.kind}\u0000${row.identity}`))fail(`bundle ${set} row`);identities.add(`${row.kind}\u0000${row.identity}`);}
 }
 for(const row of value.missingFacts){let identity;try{identity=parseOrderedCurrentCaptureJSONV1(Buffer.from(row.identity),{maxBytes:65536,maxNodes:32});}catch{fail('bundle missing identity');}if(!Array.isArray(identity)||identity.length!==2||identity.some(item=>typeof item!=='string')||JSON.stringify(identity)!==row.identity)fail('bundle missing identity');}
 const admitted=validated({directRaw:readFixed('direct'),missingPacketRaw:readFixed('missingPacket'),missingCaptureRaw:readFixed('missingCapture'),privatePacketRaw:readFixed('privatePacket'),privateCaptureRaw:readFixed('privateCapture')});
 for(const [set,rows] of Object.entries({direct:value.directFacts,missing:value.missingFacts,private:value.privateFacts})){
  const expected=new Map(admitted[`${set}Facts`].map(row=>[`${row.kind}\u0000${row.identity}`,canonicalOrderedJSON(row.fact)]));
  for(const row of rows)if(expected.get(`${row.kind}\u0000${row.identity}`)!==canonicalOrderedJSON(row.fact))fail(`bundle ${set} schema`);
 }
 if(!Object.isFrozen(value)||!Object.isFrozen(value.directFacts)||!Object.isFrozen(value.missingFacts)||!Object.isFrozen(value.privateFacts)||!Object.isFrozen(value.provenance))fail('bundle freeze');
 return true;
}
export function admitOrderedCurrentCaptureBundleV1(...inputs){
 if(inputs.length)fail('caller input refused');
 const manifest=readManifest();
 const value=validated({directRaw:readFixed('direct'),missingPacketRaw:readFixed('missingPacket'),missingCaptureRaw:readFixed('missingCapture'),privatePacketRaw:readFixed('privatePacket'),privateCaptureRaw:readFixed('privateCapture')});
 const bundle=freeze({directFacts:value.directFacts,missingFacts:value.missingFacts,privateFacts:value.privateFacts,provenance:{manifestSHA256:pins.manifest,compositionLogSHA256:manifest.compositionLogSHA256,sourceAuthority:manifest.sourceAuthority,packets:manifest.packets,captures:manifest.captures,direct:{facts:1600},missing:{facts:204,controls:18,identityEncoding:'JSON.stringify([ruleId,capturedIdentity])'},private:{facts:35,validatedRoutineRows:value.privateChecked.validatedRoutineCount,publication:'captured owner-only mode is enforced by materializeOrderedCurrentCaptureEvidenceV1'},equalOverlaps:value.equalOverlaps},installable:false,captureStatus:'LOCAL-NATIVE-VERIFIED-UNBOUND'});
 assertOrderedCurrentCaptureBundleV1(bundle);return bundle;
}
