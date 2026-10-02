// Fixed-source packet and deliberately unbound intake for the current private57 capture.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {canonicalOrderedJSON,normalizeOrderedFacts} from './build-ordered-current-integrity.mjs';
import {buildOrderedCurrentPrivateHistoricalPacketV1} from './ordered-current-private-historical-v1.mjs';

const fail=message=>{throw Error(`ordered-current private successor ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(a,b)=>canonicalOrderedJSON(a)===canonicalOrderedJSON(b);
const sourcePins=Object.freeze({
 compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
 compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
 compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
 sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
 catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',
});
const freeze=value=>{if(value&&typeof value==='object'&&!ArrayBuffer.isView(value)&&!Object.isFrozen(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};

// Historical packet authority stays bound to the complete old helper snapshot.
// The current precision private8 compiler is a separate builder dependency.
function staticPacket(){return buildOrderedCurrentPrivateHistoricalPacketV1();}

// Official artifact-generation seam. The packet remains entirely derived from
// the pinned helper sources and fixed SQL assembly; callers cannot supply data.
export function buildOrderedCurrentPrivateSuccessorPacketV1(){return staticPacket();}



function strictJSON(raw,limits={}){
 if(!Buffer.isBuffer(raw))fail('reference JSON bytes');
 const maxBytes=limits.maxBytes??67108864,maxDepth=limits.maxDepth??32,maxNodes=limits.maxNodes??1000000,maxContainerItems=limits.maxContainerItems??1000000;
 if(!Number.isSafeInteger(maxBytes)||!Number.isSafeInteger(maxDepth)||!Number.isSafeInteger(maxNodes)||!Number.isSafeInteger(maxContainerItems)||raw.length>maxBytes)fail('reference JSON byte bound');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let offset=0;
 let nodes=0;
 const whitespace=()=>{while(/[ \r\n\t]/.test(text[offset]??'x'))offset++;};
 const string=()=>{const start=offset++;let escaped=false;for(;offset<text.length;offset++){const c=text[offset];if(c==='"'&&!escaped){offset++;return JSON.parse(text.slice(start,offset));}if(c==='\\'&&!escaped)escaped=true;else escaped=false;}fail('reference JSON string');};
 const value=(depth=0)=>{
  if(depth>maxDepth||++nodes>maxNodes)fail('reference JSON bounded structure');whitespace();
  if(text[offset]==='"')return string();
  if(text[offset]==='{'){offset++;const object={},seen=new Set();whitespace();if(text[offset]==='}'){offset++;return object;}while(true){if(seen.size>=maxContainerItems)fail('reference JSON bounded container');whitespace();if(text[offset]!=='"')fail('reference JSON key');const key=string();if(seen.has(key))fail('reference JSON duplicate key');seen.add(key);whitespace();if(text[offset++]!==':')fail('reference JSON colon');Object.defineProperty(object,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});whitespace();const end=text[offset++];if(end==='}')return object;if(end!==',')fail('reference JSON object');}}
  if(text[offset]==='['){offset++;const array=[];whitespace();if(text[offset]===']'){offset++;return array;}while(true){if(array.length>=maxContainerItems)fail('reference JSON bounded container');array.push(value(depth+1));whitespace();const end=text[offset++];if(end===']')return array;if(end!==',')fail('reference JSON array');}}
  const token=text.slice(offset).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];if(!token)fail('reference JSON value');offset+=token.length;const parsed=JSON.parse(token);if(typeof parsed==='number'&&Number.isInteger(parsed)&&!Number.isSafeInteger(parsed))fail('reference JSON unsafe integer');return parsed;
 };
 const decoded=value();whitespace();if(offset!==text.length)fail('reference JSON trailing bytes');return decoded;
}
export function parseOrderedCurrentPrivateSuccessorReferenceJSONV1(raw,limits){return strictJSON(raw,limits);}
function closed(value,keys,description){if(!value||typeof value!=='object'||Array.isArray(value)||!same(Object.keys(value).sort(),keys.slice().sort()))fail(`reference ${description}`);}
function typed(value,type){
 if(value===null)return true;
 if(type==='string')return typeof value==='string';
 if(type==='boolean')return typeof value==='boolean';
 if(type==='number')return typeof value==='number'&&Number.isFinite(value);
 if(type==='integer')return Number.isSafeInteger(value);
 if(type==='array'||type==='acl')return Array.isArray(value)||type==='acl'&&typeof value==='string';
 return false;
}

export function buildOrderedCurrentPrivateSuccessorCaptureV1(inputs){
 if(!inputs||!Buffer.isBuffer(inputs.compilerArtifactRaw)||!Buffer.isBuffer(inputs.sourceContractRaw)||!Buffer.isBuffer(inputs.catalogRaw)||sha(inputs.compilerArtifactRaw)!==sourcePins.compilerArtifactSHA256||sha(inputs.sourceContractRaw)!==sourcePins.sourceContractSHA256||sha(inputs.catalogRaw)!==sourcePins.catalogSHA256)fail('source authority');
 let artifact,contract,catalog;try{artifact=strictJSON(inputs.compilerArtifactRaw);contract=strictJSON(inputs.sourceContractRaw);catalog=strictJSON(inputs.catalogRaw);}catch{fail('source authority JSON');}
 if(artifact.format!=='zasp-worker-compiled-release-v1'||artifact.checksum!==sourcePins.compilerChecksum||artifact.source_sha256!==sourcePins.compiledSourceSHA256||typeof artifact.source!=='string'||sha(artifact.source)!==sourcePins.compiledSourceSHA256||contract.format!=='ordered-current-effective-contract-v1'||catalog.format!=='zasp-worker-effective-catalog-v2')fail('source authority content');
 return freeze(staticPacket());
}
export function assertOrderedCurrentPrivateSuccessorPacketV1(packet){
 if(!same(packet,staticPacket()))fail('packet authority');
 return true;
}

export function checkOrderedCurrentPrivateSuccessorReferenceV1(raw,packet){
 assertOrderedCurrentPrivateSuccessorPacketV1(packet);
 if(!Buffer.isBuffer(raw)||raw.length<3||raw.length>packet.limits.maxBytes+1||raw.at(-1)!==10)fail('reference framing');
 let reference;try{reference=strictJSON(raw);}catch(error){if(String(error.message).includes('reference'))throw error;fail('reference JSON');}
 closed(reference,'format status installable captureStatus variant sessionUser packetSHA256 sourcePins helperPins ddlSHA256 querySHA256 postgres serverVersionNum pgcrypto originalFrame collectorFrame readOnly originalAdmission writeRollback readOnlyPostAdmission postAdmission readRollback namespaceAbsent frameRestored expectedManifestRows registrationRows publication rows'.split(' '),'envelope');
 const fixed={format:'ordered-current-private-successor-reference-v1',status:'LOCAL-REFERENCE-ONLY',installable:false,captureStatus:'CAPTURED-UNBOUND',variant:'A',sessionUser:'zasp_test',packetSHA256:sha(Buffer.from(JSON.stringify(packet))),sourcePins:packet.sourcePins,helperPins:packet.helperPins,ddlSHA256:packet.ddl.sha256,querySHA256:packet.collector.sha256,postgres:packet.database.postgres,serverVersionNum:'180003',pgcrypto:'1.4',readOnly:false,originalAdmission:true,writeRollback:true,readOnlyPostAdmission:true,postAdmission:true,readRollback:true,namespaceAbsent:true,frameRestored:true,expectedManifestRows:0,registrationRows:0,publication:{mode:'0600',atomicNoOverwrite:true}};
 for(const [key,value] of Object.entries(fixed))if(!same(reference[key],value))fail(`reference provenance ${key}`);
 const frameKeys='sessionUser role searchPath timeZone postgres serverVersionNum pgcrypto readOnly'.split(' ');
 for(const name of ['originalFrame','collectorFrame'])closed(reference[name],frameKeys,`${name} frame`);
 const original=reference.originalFrame,collector=reference.collectorFrame;
 if(original.sessionUser!=='zasp_test'||original.role!=='zasp_test'||original.readOnly||typeof original.searchPath!=='string'||!original.searchPath||typeof original.timeZone!=='string'||!original.timeZone||original.postgres!==packet.database.postgres||original.serverVersionNum!=='180003'||original.pgcrypto!=='1.4')fail('reference original frame');
 if(collector.sessionUser!=='zasp_test'||collector.role!=='zasp_discovery_authority'||collector.searchPath!=='pg_catalog'||collector.timeZone!=='UTC'||collector.readOnly||collector.postgres!==packet.database.postgres||collector.serverVersionNum!=='180003'||collector.pgcrypto!=='1.4')fail('reference collector frame');
 if(!Array.isArray(reference.rows)||reference.rows.length!==57)fail('reference row cardinality');
 const rules=new Map(packet.rules.map(rule=>[rule.id,rule])),categories={},ruleCounts={},seen=new Set(),routines=[],nonroutines=[];
 for(const row of reference.rows){
  closed(row,['kind','identity','fact'],'row envelope');
  if(typeof row.identity!=='string'||seen.has(row.identity))fail('reference duplicate identity');seen.add(row.identity);
  let key;try{key=strictJSON(Buffer.from(row.identity));}catch{fail('reference row identity');}
  if(!Array.isArray(key)||key.length!==2||key.some(value=>typeof value!=='string')||canonicalOrderedJSON(key)!==row.identity)fail('reference row identity');
  const rule=rules.get(key[0]);if(!rule||row.kind!==rule.kind)fail('reference selected rule');
  closed(row.fact,rule.fields,'fact fields');
  for(const field of rule.fields)if(!typed(row.fact[field],packet.shape.fieldTypes[rule.kind][field]))fail('reference fact type');
  categories[row.kind]=(categories[row.kind]??0)+1;ruleCounts[rule.id]=(ruleCounts[rule.id]??0)+1;
  if(row.kind==='routine')routines.push(row);else nonroutines.push(row);
 }
 for(const [kind,count] of Object.entries(packet.shape.categoryMaxRows))if((categories[kind]??0)!==count)fail('reference category cardinality');
 for(const [id,count] of Object.entries(packet.shape.ruleMaxRows))if((ruleCounts[id]??0)!==count)fail('reference rule cardinality');
 if(!same(normalizeOrderedFacts(routines),normalizeOrderedFacts(packet.expectedRoutineFacts)))fail('reference routine parity');
 // The observed routine rows prove parity only.  The returned set is limited
 // to the freshly observed object facts, leaving the compiler-derived routine
 // facts as the only routine expectation authority.
 return freeze({valid:true,validatedRoutineCount:22,nonroutineCount:35,facts:normalizeOrderedFacts(nonroutines),installable:false,captureStatus:'CAPTURED-UNBOUND'});
}
const fixedReferenceURL=new URL('./ordered-current-capture-intake-v1-artifacts/private-successor-reference.json',import.meta.url);
const fixedReferenceSHA256='b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80';

export function admitOrderedCurrentPrivateSuccessorReferenceV1(...inputs){
 if(inputs.length)fail('captured-file caller input');
 let raw;try{raw=fs.readFileSync(fixedReferenceURL);}catch(error){fail(`captured-file read (${error.message})`);}
 if(sha(raw)!==fixedReferenceSHA256)fail('captured-file authority');
 const checked=checkOrderedCurrentPrivateSuccessorReferenceV1(raw,staticPacket());
 if(checked.installable!==false||checked.captureStatus!=='CAPTURED-UNBOUND')fail('captured-file result');
 return checked;
}
export function serializeOrderedCurrentPrivateSuccessorCaptureV1(packet){
 assertOrderedCurrentPrivateSuccessorPacketV1(packet);
 const raw=Buffer.from(JSON.stringify(packet)+'\n');
 if(raw.length>16777216)fail('packet byte bound');
 return freeze({raw,sha256:sha(raw),bytes:raw.length});
}
export function materializeOrderedCurrentPrivateSuccessorCaptureV1(packet,directory){
 if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory)fail('packet directory');
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const output=path.join(directory,'private-successor-packet.json'),serialized=serializeOrderedCurrentPrivateSuccessorCaptureV1(packet);
 try{fs.writeFileSync(output,serialized.raw,{flag:'wx',mode:0o600});}catch(error){
  if(error?.code!=='EEXIST')fail(`packet materializer write (${error.message})`);
  let existing;try{existing=fs.readFileSync(output);}catch(readError){fail(`packet materializer read (${readError.message})`);}
  if(!existing.equals(serialized.raw))fail('packet materializer refuses overwrite');
 }
 return freeze({path:output,sha256:serialized.sha256,bytes:serialized.bytes});
}
