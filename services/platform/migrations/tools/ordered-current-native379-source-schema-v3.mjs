// Initial v3 source/reference boundary. Final Go/source manifest is not issued.
// Reads only fixed reviewed source bytes; no target, credentials or SQL execution.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=path.resolve(fileURLToPath(new URL('../../../../',import.meta.url)));
const tools='services/platform/migrations/tools/';
const pins=Object.freeze({
 'build-ordered-current-linux-successor-v1.mjs':'97e7172223ba7cdcc0a289ca8fcfae6f367f827029d1226a40ea261ff80f9503',
 'build-ordered-current-linux-successor-v1.test.mjs':'94dea86cf72c42b687ec28909b76b7eb06d0292190684c1b9084271a522f70a1',
 'ordered-current-linux-provenance-v1.mjs':'64b0d211765c03071d124d1443831d2d9c3f60393878eadcbaf6ac4635be80e0',
 'ordered-current-linux-provenance-v1.test.mjs':'a5f2c04c1ee1db60d9f6933e825da323bf144700fdb2b12fadf4f81c75ef3fd0',
 'ordered-current-linux-provenance-v1.json':'68425b6efc85e163c5028dadb4b8ff3ec219dfb5d7a8a2772c73a58a45dddfb5'});
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const fail=message=>{throw Error('ordered-current native379 v3 source '+message);};
// Wrong runtime must fail before evaluating the source generator's eager inputs.
if(process.version!=='v22.23.1'||process.platform!=='linux'||process.arch!=='x64')fail('Node runtime requires v22.23.1 linux x64 and approved executable SHA256');
const executable=fs.realpathSync(process.execPath);
if(!fs.lstatSync(executable).isFile()||sha(fs.readFileSync(executable))!=='93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068')fail('Node runtime requires approved executable SHA256');

// Builtins-only bootstrap: even a fixed import can execute modified source.
// Validate the complete reviewed execution/fixed-read closure before ANY local import.
const baselineExtraPins=Object.freeze({
 'ordered-current-native379-packet-v2.mjs':'b0f2c1483d009f45f9660bbb05e62fd7f7dfbae643bcd0af50023456a7ccd9c3',
 'ordered-current-native379-source-schema-v2.mjs':'da5a78ad3d5d9a19f348d99e1b44b444fe188e54e373a7d46d3fb609c3cc71a0',
 'ordered-current-native379-packet-v2-artifacts/source-inputs.json':'d3f6fac0d38478208fe1feff2f521a8b132b373aa8516771c62005a762a11ea4',
 'ordered-current-native379-packet-v2-artifacts/generated-identities.json':'9d1053e9310e27128404e45c2eeedce1dc6b42eaff004ecf0e0760c903b59f99',
 'ordered-current-native379-packet-v2-artifacts/source-fact-delta.json':'90325bea8205ec4e3f8eaa1de3c1fb0d814981cc6fbfd91e3c3e4ad3e6a9cdab'});
export function readNative379RegularSourceV3(base,relative,pin){
 if(typeof base!=='string'||!path.isAbsolute(base)||path.resolve(base)!==base||typeof relative!=='string'||path.posix.normalize(relative)!==relative||path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').some(p=>['','.','..'].includes(p))||typeof pin!=='string'||!/^[0-9a-f]{64}$/.test(pin))fail('source topology/hash grammar');
 try{
  if(fs.realpathSync(base)!==base||!fs.lstatSync(base).isDirectory())fail('root symlink/directory');
  let current=base;const parts=relative.split('/');
  for(const [index,part]of parts.entries()){
   current=path.join(current,part);const stat=fs.lstatSync(current);
   if(stat.isSymbolicLink()||(index===parts.length-1?!stat.isFile():!stat.isDirectory()))fail('nonregular or symlink '+relative);
   if(index===parts.length-1&&(stat.size<=0||stat.size>33554432))fail('file size '+relative);
  }
  const bytes=fs.readFileSync(current);if(sha(bytes)!==pin)fail('hash '+relative);return bytes;
 }catch(error){if(error.message.startsWith('ordered-current native379 v3 source '))throw error;fail('read/topology '+relative);}
}
function verifyExecutionClosure(){
 const sourceRaw=readNative379RegularSourceV3(root,tools+'ordered-current-native379-packet-v2-artifacts/source-inputs.json',baselineExtraPins['ordered-current-native379-packet-v2-artifacts/source-inputs.json']);
 const source=JSON.parse(sourceRaw);
 if(source.format!=='ordered-current-native379-source-inputs-v2'||source.installable!==false||source.nativeVerified!==false||source.status!=='SOURCE-PROVENANCE-ONLY'||Object.keys(source.files).length!==1545)fail('immutable baseline source manifest');
 let total=sourceRaw.length;
 for(const [relative,pin]of Object.entries(source.files)){
  if(!/^services\/platform\/(?:migrations\/|apiserver\/[^/]+\.go$)/.test(relative))fail('baseline scope');
  total+=readNative379RegularSourceV3(root,relative,pin).length;
 }
 for(const [name,pin]of Object.entries({...baselineExtraPins,...pins}))total+=readNative379RegularSourceV3(root,tools+name,pin).length;
 if(total>268435456)fail('execution closure bytes');
}
verifyExecutionClosure();
// Fixed literal edges; no caller, environment or target chooses imports.
const {buildOrderedCurrentLinuxSuccessorV1}=await import('./build-ordered-current-linux-successor-v1.mjs');
const {readOrderedCurrentLinuxProvenanceV1}=await import('./ordered-current-linux-provenance-v1.mjs');
export function native379V3Canonical(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){if(!Number.isSafeInteger(value))fail('noninteger/nonfinite authority');return JSON.stringify(value);}
 if(typeof value!=='object')fail('non-JSON authority');
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(value);
 if(keys.some(key=>typeof key!=='string')||Object.values(descriptors).some(d=>!Object.hasOwn(d,'value')))fail('accessor/symbol authority');
 if(Array.isArray(value)){
  if(Object.getPrototypeOf(value)!==Array.prototype||keys.length!==value.length+1)fail('array authority');
  for(let i=0;i<value.length;i++)if(!Object.hasOwn(descriptors,String(i)))fail('sparse authority');
  return '['+Array.from({length:value.length},(_,i)=>native379V3Canonical(descriptors[i].value)).join(',')+']';
 }
 if(Object.getPrototypeOf(value)!==Object.prototype)fail('object authority');
 return '{'+Object.keys(descriptors).sort().map(k=>JSON.stringify(k)+':'+native379V3Canonical(descriptors[k].value)).join(',')+'}';
}
let admitted;
export function readOrderedCurrentNative379LinuxReferenceV3(){
 if(arguments.length)fail('caller-selected source authority');
 // Recheck immutable baseline and all five newly reviewed inputs on each read.
 verifyExecutionClosure();
 if(!admitted){
  const descriptor=readOrderedCurrentLinuxProvenanceV1(),built=buildOrderedCurrentLinuxSuccessorV1();
  if(built.installable!==false||built.nativeVerified!==false||built.expectedFromTarget!==false||built.facts.length!==10052||Object.keys(built.outputs).length!==8)fail('source assembly status/cardinality');
  const manifest=JSON.parse(built.outputs['development-manifest.json']);
  const build=manifest.facts.filter(f=>f.kind==='build'&&f.identity==='provenance');
  if(build.length!==1||build[0].fact.postgres!==descriptor.identity.version||build[0].fact.pgcrypto!==descriptor.identity.pgcrypto)fail('exact Linux reference identity');
  admitted={format:'ordered-current-native379-linux-reference-v3',status:'SOURCE-REFERENCE-ONLY',installable:false,nativeVerified:false,captureAuthority:false,source5Pins:{...pins},descriptorSHA256:pins['ordered-current-linux-provenance-v1.json'],identitySHA256:descriptor.evidence.identitySHA256,identity:{postgres:descriptor.identity.version,serverVersionNum:Number(descriptor.identity.server_version_num),pgcrypto:descriptor.identity.pgcrypto},outputs:built.outputs,outputPins:Object.fromEntries(Object.entries(built.outputs).map(([name,text])=>[name,sha(text)])),manifestPayloadSHA256:manifest.payloadSHA256,referenceProvenance:build[0].fact,pending:['source5-verified-push','frozen-Go-v3-implementation','complete-reviewed-v3-source-manifest-and-artifacts','independent-full-v3-wire-and-Go-review','new-frozen-runtime-envelopes','root-owned-native589-acceptance']};
 }
 return structuredClone(admitted);
}
export function assertOrderedCurrentNative379LinuxReferenceV3(value){
 if(arguments.length!==1||native379V3Canonical(value)!==native379V3Canonical(readOrderedCurrentNative379LinuxReferenceV3()))fail('closed Linux reference/output/source/status mismatch');
 return true;
}
export function admitOrderedCurrentNative379SourceV3(){
 if(arguments.length)fail('caller-selected authority');
 fail('final source5 push, frozen Go v3 implementation and independently reviewed source manifest required');
}
