// Fixed repository-relative source authority. No native admission or provider I/O.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

const root=path.resolve(fileURLToPath(new URL('../../../../',import.meta.url)));
const manifestSHA256='44898f917fa13db57ba2e2da79fdcfe03f3f522aa2aff2e61223c397776ec99c';
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const fail=message=>{throw Error('ordered-current native379 v2 source '+message);};
const canonical=value=>JSON.stringify(value,(_,item)=>{
 if(['undefined','function','symbol','bigint'].includes(typeof item)||(typeof item==='number'&&!Number.isFinite(item)))fail('non-JSON authority');
 return item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(k=>[k,item[k]])):item;
});

// A pure topology/hash reader, not an authority selector. Execution callers use
// only admitOrderedCurrentNative379SourceV2's fixed reviewed roster.
export function readNative379RegularSourceV2(base,relative,pin){
 if(typeof base!=='string'||typeof relative!=='string'||!path.isAbsolute(base)||path.resolve(base)!==base||path.posix.normalize(relative)!==relative||path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').some(p=>['','.','..'].includes(p)))fail('path topology');
 if(typeof pin!=='string'||!/^[0-9a-f]{64}$/.test(pin))fail('hash grammar');
 try{
  if(fs.realpathSync(base)!==base||!fs.lstatSync(base).isDirectory())fail('root symlink/directory');
  let current=base;const parts=relative.split('/');
  for(const [index,part]of parts.entries()){
   current=path.join(current,part);const stat=fs.lstatSync(current);
   if(stat.isSymbolicLink()||(index===parts.length-1?!stat.isFile():!stat.isDirectory()))fail('nonregular or symlink '+relative);
   if(index===parts.length-1&&(stat.size<=0||stat.size>33554432))fail('file size '+relative);
  }
  const raw=fs.readFileSync(current);if(sha(raw)!==pin)fail('hash '+relative);return raw;
 }catch(error){if(error.message.startsWith('ordered-current native379 v2 source '))throw error;fail('read/topology '+relative);}
}

function fixed(){
 const raw=readNative379RegularSourceV2(root,'services/platform/migrations/tools/ordered-current-native379-packet-v2-artifacts/source-inputs.json',manifestSHA256);
 if(raw.length>1048576)fail('manifest byte cap');
 const source=JSON.parse(raw);
 if(source.format!=='ordered-current-native379-source-inputs-v2'||source.installable!==false||source.nativeVerified!==false||source.status!=='SOURCE-PROVENANCE-ONLY'||Object.keys(source.files).length!==1544)fail('manifest shape/cardinality');
 const implementation='services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go';
 const companion='services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go';
 const policy={implementation,excludedSourcePaths:[companion],companionBinding:'independently-reviewed-full-consumed-Go-source-module-test-binary-envelope'};
 if(canonical(source.goPacketAnchorPolicy)!==canonical(policy)||!Object.hasOwn(source.files,implementation)||Object.hasOwn(source.files,companion))fail('exact Go implementation/derived-anchor exclusion policy');
 let total=0;
 for(const [relative,pin]of Object.entries(source.files)){
  if(!/^services\/platform\/(?:migrations\/|apiserver\/[^/]+\.go$)/.test(relative))fail('unadmitted source scope '+relative);
  const bytes=readNative379RegularSourceV2(root,relative,pin);total+=bytes.length;
  if(total>268435456)fail('total source byte cap');
  if(relative.endsWith('.mjs')){
   const imports=[...bytes.toString('utf8').matchAll(/^\s*(?:import|export)\s+(?:[^'"\n]*?\s+from\s+)?['"](\.[^'"]+\.mjs)['"]/gm)].map(m=>path.posix.normalize(path.posix.join(path.posix.dirname(relative),m[1])));
   const expected=[...new Set(imports)].sort();
   if(canonical(expected)!==canonical(source.importEdges[relative]))fail('static importer closure '+relative);
   for(const imported of expected)if(!Object.hasOwn(source.files,imported))fail('missing importer '+imported);
  }
 }
 for(const importer of Object.keys(source.importEdges))if(!Object.hasOwn(source.files,importer)||!importer.endsWith('.mjs'))fail('extra importer');
 return source;
}

export function admitOrderedCurrentNative379SourceV2(){
 if(arguments.length!==0)fail('caller-selected authority');return structuredClone(fixed());
}
export function assertOrderedCurrentNative379SourceV2(source){
 if(arguments.length!==1||canonical(source)!==canonical(fixed()))fail('closed source roster/hash/status mismatch');
}
export const orderedCurrentNative379SourceManifestSHA256V2=manifestSHA256;
