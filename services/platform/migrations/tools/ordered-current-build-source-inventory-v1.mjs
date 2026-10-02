// Current source provenance only. Historical captured helper pins remain
// separate; these hashes authorize neither routine facts nor execution.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readWorkerHigherSourceInputsV1} from './ordered-current-worker-higher-integration-v1.mjs';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const tools='services/platform/migrations/tools/';
const historical=tools+'ordered-current-private-historical-v1/';
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const fail=message=>{throw Error('ordered-current build source inventory '+message);};
const manifestSHA256='8d4fee2253344603a4878751f70f96bcf7d4b4884a5cab2b6ee1016db9d40732';
const currentPins=Object.freeze({
 'ordered-current-private-historical-v1.mjs':'7876610586141346ae8281e877d8cf4e67e0f2567e7baa61fdccbe02555e4317',
 'ordered-current-private-historical-v1.test.mjs':'83c89915be313c051869cd35869da6da35bfe1bb6726488bc77132053dec86dc',
 'ordered-current-private-successor-reference.mjs':'6f81cabbd3672c70190f43f9b70918ade8ef97a392e3a491922bdd874e066450',
 'ordered-current-private-successor-reference.test.mjs':'3f4a04fabbffdb14359f002b87bd8addd55e22d2f2ba12a2f7ba07e8272936c7',
 'ordered-current-worker-higher-integration-v1.mjs':'dcce9de5596315ed425db6bcf4aa24c38b63a66ba61c1914056b2640a1528a18',
 'build-ordered-current-development-higher.test.mjs':'fc287dd32fe14e3b8f1394618e068ea06d268ee75d9c7ae2a2207fe9ded94ea1',
 'ordered-current-remaining-projection-witness-v1.mjs':'bfe7755e97da77f5c1c4b147cbed0fa05e539be7e71a16cefcd34d6f7b3376a4',
 'ordered-current-remaining-projection-witness-v1.test.mjs':'d1f0facd864a6d923346ef7953db49acde1f1549e3614835ac24823642cb0732',
 'ordered-current-remaining-projection-witness-v1-artifacts/reference.json':'3711750bab518ee5fc8f02e8b08e61a3a8ed6f3497ea109e03e9a42764b57701',
 'ordered-current-development-remaining.test.mjs':'c32001e9ffff091fd38038b7525303443859193dcb10cc9d6129d58d4dcb1520',
 'ordered-current-precision-resolver-frame-v1.mjs':'8582b04be434d19f979f0626ae2cbb295fcf6e49c4cbf18eff9bb74021ab353d',
 'ordered-current-precision-resolver-frame-v1.test.mjs':'7e9010550eb463f4023ff368ccf57de3e01ccf9e1d262091b637df26cc80e670',
 'build-ordered-current-development-private.test.mjs':'f3dbfe828801e0ad76add1717a1c0a1d4c87fc1e96000ba78e558790805adb30',
});
const fixture='services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go';
const fixtureSHA256='78427e95a296b9b636154a9d7d81e022772fe43b2503fc972c0f34e1e20488b6';
const higherPaths=Object.freeze([
 tools+'ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',
 tools+'ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',
 tools+'ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',
 'services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql',
 tools+'build-worker-readiness-graph.mjs',tools+'worker-readiness-regions.mjs',
 'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go',
 tools+'ordered-current-worker-higher-source-replay-v1.mjs',
 tools+'ordered-current-worker-higher-source-replay-v1.test.mjs',
]);
const selfPaths=Object.freeze([tools+'ordered-current-build-source-inventory-v1.mjs',tools+'ordered-current-build-source-inventory-v1.test.mjs']);
const utf8=(left,right)=>Buffer.compare(Buffer.from(left),Buffer.from(right));

function regularSource(relative){
 if(typeof relative!=='string'||relative===''||path.posix.normalize(relative)!==relative||relative.includes('\\')||path.isAbsolute(relative)||relative.split('/').some(part=>part==='..'||part==='.'||part===''))fail('source path');
 const absolute=path.resolve(root,relative);
 if(!absolute.startsWith(path.resolve(root)+path.sep))fail('source containment '+relative);
 let current=path.resolve(root);
 if(fs.realpathSync(current)!==current||!fs.lstatSync(current).isDirectory())fail('repository root');
 const parts=relative.split('/');
 for(const [index,part]of parts.entries()){
  current=path.join(current,part);
  const stat=fs.lstatSync(current);
  if(stat.isSymbolicLink()||(index===parts.length-1?!stat.isFile():!stat.isDirectory()))fail('nonregular or symlink source '+relative);
 }
 return fs.readFileSync(absolute);
}

export function readOrderedCurrentBuildSourceInventoryV1(){
 if(arguments.length!==0)fail('caller-selected authority refused; source inputs are fixed');
 try{
  const inputs={};
  const add=(relative,digest)=>{
   if(typeof digest!=='string'||!/^[0-9a-f]{64}$/.test(digest))fail('digest '+relative);
   if(Object.hasOwn(inputs,relative)&&inputs[relative]!==digest)fail('conflicting duplicate '+relative);
   if(sha(regularSource(relative))!==digest)fail('source authority '+relative);
   inputs[relative]=digest;
  };
  // Authenticate the approved manifest bytes before interpreting its roster.
  add(historical+'manifest.json',manifestSHA256);
  const manifest=JSON.parse(regularSource(historical+'manifest.json'));
  if(Object.keys(manifest).sort().join(',')!=='archiveManifestSHA256,files,format'||manifest.format!=='ordered-current-private-historical-source-v1'||manifest.archiveManifestSHA256!=='71dffc8ab32e112f92e94e4fb10eec52c399f5492a57111a311a1c3dc4065609'||!manifest.files||Array.isArray(manifest.files)||Object.keys(manifest.files).length!==27)fail('historical manifest shape/cardinality');
  const actual=[];
  function walk(directory,prefix=''){
   for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
    const relative=prefix+entry.name,absolute=path.join(directory,entry.name),stat=fs.lstatSync(absolute);
    if(stat.isSymbolicLink())fail('historical symlink '+relative);
    if(stat.isDirectory()){
     if(relative!=='tools'&&relative!=='sql')fail('historical unlisted directory '+relative);
     walk(absolute,relative+'/');
    }else if(stat.isFile())actual.push(relative);
    else fail('historical nonregular input '+relative);
   }
  }
  walk(path.join(root,historical));
  if(actual.sort(utf8).join('\n')!==['manifest.json',...Object.keys(manifest.files)].sort(utf8).join('\n'))fail('historical closed file roster');
  for(const [relative,digest]of Object.entries(manifest.files))add(historical+relative,digest);
  for(const [name,digest]of Object.entries(currentPins))add(tools+name,digest);
  add(fixture,fixtureSHA256);
  // The fixed higher reader supplies all nine raw/module/test pins. Validate
  // its complete path set and regular-file topology, not just import guesses.
  for(const relative of higherPaths)regularSource(relative);
  const higher=readWorkerHigherSourceInputsV1();
  if(Object.keys(higher).sort().join(',')!=='inputs,inventory'||Object.keys(higher.inventory).sort(utf8).join('\n')!==[...higherPaths].sort(utf8).join('\n'))fail('higher closed input roster');
  for(const [relative,digest]of Object.entries(higher.inventory))add(relative,digest);
  // The reader and its test are current source metadata, never self-pinned
  // expected truth. Their bytes are frozen by the consumer snapshot/review.
  for(const relative of selfPaths)add(relative,sha(regularSource(relative)));
  if(Object.keys(inputs).length!==53)fail('complete declared cardinality');
  return Object.freeze({format:'ordered-current-build-source-inventory-v1',status:'SOURCE-PROVENANCE-ONLY',installable:false,native:false,executable:false,inputs:Object.freeze(Object.fromEntries(Object.entries(inputs).sort(([left],[right])=>utf8(left,right))))});
 }catch(error){
  if(error.message.startsWith('ordered-current build source inventory '))throw error;
  fail('source read ('+error.message+')');
 }
}
