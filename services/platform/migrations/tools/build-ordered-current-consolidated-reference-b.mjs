import {buildOrderedConsolidatedReference} from './build-ordered-current-consolidated-reference.mjs';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const p7='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const seed=p7+'ordered-current-complete-capture-packet-A-native22-precision-final4/';
const destination=p7+'ordered-current-complete-capture-packet-B-native22-precision-final4/';
const seedManifestSHA256='71dffc8ab32e112f92e94e4fb10eec52c399f5492a57111a311a1c3dc4065609';
const seedContractSHA256='1162fbf060850000df19af6fcc8e990b4c03d2f55311bcaf56b5b1b1c1d78a9d';
const producerSHA256='a06ab7aa84d8005ca2990117d85203fb4949d47627cec56672f932f037dd8f28';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const addedSources=['services/platform/migrations/tools/build-ordered-current-consolidated-reference-b.mjs','services/platform/migrations/tools/build-ordered-current-consolidated-reference-b.test.mjs'];
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const read=relative=>fs.readFileSync(path.join(root,relative));
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const ordered=object=>Object.fromEntries(Object.entries(object).sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b))));

function reviewedSeed(){
 const manifestRaw=read(seed+'snapshot-manifest.json');
 if(sha(manifestRaw)!==seedManifestSHA256)throw Error('B emitter unreviewed seed manifest');
 const manifest=JSON.parse(manifestRaw);
 if(Object.keys(manifest.files).length!==100||manifest.files[contractName]!==seedContractSHA256||manifest.files[producer]!==producerSHA256)throw Error('B emitter seed inventory');
 for(const [relative,digest]of Object.entries(manifest.files)){
  if(sha(read(seed+relative))!==digest)throw Error('B emitter seed member drift '+relative);
  // The separate B build never repairs or replaces any shared A source/output.
  if(sha(read(relative))!==digest)throw Error('B emitter working A member drift '+relative);
 }
 return manifest;
}

export function buildOrderedConsolidatedReferenceB() {
 if(arguments.length!==0)throw Error('B emitter accepts no caller authority');
 const manifest=reviewedSeed();
 // This existing builder performs the mandatory complete source-closure assertion.
 const a=buildOrderedConsolidatedReference();
 if(sha(a.manifestRaw)!==seedManifestSHA256)throw Error('B emitter unreviewed A derivation');
 const sourceFiles=Object.fromEntries(Object.entries(a.snapshotFiles).filter(([relative])=>!relative.startsWith(packet)));
 const original=sourceFiles[producer].toString(),oldCall='loadConsolidatedReference(directory)',newCall='loadConsolidatedReferenceVariantB(directory)';
 if(sha(sourceFiles[producer])!==producerSHA256||original.split(oldCall).length!==3||original.includes(newCall))throw Error('B emitter producer substitution source');
 const changed=original.replaceAll(oldCall,newCall);
 if(changed.includes(oldCall)||changed.split(newCall).length!==3)throw Error('B emitter producer substitution count');
 sourceFiles[producer]=Buffer.from(changed);
 for(const relative of addedSources){
  if(Object.hasOwn(manifest.files,relative))throw Error('B emitter source collision');
  sourceFiles[relative]=read(relative);
 }
 const sourcePins=ordered(Object.fromEntries(Object.entries(sourceFiles).map(([relative,raw])=>[relative,sha(raw)])));
 if(Object.keys(sourcePins).length!==95)throw Error('B emitter source inventory');
 const contract={...a.contract,variant:'B',sessionUser:'zasp_e2e',sourcePins};
 const files={...a.files,[contractName]:json(contract)};
 const snapshotFiles=ordered({...sourceFiles,...files});
 if(Object.keys(snapshotFiles).length!==102)throw Error('B emitter snapshot inventory');
 const resultManifest={format:1,source:'ordered-current-complete-capture-packet-B',files:ordered(Object.fromEntries(Object.entries(snapshotFiles).map(([relative,raw])=>[relative,sha(raw)])))};
 return {files,snapshotFiles,contract,closure:a.closure,manifestRaw:json(resultManifest)};
}

function state(filename){
 try{return fs.lstatSync(filename);}catch(error){if(error.code==='ENOENT')return null;throw error;}
}
function checkedParents(relative){
 const parts=relative.split('/');let filename=root;
 for(const part of parts.slice(0,-1)){
  filename=path.join(filename,part);const item=state(filename);
  if(item&&(!item.isDirectory()||item.isSymbolicLink()))throw Error('B emitter output parent conflict');
 }
}
function inventory(directory,expected,prefix=''){
 for(const item of fs.readdirSync(directory,{withFileTypes:true})){
  const relative=prefix+item.name,filename=path.join(directory,item.name);
  if(item.isSymbolicLink())throw Error('B emitter output symlink');
  if(item.isDirectory()){
   if(![...expected].some(name=>name.startsWith(relative+'/')))throw Error('B emitter unlisted output directory');
   inventory(filename,expected,relative+'/');
  }else if(!item.isFile()||!expected.has(relative))throw Error('B emitter unlisted output member');
 }
}
function verifyOutput(relative,raw,required){
 checkedParents(destination+relative);
 const filename=path.join(root,destination,relative),item=state(filename);
 if(!item){if(required)throw Error('B emitter output absent '+relative);return;}
 if(!item.isFile()||item.isSymbolicLink()||!fs.readFileSync(filename).equals(raw))throw Error('B emitter immutable output conflict '+relative);
}
function run(mode){
 const built=buildOrderedConsolidatedReferenceB(),members={...built.snapshotFiles,'snapshot-manifest.json':built.manifestRaw};
 const output=path.join(root,destination),item=state(output);
 checkedParents(destination+'snapshot-manifest.json');
 if(item){
  if(!item.isDirectory()||item.isSymbolicLink())throw Error('B emitter output root conflict');
  inventory(output,new Set(Object.keys(members)));
 }
 // Check the whole destination before creating any member. Existing identical
 // members are idempotent; conflicts, extras and symlinks are never overwritten.
 for(const [relative,raw]of Object.entries(members))verifyOutput(relative,raw,mode==='--check');
 if(mode==='--write'){
  for(const [relative,raw]of Object.entries(members)){
   verifyOutput(relative,raw,false);
   const filename=path.join(output,relative);
   if(state(filename))continue;
   fs.mkdirSync(path.dirname(filename),{recursive:true});
   fs.writeFileSync(filename,raw,{flag:'wx'});
  }
 }
 return {variant:'B',files:Object.keys(built.files).length,rules:Object.keys(built.contract.rules).length,manifestSHA256:sha(built.manifestRaw),contractSHA256:sha(built.files[contractName])};
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url){
 if(process.argv.length!==3||!['--write','--check'].includes(process.argv[2]))throw Error('use --write or --check; B has no caller options');
 console.log(JSON.stringify(run(process.argv[2])));
}
