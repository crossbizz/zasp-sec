import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
// Root reviewed actual current A twice. These are separate successor bindings;
// historical A/B pins and their missing historical seed remain unchanged.
const seed='.superpowers/sdd/2026-10-05-reviewed-current-A-successor-v1/';
const destination='.superpowers/sdd/2026-10-05-reviewed-current-B-successor-v1/';
const seedManifestSHA256='b3d03a9e7cd86daabbd80ead85cb30a5e98f856be35c08d15227fa710dd914fa';
const seedContractSHA256='ad51418075709c382661ef4b4cede63c399eae97f5c266314a28a0b90c1e7c01';
const producerSHA256='a06ab7aa84d8005ca2990117d85203fb4949d47627cec56672f932f037dd8f28';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const addedSources=[
 'services/platform/migrations/tools/build-ordered-current-consolidated-reference-b-successor-v1.mjs',
 'services/platform/migrations/tools/build-ordered-current-consolidated-reference-b-successor-v1.test.mjs',
];
const packetNames=[contractName,packet+'consolidated-capture-coverage.json',...['demand','keys','original','resolution','witness'].map(phase=>packet+`consolidated-capture-${phase}.sql`)];
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const ordered=value=>Object.fromEntries(Object.entries(value).sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b))));
const fail=message=>{throw Error('current B successor '+message);};

function safeRelative(relative){
 if(typeof relative!=='string'||!relative||path.posix.normalize(relative)!==relative||relative.includes('\\')||relative.includes('\0')||path.isAbsolute(relative)||relative.split('/').some(part=>part===''||part==='.'||part==='..'))fail('path topology');
 return relative;
}
function state(filename){try{return fs.lstatSync(filename);}catch(error){if(error.code==='ENOENT')return null;throw error;}}
function checkedRoot(){
 const absolute=path.resolve(root),item=fs.lstatSync(absolute);
 if(!item.isDirectory()||item.isSymbolicLink()||fs.realpathSync(absolute)!==absolute)fail('root topology');
 return absolute;
}
function checkedPath(relative,allowMissing=false){
 const parts=safeRelative(relative).split('/');let filename=checkedRoot();
 for(const [index,part]of parts.entries()){
  filename=path.join(filename,part);const item=state(filename);
  if(!item){if(allowMissing)continue;fail('missing member '+relative);}
  else if(item.isSymbolicLink()||(index<parts.length-1&&!item.isDirectory()))fail('symlink/non-directory '+relative);
 }
 return filename;
}
function read(relative){
 const filename=checkedPath(relative),item=fs.lstatSync(filename);
 if(!item.isFile())fail('nonregular member '+relative);
 const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try {if(!fs.fstatSync(fd).isFile())fail('nonregular open member '+relative);return fs.readFileSync(fd);}finally{fs.closeSync(fd);}
}
function inventory(directory,expected,prefix=''){
 for(const item of fs.readdirSync(directory,{withFileTypes:true})){
  const relative=prefix+item.name,filename=path.join(directory,item.name);
  if(item.isSymbolicLink())fail('inventory symlink '+relative);
  if(item.isDirectory()){
   if(![...expected].some(name=>name.startsWith(relative+'/')))fail('unlisted directory '+relative);
   inventory(filename,expected,relative+'/');
  }else if(!item.isFile()||!expected.has(relative))fail('unlisted/nonregular member '+relative);
 }
}
function reviewedA(){
 const manifestRaw=read(seed+'snapshot-manifest.json');
 if(sha(manifestRaw)!==seedManifestSHA256)fail('unreviewed A manifest');
 const manifest=JSON.parse(manifestRaw);
 if(Object.keys(manifest).join(' ')!=='format source files'||manifest.format!==1||manifest.source!=='ordered-current-task2-tracked-authority'||Object.keys(manifest.files).length!==164||manifest.files[contractName]!==seedContractSHA256||manifest.files[producer]!==producerSHA256)fail('A manifest inventory');
 const expected=new Set(['snapshot-manifest.json',...Object.keys(manifest.files)]);
 inventory(checkedPath(seed.slice(0,-1)),expected);
 const snapshotFiles={};
 for(const [relative,digest]of Object.entries(manifest.files)){
  safeRelative(relative);if(!/^[0-9a-f]{64}$/.test(digest))fail('A member digest');
  const raw=read(seed+relative);if(sha(raw)!==digest)fail('A member drift '+relative);snapshotFiles[relative]=raw;
 }
 const contract=JSON.parse(snapshotFiles[contractName]);
 if(contract.status!=='REFERENCE-CAPTURE-ONLY'||contract.installable!==false||contract.captureReady!==true||contract.sourceFrameVersion!==1||contract.variant!=='A'||contract.sessionUser!=='zasp_test'||contract.maxRows!==10000||contract.maxBytes!==16777216||Object.keys(contract.rules).length!==1862||Object.keys(contract.sourcePins).length!==157)fail('A contract boundary');
 const sourceNames=Object.keys(manifest.files).filter(name=>!packetNames.includes(name));
 if(sourceNames.length!==157||Object.keys(contract.sourcePins).some(name=>!sourceNames.includes(name)))fail('A source/packet partition');
 for(const name of sourceNames){
  if(contract.sourcePins[name]!==manifest.files[name]||sha(read(name))!==contract.sourcePins[name])fail('current A source drift '+name);
 }
 if(packetNames.some(name=>!Object.hasOwn(snapshotFiles,name)))fail('A packet inventory');
 return {snapshotFiles,contract};
}

export function buildOrderedConsolidatedReferenceBSuccessorV1(){
 if(arguments.length!==0)fail('accepts no caller authority');
 const a=reviewedA(),snapshotFiles={...a.snapshotFiles};
 const original=snapshotFiles[producer].toString(),oldCall='loadConsolidatedReference(directory)',newCall='loadConsolidatedReferenceVariantB(directory)';
 if(sha(snapshotFiles[producer])!==producerSHA256||original.split(oldCall).length!==3||original.includes(newCall))fail('producer substitution source');
 const changed=original.replaceAll(oldCall,newCall);
 if(changed.includes(oldCall)||changed.split(newCall).length!==3)fail('producer substitution count');
 snapshotFiles[producer]=Buffer.from(changed);
 const sourcePins={...a.contract.sourcePins,[producer]:sha(snapshotFiles[producer])};
 for(const name of addedSources){
  if(Object.hasOwn(snapshotFiles,name)||Object.hasOwn(sourcePins,name))fail('added source collision');
  snapshotFiles[name]=read(name);sourcePins[name]=sha(snapshotFiles[name]);
 }
 // Preserve every reviewed original-source field, including Darwin provenance,
 // rule/phase/frame/cap identities and noninstallation. This is not native proof.
 const contract={...a.contract,variant:'B',sessionUser:'zasp_e2e',sourcePins:ordered(sourcePins)};
 snapshotFiles[contractName]=json(contract);
 const files=ordered(Object.fromEntries(packetNames.map(name=>[name,snapshotFiles[name]])));
 const sortedSnapshot=ordered(snapshotFiles);
 if(Object.keys(sourcePins).length!==159||Object.keys(sortedSnapshot).length!==166)fail('B inventory');
 const manifest={format:1,source:'ordered-current-complete-capture-packet-B-successor-v1',files:ordered(Object.fromEntries(Object.entries(sortedSnapshot).map(([name,raw])=>[name,sha(raw)])))};
 return {files,snapshotFiles:sortedSnapshot,contract,manifestRaw:json(manifest)};
}

function verifyOutput(relative,raw,required){
 const filename=checkedPath(destination+relative,true),item=state(filename);
 if(!item){if(required)fail('output absent '+relative);return;}
 if(!item.isFile()||item.isSymbolicLink()||!read(destination+relative).equals(raw))fail('immutable output conflict '+relative);
}
function run(mode){
 const built=buildOrderedConsolidatedReferenceBSuccessorV1(),members={...built.snapshotFiles,'snapshot-manifest.json':built.manifestRaw};
 const output=checkedPath(destination.slice(0,-1),true),item=state(output);
 if(item){if(!item.isDirectory()||item.isSymbolicLink())fail('output root conflict');inventory(output,new Set(Object.keys(members)));}
 // Inspect the entire immutable destination before creating any file. Partial
 // conflicts cannot cause earlier missing members to be published.
 for(const [relative,raw]of Object.entries(members))verifyOutput(relative,raw,mode==='--check');
 if(mode==='--write'){
  for(const [relative,raw]of Object.entries(members)){
   verifyOutput(relative,raw,false);const filename=checkedPath(destination+relative,true);
   if(state(filename))continue;
   fs.mkdirSync(path.dirname(filename),{recursive:true});
   checkedPath(destination+relative,true);fs.writeFileSync(filename,raw,{flag:'wx'});
  }
 }
 return {variant:'B',files:Object.keys(built.files).length,rules:Object.keys(built.contract.rules).length,sourcePins:Object.keys(built.contract.sourcePins).length,members:Object.keys(members).length,manifestSHA256:sha(built.manifestRaw),contractSHA256:sha(built.files[contractName])};
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url){
 if(process.argv.length!==3||!['--write','--check'].includes(process.argv[2]))fail('use --write or --check; no caller options');
 console.log(JSON.stringify(run(process.argv[2])));
}
