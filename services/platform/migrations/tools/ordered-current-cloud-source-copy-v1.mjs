// Linux source-regeneration evidence only. This separately versioned copier
// neither imports the native packet nor admits native/installed observations.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import childProcess from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const seedPath='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-A-cloud-v1';
const manifestSHA256='27438318b40b6664cb91e3d004a63b906589fd6f8c11dafd28755e2c32282e08';
const contractSHA256='f7da7f423768927a5497c22097189b77bdda4a266f8cce705b7074e2482dba35';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const builder='services/platform/migrations/tools/build-ordered-current-development.mjs';
const inventoryPath='services/platform/migrations/tools/ordered-current-native379-packet-v1-artifacts/source-inputs.json';
const inventorySHA256='34e3dfdfdd00c316eb9ad7300f8624f1b21543c95ed108578b739bb60e1e3229';
const supplementalPins=Object.freeze({
 'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/supplementary-query-contract2.json':'6b8fc25c4d5d0a379735d686fe1d6cde8245663a47d346dbf8cf1c11dd33418f',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/native-composition-manifest.json':'742061cb79130a9e866daa63babe914cf1052e4958ba40c798b8e030c1dd7899',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json':'c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/missing-reference-native-packet.json':'23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json':'76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/private-successor-packet.json':'6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0',
 'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/private-successor-reference.json':'b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80',
 'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/private-reference-alias-contract.json':'59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63',
 'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/supplementary-query-contract3.json':'2334ebbbad1382db7eafa47f81eec5b59f7721aaafa34b6b0d51311d959538ce',
 'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/remaining-reference-packet-manifest.json':'338026bf79be5535bf0f57206b679e5846526da676fee6b0adac75186083d7ea',
 'services/platform/migrations/sql/0072_production_temporal_discovery.up.sql':'e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940'
});


const packetNames=['contract.json','coverage.json','demand.sql','keys.sql','original.sql','resolution.sql','witness.sql'].map(name=>packet+'consolidated-capture-'+name);
const runtime=Object.freeze({version:'v22.23.1',platform:'linux',arch:'x64',executableSHA256:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068'});
const outputPins=Object.freeze(Object.fromEntries(Object.entries({
 'effective-contract4.json':'06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0',
 'development-manifest.json':'4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9',
 'development-module.sql':'4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74',
 'development-checkpoint.json':'905664791351c9714bfa4769ab94a6c11c6f1744c11ff56c165536fc71d13705',
 'development-collector.sql':'97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f',
 'development-admission.sql':'999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef',
 'consolidated-reference-contract.json':'d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff',
 'consolidated-reference-select.sql':'23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57'
}).map(([name,pin])=>[packet+name,pin])));
const limits=Object.freeze({fileBytes:33554432,seedBytes:134217728,inputBytes:134217728,outputBytes:134217728,receiptBytes:1048576,childMilliseconds:60000,childOutputBytes:33554432});
const fail=message=>{throw Error('cloud source copy refused: '+message);};
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const order=names=>names.sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b)));
const json=value=>JSON.stringify(value,(_,v)=>{
 if(['undefined','function','symbol','bigint'].includes(typeof v)||(typeof v==='number'&&!Number.isFinite(v)))fail('non-JSON receipt');
 return v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(order(Object.keys(v)).map(key=>[key,v[key]])):v;
});
const same=(a,b)=>json(a)===json(b);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&!Buffer.isBuffer(value);
function noOverrides(){
 if(process.env.NODE_OPTIONS||Object.keys(process.env).some(name=>/^ZASP_ORDERED_(?:CLOUD|CONSOLIDATED)_/.test(name)))fail('ambient authority');
}
function relativePath(relative){
 if(typeof relative!=='string'||!/^[-a-zA-Z0-9_./]+$/.test(relative)||path.isAbsolute(relative)||path.posix.normalize(relative)!==relative||relative.split('/').some(part=>['','.','..'].includes(part)))fail('repository-relative path authority');
 return relative;
}
function checkedPath(base,relative,leafDirectory=false){
 relativePath(relative);
 if(fs.realpathSync(base)!==path.resolve(base)||!fs.lstatSync(base).isDirectory())fail('root topology');
 let current=base;
 for(const [index,part]of relative.split('/').entries()){
  current=path.join(current,part);const stat=fs.lstatSync(current);
  const directory=index<relative.split('/').length-1||leafDirectory;
  if(stat.isSymbolicLink()||(directory?!stat.isDirectory():!stat.isFile()))fail('symlink/nonregular '+relative);
 }
 return current;
}
// Each consumed read is bounded and immediately compared with its fixed pin.
// O_NOFOLLOW and inode identity checks also refuse leaf replacement races.
function readPinned(base,relative,pin,maxBytes=limits.fileBytes){
 const filename=checkedPath(base,relative),before=fs.lstatSync(filename);
 if(before.size>maxBytes)fail('file byte cap '+relative);
 const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const opened=fs.fstatSync(fd);if(!opened.isFile()||opened.dev!==before.dev||opened.ino!==before.ino||opened.size>maxBytes)fail('read topology '+relative);
  const raw=fs.readFileSync(fd);if(!Buffer.isBuffer(raw)||raw.length>maxBytes||raw.length!==opened.size||sha(raw)!==pin)fail('consumed digest '+relative);
  checkedPath(base,relative);const after=fs.lstatSync(filename);
  if(after.dev!==opened.dev||after.ino!==opened.ino||after.size!==opened.size)fail('read changed '+relative);
  return raw;
 }finally{fs.closeSync(fd);}
}
function closedInventory(base,expected,prefix=''){
 const observed=[];
 for(const entry of fs.readdirSync(base,{withFileTypes:true})){
  const relative=prefix+entry.name;relativePath(relative);const filename=path.join(base,entry.name),stat=fs.lstatSync(filename);
  if(stat.isSymbolicLink())fail('inventory symlink '+relative);
  if(stat.isDirectory()){
   if(![...expected].some(name=>name.startsWith(relative+'/')))fail('unlisted directory '+relative);
   observed.push(...closedInventory(filename,expected,relative+'/'));
  }else if(!stat.isFile()||!expected.has(relative))fail('unlisted member '+relative);
  else observed.push(relative);
 }
 if(prefix===''&&!same(order(observed),order([...expected])))fail('missing/extra/duplicate inventory member');
 return observed;
}
function seedAuthority(){
 const seed=checkedPath(root,seedPath,true);
 const manifestRaw=readPinned(seed,'snapshot-manifest.json',manifestSHA256,limits.receiptBytes);
 const manifest=JSON.parse(manifestRaw);
 if(!object(manifest)||!same(order(Object.keys(manifest)),['files','format','source'])||manifest.format!==1||manifest.source!=='ordered-current-complete-capture-packet-A-cloud-v1'||!object(manifest.files)||Object.keys(manifest.files).length!==166)fail('fixed seed manifest schema');
 const pins=manifest.files;
 for(const [relative,pin]of Object.entries(pins))if(relativePath(relative)!==relative||typeof pin!=='string'||!/^[a-f0-9]{64}$/.test(pin))fail('seed member authority');
 if(pins[contractName]!==contractSHA256)fail('contract authority');
 closedInventory(seed,new Set([...Object.keys(pins),'snapshot-manifest.json']));
 let total=0;
 for(const relative of order(Object.keys(pins))){total+=readPinned(seed,relative,pins[relative]).length;if(total>limits.seedBytes)fail('seed byte cap');}
 const contract=JSON.parse(readPinned(seed,contractName,contractSHA256));
 if(contract.variant!=='A'||contract.sessionUser!=='zasp_test'||contract.installable!==false||contract.status!=='REFERENCE-CAPTURE-ONLY'||!object(contract.sourcePins)||Object.keys(contract.sourcePins).length!==159)fail('source contract schema');
 for(const [relative,pin]of Object.entries(contract.sourcePins))if(relativePath(relative)!==relative||pin!==pins[relative])fail('source roster authority');
 if(!same(order(Object.keys(pins).filter(name=>!Object.hasOwn(contract.sourcePins,name))),order([...packetNames])))fail('source/packet roster partition');
 for(const relative of [builder,'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go','services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'])if(!Object.hasOwn(contract.sourcePins,relative))fail('required cross-directory source');
 return {seed,pins:contract.sourcePins};
}
// A is a capture-source packet. Its159 pins do not contain eleven explicit
// development-producer reads. Join exactly this independent fixed subset;
// never use the remaining legacy84-member roster as a fallback file source.
function joinedAuthority(){
 const authority=seedAuthority();
 const raw=readPinned(root,inventoryPath,inventorySHA256,limits.receiptBytes),inventory=JSON.parse(raw);
 if(!object(inventory)||!same(order(Object.keys(inventory)),['files','format'])||inventory.format!=='ordered-current-native379-source-inputs-v1'||!object(inventory.files)||Object.keys(inventory.files).length!==84)fail('fixed supplemental inventory schema');
 for(const [relative,pin]of Object.entries(inventory.files)){
  relativePath(relative);
  if(!/^(tools|sql)\//.test(relative)||typeof pin!=='string'||!/^[a-f0-9]{64}$/.test(pin))fail('supplemental inventory path/digest');
 }
 const additions={...supplementalPins,[inventoryPath]:inventorySHA256};
 for(const [relative,pin]of Object.entries(supplementalPins)){
  if(inventory.files[relative.slice('services/platform/migrations/'.length)]!==pin)fail('fixed supplemental selection');
  readPinned(root,relative,pin);
 }
 for(const relative of Object.keys(additions))if(Object.hasOwn(authority.pins,relative))fail('joined source conflict');
 return {...authority,seedPins:authority.pins,pins:{...authority.pins,...additions}};
}
function verifyRuntime(){
 if(process.version!==runtime.version||process.platform!==runtime.platform||process.arch!==runtime.arch)fail('approved Linux Node runtime');
 const executable=fs.realpathSync(process.execPath);
 checkedPath(path.parse(executable).root,executable.slice(path.parse(executable).root.length));
 const before=fs.lstatSync(executable),fd=fs.openSync(executable,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>268435456||stat.dev!==before.dev||stat.ino!==before.ino)fail('Node executable topology');
  const hash=crypto.createHash('sha256'),chunk=Buffer.alloc(1048576);let count,total=0;
  while((count=fs.readSync(fd,chunk,0,chunk.length,null))!==0){total+=count;if(total>268435456)fail('Node executable cap');hash.update(chunk.subarray(0,count));}
  if(total!==stat.size||hash.digest('hex')!==runtime.executableSHA256)fail('Node executable digest');
  const after=fs.lstatSync(executable);if(after.ino!==stat.ino||after.dev!==stat.dev||after.size!==stat.size||fs.realpathSync(process.execPath)!==executable)fail('Node executable changed');
 }finally{fs.closeSync(fd);}
 return executable;
}
function bufferEntries(buffers,pins,cap){
 if(!object(buffers)||!same(order(Object.keys(buffers)),order(Object.keys(pins))))fail('buffer roster schema');
 let total=0;
 const entries=order(Object.keys(pins)).map(relative=>{
  relativePath(relative);const raw=buffers[relative];
  if(!Buffer.isBuffer(raw)||raw.length>limits.fileBytes||sha(raw)!==pins[relative])fail('buffer digest '+relative);
  total+=raw.length;if(total>cap)fail('buffer total cap');return {path:relative,bytes:raw.length,sha256:pins[relative]};
 });
 return entries;
}
function receiptFor(inputs,outputs,pins){
 const inputEntries=bufferEntries(inputs,pins,limits.inputBytes),outputEntries=bufferEntries(outputs,outputPins,limits.outputBytes);
 const receipt={format:'ordered-current-cloud-source-copy-v1',status:'SOURCE-REGENERATION-ONLY',installable:false,nativeVerified:false,executableReplacementVerified:false,captureAuthority:false,
  seed:{path:seedPath,manifestSHA256,contractSHA256,members:166,sourcePins:159},
  supplement:{inventoryPath,inventorySHA256,legacyMembers:84,dataInputs:11,authorityInputs:1,selection:'only-eleven-fixed-development-inputs'},runtime:{...runtime},limits:{...limits},
  inputs:inputEntries,outputs:outputEntries,inputReceiptSHA256:sha(json(inputEntries)),outputReceiptSHA256:sha(json(outputEntries)),
  resultAuthority:'source bytes and bounded regeneration only; native/installed/portability gates remain open'};
 if(Buffer.byteLength(json(receipt))>limits.receiptBytes)fail('receipt byte cap');return receipt;
}
function guarded(action){try{return action();}catch(error){if(error.message.startsWith('cloud source copy refused:'))throw error;fail(error.message);}}
export function buildOrderedCurrentCloudSourceCopyV1(){
 if(arguments.length!==0)fail('caller-selected source/output/hash/environment authority');
 return guarded(()=>{
  noOverrides();const executable=verifyRuntime(),authority=joinedAuthority();
  const temporary=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'zasp-cloud-source-copy-v1-'));
  try{
   if(fs.realpathSync(temporary)!==temporary||!fs.lstatSync(temporary).isDirectory()||fs.readdirSync(temporary).length!==0)fail('owned empty destination conflict');
   fs.chmodSync(temporary,0o700);
   const inputs={};
   for(const relative of order(Object.keys(authority.pins))){
    const raw=readPinned(Object.hasOwn(authority.seedPins,relative)?authority.seed:root,relative,authority.pins[relative]);
    const destination=path.join(temporary,relative);fs.mkdirSync(path.dirname(destination),{recursive:true,mode:0o700});
    // Validate created ancestors before exclusive writes; never overwrite.
    checkedPath(temporary,path.posix.dirname(relative),true);
    fs.writeFileSync(destination,raw,{flag:'wx',mode:0o600});inputs[relative]=raw;
   }
   closedInventory(temporary,new Set(Object.keys(authority.pins)));
   for(const relative of Object.keys(authority.pins))readPinned(temporary,relative,authority.pins[relative]);
   if(verifyRuntime()!==executable)fail('runtime changed before child');
   const result=childProcess.spawnSync(process.execPath,[path.join(temporary,builder),'--write'],{cwd:temporary,encoding:'utf8',timeout:limits.childMilliseconds,maxBuffer:limits.childOutputBytes,env:{PATH:path.dirname(process.execPath),TZ:'UTC',LANG:'C',LC_ALL:'C'}});
   verifyRuntime();
   if(result.error||result.signal||result.status!==0)fail('source regeneration did not complete');
   closedInventory(temporary,new Set([...Object.keys(authority.pins),...Object.keys(outputPins)]));
   for(const relative of Object.keys(authority.pins))readPinned(temporary,relative,authority.pins[relative]);
   const outputs=Object.fromEntries(order(Object.keys(outputPins)).map(relative=>[relative,readPinned(temporary,relative,outputPins[relative])]));
   const receipt=receiptFor(inputs,outputs,authority.pins);
   const final=joinedAuthority();if(!same(final.pins,authority.pins))fail('final seed drift');
   verifyRuntime();return {receipt,inputs,outputs};
  }finally{fs.rmSync(temporary,{recursive:true,force:true});}
 });
}
// Schema validation re-authenticates fixed A and every returned buffer. This
// authorizes only a source receipt, never a native packet or observation.
export function assertOrderedCurrentCloudSourceCopyV1(result){
 if(arguments.length!==1)fail('schema caller authority');
 return guarded(()=>{
  noOverrides();verifyRuntime();const authority=joinedAuthority();
  if(!object(result)||!same(order(Object.keys(result)),['inputs','outputs','receipt'])||!object(result.receipt)||!same(result.receipt,receiptFor(result.inputs,result.outputs,authority.pins)))fail('closed source-only result schema');
  return true;
 });
}
