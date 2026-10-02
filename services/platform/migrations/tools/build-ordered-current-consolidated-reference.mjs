import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {buildOrderedCaptureClosure,assertOrderedCaptureClosure} from './ordered-current-capture-closure.mjs';
import {prepareOrderedCaptureRule,compileOrderedCaptureRule} from './ordered-current-capture-sql.mjs';
import {readOrderedCurrentBuildSourceInventoryV1} from './ordered-current-build-source-inventory-v1.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const root=fileURLToPath(new URL('../../../../',import.meta.url));
const p7='.'+'superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const successorSnapshot='ordered-current-complete-capture-packet-A-native22-precision-final4/';
const artifactPrefix='services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/';
const artifactNames=Object.freeze({'ordered-current-effective-contract3.json':'effective-contract3.json','ordered-current-effective-catalog1.json':'effective-catalog1.json','ordered-current-inventory-compiled.json':'inventory-compiled.json','ordered-current-supplementary-reference1.json':'supplementary-reference1.json','ordered-current-remaining-reference1.json':'remaining-reference1.json','ordered-current-private-reference-alias1.json':'private-reference-alias1.json','ordered-current-complete-capture-wire-contract.md':'complete-capture-wire-contract.md','ordered-current-complete-capture-wire-vectors.json':'complete-capture-wire-vectors.json'});
const packetPrefix='services/platform/migrations/ordered_current/';
const phases=['demand','keys','original','resolution','witness'];
const searchPaths={'demand':'pg_catalog, public',keys:'pg_catalog',original:'pg_catalog, public',resolution:'pg_catalog, public',witness:'pg_catalog, public'};
const packetNames=['consolidated-capture-coverage.json','consolidated-capture-contract.json',...phases.map(phase=>`consolidated-capture-${phase}.sql`)];
const fixedInputs={
 'ordered-current-effective-contract3.json':'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',
 'ordered-current-effective-catalog1.json':'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',
 'ordered-current-inventory-compiled.json':'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 'ordered-current-supplementary-reference1.json':'484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b',
 'ordered-current-remaining-reference1.json':'cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797',
 'ordered-current-private-reference-alias1.json':'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607',
 'ordered-current-complete-capture-wire-contract.md':'563fe703c7dbd43edc4b87595d168e4aaaf1a13cf096779c448e0795c38509d0',
 'ordered-current-complete-capture-wire-vectors.json':'438c2f9e563ce01d0052c4e8556d1dea93185d9494d2c46f4d25b1616f059a96'
};
const acceptedNames=['ordered-current-effective-catalog1.json','ordered-current-supplementary-reference1.json','ordered-current-remaining-reference1.json','ordered-current-private-reference-alias1.json'];
const producerPaths=[
 'services/platform/apiserver/authorization_worker_consolidated_reference_boundary_test.go',
 'services/platform/apiserver/authorization_worker_consolidated_reference_controls_test.go',
 'services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go'
];
const excludedPinsPath='services/platform/apiserver/authorization_worker_consolidated_reference_pins_test.go';
const extraSourcePaths=[
 'services/platform/migrations/tools/build-ordered-current-consolidated-reference.test.mjs',
 'services/platform/migrations/tools/ordered-current-consolidated-reference.mjs',
 'services/platform/migrations/tools/ordered-current-consolidated-reference.test.mjs',
 'services/platform/migrations/sql/0080_authorization_worker_ordered_current_integrity.sql'
];
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const utf8=(left,right)=>Buffer.compare(Buffer.from(left),Buffer.from(right));
const sortedObject=entries=>Object.fromEntries([...entries].sort(([left],[right])=>utf8(left,right)));
const read=relative=>{
 if(typeof relative!=='string'||path.posix.normalize(relative)!==relative||relative.includes('\\')||relative.split('/').some(part=>part===''||part==='.'||part==='..')||path.isAbsolute(relative))throw Error('complete capture emitter source topology path');
 const base=path.resolve(root);
 if(fs.realpathSync(base)!==base||!fs.lstatSync(base).isDirectory())throw Error('complete capture emitter source topology root');
 const absolute=path.resolve(base,relative);
 if(!absolute.startsWith(base+path.sep))throw Error('complete capture emitter source topology containment');
 let current=base;
 const parts=relative.split('/');
 for(const [index,part]of parts.entries()){
  current=path.join(current,part);
  const item=fs.lstatSync(current);
  if(item.isSymbolicLink()||(index===parts.length-1?!item.isFile():!item.isDirectory()))throw Error('complete capture emitter source topology nonregular/symlink '+relative);
 }
 return fs.readFileSync(absolute);
};
function readFixedInputs(){
 const raws={};
 for(const [name,digest] of Object.entries(fixedInputs)){
  const relative=artifactPrefix+artifactNames[name],raw=read(relative);
  if(sha(raw)!==digest)throw Error('complete capture emitter input pin '+name);
  raws[name]=raw;
 }
 return raws;
}
function relativePath(filename){
 const relative=path.relative(root,path.resolve(filename)).split(path.sep).join('/');
 if(relative===''||relative==='..'||relative.startsWith('../')||path.isAbsolute(relative))throw Error('complete capture emitter source path');
 return relative;
}
function localImports(filename,source){
 const found=[];
 for(const match of source.matchAll(/^\s*(?:import|export)\s+(?:[^'"\n]*?\s+from\s+)?['"](\.[^'"]+\.mjs)['"]/gm))found.push(match[1]);
 const dynamic=[...source.matchAll(/\bimport\s*\(\s*(['"])(\.[^'"]+\.mjs)\1\s*\)/g)];
 if((source.match(/\bimport\s*\(/g)??[]).length!==dynamic.length)throw Error('complete capture emitter dynamic import '+relativePath(filename));
 for(const match of dynamic)found.push(match[2]);
 return found;
}
function sourceInventory(currentInputs){
 const entry=fileURLToPath(import.meta.url),producer=fileURLToPath(new URL('./build-ordered-current-development.mjs',import.meta.url)),pending=[entry,producer],visited=new Set,files=new Set;
 while(pending.length){
  const filename=path.resolve(pending.pop());
  if(visited.has(filename))continue;
  visited.add(filename);
  const relative=relativePath(filename),source=read(relative).toString('utf8');
  files.add(relative);
  const test=filename.replace(/\.mjs$/,'.test.mjs');
  if(test!==filename&&fs.existsSync(test))files.add(relativePath(test));
  // This one approved adapter has a fixed archived entry, verified by its
  // 32-file declared inventory. Account for that complete graph as data, not
  // by relaxing the general dynamic-import guard or ignoring dependencies.
  if(relative==='services/platform/migrations/tools/ordered-current-private-historical-v1.mjs'){
   if(sha(Buffer.from(source))!==currentInputs[relative])throw Error('complete capture emitter historical adapter authority');
   for(const declared of Object.keys(currentInputs).filter(name=>name.startsWith('services/platform/migrations/tools/ordered-current-private-historical-v1/')))files.add(declared);
   continue;
  }
  for(const specifier of localImports(filename,source))pending.push(fileURLToPath(new URL(specifier,pathToFileURL(filename))));
 }
 for(const relative of [...extraSourcePaths,...producerPaths]){
  if(!fs.existsSync(path.join(root,relative)))throw Error('complete capture emitter source absent '+relative);
  files.add(relative);
 }
 if(files.has(excludedPinsPath))throw Error('complete capture emitter pins cycle');
 return [...files].sort(utf8);
}
function addClosureSourcePins(sourceFiles,sourcePins){
 if(!sourcePins||Array.isArray(sourcePins)||typeof sourcePins!=='object')throw Error('complete capture emitter closure source pins');
 for(const [declared,digest] of Object.entries(sourcePins).sort(([left],[right])=>utf8(left,right))){
  if(typeof digest!=='string'||!/^[0-9a-f]{64}$/.test(digest))throw Error('complete capture emitter closure source pin '+declared);
  const relative=declared.includes('/')?declared:artifactPrefix+artifactNames[declared],raw=read(relative);
  if(sha(raw)!==digest)throw Error('complete capture emitter closure source pin '+relative);
  if(sourceFiles[relative]&&!sourceFiles[relative].equals(raw))throw Error('complete capture emitter closure source conflict '+relative);
  sourceFiles[relative]=raw;
 }
}
function phaseSQL(phase,queries){
 if(queries.length===0)throw Error('complete capture emitter empty phase '+phase);
 return Buffer.from(queries.map((query,index)=>`SELECT * FROM (\n${query}\n) AS capture_${phase}_${String(index+1).padStart(4,'0')}`).join('\nUNION ALL\n')+'\n');
}
function provenance(compiled,references){
 const values=references.map(reference=>({postgres:reference.postgres,serverVersionNum:reference.serverVersionNum,pgcrypto:reference.pgcrypto,variant:reference.variant,sessionUser:reference.sessionUser}));
 if(values.some(value=>value.postgres!==values[0].postgres||value.serverVersionNum!=='180003'||value.pgcrypto!=='1.4'||value.variant!=='A'||value.sessionUser!=='zasp_test'))throw Error('complete capture emitter provenance');
 if(compiled.checksum!=='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9'||sha(compiled.source)!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850')throw Error('complete capture emitter compiler');
 return values[0];
}

export function buildOrderedConsolidatedReference() {
 const currentInventory=readOrderedCurrentBuildSourceInventoryV1();
 if(Object.keys(currentInventory).sort().join(',')!=='executable,format,inputs,installable,native,status'||currentInventory.format!=='ordered-current-build-source-inventory-v1'||currentInventory.status!=='SOURCE-PROVENANCE-ONLY'||currentInventory.installable!==false||currentInventory.native!==false||currentInventory.executable!==false||Object.keys(currentInventory.inputs).length!==53)throw Error('complete capture emitter source inventory shape/status/flags');
 const inputs=readFixedInputs();
 const sourcePath='ordered-current-effective-contract3.json',catalogPath='ordered-current-effective-catalog1.json',compiledPath='ordered-current-inventory-compiled.json';
 const sourceContract=JSON.parse(inputs[sourcePath]),catalog=JSON.parse(inputs[catalogPath]),compiled=JSON.parse(inputs[compiledPath]);
 const acceptedEvidence=Object.fromEntries(acceptedNames.map(name=>[name,inputs[name]]));
 const references=acceptedNames.slice(1).map(name=>JSON.parse(inputs[name]));
 const referenceProvenance=provenance(compiled,references);
 const closure=buildOrderedCaptureClosure({sourceContract,catalog,acceptedEvidence});
 assertOrderedCaptureClosure(closure);

 const queries=Object.fromEntries(phases.map(phase=>[phase,[]])),ruleIDs=Object.fromEntries(phases.map(phase=>[phase,[]])),rules={};
 for(const rawRule of closure.rawRules){
  const rule=prepareOrderedCaptureRule(rawRule),compiledRule=compileOrderedCaptureRule(rule);
  if(compiledRule.demand)queries.demand.push(compiledRule.demand);
  if(compiledRule.keys)queries.keys.push(compiledRule.keys);
  queries[rule.sqlPhase??'original'].push(compiledRule.original);
  for(const [id,contractRule] of Object.entries(compiledRule.rules)){
   if(Object.hasOwn(rules,id)||!phases.includes(contractRule.phase))throw Error('complete capture emitter rule '+id);
   rules[id]=contractRule;ruleIDs[contractRule.phase].push(id);
  }
 }
 const sqlFiles=Object.fromEntries(phases.map(phase=>[packetPrefix+`consolidated-capture-${phase}.sql`,phaseSQL(phase,queries[phase])]));
 const coverageRaw=json(closure);

 const sourceFiles=Object.fromEntries(Object.entries(inputs).map(([name,raw])=>[artifactPrefix+artifactNames[name],raw]));
 for(const relative of sourceInventory(currentInventory.inputs))sourceFiles[relative]=read(relative);
 addClosureSourcePins(sourceFiles,closure.sourcePins);
 addClosureSourcePins(sourceFiles,currentInventory.inputs);
 const sourcePins=sortedObject(Object.entries(sourceFiles).map(([relative,raw])=>[relative,sha(raw)]));
 if(Object.hasOwn(sourcePins,excludedPinsPath))throw Error('complete capture emitter pins companion');
 const contractPhases=phases.map(phase=>({id:phase,searchPath:searchPaths[phase],timeZone:'UTC',sqlSHA256:sha(sqlFiles[packetPrefix+`consolidated-capture-${phase}.sql`]),ruleIds:ruleIDs[phase]}));
 const contract={
  format:'ordered-current-complete-capture-contract-v1',status:'REFERENCE-CAPTURE-ONLY',installable:false,captureReady:true,sourceFrameVersion:1,
  compilerArtifactSHA256:fixedInputs[compiledPath],compilerChecksum:compiled.checksum,compiledSourceSHA256:sha(compiled.source),sourceContractSHA256:fixedInputs[sourcePath],closureSHA256:sha(coverageRaw),catalog1FileSHA256:fixedInputs[catalogPath],
  requiredPostgres:referenceProvenance.postgres,requiredServerVersionNum:'180003',pgcrypto:'1.4',variant:'A',sessionUser:'zasp_test',requiredRole:'zasp_discovery_authority',requiredTimeZone:'UTC',maxRows:10000,maxBytes:16777216,
  phases:contractPhases,rules,reusedEvidence:[],sourcePins
 };
 const files={
  [packetPrefix+'consolidated-capture-coverage.json']:coverageRaw,
  [packetPrefix+'consolidated-capture-contract.json']:json(contract),
  ...sqlFiles
 };
 const orderedFiles=Object.fromEntries(packetNames.map(name=>[packetPrefix+name,files[packetPrefix+name]]));
 const snapshotFiles=sortedObject([...Object.entries(sourceFiles),...Object.entries(orderedFiles)]);
 const manifest={format:1,source:'ordered-current-task2-tracked-authority',files:sortedObject(Object.entries(snapshotFiles).map(([relative,raw])=>[relative,sha(raw)]))};
 return {files:orderedFiles,manifestRaw:json(manifest),snapshotFiles,contract,closure};
}

function compare(relative,expected,label){
 let actual;
 try{actual=read(relative);}catch(error){throw Error(label+' absent '+relative,{cause:error});}
 if(!actual.equals(expected))throw Error(label+' differs '+relative);
}
function snapshotState(filename){
 try{return fs.lstatSync(filename);}catch(error){if(error.code==='ENOENT')return null;throw error;}
}
function snapshotInventory(directory,expected,prefix=''){
 for(const item of fs.readdirSync(directory,{withFileTypes:true})){
  const relative=prefix+item.name,filename=path.join(directory,item.name);
  if(item.isSymbolicLink())throw Error('complete capture snapshot symlink '+relative);
  if(item.isDirectory()){
   if(![...expected].some(name=>name.startsWith(relative+'/')))throw Error('complete capture snapshot unlisted directory '+relative);
   snapshotInventory(filename,expected,relative+'/');
  }else if(!item.isFile()||!expected.has(relative))throw Error('complete capture snapshot unlisted member '+relative);
 }
}
function snapshot(mode,built){
 const relativeRoot=p7+successorSnapshot,output=path.join(root,relativeRoot);
 const members={...built.snapshotFiles,'snapshot-manifest.json':built.manifestRaw},expected=new Set(Object.keys(members));
 let parent=root;
 for(const part of relativeRoot.split('/').slice(0,-1)){
  parent=path.join(parent,part);const item=snapshotState(parent);
  if(item&&(!item.isDirectory()||item.isSymbolicLink()))throw Error('complete capture snapshot parent conflict '+part);
 }
 const current=snapshotState(output);
 if(current&&(!current.isDirectory()||current.isSymbolicLink()))throw Error('complete capture snapshot root conflict');
 if(current)snapshotInventory(output,expected);
 for(const [name,raw]of Object.entries(members)){
  const filename=path.join(output,name),item=snapshotState(filename);
  if(item&&(!item.isFile()||item.isSymbolicLink()||!fs.readFileSync(filename).equals(raw)))throw Error('complete capture snapshot immutable conflict '+name);
  if(mode==='--check-snapshot'&&!item)throw Error('complete capture snapshot member absent '+name);
 }
 if(mode==='--write-snapshot')for(const [name,raw]of Object.entries(members)){
  const filename=path.join(output,name);if(snapshotState(filename))continue;
  fs.mkdirSync(path.dirname(filename),{recursive:true});fs.writeFileSync(filename,raw,{flag:'wx'});
 }
 return {variant:'A',snapshot:relativeRoot,members:expected.size,manifestSHA256:sha(built.manifestRaw),contractSHA256:sha(built.files[packetPrefix+'consolidated-capture-contract.json'])};
}
function run(mode){
 const built=buildOrderedConsolidatedReference();
 if(mode==='--write-snapshot'||mode==='--check-snapshot')return snapshot(mode,built);
 if(mode==='--check'){
  for(const [relative,raw] of Object.entries(built.files))compare(relative,raw,'complete capture output');
 }else{
  for(const [relative,raw] of Object.entries(built.files)){
   const filename=path.join(root,relative);fs.mkdirSync(path.dirname(filename),{recursive:true});fs.writeFileSync(filename,raw);
  }
 }
 return {variant:'A',files:Object.keys(built.files).length,rules:Object.keys(built.contract.rules).length,manifestSHA256:sha(built.manifestRaw),contractSHA256:sha(built.files[packetPrefix+'consolidated-capture-contract.json'])};
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url){
 if(process.argv.length!==3||!['--write','--check','--write-snapshot','--check-snapshot'].includes(process.argv[2]))throw Error('use --write, --check, --write-snapshot or --check-snapshot');
 console.log(JSON.stringify(run(process.argv[2])));
}
