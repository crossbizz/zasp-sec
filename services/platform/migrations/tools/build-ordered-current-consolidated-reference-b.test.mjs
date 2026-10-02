import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {buildOrderedConsolidatedReferenceB} from './build-ordered-current-consolidated-reference-b.mjs';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const p7='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const seed=p7+'ordered-current-complete-capture-packet-A-native22-precision-final4/';
const destination=p7+'ordered-current-complete-capture-packet-B-native22-precision-final4/';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const emitter='services/platform/migrations/tools/build-ordered-current-consolidated-reference-b.mjs';
const emitterTest=emitter.replace(/\.mjs$/,'.test.mjs');
const node='/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const read=relative=>fs.readFileSync(path.join(root,relative));
const seedManifestRaw=read(seed+'snapshot-manifest.json'),seedManifest=JSON.parse(seedManifestRaw);
const aContract=JSON.parse(read(seed+contractName));
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
function ownedWorkspace(t){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-b-emitter-test-')));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 for(const name of [...Object.keys(seedManifest.files),emitter,emitterTest]){
  const to=path.join(directory,name);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(path.join(root,name),to);
 }
 for(const name of ['snapshot-manifest.json',...Object.keys(seedManifest.files)]){
  const to=path.join(directory,seed,name);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(path.join(root,seed,name),to);
 }
 // The closure adapter intentionally resolves its fixed inputs from the
 // historical p7 root.  Seed members are tracked under the generated source
 // inventory, so stage the same bytes at that authoritative adapter boundary
 // in the isolated workspace.
 const fixedNames=['ordered-current-effective-contract3.json','ordered-current-effective-catalog1.json','ordered-current-inventory-compiled.json','ordered-current-supplementary-reference1.json','ordered-current-remaining-reference1.json','ordered-current-private-reference-alias1.json','ordered-current-complete-capture-wire-contract.md','ordered-current-complete-capture-wire-vectors.json'];
 for(const name of fixedNames){
  const source=path.join(directory,seed,'services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts',name.replace(/^ordered-current-effective-contract3\.json$/,'effective-contract3.json').replace(/^ordered-current-effective-catalog1\.json$/,'effective-catalog1.json').replace(/^ordered-current-inventory-compiled\.json$/,'inventory-compiled.json').replace(/^ordered-current-supplementary-reference1\.json$/,'supplementary-reference1.json').replace(/^ordered-current-remaining-reference1\.json$/,'remaining-reference1.json').replace(/^ordered-current-private-reference-alias1\.json$/,'private-reference-alias1.json').replace(/^ordered-current-complete-capture-wire-contract\.md$/,'complete-capture-wire-contract.md').replace(/^ordered-current-complete-capture-wire-vectors\.json$/,'complete-capture-wire-vectors.json'));
  const to=path.join(directory,seed,name);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(source,to);
 }
 return directory;
}
function cli(directory,...args){return spawnSync(node,[path.join(directory,emitter),...args],{cwd:directory,encoding:'utf8',timeout:60000});}
function success(result){assert.equal(result.status,0,result.stderr||result.stdout);return JSON.parse(result.stdout);}
function refused(result){assert.notEqual(result.status,0,'unreviewed input or overwrite was accepted');assert.equal(result.stdout,'');}
function pathsUnder(directory,prefix=''){
 return fs.readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
  const name=prefix+entry.name;return entry.isDirectory()?pathsUnder(path.join(directory,entry.name),name+'/'):[name];
 }).sort();
}

// Catches an owner-only relabel that omits the fixed B loader or exact source binding.
test('B binds only the declared owner, producer and source-inventory deltas',()=>{
 assert.equal(sha(seedManifestRaw),'71dffc8ab32e112f92e94e4fb10eec52c399f5492a57111a311a1c3dc4065609');
 assert.equal(sha(read(seed+contractName)),'1162fbf060850000df19af6fcc8e990b4c03d2f55311bcaf56b5b1b1c1d78a9d');
 const b=buildOrderedConsolidatedReferenceB(),manifest=JSON.parse(b.manifestRaw);
 assert.equal(b.contract.variant,'B');assert.equal(b.contract.sessionUser,'zasp_e2e');
 const expectedContract=structuredClone(aContract);expectedContract.variant='B';expectedContract.sessionUser='zasp_e2e';
 const oldProducer=read(seed+producer).toString();
 assert.equal(oldProducer.split('loadConsolidatedReference(directory)').length-1,2);
 const expectedProducer=Buffer.from(oldProducer.replaceAll('loadConsolidatedReference(directory)','loadConsolidatedReferenceVariantB(directory)'));
 assert.deepEqual(b.snapshotFiles[producer],expectedProducer);
 expectedContract.sourcePins[producer]=sha(expectedProducer);
 for(const name of [emitter,emitterTest])expectedContract.sourcePins[name]=sha(read(name));
 expectedContract.sourcePins=Object.fromEntries(Object.entries(expectedContract.sourcePins).sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b))));
 assert.deepEqual(b.contract,expectedContract);assert.deepEqual(b.files[contractName],json(expectedContract));
 assert.equal(Object.keys(b.contract.rules).length,1862);assert.equal(Object.keys(b.contract.sourcePins).length,95);
 assert.deepEqual(Object.keys(b.files).sort(),Object.keys(seedManifest.files).filter(name=>name.startsWith(packet)).sort());
 assert.equal(manifest.source,'ordered-current-complete-capture-packet-B');assert.equal(manifest.format,1);
 const expectedNames=[...Object.keys(seedManifest.files),emitter,emitterTest].sort();
 assert.deepEqual(Object.keys(manifest.files).sort(),expectedNames);assert.deepEqual(Object.keys(b.snapshotFiles).sort(),expectedNames);
 const changed=Object.keys(seedManifest.files).filter(name=>manifest.files[name]!==seedManifest.files[name]).sort();
 assert.deepEqual(changed,[producer,contractName].sort());
 for(const name of expectedNames){assert.equal(sha(b.snapshotFiles[name]),manifest.files[name],name);if(![producer,contractName,emitter,emitterTest].includes(name))assert.deepEqual(b.snapshotFiles[name],read(seed+name),name);}
 const again=buildOrderedConsolidatedReferenceB();assert.deepEqual(again.manifestRaw,b.manifestRaw);
 for(const [name,raw]of Object.entries(b.files))assert.deepEqual(again.files[name],raw,name);
 assert.throws(()=>buildOrderedConsolidatedReferenceB({variant:'B',sessionUser:'anything',seedSHA256:sha(seedManifestRaw)}));
});

// Catches bypassing the fixed seed, member pins, current source graph or shared A packet guard.
test('CLI refuses unknown, missing or drifted A evidence before any B output',t=>{
 const directory=ownedWorkspace(t),results=[];
 for(const [label,name,mutation]of [
  ['unknown seed',seed+'snapshot-manifest.json',raw=>Buffer.concat([raw,Buffer.from('\n')])],
  ['missing member',seed+producer,()=>null],
  ['drifted member',seed+producer,raw=>Buffer.concat([raw,Buffer.from('// drift\n')])],
  ['working source drift',producer,raw=>Buffer.concat([raw,Buffer.from('// drift\n')])],
  ['shared A packet drift',packet+'consolidated-capture-demand.sql',raw=>Buffer.concat([raw,Buffer.from('-- drift\n')])]
 ]){
  const file=path.join(directory,name),original=fs.readFileSync(file),changed=mutation(original);
  try{
   if(changed===null)fs.unlinkSync(file);else fs.writeFileSync(file,changed);
   const result=cli(directory,'--write');results.push({label,refused:result.status!==0&&result.stdout==='',created:fs.existsSync(path.join(directory,destination))});
  }finally{fs.writeFileSync(file,original);}
 }
 assert.deepEqual(results.map(row=>[row.label,row.refused,row.created]),[
  ['unknown seed',true,false],['missing member',true,false],['drifted member',true,false],['working source drift',true,false],['shared A packet drift',true,false]
 ]);
});

test('fixed CLI publishes only B, verifies every member and never overwrites a conflict',t=>{
 const directory=ownedWorkspace(t),target=path.join(directory,destination);
 const before=Object.fromEntries(Object.keys(seedManifest.files).map(name=>[name,sha(fs.readFileSync(path.join(directory,name)))]));
 const first=success(cli(directory,'--write'));
 assert.equal(first.variant,'B');assert.equal(first.files,7);assert.equal(first.rules,1862);
 assert.equal(fs.existsSync(target),true);
 const manifestRaw=fs.readFileSync(path.join(target,'snapshot-manifest.json')),manifest=JSON.parse(manifestRaw);
 assert.equal(sha(manifestRaw),first.manifestSHA256);
 assert.equal(sha(fs.readFileSync(path.join(target,contractName))),first.contractSHA256);
 assert.deepEqual(pathsUnder(target),[...Object.keys(manifest.files),'snapshot-manifest.json'].sort());
 for(const [name,digest]of Object.entries(manifest.files))assert.equal(sha(fs.readFileSync(path.join(target,name))),digest,name);
 assert.deepEqual(success(cli(directory,'--write')),first);assert.deepEqual(success(cli(directory,'--check')),first);
 for(const [name,digest]of Object.entries(before))assert.equal(sha(fs.readFileSync(path.join(directory,name))),digest,name);
 const conflict=path.join(target,packet+'consolidated-capture-witness.sql'),original=fs.readFileSync(conflict);
 fs.writeFileSync(conflict,'conflict');refused(cli(directory,'--write'));assert.equal(fs.readFileSync(conflict,'utf8'),'conflict');
 fs.writeFileSync(conflict,original);
 fs.writeFileSync(path.join(target,'unlisted'),'unknown');refused(cli(directory,'--write'));refused(cli(directory,'--check'));
 fs.unlinkSync(path.join(target,'unlisted'));
 fs.unlinkSync(conflict);fs.symlinkSync(path.join(directory,packet+'consolidated-capture-witness.sql'),conflict);
 refused(cli(directory,'--write'));assert.equal(fs.lstatSync(conflict).isSymbolicLink(),true);
 for(const [name,digest]of Object.entries(before))assert.equal(sha(fs.readFileSync(path.join(directory,name))),digest,name);
});

// Catches exposing a caller-selected destination, owner, variant or trust pin.
test('CLI refuses extra arguments and has no ambient output or owner override',t=>{
 const directory=ownedWorkspace(t);
 for(const args of [[],['--variant','B'],['--write','--output','elsewhere'],['--check','--owner','zasp_test'],['--force'],['--write','--seed','anything']])refused(cli(directory,...args));
 assert.equal(fs.existsSync(path.join(directory,destination)),false);
 refused(cli(directory,'--check'));
 const elsewhere=path.join(directory,'caller-output');
 const result=spawnSync(node,[path.join(directory,emitter),'--write'],{cwd:directory,encoding:'utf8',timeout:60000,env:{...process.env,ZASP_ORDERED_CONSOLIDATED_REFERENCE_DIR:elsewhere,ZASP_ORDERED_CONSOLIDATED_REFERENCE_OUTPUT:elsewhere,ZASP_ORDERED_CONSOLIDATED_REFERENCE_VARIANT:'A',ZASP_ORDERED_CONSOLIDATED_REFERENCE_OWNER:'zasp_test'}});
 assert.equal(success(result).variant,'B');assert.equal(fs.existsSync(path.join(directory,destination)),true);assert.equal(fs.existsSync(elsewhere),false);
});
