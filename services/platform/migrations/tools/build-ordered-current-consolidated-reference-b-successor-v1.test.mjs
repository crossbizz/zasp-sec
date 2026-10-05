import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const seed='.superpowers/sdd/2026-10-05-reviewed-current-A-successor-v1/';
const destination='.superpowers/sdd/2026-10-05-reviewed-current-B-successor-v1/';
const emitter='services/platform/migrations/tools/build-ordered-current-consolidated-reference-b-successor-v1.mjs';
const emitterTest=emitter.replace(/\.mjs$/,'.test.mjs');
const prefix='services/platform/migrations/ordered_current/';
const contractName=prefix+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const read=name=>fs.readFileSync(path.join(root,name));
// A fresh checkout has the durable reviewed archive, not the ignored production
// seed. Restore only these fixed archive bytes into an owned test directory.
const archiveName='docs/internal/evidence/cloud-2026-10-05/current-A-successor-v1.tar.gz';
const archiveSHA256='b2a3a652bfa47e8b800421b791cb5f3ee6431c3241b6dfe38287d32586b6e9d3';
const archive=path.join(root,archiveName);
assert.equal(sha(read(archiveName)),archiveSHA256,'reviewed archive digest');
const listing=spawnSync('tar',['-tzf',archive],{encoding:'utf8',timeout:60000});
assert.equal(listing.status,0,listing.stderr);
const archiveMembers=listing.stdout.trimEnd().split('\n');
assert.equal(archiveMembers.length,165);assert.equal(new Set(archiveMembers).size,165);
for(const name of archiveMembers)assert.ok(name&&!path.isAbsolute(name)&&path.posix.normalize(name)===name&&!name.includes('\\')&&!name.split('/').some(part=>part===''||part==='.'||part==='..'),'archive member topology');
const kinds=spawnSync('tar',['-tvzf',archive],{encoding:'utf8',timeout:60000});
assert.equal(kinds.status,0,kinds.stderr);assert.ok(kinds.stdout.trimEnd().split('\n').every(line=>line.startsWith('-')),'archive regular files only');
const restored=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-b-successor-v1-reviewed-archive-')));
after(()=>fs.rmSync(restored,{recursive:true,force:true}));
try {
 const extraction=spawnSync('tar',['--extract','--gzip','--file',archive,'--directory',restored,'--no-same-owner','--no-same-permissions'],{encoding:'utf8',timeout:60000});
 assert.equal(extraction.status,0,extraction.stderr);
}catch(error){fs.rmSync(restored,{recursive:true,force:true});throw error;}
const seedRead=name=>fs.readFileSync(path.join(restored,name));
const manifestRaw=seedRead('snapshot-manifest.json');
assert.equal(sha(manifestRaw),'b3d03a9e7cd86daabbd80ead85cb30a5e98f856be35c08d15227fa710dd914fa');
const manifest=JSON.parse(manifestRaw);
const contract=JSON.parse(seedRead(contractName));
assert.equal(sha(seedRead(contractName)),'ad51418075709c382661ef4b4cede63c399eae97f5c266314a28a0b90c1e7c01');
assert.deepEqual(pathsUnder(restored),['snapshot-manifest.json',...Object.keys(manifest.files)].sort());
assert.deepEqual(archiveMembers.sort(),pathsUnder(restored));
for(const [name,digest]of Object.entries(manifest.files)){assert.equal(fs.lstatSync(path.join(restored,name)).isFile(),true,name);assert.equal(sha(seedRead(name)),digest,name);}
const json=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const ordered=value=>Object.fromEntries(Object.entries(value).sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b))));

function copy(from,to){fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(from,to);fs.chmodSync(to,0o600);}
function workspace(t){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-b-successor-v1-test-')));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 for(const name of ['snapshot-manifest.json',...Object.keys(manifest.files)])copy(path.join(restored,name),path.join(directory,seed,name));
 for(const name of [...Object.keys(contract.sourcePins),emitter,emitterTest])copy(path.join(root,name),path.join(directory,name));
 return directory;
}
function cli(directory,...args){return spawnSync(process.execPath,[path.join(directory,emitter),...args],{cwd:directory,encoding:'utf8',timeout:60000});}
function accepted(result){assert.equal(result.status,0,result.stderr||result.stdout);return JSON.parse(result.stdout);}
function refused(result){assert.notEqual(result.status,0);assert.equal(result.stdout,'');}
function pathsUnder(directory,prefix=''){
 return fs.readdirSync(directory,{withFileTypes:true}).flatMap(item=>item.isDirectory()?pathsUnder(path.join(directory,item.name),prefix+item.name+'/'):[prefix+item.name]).sort();
}

test('reviewed current A yields only exact B producer, owner and provenance deltas',async t=>{
 const directory=workspace(t);
 const {buildOrderedConsolidatedReferenceBSuccessorV1}=await import(pathToFileURL(path.join(directory,emitter)).href);
 assert.equal(sha(manifestRaw),'b3d03a9e7cd86daabbd80ead85cb30a5e98f856be35c08d15227fa710dd914fa');
 assert.equal(sha(seedRead(contractName)),'ad51418075709c382661ef4b4cede63c399eae97f5c266314a28a0b90c1e7c01');
 assert.equal(Object.keys(manifest.files).length,164);assert.equal(Object.keys(contract.sourcePins).length,157);
 const b=buildOrderedConsolidatedReferenceBSuccessorV1(),expected=structuredClone(contract);
 const oldProducer=seedRead(producer).toString();
 assert.equal(oldProducer.split('loadConsolidatedReference(directory)').length-1,2);
 const changed=Buffer.from(oldProducer.replaceAll('loadConsolidatedReference(directory)','loadConsolidatedReferenceVariantB(directory)'));
 expected.variant='B';expected.sessionUser='zasp_e2e';expected.sourcePins[producer]=sha(changed);
 for(const name of [emitter,emitterTest])expected.sourcePins[name]=sha(read(name));
 expected.sourcePins=ordered(expected.sourcePins);
 assert.deepEqual(b.contract,expected);assert.deepEqual(b.files[contractName],json(expected));assert.deepEqual(b.snapshotFiles[producer],changed);
 const bm=JSON.parse(b.manifestRaw),names=[...Object.keys(manifest.files),emitter,emitterTest].sort();
 assert.deepEqual(Object.keys(bm),['format','source','files']);assert.equal(bm.source,'ordered-current-complete-capture-packet-B-successor-v1');
 assert.deepEqual(Object.keys(bm.files).sort(),names);assert.deepEqual(Object.keys(b.snapshotFiles).sort(),names);
 assert.equal(Object.keys(b.contract.sourcePins).length,159);assert.equal(Object.keys(b.snapshotFiles).length,166);assert.equal(Object.keys(b.files).length,7);
 assert.equal(Object.keys(b.contract.rules).length,1862);
 assert.deepEqual(Object.keys(manifest.files).filter(name=>manifest.files[name]!==bm.files[name]).sort(),[producer,contractName].sort());
 for(const name of names){assert.equal(sha(b.snapshotFiles[name]),bm.files[name],name);if(![producer,contractName,emitter,emitterTest].includes(name))assert.deepEqual(b.snapshotFiles[name],seedRead(name),name);}
 assert.deepEqual(buildOrderedConsolidatedReferenceBSuccessorV1().manifestRaw,b.manifestRaw);
 assert.throws(()=>buildOrderedConsolidatedReferenceBSuccessorV1({seed,variant:'B'}));
});

test('admission refuses changed, missing, extra and symlink A or current sources before output',t=>{
 const directory=workspace(t),target=path.join(directory,destination);
 const cases=[
  ['manifest drift',seed+'snapshot-manifest.json','drift'],
  ['contract drift',seed+contractName,'drift'],
  ['packet drift',seed+prefix+'consolidated-capture-demand.sql','drift'],
  ['source drift',seed+producer,'drift'],
  ['source missing',seed+producer,'missing'],
  ['working drift',producer,'drift'],
  ['working missing',producer,'missing'],
  ['same-byte seed symlink',seed+producer,'symlink'],
  ['same-byte working symlink',producer,'symlink'],
 ];
 for(const [label,name,kind]of cases){
  const filename=path.join(directory,name),raw=fs.readFileSync(filename),link=filename+'.same';
  try{
   if(kind==='drift')fs.appendFileSync(filename,'\n');
   else {fs.unlinkSync(filename);if(kind==='symlink'){fs.writeFileSync(link,raw);fs.symlinkSync(link,filename);}}
   refused(cli(directory,'--write'));assert.equal(fs.existsSync(target),false,label);
  }finally{fs.rmSync(filename,{force:true});fs.writeFileSync(filename,raw);if(fs.existsSync(link))fs.unlinkSync(link);}
 }
 for(const name of [seed+'extra',seed+'services/platform/extra',seed+'unused-empty/']){
  const filename=path.join(directory,name);if(name.endsWith('/'))fs.mkdirSync(filename);else fs.writeFileSync(filename,'extra');
  refused(cli(directory,'--write'));assert.equal(fs.existsSync(target),false);fs.rmSync(filename,{recursive:true});
 }
 // Ancestor symlinks must refuse even if all descendant bytes remain identical.
 for(const name of [seed+'services/platform/apiserver','services/platform/apiserver']){
  const filename=path.join(directory,name),saved=filename+'.real';fs.renameSync(filename,saved);fs.symlinkSync(saved,filename);
  refused(cli(directory,'--write'));assert.equal(fs.existsSync(target),false);fs.unlinkSync(filename);fs.renameSync(saved,filename);
 }
});

test('fixed immutable output is exact, idempotent and refuses every conflict before writes',t=>{
 const directory=workspace(t),target=path.join(directory,destination);
 refused(cli(directory,'--check'));assert.equal(fs.existsSync(target),false);
 const sourceBefore=Object.fromEntries(Object.keys(contract.sourcePins).map(name=>[name,sha(fs.readFileSync(path.join(directory,name)))]));
 const seedBefore=Object.fromEntries(['snapshot-manifest.json',...Object.keys(manifest.files)].map(name=>[name,sha(fs.readFileSync(path.join(directory,seed,name)))]));
 const first=accepted(cli(directory,'--write'));assert.equal(first.variant,'B');assert.equal(first.sourcePins,159);assert.equal(first.members,167);
 assert.deepEqual(accepted(cli(directory,'--check')),first);assert.deepEqual(accepted(cli(directory,'--write')),first);
 const bm=JSON.parse(fs.readFileSync(path.join(target,'snapshot-manifest.json')));assert.equal(sha(fs.readFileSync(path.join(target,'snapshot-manifest.json'))),first.manifestSHA256);
 assert.deepEqual(pathsUnder(target),[...Object.keys(bm.files),'snapshot-manifest.json'].sort());
 for(const [name,digest]of Object.entries(bm.files))assert.equal(sha(fs.readFileSync(path.join(target,name))),digest,name);
 const missing=path.join(target,prefix+'consolidated-capture-keys.sql'),missingRaw=fs.readFileSync(missing);fs.unlinkSync(missing);
 const conflict=path.join(target,prefix+'consolidated-capture-witness.sql'),raw=fs.readFileSync(conflict);fs.writeFileSync(conflict,'conflict');
 refused(cli(directory,'--write'));assert.equal(fs.existsSync(missing),false);assert.equal(fs.readFileSync(conflict,'utf8'),'conflict');fs.writeFileSync(conflict,raw);fs.writeFileSync(missing,missingRaw);
 for(const name of ['extra','empty/']){const filename=path.join(target,name);if(name.endsWith('/'))fs.mkdirSync(filename);else fs.writeFileSync(filename,'extra');refused(cli(directory,'--write'));refused(cli(directory,'--check'));fs.rmSync(filename,{recursive:true});}
 fs.unlinkSync(conflict);fs.symlinkSync(path.join(directory,seed,prefix+'consolidated-capture-witness.sql'),conflict);refused(cli(directory,'--write'));assert.equal(fs.lstatSync(conflict).isSymbolicLink(),true);fs.unlinkSync(conflict);fs.writeFileSync(conflict,raw);
 for(const [name,digest]of Object.entries(sourceBefore))assert.equal(sha(fs.readFileSync(path.join(directory,name))),digest,name);
 for(const [name,digest]of Object.entries(seedBefore))assert.equal(sha(fs.readFileSync(path.join(directory,seed,name))),digest,name);
});

test('output root and parent symlinks, caller arguments and environment authority refuse',t=>{
 const directory=workspace(t),target=path.resolve(directory,destination);
 for(const args of [[],['--force'],['--write','--seed',seed],['--check','--owner','other'],['--write','--output','other']])refused(cli(directory,...args));
 const elsewhere=path.join(directory,'outside');fs.mkdirSync(elsewhere);fs.symlinkSync(elsewhere,target);refused(cli(directory,'--write'));assert.deepEqual(fs.readdirSync(elsewhere),[]);fs.unlinkSync(target);
 const sdd=path.join(directory,'.superpowers/sdd'),saved=sdd+'.real';fs.renameSync(sdd,saved);fs.symlinkSync(saved,sdd);refused(cli(directory,'--write'));fs.unlinkSync(sdd);fs.renameSync(saved,sdd);
 const result=spawnSync(process.execPath,[path.join(directory,emitter),'--write'],{cwd:directory,encoding:'utf8',timeout:60000,env:{...process.env,ZASP_ORDERED_CONSOLIDATED_REFERENCE_DIR:elsewhere,ZASP_ORDERED_CONSOLIDATED_REFERENCE_OUTPUT:elsewhere,ZASP_ORDERED_CONSOLIDATED_REFERENCE_VARIANT:'A',ZASP_ORDERED_CONSOLIDATED_REFERENCE_OWNER:'other'}});
 assert.equal(accepted(result).variant,'B');assert.deepEqual(fs.readdirSync(elsewhere),[]);
});
