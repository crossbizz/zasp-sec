import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {buildOrderedConsolidatedReference} from './build-ordered-current-consolidated-reference.mjs';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const tools='services/platform/migrations/tools/';
const emitter=tools+'build-ordered-current-consolidated-reference-cloud-v1.mjs';
const emitterTest=emitter.replace(/\.mjs$/,'.test.mjs');
const p7='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const aPath=p7+'ordered-current-complete-capture-packet-A-cloud-v1/';
const bPath=p7+'ordered-current-complete-capture-packet-B-cloud-v1/';
const packet='services/platform/migrations/ordered_current/';
const contractName=packet+'consolidated-capture-contract.json';
const producer='services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go';
const descriptor=tools+'ordered-current-worker-source-descriptor-v1.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const baseline=buildOrderedConsolidatedReference();
assert.equal(sha(baseline.manifestRaw),'a0087046b6992479753a3e59ba196e735ab1a6f6608c387e79100e1bb1f81400');
assert.equal(sha(baseline.files[contractName]),'6f5a8cc081f159b9c4e130de5969af47f2b98ccde477b3e932a2b56db4d33870');

function fixture(t){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-cloud-v1-')));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 for(const relative of [...Object.keys(baseline.contract.sourcePins),emitter,emitterTest]){
  if(!fs.existsSync(path.join(root,relative)))continue; // RED has no new emitter yet.
  const target=path.join(directory,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(root,relative),target);
 }
 // Legacy installed packets remain stale and historical paths remain distinct.
 for(const relative of Object.keys(baseline.files)){
  const target=path.join(directory,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(root,relative),target);
 }
 for(const variant of ['A','B']){
  const historical=path.join(directory,p7+`ordered-current-complete-capture-packet-${variant}-native22-precision-final4/kept-historical`);
  fs.mkdirSync(path.dirname(historical),{recursive:true});fs.writeFileSync(historical,'immutable historical '+variant);
 }
 return directory;
}
const cli=(directory,mode,options={})=>spawnSync(process.execPath,[path.join(directory,emitter),...mode],{cwd:directory,encoding:'utf8',timeout:60000,...options});
function success(result){assert.equal(result.error,undefined,String(result.error));assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);}
function refusal(result){assert.equal(result.error,undefined,String(result.error));assert.notEqual(result.status,0,'unreviewed authority accepted');assert.equal(result.stdout,'');assert.doesNotMatch(result.stderr,/UNREVIEWED_SOURCE_EXECUTED/);}
function tree(directory,prefix=''){
 if(!fs.existsSync(directory))return {};
 return Object.fromEntries(fs.readdirSync(directory,{withFileTypes:true}).flatMap(item=>{
  const relative=prefix+item.name,filename=path.join(directory,item.name);
  return item.isDirectory()?Object.entries(tree(filename,relative+'/')):[[relative,item.isSymbolicLink()?'symlink:'+fs.readlinkSync(filename):sha(fs.readFileSync(filename))]];
 }).sort(([a],[b])=>a.localeCompare(b)));
}
function published(directory,relative){
 const manifestRaw=fs.readFileSync(path.join(directory,relative,'snapshot-manifest.json')),manifest=JSON.parse(manifestRaw);
 assert.deepEqual(Object.keys(tree(path.join(directory,relative))).sort(),[...Object.keys(manifest.files),'snapshot-manifest.json'].sort());
 for(const [name,digest]of Object.entries(manifest.files))assert.equal(sha(fs.readFileSync(path.join(directory,relative,name))),digest,name);
 return {manifestRaw,manifest,contract:JSON.parse(fs.readFileSync(path.join(directory,relative,contractName)))};
}

// Break caught: B cannot use an imagined/stale A; A is deterministic and B's
// exact producer/contract delta preserves every SQL and coverage byte.
test('cloud-v1 publishes deterministic A twice and seeds B only from actual verified A',t=>{
 const directory=fixture(t),legacy=Object.fromEntries(Object.keys(baseline.files).map(name=>[name,sha(fs.readFileSync(path.join(directory,name)))]));
 refusal(cli(directory,['--write-b']));assert.equal(fs.existsSync(path.join(directory,bPath)),false);
 const first=success(cli(directory,['--write-a'])),firstTree=tree(path.join(directory,aPath));
 assert.equal(first.variant,'A');assert.equal(first.files,7);
 assert.deepEqual(success(cli(directory,['--write-a'])),first);
 assert.deepEqual(tree(path.join(directory,aPath)),firstTree);
 assert.deepEqual(success(cli(directory,['--check-a'])),first);
 const a=published(directory,aPath);
 assert.equal(a.contract.variant,'A');assert.equal(a.contract.sessionUser,'zasp_test');assert.equal(a.contract.installable,false);assert.equal(a.contract.status,'REFERENCE-CAPTURE-ONLY');
 assert.equal(Object.keys(a.contract.sourcePins).length,159);assert.equal(Object.keys(a.manifest.files).length,166);
 assert.equal(a.manifest.source,'ordered-current-complete-capture-packet-A-cloud-v1');
 const expectedPins={...baseline.contract.sourcePins};
 for(const name of [emitter,emitterTest])expectedPins[name]=sha(fs.readFileSync(path.join(directory,name)));
 assert.deepEqual(a.contract.sourcePins,expectedPins);
 assert.deepEqual(a.contract,{...baseline.contract,sourcePins:expectedPins});
 for(const [name,raw]of Object.entries(baseline.snapshotFiles))if(name!==contractName)assert.deepEqual(fs.readFileSync(path.join(directory,aPath,name)),raw,name);
 for(const name of [descriptor,'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go','services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'])assert.equal(a.contract.sourcePins[name],baseline.contract.sourcePins[name]);
 const bSummary=success(cli(directory,['--write-b'])),b=published(directory,bPath);
 assert.equal(bSummary.variant,'B');assert.deepEqual(success(cli(directory,['--check-b'])),bSummary);
 t.diagnostic(JSON.stringify({a:first,b:bSummary,baselineManifestSHA256:sha(baseline.manifestRaw)}));
 const original=fs.readFileSync(path.join(directory,aPath,producer),'utf8');
 assert.equal(original.split('loadConsolidatedReference(directory)').length-1,2);
 const changed=Buffer.from(original.replaceAll('loadConsolidatedReference(directory)','loadConsolidatedReferenceVariantB(directory)'));
 assert.deepEqual(fs.readFileSync(path.join(directory,bPath,producer)),changed);
 const expected=structuredClone(a.contract);expected.variant='B';expected.sessionUser='zasp_e2e';expected.sourcePins[producer]=sha(changed);
 assert.deepEqual(b.contract,expected);
 assert.equal(b.manifest.source,'ordered-current-complete-capture-packet-B-cloud-v1');
 assert.deepEqual(Object.keys(b.manifest.files).sort(),Object.keys(a.manifest.files).sort());
 const delta=Object.keys(a.manifest.files).filter(name=>a.manifest.files[name]!==b.manifest.files[name]).sort();
 assert.deepEqual(delta,[producer,contractName].sort());
 for(const name of Object.keys(a.manifest.files))if(!delta.includes(name))assert.deepEqual(fs.readFileSync(path.join(directory,bPath,name)),fs.readFileSync(path.join(directory,aPath,name)),name);
 assert.deepEqual(tree(path.join(directory,aPath)),firstTree);
 for(const [name,digest]of Object.entries(legacy))assert.equal(sha(fs.readFileSync(path.join(directory,name))),digest,name);
 for(const variant of ['A','B'])assert.equal(fs.readFileSync(path.join(directory,p7+`ordered-current-complete-capture-packet-${variant}-native22-precision-final4/kept-historical`),'utf8'),'immutable historical '+variant);
});

// Break caught: reviewed sources and topology must be verified before executing
// a changed importer; fixed byte pins must refuse artifacts/fixtures/descriptor.
test('cloud-v1 refuses unreviewed baseline sources and topology before module execution',async t=>{
 const directory=fixture(t);
 success(cli(directory,['--write-a']));
 fs.rmSync(path.join(directory,aPath),{recursive:true});
 for(const [name,relative,mode]of [
  ['changed importer',tools+'build-ordered-current-consolidated-reference.mjs','poison'],
  ['unlisted dependency',tools+'ordered-current-worker-source-replay-v1.mjs','dependency'],
  ['changed descriptor',descriptor,'drift'],
  ['changed artifact',tools+'ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json','drift'],
  ['changed apiserver fixture','services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go','drift'],
  ['missing dependency',descriptor,'missing'],['symlink dependency',descriptor,'symlink']
 ])await t.test(name,()=>{
  const target=path.join(directory,relative),raw=fs.readFileSync(target),outside=path.join(directory,'outside.mjs');
  try{
   if(mode==='missing')fs.unlinkSync(target);
   else if(mode==='symlink'){fs.writeFileSync(outside,raw);fs.unlinkSync(target);fs.symlinkSync(outside,target);}
   else if(mode==='dependency'){
    fs.writeFileSync(path.join(directory,tools+'unlisted-cloud-poison.mjs'),'throw Error("UNREVIEWED_SOURCE_EXECUTED");');
    fs.appendFileSync(target,"\nimport './unlisted-cloud-poison.mjs';\n");
   }else fs.appendFileSync(target,mode==='poison'?'\nthrow Error("UNREVIEWED_SOURCE_EXECUTED");':'\n');
   refusal(cli(directory,['--write-a']));assert.equal(fs.existsSync(path.join(directory,aPath)),false);
  }finally{fs.rmSync(target,{force:true});fs.writeFileSync(target,raw);}
 });
 await t.test('symlink baseline ancestor',()=>{
  const target=path.join(directory,'services/platform/migrations/sql'),outside=path.join(directory,'outside-sql');
  try{fs.renameSync(target,outside);fs.symlinkSync(outside,target);refusal(cli(directory,['--write-a']));assert.equal(fs.existsSync(path.join(directory,aPath)),false);}
  finally{fs.rmSync(target,{force:true});fs.renameSync(outside,target);}
 });
});

// Break caught: manifest tampering/partial seeds/extra members and symlink
// ancestors cannot establish A authority, even with a rewritten member digest.
test('cloud-v1 verifies closed actual A bytes and topology before publishing B',async t=>{
 const directory=fixture(t);success(cli(directory,['--write-a']));
 const manifestFile=path.join(directory,aPath,'snapshot-manifest.json'),manifestRaw=fs.readFileSync(manifestFile);
 for(const [label,relative,mode]of [
  ['manifest drift','snapshot-manifest.json','drift'],['member drift',descriptor,'drift'],['missing A member',descriptor,'missing'],['symlink A member',descriptor,'symlink'],
  ['extra A member','unlisted','extra'],['traversal manifest member','snapshot-manifest.json','traversal'],['self-consistent altered seed',descriptor,'repin']
 ])await t.test(label,()=>{
  const filename=path.join(directory,aPath,relative),raw=fs.existsSync(filename)?fs.readFileSync(filename):null,outside=path.join(directory,'seed-outside');
  try{
   if(mode==='missing')fs.unlinkSync(filename);
   else if(mode==='symlink'){fs.writeFileSync(outside,raw);fs.unlinkSync(filename);fs.symlinkSync(outside,filename);}
   else if(mode==='traversal'){const m=JSON.parse(manifestRaw);m.files['../outside']='0'.repeat(64);fs.writeFileSync(filename,JSON.stringify(m));}
   else if(mode==='extra')fs.writeFileSync(filename,'extra');
   else {fs.appendFileSync(filename,'\n');if(mode==='repin'){const m=JSON.parse(manifestRaw);m.files[relative]=sha(fs.readFileSync(filename));fs.writeFileSync(manifestFile,JSON.stringify(m,null,2)+'\n');}}
   refusal(cli(directory,['--write-b']));assert.equal(fs.existsSync(path.join(directory,bPath)),false);
  }finally{fs.rmSync(filename,{force:true});if(raw)fs.writeFileSync(filename,raw);fs.writeFileSync(manifestFile,manifestRaw);}
 });
 await t.test('symlink A root',()=>{
  const target=path.resolve(directory,aPath),outside=path.join(directory,'outside-A');
  try{fs.renameSync(target,outside);fs.symlinkSync(outside,target);refusal(cli(directory,['--write-b']));assert.equal(fs.existsSync(path.join(directory,bPath)),false);}
  finally{fs.rmSync(target,{force:true});fs.renameSync(outside,target);}
 });
});

// Break caught: a later destination conflict cannot permit earlier missing
// members to be written; no force/ambient authority can redirect publication.
test('cloud-v1 preflights all destinations and refuses caller or ambient overrides',async t=>{
 const directory=fixture(t);success(cli(directory,['--write-a']));success(cli(directory,['--write-b']));
 for(const [variant,destination]of [['a',aPath],['b',bPath]])await t.test(variant+' destination preflight',()=>{
  const first=path.join(directory,destination,packet+'consolidated-capture-demand.sql'),last=path.join(directory,destination,packet+'consolidated-capture-witness.sql'),firstRaw=fs.readFileSync(first),lastRaw=fs.readFileSync(last);
  try{
   fs.unlinkSync(first);fs.writeFileSync(last,'conflict');const before=tree(path.join(directory,destination));
   refusal(cli(directory,['--write-'+variant]));assert.deepEqual(tree(path.join(directory,destination)),before);assert.equal(fs.existsSync(first),false);
   fs.writeFileSync(last,lastRaw);fs.writeFileSync(first,firstRaw);
   const extra=path.join(directory,destination,'unlisted');fs.writeFileSync(extra,'extra');
   refusal(cli(directory,['--write-'+variant]));refusal(cli(directory,['--check-'+variant]));fs.unlinkSync(extra);
   const extraDirectory=path.join(directory,destination,'unlisted-directory');fs.mkdirSync(extraDirectory);refusal(cli(directory,['--write-'+variant]));fs.rmdirSync(extraDirectory);
   fs.unlinkSync(last);fs.symlinkSync(first,last);refusal(cli(directory,['--write-'+variant]));assert.equal(fs.lstatSync(last).isSymbolicLink(),true);
  }finally{fs.rmSync(first,{force:true});fs.rmSync(last,{force:true});fs.writeFileSync(first,firstRaw);fs.writeFileSync(last,lastRaw);}
 });
 await t.test('symlink output ancestor preflight',()=>{
  const target=path.resolve(directory,p7),outside=path.join(directory,'outside-p7');
  try{
   fs.renameSync(target,outside);fs.symlinkSync(outside,target);const before=tree(outside);
   refusal(cli(directory,['--write-a']));refusal(cli(directory,['--write-b']));assert.deepEqual(tree(outside),before);
  }finally{fs.rmSync(target,{force:true});fs.renameSync(outside,target);}
 });
 for(const args of [[],['--write'],['--write-a','--output','elsewhere'],['--write-b','--seed',aPath],['--force']])refusal(cli(directory,args));
 for(const variable of ['ZASP_ORDERED_CONSOLIDATED_REFERENCE_DIR','ZASP_ORDERED_CLOUD_REFERENCE_SEED','ZASP_ORDERED_CLOUD_REFERENCE_VARIANT']){
  const before=tree(path.join(directory,bPath));refusal(cli(directory,['--write-b'],{env:{...process.env,[variable]:'caller-authority'}}));assert.deepEqual(tree(path.join(directory,bPath)),before);
 }
 const selected=spawnSync(process.execPath,['--input-type=module','-e',`import {buildOrderedCurrentCloudReferenceA as build} from './${emitter}'; await build({root:'caller-authority'});`],{cwd:directory,encoding:'utf8'});refusal(selected);
});

// Break caught: a read-time substitute restored before final seed preflight
// must never be admitted into B and freshly pinned as if it came from A.
test('cloud-v1 binds each consumed A member against one-shot read substitution',async t=>{
 const directory=fixture(t);success(cli(directory,['--write-a']));
 for(const relative of [producer,contractName])await t.test(relative,()=>{
  const script=`import assert from 'node:assert/strict'; import fs from 'node:fs'; import {buildOrderedCurrentCloudReferenceB as build} from './${emitter}';
   const target=${JSON.stringify(path.join(directory,aPath,relative))}, original=fs.readFileSync(target), read=fs.readFileSync;
   let reads=0,intercepted=false,refused=false;
   fs.readFileSync=function(filename,...args){const raw=read.call(this,filename,...args);if(String(filename)===target&&++reads===2){intercepted=true;
    ${relative===producer?"return Buffer.concat([raw,Buffer.from('\\n// substituted producer fixture\\n')]);":"const changed=JSON.parse(raw);changed.maxRows=9999;return Buffer.from(JSON.stringify(changed,null,2)+'\\n');"}
   }return raw;};
   try{await build();}catch{refused=true;}finally{fs.readFileSync=read;}
   assert.equal(intercepted,true,'actual seed read reached');assert.equal(refused,true,'transient seed substitution was admitted');assert.deepEqual(fs.readFileSync(target),original,'on-disk A must remain unchanged');`;
  const result=spawnSync(process.execPath,['--input-type=module','-e',script],{cwd:directory,encoding:'utf8',timeout:60000});
  assert.equal(result.error,undefined,String(result.error));assert.equal(result.status,0,result.stderr);
 });
 assert.equal(fs.existsSync(path.join(directory,bPath)),false);
});
