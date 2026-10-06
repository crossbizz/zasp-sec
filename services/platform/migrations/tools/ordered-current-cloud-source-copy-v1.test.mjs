import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import childProcess from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const modulePath='services/platform/migrations/tools/ordered-current-cloud-source-copy-v1.mjs';
const seedPath='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-A-cloud-v1';
const manifestName='snapshot-manifest.json';
const fixtures=['services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go','services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'];
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
// Independently authorized development inputs omitted by capture-source A.
const inventoryPath='services/platform/migrations/tools/ordered-current-native379-packet-v1-artifacts/source-inputs.json';
const inventoryPin='34e3dfdfdd00c316eb9ad7300f8624f1b21543c95ed108578b739bb60e1e3229';
const supplements={
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
};

const outputPins={
 'effective-contract4.json':'06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0',
 'development-manifest.json':'4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9',
 'development-module.sql':'4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74',
 'development-checkpoint.json':'905664791351c9714bfa4769ab94a6c11c6f1744c11ff56c165536fc71d13705',
 'development-collector.sql':'97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f',
 'development-admission.sql':'999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef',
 'consolidated-reference-contract.json':'d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff',
 'consolidated-reference-select.sql':'23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57'
};
function tree(directory,prefix=''){
 return Object.fromEntries(fs.readdirSync(directory,{withFileTypes:true}).flatMap(item=>{
  const relative=prefix+item.name,filename=path.join(directory,item.name);
  return item.isDirectory()?Object.entries(tree(filename,relative+'/')):[[relative,item.isSymbolicLink()?'symlink:'+fs.readlinkSync(filename):sha(fs.readFileSync(filename))]];
 }).sort(([a],[b])=>Buffer.compare(Buffer.from(a),Buffer.from(b))));
}
async function fixture(t){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-cloud-copy-test-')));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const seed=path.join(directory,seedPath);
 fs.mkdirSync(path.dirname(seed),{recursive:true});fs.cpSync(path.join(root,seedPath),seed,{recursive:true});
 for(const relative of [inventoryPath,...Object.keys(supplements)]){const target=path.join(directory,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(root,relative),target);}
 const target=path.join(directory,modulePath);fs.mkdirSync(path.dirname(target),{recursive:true});
 let api={};
 if(fs.existsSync(path.join(root,modulePath))){fs.copyFileSync(path.join(root,modulePath),target);api=await import(pathToFileURL(target));}
 return {directory,seed,api};
}
function requireAPI(api){assert.equal(typeof api.buildOrderedCurrentCloudSourceCopyV1,'function','fixed cloud source copier is required');assert.equal(typeof api.assertOrderedCurrentCloudSourceCopyV1,'function','closed source-only schema is required');}
function refuses(api,...args){requireAPI(api);assert.throws(()=>api.buildOrderedCurrentCloudSourceCopyV1(...args),/cloud source copy refused/);}

// Break caught: migration-relative copying loses the two actual apiserver
// inputs; missing real regeneration, root writes, unsafe flags or weak receipts.
test('cloud source copy regenerates fixed A twice with both fixture bytes and leaves checkout untouched',async t=>{
 const {directory,seed,api}=await fixture(t);requireAPI(api);
 const before=tree(directory),rootManifest=fs.readFileSync(path.join(root,seedPath,manifestName));
 const first=api.buildOrderedCurrentCloudSourceCopyV1(),second=api.buildOrderedCurrentCloudSourceCopyV1();
 assert.deepEqual(first.receipt,second.receipt);assert.deepEqual(first.inputs,second.inputs);assert.deepEqual(first.outputs,second.outputs);
 assert.equal(first.receipt.status,'SOURCE-REGENERATION-ONLY');
 for(const flag of ['installable','nativeVerified','executableReplacementVerified','captureAuthority'])assert.equal(first.receipt[flag],false,flag);
 assert.equal(first.receipt.seed.manifestSHA256,'27438318b40b6664cb91e3d004a63b906589fd6f8c11dafd28755e2c32282e08');
 assert.equal(Object.keys(first.inputs).length,171);assert.equal(Object.keys(first.outputs).length,8);
 for(const relative of fixtures)assert.deepEqual(first.inputs[relative],fs.readFileSync(path.join(seed,relative)),relative);
 for(const [name,pin]of Object.entries(outputPins))assert.equal(sha(first.outputs['services/platform/migrations/ordered_current/'+name]),pin,name);
 assert.equal(JSON.parse(first.outputs['services/platform/migrations/ordered_current/development-checkpoint.json']).nativeVerified,false);
 assert.equal(JSON.parse(first.outputs['services/platform/migrations/ordered_current/development-manifest.json']).installable,false);
 assert.equal(api.assertOrderedCurrentCloudSourceCopyV1(first),true);
 assert.equal(first.receipt.supplement.inventorySHA256,inventoryPin);assert.equal(first.receipt.supplement.dataInputs,11);
 for(const [relative,pin]of Object.entries({...supplements,[inventoryPath]:inventoryPin}))assert.equal(sha(first.inputs[relative]),pin,relative);
 assert.deepEqual(tree(directory),before);assert.deepEqual(fs.readFileSync(path.join(root,seedPath,manifestName)),rootManifest);
 // Break caught: receipt-only validation or permissive schema admits tampered
 // buffers, added authority, forged flags, wrong counts and duplicate paths.
 for(const [label,change]of [
  ['input buffer',v=>{v.inputs[fixtures[0]]=Buffer.from('substituted');}],
  ['output buffer',v=>{v.outputs['services/platform/migrations/ordered_current/development-module.sql']=Buffer.from('substituted');}],
  ['native flag',v=>{v.receipt.nativeVerified=true;}],
  ['extra receipt authority',v=>{v.receipt.trustedHash='0'.repeat(64);}],
  ['duplicate receipt path',v=>{v.receipt.inputs.push(v.receipt.inputs[0]);}],
  ['extra input',v=>{v.inputs['outside']=Buffer.from('extra');}],
  ['unbounded byte count',v=>{v.receipt.outputs[0].bytes=Number.MAX_SAFE_INTEGER;}]
 ])await t.test(label,()=>{
  const changed={receipt:structuredClone(first.receipt),inputs:{...first.inputs},outputs:{...first.outputs}};change(changed);
  assert.throws(()=>api.assertOrderedCurrentCloudSourceCopyV1(changed),/cloud source copy refused/);
 });
});

// Break caught: the fixed manifest must authenticate all166 members including
// the seven uncopied packet files; neither topology nor rewritten pins suffice.
test('cloud source copy refuses altered missing extra symlink and malformed seed authority',async t=>{
 const {directory,seed,api}=await fixture(t);requireAPI(api);
 const manifest=path.join(seed,manifestName),manifestRaw=fs.readFileSync(manifest);
 for(const [label,relative,mode]of [
  ['changed readiness fixture',fixtures[0],'change'],['changed precision fixture',fixtures[1],'change'],
  ['absent readiness fixture',fixtures[0],'missing'],['absent precision fixture',fixtures[1],'missing'],
  ['changed packet member','services/platform/migrations/ordered_current/consolidated-capture-witness.sql','change'],
  ['file symlink',fixtures[0],'symlink'],['unlisted member','unlisted','extra'],
  ['unlisted directory','unlisted/entry','extra'],['manifest changed',manifestName,'change'],
  ['traversal authority',manifestName,'traversal'],['absolute authority',manifestName,'absolute'],
  ['duplicate authority',manifestName,'duplicate'],['self-consistent repin',fixtures[1],'repin']
 ])await t.test(label,()=>{
  const filename=path.join(seed,relative),raw=fs.existsSync(filename)?fs.readFileSync(filename):null,outside=path.join(directory,'outside');
  try{
   if(mode==='missing')fs.unlinkSync(filename);
   else if(mode==='symlink'){fs.writeFileSync(outside,raw);fs.unlinkSync(filename);fs.symlinkSync(outside,filename);}
   else if(mode==='extra'){fs.mkdirSync(path.dirname(filename),{recursive:true});fs.writeFileSync(filename,'extra');}
   else if(mode==='traversal'||mode==='absolute'){const m=JSON.parse(manifestRaw);m.files[mode==='traversal'?'../outside':'/outside']='0'.repeat(64);fs.writeFileSync(manifest,JSON.stringify(m));}
   else if(mode==='duplicate')fs.writeFileSync(manifest,manifestRaw.toString().replace('"format": 1','"format": 1, "format": 1'));
   else{fs.appendFileSync(filename,'\n');if(mode==='repin'){const m=JSON.parse(manifestRaw);m.files[relative]=sha(fs.readFileSync(filename));fs.writeFileSync(manifest,JSON.stringify(m));}}
   refuses(api);
  }finally{fs.rmSync(filename,{force:true});if(raw)fs.writeFileSync(filename,raw);fs.writeFileSync(manifest,manifestRaw);fs.rmSync(path.join(seed,'unlisted'),{recursive:true,force:true});}
 });
 for(const relative of ['services/platform/apiserver',seedPath])await t.test('symlink ancestor '+relative,()=>{
  const filename=relative===seedPath?seed:path.join(seed,relative),outside=path.join(directory,'moved');
  try{fs.renameSync(filename,outside);fs.symlinkSync(outside,filename);refuses(api);}
  finally{fs.unlinkSync(filename);fs.renameSync(outside,filename);}
 });
 await t.test('absent fixed seed',()=>{const moved=seed+'-absent';try{fs.renameSync(seed,moved);refuses(api);}finally{fs.renameSync(moved,seed);}});
});

// Break caught: arbitrary args or ambient runtime/source options gain authority;
// a child sees secrets through inherited env or an unapproved executable runs.
test('cloud source copy rejects caller authority and unsafe ambient runtime overrides',async t=>{
 const {api}=await fixture(t);requireAPI(api);
 for(const arg of [{source:'/tmp'}, {output:'/tmp'}, {trustedHash:'0'.repeat(64)}, {env:{PATH:'/tmp'}}])await t.test(JSON.stringify(arg),()=>refuses(api,arg));
 for(const key of ['NODE_OPTIONS','ZASP_ORDERED_CLOUD_SOURCE_COPY_TRUSTED_HASH','ZASP_ORDERED_CLOUD_REFERENCE_SOURCE'])await t.test(key,()=>{
  const previous=process.env[key];try{process.env[key]='untrusted';refuses(api);}finally{if(previous===undefined)delete process.env[key];else process.env[key]=previous;}
 });
 await t.test('unapproved running runtime',()=>{const descriptor=Object.getOwnPropertyDescriptor(process,'version');try{Object.defineProperty(process,'version',{value:'v22.23.0'});refuses(api);}finally{Object.defineProperty(process,'version',descriptor);}});
});

// Break caught: two-pass preflight trusts a substituted consumed read which is
// restored before final verification. Real reads are kept except this attack.
test('cloud source copy digest-checks transient consumed fixture buffer before any child execution',async t=>{
 const {directory,seed,api}=await fixture(t);requireAPI(api);
 for(const relative of [...fixtures,...Object.keys(supplements),inventoryPath])await t.test(relative,()=>{
  const target=path.join(fixtures.includes(relative)?seed:directory,relative),originalOpen=fs.openSync,originalRead=fs.readFileSync,originalSpawn=childProcess.spawnSync,descriptors=new Map();let reads=0,children=0;
  try{
   fs.openSync=function(filename,...args){const fd=originalOpen.call(this,filename,...args);descriptors.set(fd,String(filename));return fd;};
   fs.readFileSync=function(filename,...args){const raw=originalRead.call(this,filename,...args);if((typeof filename==='number'?descriptors.get(filename):String(filename))===target&&++reads===2)return Buffer.concat([raw,Buffer.from('\ntransient-substitution')]);return raw;};
   childProcess.spawnSync=function(...args){children++;return originalSpawn.apply(this,args);};
   refuses(api);assert.ok(reads>=2,'attack reached consumed read');assert.equal(children,0,'changed source executed');
  }finally{fs.openSync=originalOpen;fs.readFileSync=originalRead;childProcess.spawnSync=originalSpawn;}
 });
});

// Break caught: child launch inherits environment, writes outside owned temp,
// incomplete copies omit fixtures, output conflicts are overwritten, or final
// seed/runtime verification is missing. The actual development builder runs.
test('cloud source copy uses an empty owned repo fixed environment and final seed drift checks',async t=>{
 const {seed,api}=await fixture(t);requireAPI(api);
 const originalSpawn=childProcess.spawnSync;let temporary,completed=false;
 try{
  childProcess.spawnSync=function(executable,args,options){
   temporary=options.cwd;assert.equal(executable,process.execPath);assert.deepEqual(options.env,{PATH:path.dirname(process.execPath),TZ:'UTC',LANG:'C',LC_ALL:'C'});
   assert.ok(!Object.hasOwn(options.env,'SECRET_CLOUD_COPY_TEST'));assert.deepEqual(args,[path.join(temporary,'services/platform/migrations/tools/build-ordered-current-development.mjs'),'--write']);
   for(const relative of fixtures)assert.deepEqual(fs.readFileSync(path.join(temporary,relative)),fs.readFileSync(path.join(seed,relative)));
   const result=originalSpawn.call(this,executable,args,options);completed=result.status===0;assert.equal(result.status,0,result.stderr);
   fs.appendFileSync(path.join(seed,fixtures[0]),'\nseed-drift-after-build');return result;
  };
  process.env.SECRET_CLOUD_COPY_TEST='must-not-inherit';assert.throws(()=>api.buildOrderedCurrentCloudSourceCopyV1(),/cloud source copy refused: consumed digest services\/platform\/apiserver\/authorization_worker_ordered_readiness_capture_test.go/);assert.equal(completed,true,'actual development builder must complete before drift attack');assert.ok(temporary);assert.equal(fs.existsSync(temporary),false,'owned temp survived failed attempt');
 }finally{childProcess.spawnSync=originalSpawn;delete process.env.SECRET_CLOUD_COPY_TEST;fs.copyFileSync(path.join(root,seedPath,fixtures[0]),path.join(seed,fixtures[0]));}
 await t.test('destination conflict is refused before copy or child',()=>{
  const originalTemporary=fs.mkdtempSync,originalWrite=fs.writeFileSync;let copied=0,owned;
  try{
   fs.mkdtempSync=function(...args){owned=originalTemporary.apply(this,args);originalWrite(path.join(owned,'conflict'),'owned-conflict');return owned;};
   fs.writeFileSync=function(...args){copied++;return originalWrite.apply(this,args);};
   refuses(api);assert.equal(copied,0);assert.ok(owned);assert.equal(fs.existsSync(owned),false);
  }finally{fs.mkdtempSync=originalTemporary;fs.writeFileSync=originalWrite;}
 });
});


// Break caught: the A-only closure must not silently skip the eleven explicitly
// joined producer inputs or their fixed legacy-inventory metadata. Every case
// must refuse before child execution, rather than fail later on missing data.
test('cloud source copy joins only eleven fixed supplemental inputs and refuses their authority drift before execution',async t=>{
 const {directory,api}=await fixture(t);requireAPI(api);
 for(const relative of [inventoryPath,...Object.keys(supplements)])for(const mode of ['changed','absent','symlink'])await t.test(relative+' '+mode,()=>{
  const target=path.join(directory,relative),raw=fs.readFileSync(target),outside=path.join(directory,'outside-supplement'),originalSpawn=childProcess.spawnSync;let children=0;
  try{
   childProcess.spawnSync=function(...args){children++;return originalSpawn.apply(this,args);};
   if(mode==='changed')fs.appendFileSync(target,'\n');
   if(mode==='absent')fs.unlinkSync(target);
   if(mode==='symlink'){fs.writeFileSync(outside,raw);fs.unlinkSync(target);fs.symlinkSync(outside,target);}
   refuses(api);assert.equal(children,0,'unverified supplemental authority reached child');
  }finally{childProcess.spawnSync=originalSpawn;fs.rmSync(target,{force:true});fs.writeFileSync(target,raw);fs.rmSync(outside,{force:true});}
 });
 await t.test('supplement ancestor symlink',()=>{
  const target=path.join(directory,'services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts'),outside=path.join(directory,'outside-intake'),originalSpawn=childProcess.spawnSync;let children=0;
  try{childProcess.spawnSync=function(...args){children++;return originalSpawn.apply(this,args);};fs.renameSync(target,outside);fs.symlinkSync(outside,target);refuses(api);assert.equal(children,0);}
  finally{childProcess.spawnSync=originalSpawn;fs.unlinkSync(target);fs.renameSync(outside,target);}
 });
});
