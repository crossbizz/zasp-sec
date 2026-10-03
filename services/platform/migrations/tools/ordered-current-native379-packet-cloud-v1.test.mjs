import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const api=()=>import('./ordered-current-native379-packet-cloud-v1.mjs');
let packet;
const load=async()=>{const a=await api();packet??=a.admitOrderedCurrentNative379PacketCloudV1();return [a,structuredClone(packet)];};
const phases=['preflight','pristine-truth','drift','forged-entry','null-error-lazy-demand','frame-restoration','cleanup-result'];
test('actual fixed171 source regenerates twice into deterministic complete cloud packet',async()=>{
 const [a,p]=await load(),q=a.admitOrderedCurrentNative379PacketCloudV1();const left=a.serializeOrderedCurrentNative379PacketCloudV1(p),right=a.serializeOrderedCurrentNative379PacketCloudV1(q);
 assert.ok(left.raw.equals(right.raw));assert.equal(left.sha256,sha(left.raw));assert.deepEqual(a.parseOrderedCurrentNative379PacketCloudV1(left.raw),p);
 assert.equal(p.format,'ordered-current-native379-packet-cloud-v1');assert.equal(p.expectedFacts.length,10052);assert.equal(p.rules.length,379);assert.equal(new Set(p.rules.map(r=>r.id)).size,379);assert.equal(p.sourceInventory.sites.length,565);assert.equal(p.sourceInventory.unclassified,0);assert.equal(p.entry.privateRoutineFacts.length,8);
 assert.equal(p.authority.sourceReceipt.inputs.length,171);assert.equal(p.authority.sourceReceipt.outputs.length,8);assert.deepEqual(p.phases.map(x=>x.id),phases);
 for(const k of ['installable','nativeVerified','captureAuthority'])assert.equal(p[k],false);
 assert.deepEqual(new Set(p.controls.flatMap(c=>c.ruleIds)),new Set(p.rules.map(r=>r.id)));
 for(const c of p.controls){assert.ok(c.program.steps.length);assert.ok(c.sourceSite.siteSHA256);assert.equal(c.restoration.beforeNextProbe,true);assert.equal(c.restoration.timeoutIsDenial,false);}
});
test('closed cloud authority refuses historical/corrupt/omitted/duplicate/overflow packets',async()=>{
 const [a,p]=await load();for(const mutate of [q=>q.format='ordered-current-native379-packet-v1',q=>q.expectedFacts.pop(),q=>q.expectedFacts.push(q.expectedFacts[0]),q=>q.rules.pop(),q=>q.rules.push(q.rules[0]),q=>q.controls.pop(),q=>q.controls.push(q.controls[0]),q=>q.entry.privateRoutineFacts.pop(),q=>q.limits.maxRows++,q=>q.installable=true,q=>q.sourceInventory.sites.pop(),q=>q.authority.sourceReceipt.inputs.pop(),q=>q.controls[0].sourceSite.frame.owner='forged']){const q=structuredClone(p);mutate(q);assert.throws(()=>a.assertOrderedCurrentNative379PacketCloudV1(q),/native379 cloud/);}
 assert.throws(()=>a.admitOrderedCurrentNative379PacketCloudV1({path:'/tmp/forged'}),/authority/);assert.throws(()=>a.assertOrderedCurrentNative379PacketCloudV1(p,{}),/authority/);
 const wire=a.serializeOrderedCurrentNative379PacketCloudV1(p).raw;for(const raw of [wire.subarray(0,wire.length-2),Buffer.concat([wire,Buffer.from('{}')]),Buffer.alloc(p.limits.maxPacketBytes+1)])assert.throws(()=>a.parseOrderedCurrentNative379PacketCloudV1(raw),/native379 cloud/);
});
test('observation accounting preserves complete source rows and unchanged finite caps',async()=>{
 const [a,p]=await load();const o={truncated:false,phases:p.phases.map(x=>({id:x.id,rows:x.id==='pristine-truth'?10052:0,bytes:0,milliseconds:0,rules:x.id==='pristine-truth'?p.rules.map(r=>({id:r.id,rows:r.expectedFacts})):[],controls:x.controlIds})),totalRows:10052,totalBytes:0,totalMilliseconds:0};assert.equal(a.assertOrderedCurrentNative379ObservationBoundsCloudV1(o,p),undefined);
 for(const mutate of [q=>q.truncated=true,q=>q.phases.pop(),q=>q.phases[1].rows++,q=>q.phases[1].rules.pop(),q=>q.phases[3].controls.pop(),q=>q.phases[0].bytes=1048577,q=>q.totalRows++,q=>q.phases.reverse(),q=>q.phases[1].rules.push(q.phases[1].rules[0]),q=>q.phases[0].milliseconds=NaN]){const q=structuredClone(o);mutate(q);assert.throws(()=>a.assertOrderedCurrentNative379ObservationBoundsCloudV1(q,p),/native379 cloud/);}
});
test('fixed packet preserves exact rule/private rosters reserved build row and every semantic obligation',async()=>{
 const [a,p]=await load();
 assert.equal(sha(JSON.stringify(p.rules.map(r=>r.id).sort())),'46132d77e0c6314aa0e158b041e06a1ddbbc803a79c0a09bd0208acd9a8c3744');
 assert.equal(sha(JSON.stringify(p.entry.privateRoutineFacts.map(row=>JSON.parse(row.identity)[1]).sort())),'f4c5d367b4225da500b015688c5c830f104bc041b7e91142fa5ddf6fd81eda9d');
 assert.equal(p.expectedFacts.filter(row=>row.kind==='build').length,1);
 assert.equal(p.rules.reduce((n,r)=>n+r.expectedFacts,0)+1,p.expectedFacts.length);
 const categories=new Set(p.controls.map(c=>c.category));
 for(const name of ['private-source-drift','body','owner','acl','default-acl','config','rls','constraint','index','trigger','saved-definition','registration','addition','missing-dependency','explicit-null','empty','duplicate-bag','scalar-zero','scalar-many','invalid-cast','reg-object','lazy-unselected','lazy-selected','aggregate-order','first-error','forged-evaluator','forged-entry','wrong-manifest','wrong-caller','post-admission-drift','frame'])assert.ok(categories.has(name),name);
 for(const c of p.controls){for(const step of c.program.steps)assert.equal(step.sqlSHA256,sha(step.sql));assert.equal(c.mutationSHA256,sha(JSON.stringify(c.mutation,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v)));}
 for(const count of [10053,10089]){const q=structuredClone(p);q.expectedFacts.length=count;assert.throws(()=>a.assertOrderedCurrentNative379PacketCloudV1(q),/native379 cloud/);}
 for(const mutate of [q=>q.expectedFacts[0].fact={},q=>q.rules[0].expectedFacts++,q=>q.entry.independentAdmission.sql+=' ',q=>q.coverage.families.pop(),q=>q.phases[3].controlIds.pop(),q=>q.controls.find(c=>c.expected.firstError).expected.firstError.sqlState='XXXXX',q=>q.nativeVerified=true,q=>q.authority.packetModules['outside']='0'.repeat(64)]){const q=structuredClone(p);mutate(q);assert.throws(()=>a.assertOrderedCurrentNative379PacketCloudV1(q),/native379 cloud/);}
 const wire=a.serializeOrderedCurrentNative379PacketCloudV1(p).raw;
 assert.throws(()=>a.parseOrderedCurrentNative379PacketCloudV1(Buffer.from(wire.toString().replace('{','{"format":"forged",'))),/native379 cloud/);
});
test('packet records and rechecks its own four reviewed generator sources without self output pins',async()=>{
 const [a,p]=await load();
 const names=['ordered-current-native379-packet-cloud-v1.mjs','ordered-current-native379-packet-cloud-v1.test.mjs','ordered-current-native379-entry-frame-cloud-v1.mjs','ordered-current-native379-entry-frame-cloud-v1.test.mjs'];
 assert.deepEqual(Object.keys(p.authority.generatorSources).sort(),names.sort());
 for(const name of names)assert.equal(p.authority.generatorSources[name],sha(fs.readFileSync(path.join(root,'services/platform/migrations/tools',name))));
 assert.equal(p.authority.generatorSourceStatus,'SOURCE-PROVENANCE-ONLY');
 const target=path.join(root,'services/platform/migrations/tools/ordered-current-native379-entry-frame-cloud-v1.test.mjs'),read=fs.readFileSync;
 try{
  fs.readFileSync=function(filename,...args){const raw=read.call(this,filename,...args);return String(filename)===target?Buffer.concat([raw,Buffer.from('transient generator drift')]):raw;};
  assert.throws(()=>a.assertOrderedCurrentNative379PacketCloudV1(p),/native379 cloud/);
 }finally{fs.readFileSync=read;}
});

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const modulePath='services/platform/migrations/tools/ordered-current-native379-packet-cloud-v1.mjs';
const seedPath='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-A-cloud-v1';
function isolated(t,p){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'zasp-native379-cloud-')));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 for(const relative of [...p.authority.sourceReceipt.inputs.map(row=>row.path),...Object.keys(p.authority.packetModules).map(name=>'services/platform/migrations/tools/'+name),...['ordered-current-native379-packet-cloud-v1.test.mjs','ordered-current-native379-entry-frame-cloud-v1.test.mjs'].map(name=>'services/platform/migrations/tools/'+name),modulePath]){
  const filename=path.join(directory,relative);fs.mkdirSync(path.dirname(filename),{recursive:true});fs.copyFileSync(path.join(root,relative),filename);
 }
 fs.mkdirSync(path.dirname(path.join(directory,seedPath)),{recursive:true});fs.cpSync(path.join(root,seedPath),path.join(directory,seedPath),{recursive:true});
 return directory;
}
function probe(directory,script=`import {admitOrderedCurrentNative379PacketCloudV1 as admit} from './${modulePath}'; admit();`){return spawnSync(process.execPath,['--input-type=module','-e',script],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''},timeout:60000,maxBuffer:1024*1024});}
test('fixed compiler and source authority refuse missing changed symlink and transient consumed bytes',async t=>{
 const [,p]=await load(),directory=isolated(t,p);
 for(const relative of [...Object.keys(p.authority.packetModules).map(name=>'services/platform/migrations/tools/'+name),seedPath+'/services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'])for(const mode of ['missing','changed','symlink'])await t.test(relative+'/'+mode,()=>{
  const filename=path.join(directory,relative),raw=fs.readFileSync(filename),outside=path.join(directory,'substitute');
  try{fs.unlinkSync(filename);if(mode==='changed')fs.writeFileSync(filename,Buffer.concat([raw,Buffer.from('\nthrow Error("UNREVIEWED_EXECUTED");\n')]));if(mode==='symlink'){fs.writeFileSync(outside,raw);fs.symlinkSync(outside,filename);}
   const r=probe(directory);assert.equal(r.error,undefined);assert.notEqual(r.status,0);assert.equal(r.stdout,'');assert.doesNotMatch(r.stderr,/^Error: UNREVIEWED_EXECUTED/m);
  }finally{fs.rmSync(filename,{force:true});fs.writeFileSync(filename,raw);}
 });
 const script=`import assert from 'node:assert/strict';import fs from 'node:fs';import childProcess from 'node:child_process';import {admitOrderedCurrentNative379PacketCloudV1 as admit} from './${modulePath}';
 const target=${JSON.stringify(path.join(directory,seedPath,'services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'))};const open=fs.openSync,read=fs.readFileSync,spawn=childProcess.spawnSync,descriptors=new Map();let reads=0,children=0;
 fs.openSync=function(filename,...args){const fd=open.call(this,filename,...args);descriptors.set(fd,String(filename));return fd;};fs.readFileSync=function(filename,...args){const raw=read.call(this,filename,...args);if(descriptors.get(filename)===target&&++reads===2)return Buffer.concat([raw,Buffer.from('substitution')]);return raw;};childProcess.spawnSync=function(...args){children++;return spawn.apply(this,args);};
 try{assert.throws(()=>admit(),/consumed digest/);assert.ok(reads>=2);assert.equal(children,0);}finally{fs.openSync=open;fs.readFileSync=read;childProcess.spawnSync=spawn;}`;
 const r=probe(directory,script);assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);
});
