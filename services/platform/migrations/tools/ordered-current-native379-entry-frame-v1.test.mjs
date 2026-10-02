import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

const moduleURL=new URL('./ordered-current-native379-entry-frame-v1.mjs',import.meta.url);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
let api,input;
async function load(){
 assert.ok(fs.existsSync(moduleURL),'closed entry/frame builder is required');
 api??=await import(moduleURL);
 if(!input){
  const inventoryRaw=fs.readFileSync(new URL('./ordered-current-native379-packet-v1-artifacts/source-inputs.json',import.meta.url));
   assert.equal(sha(inventoryRaw),'b6626e6b1f59482a908a3b1cf6b714a6a08de7fd5087d307dfe1b659af067392');
  const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'native379-entry-source-'));
  try{
   const migrations=path.join(temporary,'services/platform/migrations');
   for(const [relative,pin]of Object.entries(JSON.parse(inventoryRaw).files)){
    const raw=fs.readFileSync(new URL('../'+relative,import.meta.url));assert.equal(sha(raw),pin);
    const destination=path.join(migrations,relative);fs.mkdirSync(path.dirname(destination),{recursive:true});fs.writeFileSync(destination,raw,{flag:'wx'});
   }
   const build=spawnSync(process.execPath,[path.join(migrations,'tools/build-ordered-current-development.mjs'),'--write'],{cwd:temporary,encoding:'utf8',timeout:60000,maxBuffer:33554432,env:{PATH:path.dirname(process.execPath),TZ:'UTC',LANG:'C'}});
   assert.equal(build.status,0,build.stderr);
   input=Object.fromEntries(Object.entries({contractRaw:'effective-contract4.json',moduleRaw:'development-module.sql',manifestRaw:'development-manifest.json',admissionRaw:'development-admission.sql'}).map(([key,name])=>[key,fs.readFileSync(path.join(migrations,'ordered_current',name))]));
  }finally{fs.rmSync(temporary,{recursive:true,force:true});}
 }
 return api.buildOrderedCurrentNative379EntryFrameV1(input);
}

test('actual evaluator and require are pinned to the exact expected literal and independent admission',async()=>{
 const value=await load();
 assert.equal(value.entry.evaluator,'zasp_authorization80_ordered_current.catalog(text)');
 assert.equal(value.entry.entry,'zasp_authorization80_ordered_current.require(text)');
 assert.equal(value.entry.manifest,'560797e61ca951c61c8ca29d722644f74b81d80020b80be648852b5b5de050f0');
 assert.equal(value.entry.manifestLiteral,"'560797e61ca951c61c8ca29d722644f74b81d80020b80be648852b5b5de050f0'");
 assert.equal(value.entry.owner,'zasp_discovery_authority');
 assert.deepEqual(value.entry.allowedCallers,['zasp_discovery_authority']);
 assert.deepEqual(value.entry.refusedCallers,['zasp_security_agent_worker']);
 assert.equal(value.entry.privateRoutineFacts.length,7);
 assert.equal(value.counts.controls,18);assert.equal(value.counts.entry,9);assert.equal(value.counts.frame,9);
 const baseline=value.controls.find(c=>c.id==='entry:actual-evaluator');
 assert.equal(baseline.program.steps.find(s=>s.id==='probe').sql,`SELECT zasp_authorization80_ordered_current.catalog(${value.entry.manifestLiteral});`);
 assert.deepEqual(baseline.expected,{outcome:'accept',sqlState:null,firstError:null});
});

test('all controls bind exact ordered SQL, typed outcomes, mutation operands and rollback assertions',async()=>{
 const value=await load();assert.equal(new Set(value.controls.map(c=>c.id)).size,18);
 for(const c of value.controls){
  assert.equal(c.program.format,'native379-sql-program-v1');assert.ok(c.program.steps.length>=6,c.id);
  for(const step of c.program.steps){assert.ok(step.id&&step.role&&step.sql&&step.expected,c.id);assert.equal(step.sqlSHA256,sha(step.sql),c.id);}
  assert.ok(Object.keys(c.mutation.operands).length,c.id);assert.equal(c.mutation.sqlSHA256,sha(c.mutation.sql));
  assert.ok(c.sourceSite.sourceIdentity);assert.ok(c.sourceSite.end>c.sourceSite.start);assert.equal(c.sourceFrameSHA256,sha(JSON.stringify(c.sourceSite.frame)));
  assert.ok(c.restoration.snapshotSQL&&c.restoration.restoreSQL&&c.restoration.assertionSQL,c.id);
  assert.match(c.restoration.restoreSQL,/ROLLBACK;/);assert.equal(c.restoration.expectedTransactionStatus,'I');assert.equal(c.restoration.beforeNextProbe,true);
  assert.deepEqual(c.program.steps.slice(-2).map(s=>s.id),['restore','assert-restored']);
  if(c.expected.firstError){assert.ok(c.expected.firstError.end>c.expected.firstError.start);assert.equal(c.expected.firstError.siteSHA256,sha(c.expected.firstError.sql));}
 }
});

test('forged implementations are refused by independent admission before any protected call',async()=>{
 const value=await load();
 for(const id of ['forged-evaluator','forged-entry']){
  const c=value.controls.find(c=>c.id==='entry:'+id),probe=c.program.steps.find(s=>s.id==='probe');
  assert.match(c.mutation.sql,/CREATE OR REPLACE FUNCTION zasp_authorization80_ordered_current\./);
  assert.equal(c.expected.sqlState,'42501');assert.equal(c.expected.firstError.stage,'independent-private-admission');
  assert.ok(probe.sql.indexOf('native379 independent admission refused')<probe.sql.lastIndexOf('PERFORM zasp_authorization80_ordered_current.require('));
  assert.equal(c.mutation.operands.signature,id==='forged-entry'?'zasp_authorization80_ordered_current.require(text)':'zasp_authorization80_ordered_current.catalog(text)');
 }
 for(const id of ['wrong-manifest','extra-expected-row','missing-expected-row','post-admission-drift']){
  const c=value.controls.find(c=>c.id==='entry:'+id);assert.equal(c.expected.sqlState,'42501');assert.equal(c.expected.firstError.stage,'entry-require');
 }
 const post=value.controls.find(c=>c.id==='entry:post-admission-drift');
 assert.ok(post.program.steps.findIndex(s=>s.id==='admit-before-mutation')<post.program.steps.findIndex(s=>s.id==='mutate'));
 assert.match(post.mutation.sql,/UPDATE zasp_authorization80_ordered_current.registration/);
});

test('frame controls name concrete before/mutated/restored values and preserve first native error',async()=>{
 const value=await load();
 for(const dimension of ['role','search_path','timezone','read_only','transaction','advisory_locks','schema_locks','catalog','source-config']){
  const c=value.controls.find(c=>c.id==='restore:'+dimension);assert.ok(c,dimension);
  assert.ok(c.frame.before.query&&Object.hasOwn(c.frame.before,'value'));assert.ok(c.frame.mutated.query&&Object.hasOwn(c.frame.mutated,'value'));
  assert.equal(c.frame.restored.query,c.restoration.assertionSQL);assert.equal(c.frame.restored.value,true);
  assert.ok(c.frame.protectedProbeSQL);assert.equal(c.frame.sourceIdentity,c.sourceSite.sourceIdentity);
 }
 const transaction=value.controls.find(c=>c.id==='restore:transaction');
 assert.equal(transaction.program.steps.find(s=>s.id==='mutate').expected.sqlState,'22012');
 assert.equal(transaction.program.steps.find(s=>s.id==='probe').expected.sqlState,'25P02');
 assert.equal(transaction.expected.firstError.sqlState,'22012');
 assert.match(value.controls.find(c=>c.id==='restore:source-config').mutation.sql,/ALTER FUNCTION .* SET TimeZone TO 'Pacific\/Honolulu'/);
});

test('caller SQL paths hashes altered signatures manifests and incomplete bytes cannot enter authority',async()=>{
 await load();
 for(const value of [undefined,null,{},Object.values(input),{...input,path:'/tmp/authority'},{...input,sql:'SELECT true'},{...input,hash:'0'.repeat(64)}])assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1(value),/native379 entry-frame/);
 for(const key of Object.keys(input)){
  const missing={...input};delete missing[key];assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1(missing),/native379 entry-frame/);
  const stale={...input,[key]:Buffer.concat([input[key],Buffer.from(' ')] )};assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1(stale),/native379 entry-frame/);
 }
 assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1(input,{sql:'SELECT true'}),/native379 entry-frame/);
});

test('closed assertion rejects missing extra duplicate unknown controls and incomplete restoration',async()=>{
 const value=await load();assert.equal(api.assertOrderedCurrentNative379EntryFrameV1(value,input),undefined);
 for(const mutate of [v=>v.controls.pop(),v=>v.controls.push(v.controls[0]),v=>v.controls.push({id:'unknown'}),v=>v.controls.reverse(),v=>v.entry.entry='forged.require(text)',v=>v.entry.manifest='0'.repeat(64),v=>delete v.controls[0].restoration.assertionSQL,v=>v.controls[0].program.steps[0].sql='SELECT true',v=>v.controls[0].mutation.operands={},v=>v.controls[0].expected.firstError=undefined]){
  const changed=structuredClone(value);mutate(changed);assert.throws(()=>api.assertOrderedCurrentNative379EntryFrameV1(changed,input),/native379 entry-frame/);
 }
});

test('authority input rejects accessor properties and symbol keys without invoking caller code',async()=>{
 await load();
 let reads=0;const accessor={...input};Object.defineProperty(accessor,'moduleRaw',{get(){reads++;return input.moduleRaw;},enumerable:true});
 assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1(accessor),/native379 entry-frame/);assert.equal(reads,0);
 assert.throws(()=>api.buildOrderedCurrentNative379EntryFrameV1({...input,[Symbol('path')]:'/tmp/caller'}),/native379 entry-frame/);
});

test('pristine protected acceptance uses read-only while mutations have an explicit isolated rollback envelope',async()=>{
 const value=await load();
 for(const id of ['entry:actual-entry','entry:actual-evaluator']){
  const c=value.controls.find(c=>c.id===id);assert.equal(c.program.evaluationFrame.id,'protected-evaluation');assert.equal(c.program.evaluationFrame.access,'read-only');
  assert.match(c.program.steps.find(s=>s.id==='setup').sql,/BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;/);
 }
 for(const c of value.controls.filter(c=>!['entry:actual-entry','entry:actual-evaluator'].includes(c.id))){assert.equal(c.program.evaluationFrame.id,'mutation-envelope');assert.equal(c.program.evaluationFrame.visibility,'same-connection-uncommitted-mutation');assert.equal(c.program.evaluationFrame.commitForbidden,true);}
 for(const c of value.controls){assert.deepEqual(c.restoration.connectionIdentity.expected,[{binding:'owned-session-user'},{binding:'owned-backend-pid'}]);assert.doesNotMatch(c.restoration.assertionSQL,/pg_advisory_(?:xact_)?lock\(/);}
});
