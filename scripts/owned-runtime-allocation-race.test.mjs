import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import net from 'node:net';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {observeRetainedAllocation} from './owned-runtime-lifetime.mjs';

const operations={lstat:fs.lstat,readdir:fs.readdir,realpath:fs.realpath,statfs:fs.statfs};
async function fixture(t){const parent=await fs.mkdtemp(join(tmpdir(),'owned-allocation-race-'));t.after(()=>fs.rm(parent,{recursive:true,force:true}));const roots=['state','archive','raw'].map(name=>join(parent,name));for(const root of roots)await fs.mkdir(root,{mode:0o700});return {parent,roots};}
test('one vanished descendant requires a fresh complete walk of every pinned root',async t=>{
 const {roots}=await fixture(t);await fs.writeFile(join(roots[0],'retained'),Buffer.alloc(4096),{mode:0o600});const vanished=join(roots[1],'vanished');await fs.writeFile(vanished,'owned',{mode:0o600});const walks=[];let removed=false;
 const io={...operations,readdir:async(path,...args)=>{const names=await fs.readdir(path,...args);walks.push(path);if(path===roots[1]&&!removed){removed=true;await fs.unlink(vanished);}return names;}};
 const result=await observeRetainedAllocation(roots,io);assert.ok(result.allocated>0n);assert.deepEqual(walks,[roots[0],roots[1],...roots]);
});
test('partial allocation high water and minimum observed free space survive the complete retry',async t=>{
 const {roots}=await fixture(t),large=join(roots[0],'large'),vanished=join(roots[1],'vanished');await fs.writeFile(large,Buffer.alloc(32768),{mode:0o600});await fs.writeFile(vanished,'owned',{mode:0o600});const original=await fs.lstat(large,{bigint:true});let removed=false,samples=0;
 const io={...operations,readdir:async(path,...args)=>{const names=await fs.readdir(path,...args);if(path===roots[1]&&!removed){removed=true;await fs.unlink(vanished);await fs.unlink(large);}return names;},statfs:async(...args)=>{const actual=await fs.statfs(...args);return {...actual,bsize:1n,bavail:++samples===1?40n:100n};}};
 const result=await observeRetainedAllocation(roots,io);assert.ok(original.blocks>0n);assert.ok(result.allocated>=original.blocks*512n);assert.equal(result.free,40n);assert.equal(samples,4);
});
test('synthetic inventory control keeps the original aggregate entry cap across attempts',async t=>{
 const {roots}=await fixture(t),file=join(roots[2],'fixture');await fs.writeFile(file,'',{mode:0o600});const original=await fs.lstat(file,{bigint:true});let passes=0;
 const io={...operations,readdir:async(path,...args)=>{if(path!==roots[0])return fs.readdir(path,...args);passes++;return passes===1?['vanished',...Array.from({length:60000},(_,i)=>'virtual-'+i)]:Array.from({length:45000},(_,i)=>'virtual-'+i);},lstat:async(path,...args)=>{if(path===join(roots[0],'vanished'))throw Object.assign(Error('private disappearance'),{code:'ENOENT'});if(path.startsWith(roots[0]+'/virtual-'))return Object.assign(Object.create(Object.getPrototypeOf(original)),original,{ino:1000000000000000000n+BigInt(path.split('virtual-')[1])});return fs.lstat(path,...args);}};
 await assert.rejects(observeRetainedAllocation(roots,io));assert.equal(passes,2);
});
test('missing and replaced roots cannot be admitted by the retry',async t=>{
 for(const replacement of [false,true])await t.test(String(replacement),async t=>{
  const {roots,parent}=await fixture(t);const victim=join(roots[0],'vanished');await fs.writeFile(victim,'owned',{mode:0o600});let changed=false;
  const io={...operations,readdir:async(path,...args)=>{const names=await fs.readdir(path,...args);if(path===roots[0]&&!changed){changed=true;await fs.rename(roots[0],join(parent,'retired'));if(replacement)await fs.mkdir(roots[0],{mode:0o700});}return names;}};
  await assert.rejects(observeRetainedAllocation(roots,io));
 });
 const {roots}=await fixture(t);await fs.rmdir(roots[0]);let reads=0;await assert.rejects(observeRetainedAllocation(roots,{...operations,readdir:async(...args)=>{reads++;return fs.readdir(...args);}}));assert.equal(reads,0);
});
test('a second vanished descendant and permission failures are never skipped',async t=>{
 const {roots}=await fixture(t);let passes=0;const file=join(roots[0],'ephemeral');await fs.writeFile(file,'owned',{mode:0o600});
 const io={...operations,readdir:async(path,...args)=>{if(path===roots[0]){passes++;if(passes===2)await fs.writeFile(file,'owned',{mode:0o600});}const names=await fs.readdir(path,...args);if(path===roots[0])await fs.unlink(file);return names;}};
 await assert.rejects(observeRetainedAllocation(roots,io));assert.equal(passes,2);
 let denied=0;await assert.rejects(observeRetainedAllocation(roots,{...operations,readdir:async()=>{denied++;throw Object.assign(Error('private permission detail'),{code:'EACCES'});}}));assert.equal(denied,1);
});
test('retry retains node, link and socket refusal rather than admitting a changed descendant',async t=>{
 for(const kind of ['symlink','hardlink','socket'])await t.test(kind,async t=>{
  const {roots,parent}=await fixture(t);const victim=join(roots[0],'vanished'),unsafe=join(roots[0],'replacement');await fs.writeFile(victim,'owned',{mode:0o600});let pass=0,server;
  const io={...operations,readdir:async(path,...args)=>{if(path===roots[0]&&++pass===2){if(kind==='symlink')await fs.symlink(parent,unsafe);else if(kind==='hardlink'){const original=join(roots[2],'original');await fs.writeFile(original,'owned',{mode:0o600});await fs.link(original,unsafe);}else{server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(unsafe,resolve);});}}const names=await fs.readdir(path,...args);if(path===roots[0]&&pass===1)await fs.unlink(victim);return names;}};
  try{await assert.rejects(observeRetainedAllocation(roots,io));assert.equal(pass,2);}finally{if(server)await new Promise(resolve=>server.close(resolve));}
 });
});
