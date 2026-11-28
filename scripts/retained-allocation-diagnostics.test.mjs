import test from 'node:test';
import assert from 'node:assert/strict';
import fs, {mkdtemp,mkdir,rm,symlink,writeFile,link,rename,lstat} from 'node:fs/promises';
import {syncBuiltinESMExports} from 'node:module';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {observeRetainedAllocation,startRetainedOwnedRuntimeLifetime} from './owned-runtime-lifetime.mjs';
import {describeOwnedRuntimeStartupFailure,ownedRuntimeStartupFailureAnnotation} from './owned-runtime-startup-diagnostics.mjs';

for (const kind of ['socket','symlink','hardlink','missing']) test(`retained observer reports fixed ${kind} refusal without revealing paths`,async()=>{
 const parent=await mkdtemp(path.join(tmpdir(),'zasp-observation-'));let server;
 try {
  const roots=['state','archive','raw'].map(name=>path.join(parent,name));
  for(const root of roots)await mkdir(root,{mode:0o700});
  if(kind==='socket'){server=createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(path.join(roots[0],'grpc.sock'),resolve);});}
  if(kind==='symlink')await symlink('/tmp',path.join(roots[0],'escape'));
  if(kind==='hardlink'){await writeFile(path.join(roots[0],'owned'),'fixture');await link(path.join(roots[0],'owned'),path.join(roots[2],'alias'));}
  if(kind==='missing')await rm(roots[0],{recursive:true});
  const config={stateRoot:roots[0],archiveRoot:roots[1],rawRoot:roots[2],run:'0123456789abcdef'};
  const adapters={observe:()=>observeRetainedAllocation(roots)};
  let failure;try{await startRetainedOwnedRuntimeLifetime(config,adapters);assert.fail('invalid allocation accepted');}catch(error){failure=error;}
  const expected={socket:'allocation-socket',symlink:'allocation-link',hardlink:'allocation-link',missing:'allocation-missing'}[kind];
  assert.deepEqual(describeOwnedRuntimeStartupFailure(failure),{phase:'retained-allocation-observe',kind:expected});
  const annotation=ownedRuntimeStartupFailureAnnotation(failure);
  assert.equal(annotation,`::error::Observed owned runtime startup: phase=retained-allocation-observe; failure=${expected}.\n`);
  assert.equal(annotation.includes(parent),false);
 } finally {if(server)await new Promise(resolve=>server.close(resolve));await rm(parent,{recursive:true,force:true});}
});

for(const reason of ['reserve','budget','value'])test(`sampled ${reason} refusal remains closed and joins services`,async()=>{
 let sample,observations=0,joined=false;
 const adapters={observe:async()=>++observations===1?{free:4_000_000_000n,allocated:1n}:reason==='reserve'?{free:1n,allocated:1n}:reason==='budget'?{free:4_000_000_000n,allocated:536870913n}:{free:4_000_000_000n,allocated:-1n},reopen:async()=>({}),closeTool:async()=>{},setTimer:fn=>{sample=fn;return 1;},clearTimer:()=>{},start:async()=>({environment:{},completed:new Promise(()=>{}),close:async()=>{await new Promise(resolve=>setImmediate(resolve));joined=true;}})};
 const owner=await startRetainedOwnedRuntimeLifetime({stateRoot:'/state',archiveRoot:'/archive',rawRoot:'/raw',run:'0123456789abcdef'},adapters);
 sample();let failure;try{await owner.completed;assert.fail('resource violation accepted');}catch(error){failure=error;}
 assert.equal(joined,true);
 assert.deepEqual(describeOwnedRuntimeStartupFailure(failure),{phase:'retained-sampled-resource',kind:`resource-${reason}`});
 await owner.close();
});

for (const scenario of ['state-file', 'archive-file', 'raw-file', 'state-root-replaced', 'persistent-churn', 'unsafe-replacement']) {
 test('retained allocation handles directory churn: '+scenario, async t => {
  const parent = await mkdtemp(path.join(tmpdir(), 'zasp-retained-churn-'));
  const roots = ['state','archive','raw'].map(name => path.join(parent, name));
  const affected = roots[scenario === 'archive-file' ? 1 : scenario === 'raw-file' ? 2 : 0];
  const temporary = path.join(affected, 'temporary');
  const stable = path.join(affected, 'stable');
  let observed = 0;
  const original = fs.readdir;
  let reader;
  try {
   for (const root of roots) await mkdir(root, {mode:0o700});
   await writeFile(stable, Buffer.alloc(128 * 1024));
   await writeFile(temporary, 'temporary');
   reader = t.mock.method(fs, 'readdir', async function(directory, ...args) {
    if (directory !== affected) return original(directory, ...args);
    if (scenario === 'persistent-churn' && observed > 0) await writeFile(temporary, 'new');
    const names = await original(directory, ...args);
    observed++;
    if (observed === 1 || scenario === 'persistent-churn') {
     if (scenario === 'state-root-replaced') {
      await rename(affected, path.join(parent, 'old-root'));
      await mkdir(affected, {mode:0o700});
     } else {
      await rm(temporary);
      if (scenario === 'unsafe-replacement') await symlink(parent, path.join(affected, 'link'));
     }
    }
    return names;
   });
   syncBuiltinESMExports();
   if (scenario === 'state-file') {
    const value = await observeRetainedAllocation(roots);
    const kept = [...roots, stable];
    const allocation = await Promise.all(kept.map(file => lstat(file, {bigint:true})));
    assert.equal(value.allocated, allocation.reduce((sum, stat) => sum + stat.blocks * 512n, 0n));
    assert.equal(observed, 2);
   } else {
    await assert.rejects(observeRetainedAllocation(roots));
    assert.equal(observed, scenario === 'persistent-churn' ? 3 : scenario === 'unsafe-replacement' ? 2 : 1);
   }
  } finally {
   reader?.mock.restore();
   syncBuiltinESMExports();
   await rm(parent, {recursive:true,force:true});
  }
 });
}
