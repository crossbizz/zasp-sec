import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,rm,symlink,writeFile,link} from 'node:fs/promises';
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
