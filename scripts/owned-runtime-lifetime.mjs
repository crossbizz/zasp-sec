import {recordOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';
export {describeOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';
import { lstat, readdir, realpath, statfs } from 'node:fs/promises';
import path from 'node:path';
import { loadOfficialHeldTool, reopenOfficialHeldTool, closeHeldTool } from './official-held-tools.mjs';
import { startOwnedRuntimeServices } from './owned-runtime-services.mjs';

const RESERVE=2684354560n,BUDGET=536870912n,MARGIN=33554432n;
const fail=()=>{throw Error('owned runtime resource unavailable');};
export async function observeOwnedAllocation(root){
 const first=await lstat(root,{bigint:true});if(!first.isDirectory()||first.isSymbolicLink()||(first.mode&0o077n)!==0n||first.uid!==BigInt(process.getuid())||await realpath(root)!==root)fail();
 const pending=[root];let bytes=0n,entries=0;
 while(pending.length){const current=pending.pop(),info=await lstat(current,{bigint:true});if(++entries>100000||info.dev!==first.dev||info.isSymbolicLink()||!info.isDirectory()&&!info.isFile())fail();bytes+=info.blocks*512n;if(info.isDirectory()){const names=await readdir(current);if(names.length+entries>100000)fail();for(const name of names)pending.push(path.join(current,name));}}
 const last=await lstat(root,{bigint:true});if(first.dev!==last.dev||first.ino!==last.ino)fail();const disk=await statfs(root,{bigint:true});return {free:disk.bavail*disk.bsize,allocated:bytes};
}
const defaults={observe:observeOwnedAllocation,load:loadOfficialHeldTool,closeTool:closeHeldTool,start:startOwnedRuntimeServices,setTimer:setTimeout,clearTimer:clearTimeout};

// This owner keeps the sampled disk guard alive after startup. Its completion
// settles only after service/tool joins; the caller removes its allocation last.
export async function startOwnedRuntimeLifetime(config,adapters=defaults){
 if(!config||Object.getPrototypeOf(config)!==Object.prototype||Object.keys(config).length!==2||!Object.hasOwn(config,'root')||!Object.hasOwn(config,'run')||typeof config.root!=='string'||!path.isAbsolute(config.root)||path.normalize(config.root)!==config.root||typeof config.run!=='string'||!/^[a-f0-9]{16}$/.test(config.run))fail();
 const initial=await adapters.observe(config.root);if(typeof initial.free!=='bigint'||typeof initial.allocated!=='bigint'||initial.free<RESERVE+BUDGET+MARGIN||initial.allocated>BUDGET||initial.allocated<0n)fail();
 const controller=new AbortController(),tools={};let services,timer,sampling=Promise.resolve(),stopped=false,closePromise,rejectResource;
 const resourceFailure=new Promise((_,reject)=>{rejectResource=reject;});void resourceFailure.catch(()=>{});
 const close=()=>closePromise??=(async()=>{stopped=true;controller.abort();adapters.clearTimer(timer);await sampling;let failed=false;if(services){try{await services.close();}catch{failed=true;}}for(const tool of Object.values(tools)){try{await adapters.closeTool(tool);}catch{failed=true;}}if(failed)throw Error('owned runtime cleanup incomplete');})();
 const sample=()=>{if(stopped)return;sampling=(async()=>{try{const value=await adapters.observe(config.root);if(typeof value.free!=='bigint'||typeof value.allocated!=='bigint'||value.free<RESERVE||value.allocated>BUDGET||value.allocated<0n)fail();}catch{controller.abort();rejectResource(Error('owned runtime sampled resource refusal'));}finally{if(!stopped&&!controller.signal.aborted)timer=adapters.setTimer(sample,100);}})();};
 timer=adapters.setTimer(sample,100);
 let loading=Promise.resolve();
 try{
  loading=(async()=>{for(const name of ['temporal','openfga']){if(controller.signal.aborted)fail();tools[name]=await adapters.load(name,path.join(config.root,name+'.tar.gz'),path.join(config.root,name+'-held'));if(controller.signal.aborted)fail();}services=await adapters.start({run:config.run,rootParent:config.root,tools},undefined,controller.signal);return services;})();
  await Promise.race([loading,resourceFailure]);
  const completed=Promise.race([services.completed,resourceFailure]).then(async value=>{await close();return value;},async error=>{await close();throw error;});void completed.catch(()=>{});
  return Object.freeze({environment:services.environment,completed,close,root:config.root,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
 }catch(error){controller.abort();try{await loading;}catch{/* Preserve the original failure after joining the losing startup operation. */}await close();throw error;}
}

export async function observeRetainedAllocation(roots){
 const identities=new Set();let allocated=0n,free,device,entries=0;
 for(const root of roots){const before=await lstat(root,{bigint:true});if(!before.isDirectory()||before.isSymbolicLink()||(before.mode&0o077n)!==0n||before.uid!==BigInt(process.getuid())||await realpath(root)!==root||device!==undefined&&before.dev!==device)fail();device=before.dev;const pending=[root];
  while(pending.length){const current=pending.pop(),info=await lstat(current,{bigint:true});const identity=info.dev+':'+info.ino;if(++entries>100000||info.dev!==device||info.uid!==BigInt(process.getuid())||identities.has(identity)||info.isSymbolicLink()||!info.isDirectory()&&!info.isFile()||info.isFile()&&info.nlink!==1n)fail();identities.add(identity);allocated+=info.blocks*512n;if(info.isDirectory()){const names=await readdir(current);if(names.length+entries>100000)fail();for(const name of names)pending.push(path.join(current,name));}}
  const after=await lstat(root,{bigint:true});if(before.dev!==after.dev||before.ino!==after.ino||before.uid!==after.uid||before.mode!==after.mode||await realpath(root)!==root)fail();const disk=await statfs(root,{bigint:true}),observed=disk.bavail*disk.bsize;free=free===undefined?observed:free<observed?free:observed;
 }
 return {allocated,free};
}
const retainedDefaults={...defaults,observe:observeRetainedAllocation,reopen:reopenOfficialHeldTool};
export async function startRetainedOwnedRuntimeLifetime(config,adapters=retainedDefaults){
 let diagnosticPhase='retained-input';
 try{
 const keys=['stateRoot','archiveRoot','rawRoot','run'];if(!config||Object.getPrototypeOf(config)!==Object.prototype||Object.keys(config).length!==keys.length||!keys.every(key=>Object.hasOwn(config,key))||typeof config.run!=='string'||!/^[a-f0-9]{16}$/.test(config.run))fail();
 diagnosticPhase='retained-roots';
 const roots=['stateRoot','archiveRoot','rawRoot'].map(key=>config[key]);if(!roots.every(root=>typeof root==='string'&&path.isAbsolute(root)&&path.normalize(root)===root)||roots.some((root,index)=>roots.some((other,otherIndex)=>index!==otherIndex&&(root===other||root.startsWith(other+'/')))))fail();
 diagnosticPhase='retained-allocation-observe';
 const initial=await adapters.observe(roots);diagnosticPhase='retained-startup-budget';if(typeof initial.free!=='bigint'||typeof initial.allocated!=='bigint'||initial.allocated<0n||initial.allocated>BUDGET||initial.free<RESERVE+(BUDGET-initial.allocated)+MARGIN)fail();
 const controller=new AbortController(),tools={};let services,timer,sampling=Promise.resolve(),stopped=false,closePromise,rejectResource;
 const resourceFailure=new Promise((_,reject)=>{rejectResource=reject;});void resourceFailure.catch(()=>{});
 const close=()=>closePromise??=(async()=>{stopped=true;controller.abort();adapters.clearTimer(timer);await sampling;let failed=false;if(services){try{await services.close();}catch{failed=true;}}for(const tool of Object.values(tools)){try{await adapters.closeTool(tool);}catch{failed=true;}}if(failed)throw recordOwnedRuntimeStartupFailure(Error('owned runtime cleanup incomplete'),'retained-cleanup','cleanup-incomplete');})();
 const sample=()=>{if(stopped)return;sampling=(async()=>{try{const value=await adapters.observe(roots);if(typeof value.free!=='bigint'||typeof value.allocated!=='bigint'||value.free<RESERVE||value.allocated>BUDGET||value.allocated<0n)fail();}catch{controller.abort();rejectResource(recordOwnedRuntimeStartupFailure(Error('owned runtime sampled resource refusal'),'retained-sampled-resource'));}finally{if(!stopped&&!controller.signal.aborted)timer=adapters.setTimer(sample,100);}})();};
 diagnosticPhase='retained-sampler-start';
 timer=adapters.setTimer(sample,100);let loading=Promise.resolve();
 try{loading=(async()=>{for(const name of ['temporal','openfga']){if(controller.signal.aborted)fail();diagnosticPhase=name==='temporal'?'retained-temporal-custody':'retained-openfga-custody';tools[name]=await adapters.reopen(name,path.join(config.archiveRoot,name+'.tar.gz'),path.join(config.rawRoot,name+'-held'));if(controller.signal.aborted)fail();}diagnosticPhase='retained-service-start';services=await adapters.start({run:config.run,rootParent:config.stateRoot,tools},undefined,controller.signal);return services;})();await Promise.race([loading,resourceFailure]);
  const completed=Promise.race([services.completed,resourceFailure]).then(async value=>{await close();return value;},async error=>{await close();throw error;});void completed.catch(()=>{});return Object.freeze({environment:services.environment,completed,close,root:config.stateRoot,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
 }catch(error){controller.abort();try{await loading;}catch{/* Preserve the original failure after joining the losing startup operation. */}await close();throw error;}

 }catch(error){recordOwnedRuntimeStartupFailure(error,diagnosticPhase);throw error;}
}
