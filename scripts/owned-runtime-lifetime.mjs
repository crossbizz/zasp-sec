import {recordOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';
export {describeOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';
import { lstat, readdir, realpath, statfs } from 'node:fs/promises';
import path from 'node:path';
import { loadOfficialHeldTool, reopenOfficialHeldTool, closeHeldTool } from './official-held-tools.mjs';
import { startOwnedRuntimeServices, validOwnedOpenFGAPostgresDSN } from './owned-runtime-services.mjs';

const RESERVE=2684354560n,BUDGET=536870912n,MARGIN=33554432n;
const fail=()=>{throw Error('owned runtime resource unavailable');};
// Closed reason labels distinguish resource failures without publishing paths,
// process output, credentials, or caller-controlled error properties.
const allocationReasons=new WeakMap();
const allocationFail=kind=>{const error=Error('owned runtime resource unavailable');allocationReasons.set(error,kind);throw error;};
function checkRetainedSample(value){
 if(typeof value.free!=='bigint'||typeof value.allocated!=='bigint'||value.allocated<0n)allocationFail('resource-value');
 if(value.free<RESERVE)allocationFail('resource-reserve');
 if(value.allocated>BUDGET)allocationFail('resource-budget');
}
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
 if(!config||Object.getPrototypeOf(config)!==Object.prototype||(Object.keys(config).length!==2&&!(Object.keys(config).length===3&&Object.hasOwn(config,'openfgaPostgresDSN')&&validOwnedOpenFGAPostgresDSN(config.openfgaPostgresDSN)))||!Object.hasOwn(config,'root')||!Object.hasOwn(config,'run')||typeof config.root!=='string'||!path.isAbsolute(config.root)||path.normalize(config.root)!==config.root||typeof config.run!=='string'||!/^[a-f0-9]{16}$/.test(config.run))fail();
 const initial=await adapters.observe(config.root);if(typeof initial.free!=='bigint'||typeof initial.allocated!=='bigint'||initial.free<RESERVE+BUDGET+MARGIN||initial.allocated>BUDGET||initial.allocated<0n)fail();
 const controller=new AbortController(),tools={};let services,timer,sampling=Promise.resolve(),stopped=false,closePromise,rejectResource;
 const resourceFailure=new Promise((_,reject)=>{rejectResource=reject;});void resourceFailure.catch(()=>{});
 const close=()=>closePromise??=(async()=>{stopped=true;controller.abort();adapters.clearTimer(timer);await sampling;let failed=false;if(services){try{await services.close();}catch{failed=true;}}for(const tool of Object.values(tools)){try{await adapters.closeTool(tool);}catch{failed=true;}}if(failed)throw Error('owned runtime cleanup incomplete');})();
 // Startup failure cleanup must stop and join this observer before removing state.
 const beforeStartupCleanup=async()=>{stopped=true;adapters.clearTimer(timer);await sampling;};
 const sample=()=>{if(stopped)return;sampling=(async()=>{try{const value=await adapters.observe(config.root);if(typeof value.free!=='bigint'||typeof value.allocated!=='bigint'||value.free<RESERVE||value.allocated>BUDGET||value.allocated<0n)fail();}catch{controller.abort();rejectResource(Error('owned runtime sampled resource refusal'));}finally{if(!stopped&&!controller.signal.aborted)timer=adapters.setTimer(sample,100);}})();};
 timer=adapters.setTimer(sample,100);
 let loading=Promise.resolve();
 try{
  loading=(async()=>{for(const name of ['temporal','openfga']){if(controller.signal.aborted)fail();tools[name]=await adapters.load(name,path.join(config.root,name+'.tar.gz'),path.join(config.root,name+'-held'));if(controller.signal.aborted)fail();}services=await adapters.start({run:config.run,rootParent:config.root,tools,...(Object.hasOwn(config,'openfgaPostgresDSN')?{openfgaPostgresDSN:config.openfgaPostgresDSN}:{})},undefined,controller.signal,beforeStartupCleanup);return services;})();
  await Promise.race([loading,resourceFailure]);
  const completed=Promise.race([services.completed,resourceFailure]).then(async value=>{await close();return value;},async error=>{await close();throw error;});void completed.catch(()=>{});
  return Object.freeze({environment:services.environment,...(services.withdrawOldCredential?{oldTokenFile:services.oldTokenFile,newTokenFile:services.newTokenFile,withdrawOldCredential:services.withdrawOldCredential}:{}),completed,close,root:config.root,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
 }catch(error){controller.abort();try{await loading;}catch{/* Preserve the original failure after joining the losing startup operation. */}await close();throw error;}
}

const retainedFileOperations=Object.freeze({lstat,readdir,realpath,statfs});
export async function observeRetainedAllocation(roots,io=retainedFileOperations){
 try {
  if(!io||Object.getPrototypeOf(io)!==Object.prototype||Object.keys(io).length!==4||!['lstat','readdir','realpath','statfs'].every(name=>typeof io[name]==='function'))allocationFail('allocation-io');
  const pins=[];let device;
  // A retry never adopts replacement roots. Pin every root before either walk.
  for(const root of roots){
   const info=await io.lstat(root,{bigint:true});
   if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o077n)!==0n||info.uid!==BigInt(process.getuid())||await io.realpath(root)!==root||device!==undefined&&info.dev!==device)allocationFail('allocation-root');
   device=info.dev;pins.push({root,info});
  }
  const checkRoot=async({root,info})=>{
   const current=await io.lstat(root,{bigint:true});
   if(current.dev!==info.dev||current.ino!==info.ino||current.uid!==info.uid||current.mode!==info.mode||!current.isDirectory()||current.isSymbolicLink()||await io.realpath(root)!==root)allocationFail('allocation-root');
  };
  const missingDescendants=new WeakSet();let entries=0,peakAllocated=0n,minimumFree;
  const descendantOperation=async(root,current,operation)=>{
   try{return await operation();}
   catch(error){
    // Only disappearance of a generated, strict descendant during lstat or
    // readdir can restart the whole observation. Root and other I/O fail shut.
    if(error instanceof Error&&error.code==='ENOENT'&&current!==root&&current.startsWith(root+'/')&&path.normalize(current)===current)missingDescendants.add(error);
    throw error;
   }
  };
  for(let attempt=0;attempt<2;attempt++){
   const identities=new Set();let allocated=0n;
   try{
    for(const pin of pins){
     const {root}=pin;await checkRoot(pin);const pending=[root];
     while(pending.length){
      const current=pending.pop();if(++entries>100000)allocationFail('allocation-limit');
      const info=await descendantOperation(root,current,()=>io.lstat(current,{bigint:true})),identity=info.dev+':'+info.ino;
      if(info.dev!==device||info.uid!==BigInt(process.getuid())||identities.has(identity))allocationFail('allocation-identity');
      if(info.isSymbolicLink()||info.isFile()&&info.nlink!==1n)allocationFail('allocation-link');
      if(info.isSocket())allocationFail('allocation-socket');
      if(!info.isDirectory()&&!info.isFile())allocationFail('allocation-node');
      identities.add(identity);allocated+=info.blocks*512n;if(allocated>peakAllocated)peakAllocated=allocated;
      if(info.isDirectory()){
       const names=await descendantOperation(root,current,()=>io.readdir(current));
       if(names.length+entries>100000)allocationFail('allocation-limit');
       for(const name of names)pending.push(path.join(current,name));
      }
     }
     await checkRoot(pin);
     const disk=await io.statfs(root,{bigint:true}),free=disk.bavail*disk.bsize;
     minimumFree=minimumFree===undefined?free:free<minimumFree?free:minimumFree;
    }
    for(const pin of pins)await checkRoot(pin);
    return {allocated:peakAllocated,free:minimumFree};
   }catch(error){
    if(attempt!==0||!missingDescendants.has(error))throw error;
    for(const pin of pins)await checkRoot(pin);
    // Keep the aggregate work cap, partial allocation high-water mark and
    // lowest observed reserve. No entry is omitted from the successful walk.
   }
  }
 } catch(error) {
  if(error instanceof Error&&!allocationReasons.has(error))allocationReasons.set(error,error.code==='ENOENT'?'allocation-missing':'allocation-io');
  throw error;
 }
}
const retainedDefaults={...defaults,observe:observeRetainedAllocation,reopen:reopenOfficialHeldTool};
export async function startRetainedOwnedRuntimeLifetime(config,adapters=retainedDefaults){
 let diagnosticPhase='retained-input';
 try{
 const keys=['stateRoot','archiveRoot','rawRoot','run'];if(!config||Object.getPrototypeOf(config)!==Object.prototype||(Object.keys(config).length!==keys.length&&!(Object.keys(config).length===keys.length+1&&Object.hasOwn(config,'openfgaPostgresDSN')&&validOwnedOpenFGAPostgresDSN(config.openfgaPostgresDSN)))||!keys.every(key=>Object.hasOwn(config,key))||typeof config.run!=='string'||!/^[a-f0-9]{16}$/.test(config.run))fail();
 diagnosticPhase='retained-roots';
 const roots=['stateRoot','archiveRoot','rawRoot'].map(key=>config[key]);if(!roots.every(root=>typeof root==='string'&&path.isAbsolute(root)&&path.normalize(root)===root)||roots.some((root,index)=>roots.some((other,otherIndex)=>index!==otherIndex&&(root===other||root.startsWith(other+'/')))))fail();
 diagnosticPhase='retained-allocation-observe';
 const initial=await adapters.observe(roots);diagnosticPhase='retained-startup-budget';if(typeof initial.free!=='bigint'||typeof initial.allocated!=='bigint'||initial.allocated<0n||initial.allocated>BUDGET||initial.free<RESERVE+(BUDGET-initial.allocated)+MARGIN)fail();
 const controller=new AbortController(),tools={};let services,timer,sampling=Promise.resolve(),stopped=false,closePromise,rejectResource;
 const resourceFailure=new Promise((_,reject)=>{rejectResource=reject;});void resourceFailure.catch(()=>{});
 const close=()=>closePromise??=(async()=>{stopped=true;controller.abort();adapters.clearTimer(timer);await sampling;let failed=false;if(services){try{await services.close();}catch{failed=true;}}for(const tool of Object.values(tools)){try{await adapters.closeTool(tool);}catch{failed=true;}}if(failed)throw recordOwnedRuntimeStartupFailure(Error('owned runtime cleanup incomplete'),'retained-cleanup','cleanup-incomplete');})();
 // Startup failure cleanup must stop and join this observer before removing state.
 const beforeStartupCleanup=async()=>{stopped=true;adapters.clearTimer(timer);await sampling;};
 const sample=()=>{if(stopped)return;sampling=(async()=>{try{const value=await adapters.observe(roots);checkRetainedSample(value);}catch(error){controller.abort();rejectResource(recordOwnedRuntimeStartupFailure(Error('owned runtime sampled resource refusal'),'retained-sampled-resource',allocationReasons.get(error)??'refused'));}finally{if(!stopped&&!controller.signal.aborted)timer=adapters.setTimer(sample,100);}})();};
 diagnosticPhase='retained-sampler-start';
 timer=adapters.setTimer(sample,100);let loading=Promise.resolve();
 try{loading=(async()=>{for(const name of ['temporal','openfga']){if(controller.signal.aborted)fail();diagnosticPhase=name==='temporal'?'retained-temporal-custody':'retained-openfga-custody';tools[name]=await adapters.reopen(name,path.join(config.archiveRoot,name+'.tar.gz'),path.join(config.rawRoot,name+'-held'));if(controller.signal.aborted)fail();}diagnosticPhase='retained-service-start';services=await adapters.start({run:config.run,rootParent:config.stateRoot,tools,...(Object.hasOwn(config,'openfgaPostgresDSN')?{openfgaPostgresDSN:config.openfgaPostgresDSN}:{})},undefined,controller.signal,beforeStartupCleanup);return services;})();await Promise.race([loading,resourceFailure]);
  const completed=Promise.race([services.completed,resourceFailure]).then(async value=>{await close();return value;},async error=>{await close();throw error;});void completed.catch(()=>{});return Object.freeze({environment:services.environment,...(services.withdrawOldCredential?{oldTokenFile:services.oldTokenFile,newTokenFile:services.newTokenFile,withdrawOldCredential:services.withdrawOldCredential}:{}),completed,close,root:config.stateRoot,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
 }catch(error){controller.abort();try{await loading;}catch{/* Preserve the original failure after joining the losing startup operation. */}await close();throw error;}

 }catch(error){recordOwnedRuntimeStartupFailure(error,diagnosticPhase,allocationReasons.get(error)??'refused');throw error;}
}
