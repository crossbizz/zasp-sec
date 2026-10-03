import { createHash, randomBytes } from 'node:crypto';
import { readFile, lstat, realpath, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import {captureStart,observeOwnedListener}from './owned-listener.mjs';
import { heldToolName, verifyHeldTool, spawnHeldTool, closeHeldTool } from './official-held-tools.mjs';
const MODEL_SHA='329f49e1f2effecbe1a0e9caf6c89be939b1e36e034155d74977bfc82c73cc2c';
const hash=b=>createHash('sha256').update(b).digest('hex');
const fail=()=>{throw Error('owned runtime fixture unavailable');};
const exact=(v,k)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===k.length&&k.every(x=>Object.hasOwn(v,x));
const ulid=v=>typeof v==='string'&&/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(v);
class CleanupIncomplete extends Error { constructor(){super('owned runtime cleanup incomplete');} }
const lifetimes=new WeakMap();
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value!==null&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
function exactModel(expected,actual,id){if(!actual||actual.id!==id)return false;const model=structuredClone(actual);delete model.id;if(!Array.isArray(model.type_definitions)||model.type_definitions.length!==expected.type_definitions.length)return false;for(let i=0;i<model.type_definitions.length;i++){for(const field of ['relations','metadata'])if(!Object.hasOwn(expected.type_definitions[i],field)&&model.type_definitions[i][field]&&Object.getPrototypeOf(model.type_definitions[i][field])===Object.prototype&&Object.keys(model.type_definitions[i][field]).length===0)delete model.type_definitions[i][field];}return canonical(expected)===canonical(model);}
const defaultAdapters={
 verify:async tools=>{for(const name of ['temporal','openfga']){if(heldToolName(tools[name])!==name)fail();await verifyHeldTool(tools[name]);}},
 makeRoot:async(run,parent)=>{const info=await lstat(parent);if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o077)!==0||info.uid!==process.getuid()||await realpath(parent)!==parent)fail();return mkdtemp(path.join(parent,'zasp-browser-'+run+'-'));},
 writeToken:async(root,token)=>{await mkdir(path.join(root,'home'),{mode:0o700});await writeFile(path.join(root,'openfga.token'),token,{flag:'wx',mode:0o600});},
 now:()=>Date.now(), wait:milliseconds=>delay(milliseconds),
 token:()=>randomBytes(32).toString('hex'),
 reservePort:()=>new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(error=>error?reject(error):resolve(port));});}),
 start:async(name,args,options)=>{const owner=await spawnHeldTool(options.tool,args,{cwd:options.cwd,env:options.env,maxOutputBytes:1024*1024});try{lifetimes.set(owner,await captureStart(owner.child.pid));return owner;}catch(error){await owner.stop();throw error;}},
 listener:async(name,owner,port)=>observeOwnedListener({pid:owner.child.pid,start:lifetimes.get(owner),port}),
 command:async(tool,args,options)=>{const owner=await spawnHeldTool(tool,args,{cwd:options.cwd,env:options.env,maxOutputBytes:1024*1024});let cleanup;
  const cancel=()=>{cleanup??=owner.stop();void cleanup.catch(()=>{});};
  options.signal.addEventListener('abort',cancel,{once:true});if(options.signal.aborted)cancel();
  let result,operationError,operationFailed=false,cleanupFailed=false;
  try{const completed=await owner.completed;if(options.signal.aborted||completed.status!==0||completed.signal||completed.outputLimitExceeded)fail();result=JSON.parse(completed.stdout);}
  catch(error){operationError=error;operationFailed=true;}
  finally{options.signal.removeEventListener('abort',cancel);try{await (cleanup??owner.stop());}catch{cleanupFailed=true;}}
  if(cleanupFailed)throw new CleanupIncomplete();if(operationFailed)throw operationError;return result;
 },
 request:async(url,options)=>{const response=await fetch(url,{...options,signal:options.signal});if(!response.ok){await response.body?.cancel();fail();}const reader=response.body.getReader();let size=0;const chunks=[];try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>1024*1024)fail();chunks.push(Buffer.from(value));}return JSON.parse(Buffer.concat(chunks).toString('utf8'));}finally{await reader.cancel();}},
 health:async(url,signal)=>{const response=await fetch(url,{redirect:'error',signal});try{return response.ok;}finally{await response.body?.cancel();}},
 removeRoot:root=>rm(root,{recursive:true,force:false}),
};
// This is service ownership/model publication only. It does not install SQL,
// register principals/verifiers, acknowledge projection, or grant acceptance.
// Production tools are opaque capabilities minted from exact official archives and consumed members. Test adapters never mint production authority.
export async function startOwnedRuntimeServices(config,adapters=defaultAdapters,signal){
 if((signal!==undefined&&!(signal instanceof AbortSignal))||!exact(config,['run','rootParent','tools'])||typeof config.run!=='string'||!/^[a-f0-9]{16}$/.test(config.run)||!exact(config.tools,['temporal','openfga'])||typeof config.rootParent!=='string'||!path.isAbsolute(config.rootParent)||path.normalize(config.rootParent)!==config.rootParent)fail();
 if(adapters===defaultAdapters){for(const name of ['temporal','openfga'])if(heldToolName(config.tools[name])!==name)fail();}
 else for(const name of ['temporal','openfga']){const t=config.tools[name];if(!exact(t,['path','archive','sha256'])||path.basename(t.path??'')!==name)fail();}
 const model=await readFile(new URL('./product-model.json',import.meta.url));if(hash(model)!==MODEL_SHA)fail();
 try{await adapters.verify(config.tools);}catch(error){if(adapters===defaultAdapters)await Promise.allSettled(Object.values(config.tools).map(closeHeldTool));throw error;}
 let root;try{root=await adapters.makeRoot(config.run,config.rootParent);}catch(error){if(adapters===defaultAdapters)await Promise.allSettled(Object.values(config.tools).map(closeHeldTool));throw error;}
 const owners=[],operations=new Set();let closePromise,exited=false,incompleteOperation=false,aborted=signal?.aborted??false;
 const abort=()=>{aborted=true;for(const op of operations)op.controller.abort();};signal?.addEventListener('abort',abort,{once:true});
 const close=()=>closePromise??=(async()=>{let incomplete=incompleteOperation;for(const op of operations)op.controller.abort();await Promise.allSettled([...operations].map(op=>op.finalized));incomplete||=incompleteOperation;for(const owner of owners.slice().reverse()){try{await owner.stop();}catch{incomplete=true;}}if(adapters===defaultAdapters)for(const tool of Object.values(config.tools)){try{await closeHeldTool(tool);}catch{incomplete=true;}}signal?.removeEventListener('abort',abort);if(incomplete)throw new CleanupIncomplete();await adapters.removeRoot(root);})();
 const namespace='zasp-browser-'+config.run;
 const guard=async action=>{
  if(exited||aborted)fail();const controller=new AbortController();let timer;
  const op={controller};op.finalized=Promise.resolve().then(()=>action(controller.signal));operations.add(op);
  void op.finalized.catch(error=>{if(error instanceof CleanupIncomplete)incompleteOperation=true;});
  let result,operationError,operationFailed=false;
  try{result=await Promise.race([op.finalized,new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(Error('cancelled')),{once:true})),...owners.map(owner=>owner.completed.then(fail,fail)),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('deadline')),5000);})]);if(exited||aborted)fail();}
  catch(error){operationError=error;operationFailed=true;}
  finally{clearTimeout(timer);controller.abort();try{await op.finalized;}catch(error){if(error instanceof CleanupIncomplete)incompleteOperation=true;}operations.delete(op);}
  if(incompleteOperation)throw new CleanupIncomplete();if(operationFailed)throw operationError;return result;
 };
 try{
  const token=adapters.token();if(typeof token!=='string'||!/^[a-f0-9]{64}$/.test(token))fail();await adapters.writeToken(root,token);
  const temporalPort=await adapters.reservePort(),fgaPort=await adapters.reservePort();if(![temporalPort,fgaPort].every(v=>Number.isSafeInteger(v)&&v>=1024&&v<=65535)||temporalPort===fgaPort)fail();
  const temporalAddress='127.0.0.1:'+temporalPort,fgaURL='http://127.0.0.1:'+fgaPort;
  const env={PATH:'/usr/bin:/bin',HOME:path.join(root,'home'),TMPDIR:root,LANG:'C',LC_ALL:'C'};
  if(aborted)fail();owners.push(await adapters.start('temporal',['server','start-dev','--ip','127.0.0.1','--port',String(temporalPort),'--headless','--db-filename',path.join(root,'temporal.sqlite'),'--namespace',namespace],{tool:config.tools.temporal,cwd:root,env}));
  if(aborted)fail();owners.push(await adapters.start('openfga',['run'],{tool:config.tools.openfga,cwd:root,env:{...env,OPENFGA_HTTP_ADDR:'127.0.0.1:'+fgaPort,OPENFGA_GRPC_ADDR:'127.0.0.1:0',OPENFGA_DATASTORE_ENGINE:'memory',OPENFGA_AUTHN_METHOD:'preshared',OPENFGA_AUTHN_PRESHARED_KEYS:token,OPENFGA_PLAYGROUND_ENABLED:'false',OPENFGA_METRICS_ENABLED:'false',OPENFGA_LOG_LEVEL:'warn'}}));
  for(const owner of owners)void owner.completed.then(()=>{exited=true;},()=>{exited=true;});
  // Poll only read-only namespace describe; no existing namespace is modified.
  const deadline=adapters.now()+45000;let described;
  for(;;){try{described=await guard(signal=>adapters.command(config.tools.temporal,['operator','namespace','describe','--namespace',namespace,'--address',temporalAddress,'--output','json'],{cwd:root,env,signal}));if(described?.namespaceInfo?.name===namespace)break;}catch{if(exited||aborted||incompleteOperation)fail();}if(adapters.now()>=deadline)fail();await adapters.wait(100);}
  for(const [name,owner,port]of [['temporal',owners[0],temporalPort],['openfga',owners[1],fgaPort]]){let matched=false;while(adapters.now()<deadline){try{await guard(signal=>adapters.listener(name,owner,port,signal));matched=true;break;}catch{if(exited||aborted||incompleteOperation)fail();}await adapters.wait(100);}if(!matched)fail();}
  const post=async(url,body)=>{await guard(signal=>adapters.listener('openfga',owners[1],fgaPort,signal));const result=await guard(signal=>adapters.request(url,{method:'POST',redirect:'error',signal,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body)}));await guard(signal=>adapters.listener('openfga',owners[1],fgaPort,signal));return result;};
  // Service startup may still be pending; repeated CreateStore is NOT used as a health probe.
  if(adapters.health){let healthy=false;while(adapters.now()<deadline){try{await guard(signal=>adapters.listener('openfga',owners[1],fgaPort,signal));healthy=await guard(signal=>adapters.health(fgaURL+'/healthz',signal));if(healthy)break;}catch{if(exited||aborted||incompleteOperation)fail();}await adapters.wait(100);}if(!healthy)fail();}
  const store=await post(fgaURL+'/stores',{name:'zasp-browser-'+config.run});if(!ulid(store?.id))fail();
  const published=await post(fgaURL+'/stores/'+store.id+'/authorization-models',JSON.parse(model));if(!ulid(published?.authorization_model_id))fail();
  await guard(signal=>adapters.listener('openfga',owners[1],fgaPort,signal));
  const readback=await guard(signal=>adapters.request(fgaURL+'/stores/'+store.id+'/authorization-models/'+published.authorization_model_id,{method:'GET',redirect:'error',signal,headers:{Authorization:'Bearer '+token}}));
  if(!exactModel(JSON.parse(model),readback?.authorization_model,published.authorization_model_id))fail();
  await guard(signal=>adapters.listener('openfga',owners[1],fgaPort,signal));
  const environment=Object.freeze({ZASP_RUNTIME_SERVICES_ENABLED:'true',ZASP_ENVIRONMENT:'test',ZASP_RUNTIME_SERVICES_TIMEOUT:'5s',ZASP_TEMPORAL_ADDRESS:temporalAddress,ZASP_TEMPORAL_NAMESPACE:namespace,ZASP_TEMPORAL_TASK_QUEUE:'zasp-browser-main-'+config.run,ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE:'zasp-browser-discovery-'+config.run,ZASP_OPENFGA_URL:fgaURL,ZASP_OPENFGA_STORE_ID:store.id,ZASP_OPENFGA_MODEL_ID:published.authorization_model_id,ZASP_OPENFGA_TOKEN_FILE:path.join(root,'openfga.token')});
  const completed=Promise.race(owners.map(owner=>owner.completed));void completed.catch(()=>{});
  return Object.freeze({environment,root,close,completed,projection:'pending',acceptance:false,native:false,production:false,upgradeInstalled:false,deployed:false,ledger:false});
 }catch{try{await close();}catch{throw Error('owned runtime cleanup incomplete');}throw Error('owned runtime fixture unavailable');}
}
