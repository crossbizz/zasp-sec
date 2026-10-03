import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startOwnedRuntimeServices } from './owned-runtime-services.mjs';
const product=JSON.parse(readFileSync(new URL('./product-model.json',import.meta.url)));
const store='01K00000000000000000000001', model='01K00000000000000000000002';
function harness(failure) {
 const calls=[];let count=0;let ticks=0;
 const adapters={
  now:()=>failure==='temporal'?(ticks++*45001):0,wait:async()=>{},
  verify: async()=>{calls.push('verify');if(failure==='verify')throw Error('private');},
  makeRoot:async()=>'/owned/run-0123456789abcdef', writeToken:async()=>calls.push('token-write'),
  reservePort:async()=>32100+(++count), token:()=>Buffer.alloc(32,1).toString('hex'),
  start:(name,args,options)=>{calls.push(['start',name,args,options]);return {completed:failure==='exited'?Promise.resolve({status:1}):new Promise(()=>{}),stop:async()=>{calls.push('join-'+name);if(failure==='cleanup-'+name)throw Error('private');}};},
  command:async(name,args)=>{calls.push(['command',name,args]);if(failure==='temporal')throw Error('private');return {namespaceInfo:{name:'zasp-browser-0123456789abcdef'}};},
  listener:async()=>{calls.push('listener-owned');},
  request:async(url,options)=>{calls.push(['request',url,options]);if(options.method==='GET'){const value=structuredClone(product);if(failure==='readback')value.type_definitions[3].relations={};return {authorization_model:{id:model,...value}};}if(failure==='store'&&url.endsWith('/stores'))throw Error('private');if(failure==='model'&&url.endsWith('/authorization-models'))throw Error('private');return url.endsWith('/stores')?{id:failure==='invalid-store'?'invalid':store}:{authorization_model_id:failure==='invalid-model'?'invalid':model};},
  removeRoot:async()=>calls.push('remove'),
 };
 const config={run:'0123456789abcdef',rootParent:'/owned',tools:{temporal:{path:'/reviewed/temporal',archive:'/reviewed/temporal.tar.gz',sha256:'a'.repeat(64)},openfga:{path:'/reviewed/openfga',archive:'/reviewed/openfga.tar.gz',sha256:'b'.repeat(64)}}};
 return {calls,adapters,config};
}
test('real-path orchestration binds namespace and published store/model before returning',async()=>{
 const h=harness();const value=await startOwnedRuntimeServices(h.config,h.adapters);
 assert.equal(value.environment.ZASP_RUNTIME_SERVICES_ENABLED,'true');assert.equal(value.environment.ZASP_OPENFGA_STORE_ID,store);assert.equal(value.environment.ZASP_OPENFGA_MODEL_ID,model);
 assert.equal(value.environment.ZASP_TEMPORAL_NAMESPACE,'zasp-browser-0123456789abcdef');assert.notEqual(value.environment.ZASP_TEMPORAL_TASK_QUEUE,value.environment.ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE);
 assert.equal(value.acceptance,false);assert.equal(value.projection,'pending');
 const posts=h.calls.filter(v=>Array.isArray(v)&&v[0]==='request');assert.equal(posts.length,3);assert.ok(posts[1][1].includes(store));assert.equal(JSON.parse(posts[1][2].body).schema_version,'1.1');assert.equal(posts[0][2].redirect,'error');assert.equal(posts[0][2].headers.Authorization,posts[1][2].headers.Authorization);
 const launches=h.calls.filter(v=>Array.isArray(v)&&v[0]==='start');assert.equal(launches.length,2);assert.ok(launches[0][2].includes('127.0.0.1'));assert.equal(launches[1][3].env.OPENFGA_HTTP_ADDR,'127.0.0.1:32102');assert.equal(launches[1][3].env.OPENFGA_DATASTORE_ENGINE,'memory');
 await value.close();await value.close();assert.deepEqual(h.calls.filter(v=>typeof v==='string'&&v.startsWith('join-')),['join-openfga','join-temporal']);assert.equal(h.calls.filter(v=>v==='remove').length,1);
});
for(const failure of ['temporal','store','model','invalid-store','invalid-model'])test('failure '+failure+' joins every owned child before removing state',async()=>{
 const h=harness(failure);await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters),/^Error: owned runtime fixture unavailable$/);
 assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);
});
test('cleanup failure joins remaining children and retains state',async()=>{const h=harness('cleanup-openfga');const value=await startOwnedRuntimeServices(h.config,h.adapters);await assert.rejects(value.close(),/^Error: owned runtime cleanup incomplete$/);assert.ok(h.calls.includes('join-temporal'));assert.ok(!h.calls.includes('remove'));});
for(const field of ['run','tools'])test('missing '+field+' refuses before any launch',async()=>{const h=harness();delete h.config[field];await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.equal(h.calls.length,0);});
test('ambient authority options refused before launch',async()=>{const h=harness();h.config.ready=true;await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.equal(h.calls.length,0);});

test('unadmitted tools refuse before any launch or state allocation',async()=>{const h=harness('verify');await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.deepEqual(h.calls,['verify']);});
test('unexpected owned child exit refuses publication and joins both children',async()=>{const h=harness('exited');await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);});
test('caller command overrides refuse before launch',async()=>{const h=harness();h.config.tools.openfga.args=['unsafe'];await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.equal(h.calls.length,0);});

test('service exit cancels and joins losing finite command before service cleanup',async()=>{
 const h=harness();let finish;let signal;let departed;let startedResolve;const started=new Promise(resolve=>{startedResolve=resolve;});
 h.adapters.start=(name)=>{h.calls.push('start-'+name);return {completed:name==='temporal'?new Promise(resolve=>{departed=resolve;}):new Promise(()=>{}),stop:async()=>h.calls.push('join-'+name)};};
 h.adapters.command=async(_name,_args,options)=>{signal=options.signal;h.calls.push('finite-start');startedResolve();return new Promise(resolve=>{finish=()=>{h.calls.push('finite-joined');resolve({namespaceInfo:{name:'zasp-browser-0123456789abcdef'}});};});};
 const running=startOwnedRuntimeServices(h.config,h.adapters);void running.catch(()=>{});await started;departed({status:1});await new Promise(resolve=>setImmediate(resolve));
 const aborted=signal?.aborted,earlyClose=h.calls.includes('join-openfga'),earlyRemove=h.calls.includes('remove');
 finish();await assert.rejects(running);assert.ok(aborted,'losing command receives cancellation');assert.ok(!earlyClose);assert.ok(!earlyRemove);assert.ok(h.calls.indexOf('finite-joined')<h.calls.indexOf('join-openfga'));assert.equal(h.calls.at(-1),'remove');
});
test('service exit cancels and finalizes losing publication before service cleanup',async()=>{
 const h=harness();let finish;let signal;let departed;let startedResolve;const started=new Promise(resolve=>{startedResolve=resolve;});
 h.adapters.start=(name)=>({completed:name==='openfga'?new Promise(resolve=>{departed=resolve;}):new Promise(()=>{}),stop:async()=>h.calls.push('join-'+name)});
 h.adapters.request=async(_url,options)=>{signal=options.signal;h.calls.push('publish-start');startedResolve();return new Promise(resolve=>{finish=()=>{h.calls.push('publish-finalized');resolve({id:store});};});};
 const running=startOwnedRuntimeServices(h.config,h.adapters);void running.catch(()=>{});await started;departed({status:1});await new Promise(resolve=>setImmediate(resolve));
 const aborted=signal?.aborted,earlyClose=h.calls.includes('join-openfga'),earlyRemove=h.calls.includes('remove');
 finish();await assert.rejects(running);assert.ok(aborted,'losing request receives cancellation');assert.ok(!earlyClose);assert.ok(!earlyRemove);assert.ok(h.calls.indexOf('publish-finalized')<h.calls.indexOf('join-openfga'));assert.equal(h.calls.at(-1),'remove');
});

test('health poll losing to service exit is canceled and finalized before service cleanup',async()=>{
 const h=harness();let finish,signal,departed,startedResolve;const started=new Promise(resolve=>{startedResolve=resolve;});
 h.adapters.start=(name)=>({completed:name==='openfga'?new Promise(resolve=>{departed=resolve;}):new Promise(()=>{}),stop:async()=>h.calls.push('join-'+name)});
 h.adapters.health=async(_url,operationSignal)=>{signal=operationSignal;h.calls.push('health-start');startedResolve();return new Promise(resolve=>{finish=()=>{h.calls.push('health-finalized');resolve(true);};});};
 const running=startOwnedRuntimeServices(h.config,h.adapters);void running.catch(()=>{});await started;departed({status:1});await new Promise(resolve=>setImmediate(resolve));
 const aborted=signal?.aborted,earlyClose=h.calls.includes('join-openfga'),earlyRemove=h.calls.includes('remove');finish();await assert.rejects(running);
 assert.ok(aborted);assert.ok(!earlyClose);assert.ok(!earlyRemove);assert.ok(h.calls.indexOf('health-finalized')<h.calls.indexOf('join-openfga'));assert.equal(h.calls.at(-1),'remove');assert.equal(h.calls.filter(v=>Array.isArray(v)&&v[0]==='request').length,0);
});

test('authenticated exact model readback is required before returning configuration',async()=>{const h=harness('readback');await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);});
test('foreign listener refuses before sending authentication token',async()=>{const h=harness();h.adapters.listener=async()=>{throw Error('foreign');};h.adapters.now=(()=>{let n=0;return()=>n++*45001;})();await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.equal(h.calls.filter(v=>Array.isArray(v)&&v[0]==='request').length,0);assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);});

for(const parent of [undefined,'relative','/owned/../elsewhere'])test('noncanonical allocation parent refuses before launch '+String(parent),async()=>{const h=harness();h.config.rootParent=parent;await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.equal(h.calls.length,0);});
test('resource cancellation finalizes finite command before reverse service joins and allocation removal',async()=>{
 const h=harness(),controller=new AbortController();let finish,signal,ready;const started=new Promise(resolve=>{ready=resolve;});
 h.adapters.command=async(_tool,_args,options)=>{signal=options.signal;h.calls.push('command-pending');ready();return new Promise(resolve=>{finish=()=>{h.calls.push('command-finalized');resolve({namespaceInfo:{name:'zasp-browser-0123456789abcdef'}});};});};
 const running=startOwnedRuntimeServices(h.config,h.adapters,controller.signal);void running.catch(()=>{});await started;controller.abort();await new Promise(resolve=>setImmediate(resolve));
 const canceled=signal.aborted,joinedEarly=h.calls.includes('join-openfga'),removedEarly=h.calls.includes('remove');finish();await assert.rejects(running);
 assert.ok(canceled);assert.equal(joinedEarly,false);assert.equal(removedEarly,false);assert.ok(h.calls.indexOf('command-finalized')<h.calls.indexOf('join-openfga'));assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);
});

test('array-shaped empty metadata is not a protobuf empty-object normalization',async()=>{const h=harness(),request=h.adapters.request;h.adapters.request=async(url,options)=>{const value=await request(url,options);if(options.method==='GET'){const type=value.authorization_model.type_definitions.find(type=>!Object.hasOwn(type,'metadata'));assert.ok(type);type.metadata=[];}return value;};await assert.rejects(startOwnedRuntimeServices(h.config,h.adapters));assert.deepEqual(h.calls.slice(-3),['join-openfga','join-temporal','remove']);});

import {createRequire}from 'node:module';
const sourceTS=createRequire(new URL('../package.json',import.meta.url))('typescript');
function actualServiceClosures(){const source=readFileSync(new URL('./owned-runtime-services.mjs',import.meta.url),'utf8'),ast=sourceTS.createSourceFile('services.mjs',source,sourceTS.ScriptTarget.Latest,true,sourceTS.ScriptKind.JS);const cleanup=ast.statements.find(n=>sourceTS.isClassDeclaration(n)&&n.name.text==='CleanupIncomplete');const Cleanup=new Function(`return (${cleanup.getText(ast)});`)();let defaults,guard;function visit(n){if(sourceTS.isVariableDeclaration(n)&&n.name.getText(ast)==='defaultAdapters')defaults=n.initializer;if(sourceTS.isVariableDeclaration(n)&&n.name.getText(ast)==='guard')guard=n.initializer;sourceTS.forEachChild(n,visit);}visit(ast);const command=defaults.properties.find(n=>n.name.getText(ast)==='command').initializer.getText(ast);assert.ok(guard);return {Cleanup,command,guard:guard.getText(ast)};}
function actualDefaultCommand(owner){const {Cleanup,command}=actualServiceClosures();const actionError=Error('owned action refusal');return {Cleanup,actionError,command:new Function('spawnHeldTool','fail','CleanupIncomplete',`return (${command});`)(async()=>owner,()=>{throw actionError;},Cleanup)};}
test('actual finite service command preserves original rejection and cleanup refusal precedence',async()=>{const original=Error('owned original failure');for(const operationFailure of [false,true])for(const cleanupFailure of [false,true]){const owner={completed:operationFailure?Promise.reject(original):Promise.resolve({status:0,signal:null,stdout:'{"value":1}'}),stop:async()=>{if(cleanupFailure)throw Error('owned stop failure');}};const value=actualDefaultCommand(owner),pending=value.command({},[],{signal:new AbortController().signal});if(cleanupFailure)await assert.rejects(pending,e=>e instanceof value.Cleanup);else if(operationFailure)await assert.rejects(pending,e=>e===original);else assert.deepEqual(await pending,{value:1});}const value=actualDefaultCommand({completed:Promise.reject(undefined),stop:async()=>{}});await value.command({},[],{signal:new AbortController().signal}).then(()=>assert.fail('undefined rejection must not become success'),error=>assert.equal(error,undefined));});
test('actual finite service command cancellation awaits delayed cleanup even after producer completion',async()=>{let finish,stopStarted;const entered=new Promise(r=>stopStarted=r),owner={completed:Promise.resolve({status:0,signal:null,stdout:'{}'}),stop:()=>{stopStarted();return new Promise((_,reject)=>finish=()=>reject(Error('owned join refused')));}};const value=actualDefaultCommand(owner),controller=new AbortController();let settled=false;const pending=value.command({},[],{signal:controller.signal}).catch(e=>{settled=true;return e;});controller.abort();await entered;await new Promise(r=>setImmediate(r));assert.equal(settled,false);finish();assert.ok((await pending)instanceof value.Cleanup);});
test('actual service guard preserves operation identity and sticky cleanup class while deleting operation records',async()=>{const {Cleanup,guard}=actualServiceClosures();for(const kind of ['success','error','cleanup','undefined','sticky']){const original=kind==='cleanup'?new Cleanup():Error('owned action');const actual=new Function('fail','CleanupIncomplete','sticky',`let exited=false,aborted=false,incompleteOperation=sticky;const owners=[],operations=new Set();const guard=${guard};return {guard,state:()=>({incompleteOperation,operations:operations.size})};`)(()=>{throw Error('owner unavailable');},Cleanup,kind==='sticky');const pending=actual.guard(()=>(kind==='success'||kind==='sticky')?Promise.resolve(42):Promise.reject(kind==='undefined'?undefined:original));if(kind==='success')assert.equal(await pending,42);else await pending.then(()=>assert.fail('refusal must remain rejected'),error=>(kind==='cleanup'||kind==='sticky')?assert.ok(error instanceof Cleanup):assert.equal(error,kind==='undefined'?undefined:original));assert.equal(actual.state().operations,0);assert.equal(actual.state().incompleteOperation,kind==='cleanup'||kind==='sticky');}});
