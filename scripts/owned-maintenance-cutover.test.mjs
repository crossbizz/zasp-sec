import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runOwnedMaintenanceCutover} from './owned-maintenance-cutover.mjs';
const organization='pid_00010203-0405-4607-8809-0a0b0c0d0e0f';
async function fixture(t,mode='ok'){
 const root=await mkdtemp(join(tmpdir(),'zasp-cutover-protocol-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const trace=join(root,'trace');await writeFile(trace,'');
 const script=async(name,source)=>{const p=join(root,name);await writeFile(p,`#!${process.execPath}\n${source}`,{mode:0o700});return p;};
 const common=`const fs=require('node:fs');const trace=${JSON.stringify(trace)};const mark=x=>fs.appendFileSync(trace,x+'\\n');mark(process.pid.toString());`;
 const reconcile=await script('writer',`${common}
 process.stdin.resume();
 ${mode==='missing-receipt'?'':`console.log(JSON.stringify({organization_id:${JSON.stringify(organization)},status:'applied',receipt:{Applied:true,TupleCount:1}}));`}
 console.log(JSON.stringify({status:'writer-held'}));process.stdin.on('end',()=>{mark('writer-closed');});`);
 const cutover=await script('cutover',`${common}
 console.log(JSON.stringify({status:${JSON.stringify(mode==='bad-status'?'secret-dependency-error':'withdrawal-required')}}));
 ${mode==='timeout'?'setInterval(()=>{},1000);':`let input='';process.stdin.on('data',v=>input+=v);process.stdin.on('end',()=>{if(input!=='continue\\n')process.exitCode=1;else {mark('activated');console.log(JSON.stringify({status:'activated'}));}});`}`);
 const oldEnvironment={ZASP_OPENFGA_TOKEN_FILE:join(root,'old')};
 const newEnvironment={ZASP_OPENFGA_TOKEN_FILE:join(root,'new'),ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM:'a'.repeat(64),ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM:'b'.repeat(64),ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM:'c'.repeat(64)};
 const options={reconcile,cutover,organization,oldEnvironment,newEnvironment,operatorEnvironment:{},timeoutMs:2000,withdrawOldCredential:async()=>{assert.match(await readFile(trace,'utf8'),/writer-closed\n/);await writeFile(trace,'withdrawn\n',{flag:'a'});if(mode==='withdraw-fails')throw Error('private credential detail');}};
 return {options,trace};
}
test('owned cutover orders real writer exit, credential withdrawal and fixed handshake',async t=>{
 const {options,trace}=await fixture(t);assert.deepEqual(await runOwnedMaintenanceCutover(options),{activated:true});
 assert.match(await readFile(trace,'utf8'),/writer-closed\nwithdrawn\nactivated\n$/);
});
for(const mode of ['missing-receipt','bad-status','withdraw-fails','timeout'])test(`owned cutover refuses ${mode} and joins owned processes`,{timeout:10000},async t=>{
 const {options,trace}=await fixture(t,mode);if(mode==='timeout')options.timeoutMs=1000;
 await assert.rejects(runOwnedMaintenanceCutover(options),{message:'owned maintenance cutover refused'});
 const log=await readFile(trace,'utf8');assert.doesNotMatch(log,/activated/);
 for(const line of log.split('\n').filter(x=>/^\d+$/.test(x))){assert.throws(()=>process.kill(Number(line),0),{code:'ESRCH'});}
});
test('owned cutover rejects ambient active old writer configuration before spawning',async t=>{
 const {options,trace}=await fixture(t);options.oldEnvironment.ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM='b'.repeat(64);
 await assert.rejects(runOwnedMaintenanceCutover(options),{message:'owned maintenance cutover refused'});assert.equal(await readFile(trace,'utf8'),'');
});

test('deadline aborts and joins in-flight withdrawal finalizer before returning', {timeout:10000}, async t=>{
 const {options,trace}=await fixture(t);options.timeoutMs=1000;
 let release,observeAbort,finalized=false,settled=false;
 const gate=new Promise(resolve=>{release=resolve;});
 const aborted=new Promise(resolve=>{observeAbort=resolve;});
 options.withdrawOldCredential=async signal=>{
   try {
     if(signal instanceof AbortSignal){
       if(signal.aborted)observeAbort();else signal.addEventListener('abort',observeAbort,{once:true});
     }
     await gate;
   }finally{finalized=true;}
 };
 const pending=runOwnedMaintenanceCutover(options);
 const settlement=pending.then(()=>{settled=true;},()=>{settled=true;});
 try {
   assert.equal(await Promise.race([aborted.then(()=> 'aborted'),settlement.then(()=> 'returned')]),'aborted');
   assert.equal(settled,false,'returned before the withdrawal finalizer joined');
   assert.equal(finalized,false);
 }finally{release();}
 await assert.rejects(pending,{message:'owned maintenance cutover refused'});
 assert.equal(finalized,true);
 assert.doesNotMatch(await readFile(trace,'utf8'),/activated/);
});
