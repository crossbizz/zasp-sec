import { isAbsolute } from 'node:path';
import { spawnOwnedCommand } from './owned-command.mjs';

const refused = () => new Error('owned maintenance cutover refused');
const exactStatus = (value,status) => value && Object.keys(value).length===1 && value.status===status;
function channel(owned) {
  let buffer='',queue=[],waiting,ended=false,failed=false;
  const fail=()=>{failed=true;if(waiting){waiting.reject(refused());waiting=undefined;}};
  owned.child.stdout.on('data',chunk=>{
    buffer+=chunk.toString('utf8');
    if(Buffer.byteLength(buffer)>65536){fail();void owned.stop().catch(()=>{});return;}
    for(let at;(at=buffer.indexOf('\n'))>=0;){
      const line=buffer.slice(0,at);buffer=buffer.slice(at+1);
      let value;try{value=JSON.parse(line);}catch{fail();return;}
      if(queue.length>=4){fail();void owned.stop().catch(()=>{});return;}
      if(waiting){const current=waiting;waiting=undefined;current.resolve(value);}else queue.push(value);
    }
  });
  owned.child.stderr.on('data',()=>fail());
  owned.completed.then(()=>{ended=true;if(buffer.length)fail();else if(waiting)fail();},fail);
  return {next(){if(failed)return Promise.reject(refused());if(queue.length)return Promise.resolve(queue.shift());if(ended||waiting)return Promise.reject(refused());return new Promise((resolve,reject)=>{waiting={resolve,reject};});},empty(){return !failed&&!buffer.length&&!queue.length;}};
}
function environment(value){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.entries(value).every(([k,v])=>/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)&&typeof v==='string');}
function succeeded(result){if(result.status!==0||result.signal!==null||result.stderr!==''||result.outputLimitExceeded)throw refused();}
// This helper owns both actual command lifetimes. It supplies no process proof
// or withdrawal hash; the Go coordinator measures those facts independently.
export async function runOwnedMaintenanceCutover({reconcile,cutover,organization,oldEnvironment,newEnvironment,operatorEnvironment,withdrawOldCredential,timeoutMs=30000,cwd}) {
  if(![reconcile,cutover].every(x=>typeof x==='string'&&isAbsolute(x))||typeof organization!=='string'||!/^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(organization)||![oldEnvironment,newEnvironment,operatorEnvironment].every(environment)||typeof withdrawOldCredential!=='function'||!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>30000)throw refused();
  const names=['ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM','ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM','ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM'];
  if(names.some(n=>oldEnvironment[n])||names.some(n=>!/^[a-f0-9]{64}$/.test(newEnvironment[n]??'')))throw refused();
  let writer,activation,timer,closed=false,succeededWork=false;
  const withdrawal=new AbortController();
  const active=()=>{if(closed)throw refused();};
  const work=async()=>{
    writer=spawnOwnedCommand(reconcile,['-mode=reconcile-and-hold',`-organization=${organization}`,'-timeout=2m'],{cwd,env:oldEnvironment,keepStdinOpen:true,maxOutputBytes:65536});
    const wc=channel(writer);
    const receipt=await wc.next();
    if(receipt.organization_id!==organization||receipt.status!=='applied'||receipt.receipt?.Applied!==true||!Number.isSafeInteger(receipt.receipt.TupleCount)||receipt.receipt.TupleCount<0)throw refused();
    if(!exactStatus(await wc.next(),'writer-held')||!wc.empty())throw refused();
    active();
    activation=spawnOwnedCommand(cutover,['-mode=activate',`-organization=${organization}`,`-old-writer-pid=${writer.child.pid}`],{cwd,env:{...newEnvironment,...operatorEnvironment,ZASP_CONTROLLED_OLD_TOKEN_FILE:oldEnvironment.ZASP_OPENFGA_TOKEN_FILE,ZASP_CONTROLLED_NEW_TOKEN_FILE:newEnvironment.ZASP_OPENFGA_TOKEN_FILE},keepStdinOpen:true,maxOutputBytes:65536});
    const ac=channel(activation);
    if(!exactStatus(await ac.next(),'withdrawal-required')||!ac.empty())throw refused();
    writer.child.stdin.end();succeeded(await writer.completed);if(!wc.empty())throw refused();
    active();await withdrawOldCredential(withdrawal.signal);active();
    activation.child.stdin.end('continue\n');
    if(!exactStatus(await ac.next(),'activated'))throw refused();
    succeeded(await activation.completed);if(!ac.empty())throw refused();
    return {activated:true};
  };
  // The credential owner must honor cancellation and join its bounded normal
  // stop/restart finalizers before settling this callback. Never discard it.
  const workPromise=work();
  try{const result=await Promise.race([workPromise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(refused()),timeoutMs);})]);succeededWork=true;return result;}
  catch{throw refused();}
  finally{
    closed=true;clearTimeout(timer);if(!succeededWork)withdrawal.abort();
    const cleanup=await Promise.allSettled([activation?.stop(),writer?.stop()]);
    // Stopping the children releases any pending protocol reads. The retained
    // work also joins a credential withdrawal already in progress on timeout.
    await workPromise.catch(()=>{});
    if(cleanup.some(result=>result.status!=='fulfilled'))throw refused();
  }
}
