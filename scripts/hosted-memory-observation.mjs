import assert from 'node:assert/strict';
import { open } from 'node:fs/promises';
import path from 'node:path';

// Kernel metadata only. No environment fallback, invented reserve or service authority.
async function boundedRead(file,cap){const handle=await open(file,'r');try{const bytes=Buffer.alloc(cap+1);let length=0;while(length<bytes.length){const result=await handle.read(bytes,length,bytes.length-length,null);if(!result.bytesRead)break;length+=result.bytesRead;}assert.ok(length<=cap);return bytes.subarray(0,length).toString('utf8');}finally{await handle.close();}}
const canonical=value=>typeof value==='string'&&value.startsWith('/')&&path.posix.normalize(value)===value&&!/[\0\r\n\t]/.test(value)&&!value.split('/').includes('..');
function decoded(value){return value.replace(/\\(040|011|012|134)/g,(_,octal)=>String.fromCharCode(Number.parseInt(octal,8)));}
function integer(value){assert.match(value,/^(0|[1-9][0-9]*)$/);return BigInt(value);}

// Injectable reader is for stdlib parser controls only; actual runner uses the
// default bounded kernel reader and accepts no caller-selected paths or reader.
export async function observeHostedMemory(read=boundedRead){
 const meminfo=await read('/proc/meminfo',65536);const hosts=[...meminfo.matchAll(/^MemAvailable:\s+([0-9]+) kB$/gm)];assert.equal(hosts.length,1);
 const host=integer(hosts[0][1])*1024n;assert.ok(host<=BigInt(Number.MAX_SAFE_INTEGER));
 const memberships=(await read('/proc/self/cgroup',65536)).trim().split('\n');assert.ok(memberships.length<=256);
 const unified=memberships.filter(row=>row.startsWith('0::'));assert.equal(unified.length,1,'unified memory hierarchy required');const member=unified[0].slice(3);assert.ok(canonical(member));
 const mountRows=(await read('/proc/self/mountinfo',1024*1024)).trim().split('\n');assert.ok(mountRows.length<=8192);
 const mounts=mountRows.map(row=>row.split(' - ')).filter(row=>row.length===2&&row[1].split(' ')[0]==='cgroup2').map(row=>{const fields=row[0].split(' ');assert.ok(fields.length>=6);return {root:decoded(fields[3]),mount:decoded(fields[4])};});
 const selected=mounts.filter(row=>row.mount==='/sys/fs/cgroup');assert.equal(selected.length,1);const mount=selected[0];assert.ok(canonical(mount.root)&&canonical(mount.mount));
 // Subtree mounts hide possible finite ancestors. Refuse this unknown scope.
 assert.equal(mount.root,'/','complete visible cgroup hierarchy required');
 const segments=member.split('/').filter(Boolean);assert.ok(segments.length<=256);let available=host,finite=0,observed=0;
 for(let depth=segments.length;depth>=0;depth--){
  const directory=path.posix.join(mount.mount,...segments.slice(0,depth));assert.ok(directory===mount.mount||directory.startsWith(mount.mount+'/'));observed++;
  let maximum;
  try{maximum=(await read(directory+'/memory.max',64)).trim();}
  catch(error){
   if(error?.code!=='ENOENT')throw error;
   // The true hierarchy root has no resource-control memory.max on native VMs.
   // A nonroot without its memory controller cannot define a limit; still walk
   // every ancestor. Available-but-unreadable interfaces fail closed.
   if(depth!==0){const controllers=(await read(directory+'/cgroup.controllers',4096)).trim().split(/\s+/);assert.ok(!controllers.includes('memory'),'missing active memory interface');}
   continue;
  }
  if(maximum==='max')continue;
  const limit=integer(maximum),current=integer((await read(directory+'/memory.current',64)).trim());finite++;const remaining=limit-current;if(remaining<available)available=remaining;
 }
 return Object.freeze({availableBytes:Number(available<0n?0n:available),hostAvailableBytes:Number(host),finiteAncestorLimits:finite,visibleGroupsObserved:observed,basis:'minimum-host-MemAvailable-and-all-visible-finite-cgroup-ancestors'});
}
