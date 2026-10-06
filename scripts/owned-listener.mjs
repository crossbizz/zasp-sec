import {readFile,readdir,readlink}from'node:fs/promises';
const refuse=()=>{throw Error('owned listener unavailable');};
const defaultReaders={read:async p=>{const value=await readFile(p,'utf8');if(Buffer.byteLength(value)>1024*1024)refuse();return value;},fds:p=>readdir(p),link:p=>readlink(p)};
function parseStat(raw,pid){const last=raw.lastIndexOf(')');if(!raw.startsWith(pid+' (')||last<0)refuse();const fields=raw.slice(last+1).trim().split(/\s+/);if(fields.length<20||['Z','X'].includes(fields[0])||!/^[0-9]+$/.test(fields[19]))refuse();return fields[19];}
export async function captureStart(pid,readers=defaultReaders){if(!Number.isSafeInteger(pid)||pid<=1)refuse();return parseStat(await readers.read(`/proc/${pid}/stat`),pid);}
// Runtime caller supplies only its actual owned spawn PID; config cannot choose a PID.
export async function observeOwnedListener({pid,start,port},readers=defaultReaders){
 if(!Number.isSafeInteger(port)||port<1024||port>65535||await captureStart(pid,readers)!==start)refuse();
 const rows=(await readers.read('/proc/net/tcp')).trim().split('\n').slice(1);if(rows.length>8192)refuse();const address='0100007F:'+port.toString(16).toUpperCase().padStart(4,'0');
 const selected=rows.map(row=>row.trim().split(/\s+/)).filter(row=>row[1]===address&&row[3]==='0A');if(selected.length!==1||!/^[1-9][0-9]*$/.test(selected[0][9]??''))refuse();const inode=selected[0][9];
 const fds=await readers.fds(`/proc/${pid}/fd`);if(fds.length>4096||fds.some(fd=>!/^[0-9]+$/.test(fd)))refuse();let owns=false;for(const fd of fds){try{if(await readers.link(`/proc/${pid}/fd/${fd}`)===`socket:[${inode}]`)owns=true;}catch{/* Descriptors may disappear; an owned matching socket remains mandatory. */}}
 if(!owns||await captureStart(pid,readers)!==start)refuse();return Object.freeze({pid,start,port,inode});
}
