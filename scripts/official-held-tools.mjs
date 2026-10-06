import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { open, mkdir, rm, lstat, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { spawnFixedFDCommand } from './owned-fixed-fd-command.mjs';
const profiles=Object.freeze({temporal:{sha:'09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5',compressed:45298806,expanded:160*1024*1024,binary:156328098},openfga:{sha:'0230a0f72c7bcc8ae6aeddd9dbf6d519e52934ab714b2900ce164d165b6df389',compressed:21232870,expanded:64*1024*1024,binary:64*1024*1024}});
const members={"temporal":[["LICENSE",1108],["temporal",156328098]],"openfga":[["assets/assets.go",538],["assets/migrations/mysql/001_initialize_schema.sql",1466],["assets/migrations/mysql/002_add_authorization_model_version.sql",182],["assets/migrations/mysql/003_add_reverse_lookup_index.sql",159],["assets/migrations/mysql/004_add_authorization_model_serialized_protobuf.sql",167],["assets/migrations/mysql/005_add_conditions_to_tuples.sql",385],["assets/migrations/mysql/006_extend_object_id.sql",140],["assets/migrations/mysql/007_collate_object_id.sql",498],["assets/migrations/mysql/008_collate_identifiers.sql",2753],["assets/migrations/mysql/collation_migrations.md",3465],["assets/migrations/postgres/001_initialize_schema.sql",1518],["assets/migrations/postgres/002_add_authorization_model_version.sql",176],["assets/migrations/postgres/003_add_reverse_lookup_index.sql",160],["assets/migrations/postgres/004_add_authorization_model_serialized_protobuf.sql",164],["assets/migrations/postgres/005_add_conditions_to_tuples.sql",363],["assets/migrations/postgres/006_add_collate_index.sql",427],["assets/migrations/sqlite/005_initialize_schema.sql",2314],["assets/migrations/sqlite/006_add_store_ulid_index.sql",118],["assets/playground/index.html",379],["assets/tests/abac_tests.yaml",100213],["assets/tests/consolidated_1_1_tests.yaml",276330],["openfga",64577698]]};
const held=new WeakMap();const digest=value=>createHash('sha256').update(value).digest('hex');
const refuse=()=>{throw Error('official held tool refused');};
const field=(h,start,len)=>{const b=h.subarray(start,start+len);const zero=b.indexOf(0);const content=zero<0?b:b.subarray(0,zero);if(b.some(x=>x>127)||zero>=0&&b.subarray(zero).some(x=>x!==0))refuse();return content.toString('ascii');};
const octal=(h,start,len)=>{const v=h.subarray(start,start+len).toString('ascii').replace(/[\0 ]+$/,'').replace(/^ +/,'');if(!/^[0-7]+$/.test(v))refuse();const n=Number.parseInt(v,8);if(!Number.isSafeInteger(n))refuse();return n;};
// Pure parsing does not mint executable capabilities or bypass official pins.
export function parseTar(name,tar){
 const p=profiles[name];if(!p||!Buffer.isBuffer(tar)||tar.length>p.expanded||tar.length%512!==0)refuse();let offset=0,bytes;const seen=new Set();
 while(offset+512<=tar.length){const h=tar.subarray(offset,offset+512);if(h.every(x=>x===0)){if(offset+1024>tar.length||tar.subarray(offset).some(x=>x!==0))refuse();if(!bytes||seen.size!==members[name].length)refuse();return {member:name,bytes,inventory:[...seen].sort()};}
  if(seen.size>=members[name].length||field(h,257,6)!=='ustar'||h[263]!==48||h[264]!==48||field(h,345,155)!==''||h[156]!==48)refuse();let checksum=0;for(let i=0;i<512;i++)checksum+=(i>=148&&i<156)?32:h[i];if(checksum!==octal(h,148,8))refuse();
  const member=field(h,0,100),size=octal(h,124,12);const expected=members[name][seen.size];if(member!==expected[0]||seen.has(member)||field(h,157,100)!==''||size<1||size>expected[1]||size>(member===name?p.binary:1024*1024))refuse();seen.add(member);
  const end=offset+512+size,next=offset+512+Math.ceil(size/512)*512;if(next>tar.length||tar.subarray(end,next).some(x=>x!==0))refuse();if(member===name)bytes=Buffer.from(tar.subarray(offset+512,end));offset=next;
 }refuse();
}
async function readHeld(handle,max){const stat=await handle.stat();if(!stat.isFile()||stat.size<1||stat.size>max||stat.nlink!==1||(stat.mode&0o022)!==0)refuse();const value=Buffer.alloc(stat.size);let n=0;while(n<value.length){const r=await handle.read(value,n,value.length-n,n);if(!r.bytesRead)refuse();n+=r.bytesRead;}const after=await handle.stat();if(stat.dev!==after.dev||stat.ino!==after.ino||stat.size!==after.size||stat.mtimeMs!==after.mtimeMs)refuse();return {stat,bytes:value};}
export async function loadOfficialHeldTool(name,archivePath,ownedDirectory){
 const p=profiles[name];if(process.platform!=='linux'||!p||!path.isAbsolute(archivePath)||!path.isAbsolute(ownedDirectory))refuse();
 const input=await open(archivePath,constants.O_RDONLY|constants.O_NOFOLLOW);let parsed,archiveSHA;try{const {bytes}=await readHeld(input,p.compressed);archiveSHA=digest(bytes);if(bytes.length!==p.compressed||archiveSHA!==p.sha)refuse();parsed=parseTar(name,gunzipSync(bytes,{maxOutputLength:p.expanded}));}finally{await input.close();}
 if(parsed.bytes.length<64||!parsed.bytes.subarray(0,4).equals(Buffer.from([127,69,76,70]))||parsed.bytes[4]!==2||parsed.bytes[5]!==1||parsed.bytes.readUInt16LE(18)!==62||![2,3].includes(parsed.bytes.readUInt16LE(16)))refuse();
 await mkdir(ownedDirectory,{mode:0o700});const output=path.join(ownedDirectory,name);let writer,reader,createdOutput=false;
 try{writer=await open(output,constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW|constants.O_RDWR,0o500);createdOutput=true;await writer.writeFile(parsed.bytes);await writer.sync();const created=await writer.stat();await writer.close();writer=undefined;
  reader=await open(output,constants.O_RDONLY|constants.O_NOFOLLOW);const consumed=await readHeld(reader,p.binary);if(consumed.stat.ino!==created.ino||consumed.stat.dev!==created.dev||digest(consumed.bytes)!==digest(parsed.bytes))refuse();
  const capability=Object.freeze({name});held.set(capability,{handle:reader,path:output,identity:{dev:created.dev,ino:created.ino,size:created.size},sha:digest(parsed.bytes),archiveSHA,inventory:parsed.inventory,owners:new Set(),closed:false});reader=undefined;return capability;
 }catch(error){await writer?.close().catch(()=>{});await reader?.close().catch(()=>{});if(createdOutput)await rm(output,{force:true}).catch(()=>{});await rm(ownedDirectory,{recursive:false}).catch(()=>{});throw error;}
}
export function heldToolName(tool){const state=held.get(tool);if(!state||state.closed||state.closing)refuse();return tool.name;}
async function verifyState(tool,allowClosing=false){const state=held.get(tool);if(!state||state.closed||(!allowClosing&&state.closing))refuse();const read=await readHeld(state.handle,profiles[tool.name].binary);if(state.closed||(!allowClosing&&state.closing)||read.stat.dev!==state.identity.dev||read.stat.ino!==state.identity.ino||read.stat.size!==state.identity.size||digest(read.bytes)!==state.sha)refuse();return Object.freeze({name:tool.name,archiveSHA256:state.archiveSHA,member:tool.name,memberSHA256:state.sha,inventory:Object.freeze([...state.inventory]),device:read.stat.dev,inode:read.stat.ino,bytes:read.stat.size,executionPath:'/proc/self/fd/3',protectedNativeAuthority:false});}
export async function verifyHeldTool(tool){return verifyState(tool);}
export async function spawnHeldTool(tool,args,options={}){
 const state=held.get(tool);await verifyHeldTool(tool);if(!state||state.closed||state.closing||Object.hasOwn(options,'stdio'))refuse();const owner=spawnFixedFDCommand(state.handle.fd,args,options);const record={stop:owner.stop};
 let completed;completed=(async()=>{try{const result=await owner.completed;await verifyState(tool,true);return result;}finally{state.owners.delete(record);}})();record.completed=completed;state.owners.add(record);void completed.catch(()=>{});
 try{if(!await owner.spawned){await owner.stop();await completed.catch(()=>{});refuse();}}catch(error){await owner.stop().catch(()=>{});throw error;}
 return {child:owner.child,completed,stop:async()=>{await owner.stop();await completed;}};
}
export async function closeHeldTool(tool){const state=held.get(tool);if(!state)return;if(state.closePromise)return state.closePromise;state.closing=true;return state.closePromise=(async()=>{let failed=false;for(const owner of [...state.owners]){try{await owner.stop();await owner.completed;}catch{failed=true;}}try{await verifyState(tool,true);}catch{failed=true;}finally{await state.handle.close();state.closed=true;}if(failed||state.owners.size)throw Error('held tool cleanup incomplete');})();}

// Reopening retains the official archive as authority. Existing paths/hashes
// alone never mint a capability, and no admitted member is copied or deleted.
export async function reopenOfficialHeldTool(name,archivePath,ownedDirectory){
 const p=profiles[name];if(process.platform!=='linux'||!p||!path.isAbsolute(archivePath)||!path.isAbsolute(ownedDirectory)||path.normalize(archivePath)!==archivePath||path.normalize(ownedDirectory)!==ownedDirectory)refuse();
 const directory=await lstat(ownedDirectory);if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==process.getuid()||(directory.mode&0o7777)!==0o700||await realpath(ownedDirectory)!==ownedDirectory)refuse();
 const input=await open(archivePath,constants.O_RDONLY|constants.O_NOFOLLOW);let parsed,archiveSHA;
 try{const {bytes}=await readHeld(input,p.compressed);archiveSHA=digest(bytes);if(bytes.length!==p.compressed||archiveSHA!==p.sha)refuse();parsed=parseTar(name,gunzipSync(bytes,{maxOutputLength:p.expanded}));}finally{await input.close();}
 if(parsed.bytes.length<64||!parsed.bytes.subarray(0,4).equals(Buffer.from([127,69,76,70]))||parsed.bytes[4]!==2||parsed.bytes[5]!==1||parsed.bytes.readUInt16LE(18)!==62||![2,3].includes(parsed.bytes.readUInt16LE(16)))refuse();
 const output=path.join(ownedDirectory,name),before=await lstat(output);if(!before.isFile()||before.isSymbolicLink()||before.uid!==process.getuid()||(before.mode&0o7777)!==0o500||before.nlink!==1)refuse();
 let reader;try{reader=await open(output,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const consumed=await readHeld(reader,p.binary);const after=await lstat(output),parent=await lstat(ownedDirectory);
  if(consumed.stat.ino!==before.ino||consumed.stat.dev!==before.dev||after.ino!==before.ino||after.dev!==before.dev||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.uid!==before.uid||(after.mode&0o7777)!==0o500||after.nlink!==1||parent.ino!==directory.ino||parent.dev!==directory.dev||parent.uid!==directory.uid||(parent.mode&0o7777)!==0o700||await realpath(ownedDirectory)!==ownedDirectory||!consumed.bytes.equals(parsed.bytes))refuse();
  const capability=Object.freeze({name});held.set(capability,{handle:reader,path:output,identity:{dev:consumed.stat.dev,ino:consumed.stat.ino,size:consumed.stat.size},sha:digest(parsed.bytes),archiveSHA,inventory:parsed.inventory,owners:new Set(),closed:false});reader=undefined;return capability;
 }finally{await reader?.close();}
}
