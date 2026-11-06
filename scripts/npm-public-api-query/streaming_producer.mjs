// Complete-source streaming component. Global production release admission stays separate.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {exactJSON,lockedProductionInventory} from '../npm-public-corpus.mjs';
import {loadPinnedSemver} from '../npm-public-corpus-semver.mjs';
import {observeHostedMemory} from '../hosted-memory-observation.mjs';
const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const {semver}=loadPinnedSemver(ROOT);
const MAX=1<<20,PROFILE='official-github-complete-source-stream-v2';
// Must be replaced only by a reviewed real first-window receipt, never a CLI proof Boolean.
const REVIEWED_ACTUAL_ARCHIVE_PROFILE_SHA256='';
const fail=()=>{throw Error('official npm source stream refused');};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const closed=(x,keys)=>object(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const oid=x=>typeof x==='string'&&/^[a-f0-9]{40}$/.test(x);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function version(x){if(typeof x!=='string'||x.length>256)return false;const v=semver.parse(x,{loose:false});return v!==null&&v.version+(v.build.length?'+'+v.build.join('.'):'')===x;}
function timestamp(x){return typeof x==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(x)&&Number.isFinite(Date.parse(x))&&Date.parse(x)<=Date.now();}
export function frame(value){const raw=Buffer.from(JSON.stringify(value));if(!raw.length||raw.length>MAX)fail();const head=Buffer.alloc(4);head.writeUInt32BE(raw.length);return Buffer.concat([head,raw]);}

export function createMatcher(lock){
 const inventory=lockedProductionInventory(lock);const byName=new Map();for(const item of inventory.components){if(!byName.has(item.name))byName.set(item.name,[]);byName.get(item.name).push(item);}
 const findings=[],seen=new Set();let count=0,affected=0,events=0,comparisons=0,bytes=0;
 function charge(kind,n=1){if(!Number.isSafeInteger(n)||n<0)fail();if(kind==='affected'){affected+=n;if(affected>1e6)fail();}else if(kind==='events'){events+=n;if(events>2e6)fail();}else {comparisons+=n;if(comparisons>1e8)fail();}}
 function metadata(value,depth=0){if(value===undefined)return;if(depth>64||(!object(value)&&!Array.isArray(value)))fail();for(const [key,item] of Object.entries(value)){if(/range|affected|version|fix|introduc|limit/i.test(key))fail();if(object(item)||Array.isArray(item))metadata(item,depth+1);}}
 function validateEntry(entry){
  if(!object(entry)||!object(entry.package)||typeof entry.package.ecosystem!=='string'||typeof entry.package.name!=='string')fail();
  if(entry.package.ecosystem!=='npm')return null;
  charge('affected');if(Object.keys(entry).some(k=>!['package','versions','ranges','database_specific','ecosystem_specific','severity'].includes(k)))fail();if(!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(entry.package.name)||entry.package.name.length>214)fail();
  metadata(entry.database_specific);metadata(entry.ecosystem_specific);let covered=false;const versions=[],intervals=[];
  if(entry.versions!==undefined){if(!Array.isArray(entry.versions)||entry.versions.length>1e6)fail();for(const v of entry.versions){charge('events');if(!version(v))fail();versions.push(v);}covered||=versions.length>0;}
  if(entry.ranges!==undefined){if(!Array.isArray(entry.ranges)||entry.ranges.length>1e6)fail();for(const range of entry.ranges){
   if(!object(range)||Object.keys(range).some(k=>!['type','events','database_specific','ecosystem_specific'].includes(k))||range.type!=='SEMVER'||!Array.isArray(range.events)||!range.events.length)fail();metadata(range.database_specific);metadata(range.ecosystem_specific);let start=null,previous=null;covered=true;
   for(const event of range.events){charge('events');if(!object(event)||Object.keys(event).length!==1)fail();const [kind,bound]=Object.entries(event)[0];
    if(kind==='introduced'){if(start!==null||(bound!=='0'&&!version(bound))||(previous!==null&&(bound==='0'||semver.lt(bound,previous))))fail();start=bound;}
    else if(['fixed','last_affected','limit'].includes(kind)){if(start===null||!version(bound)||(start!=='0'&&semver.gt(start,bound)))fail();intervals.push({start,end:bound,inclusive:kind==='last_affected'});start=null;previous=bound;}
    else fail();
   }
   if(start!==null)intervals.push({start,end:null,inclusive:false});
  }}
  if(!covered)fail();return {name:entry.package.name,versions,intervals};
 }
 return {
  accept(message){
   if(!closed(message,['type','path','blobOID','sha256','record'])||message.type!=='npm'||typeof message.path!=='string'||!/^advisories\/(github-reviewed|unreviewed)\/[A-Za-z0-9_./-]+\.json$/.test(message.path)||message.path.includes('..')||!oid(message.blobOID)||!hex(message.sha256))fail();
   const record=message.record;if(!object(record)||!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(record.id)||!timestamp(record.modified)||!timestamp(record.published)||!Array.isArray(record.affected)||!record.affected.length||(record.withdrawn!==undefined&&!timestamp(record.withdrawn))||seen.has(record.id)||++count>500000)fail();
   seen.add(record.id);
   // Validate ALL npm entries before looking up any installed package name.
   const entries=record.affected.map(validateEntry).filter(Boolean);if(!entries.length)fail();const matches=[];
   for(const entry of entries)for(const item of byName.get(entry.name)??[]){
    let hit=false;for(const v of entry.versions){charge('comparison');hit||=v===item.version;}
    for(const interval of entry.intervals){charge('comparison',2);hit||=(interval.start==='0'||semver.gte(item.version,interval.start))&&(interval.end===null||(interval.inclusive?semver.lte(item.version,interval.end):semver.lt(item.version,interval.end)));}
    if(hit)matches.push({location:item.location,name:item.name,version:item.version});
   }
   if(matches.length){const severity=['LOW','MODERATE','HIGH','CRITICAL'].includes(record.database_specific?.severity)?record.database_specific.severity:'UNKNOWN';const finding={id:record.id,severity,withdrawn:record.withdrawn??null,path:message.path,blobOID:message.blobOID,advisorySHA256:message.sha256,matches};bytes+=Buffer.byteLength(JSON.stringify(finding));if(findings.length>=100000||bytes>(32<<20))fail();findings.push(finding);}
  },
  result(){return {profile:PROFILE,lockSHA256:inventory.lockSHA256,productionLockEntries:inventory.components.length,npmRecords:count,findings,work:{affectedEntries:affected,rangeEvents:events,comparisons},releaseAccepted:false};}
 };
}

export async function consumeFrames(readable,matcher,binding){
 if(!oid(binding.commit)||!hex(binding.lockSHA256))fail();let buffer=Buffer.alloc(0),start=null,final=null;
 for await(const chunk of readable){
  if(final)fail();if(!Buffer.isBuffer(chunk))fail();
  let offset=0;
  while(offset<chunk.length){
   const take=Math.min(chunk.length-offset,MAX+4-buffer.length);if(take<=0)fail();buffer=Buffer.concat([buffer,chunk.subarray(offset,offset+take)]);offset+=take;
   while(buffer.length>=4){const length=buffer.readUInt32BE();if(!length||length>MAX)fail();if(buffer.length<length+4)break;
    const value=exactJSON(buffer.subarray(4,length+4));buffer=buffer.subarray(length+4);
    if(final||!object(value))fail();
    if(!start){if(!closed(value,['type','profile','commit','root','lockSHA256'])||value.type!=='start'||value.profile!==PROFILE||value.commit!==binding.commit||value.lockSHA256!==binding.lockSHA256||!oid(value.root))fail();start=value;}
    else if(value.type==='npm')matcher.accept(value);
    else if(value.type==='probe'){const keys=['type','prefix','pax','membersVerified','lastCanonicalPath','expandedBytesRead','releaseAccepted','commit','root','lockSHA256','compressedBytes','compressedSHA256'];if(!closed(value,keys)||!Number.isSafeInteger(value.membersVerified)||value.membersVerified<1||value.membersVerified>127||!Number.isSafeInteger(value.expandedBytesRead)||value.expandedBytesRead>MAX||!Number.isSafeInteger(value.compressedBytes)||value.compressedBytes>MAX||!hex(value.compressedSHA256)||binding.mode!=='probe'||value.commit!==start.commit||value.root!==start.root||value.lockSHA256!==start.lockSHA256||value.releaseAccepted!==false)fail();final=value;}
    else if(value.type==='final'){
     const keys=['type','commit','root','lockSHA256','selectedFiles','selectedBytes','npmRecords','npmBytes','allArchiveMembers','fullSelectedRosterSHA256','expandedArchiveBytes','compressedBytes','compressedSHA256','releaseAccepted'];
     if(!closed(value,keys)||value.commit!==start.commit||value.root!==start.root||value.lockSHA256!==start.lockSHA256||value.releaseAccepted!==false||!hex(value.fullSelectedRosterSHA256)||!hex(value.compressedSHA256))fail();
     for(const field of ['selectedFiles','selectedBytes','npmRecords','npmBytes','allArchiveMembers','expandedArchiveBytes','compressedBytes'])if(!Number.isSafeInteger(value[field])||value[field]<0)fail();
     if(value.selectedFiles>500000||value.selectedBytes>2**30||value.npmBytes>512*2**20||value.compressedBytes>256*2**20||value.expandedArchiveBytes>2**31||value.allArchiveMembers>1000128||value.npmRecords!==matcher.result().npmRecords||value.npmRecords>value.selectedFiles)fail();final=value;
    }else fail();
   }
  }
 }
 if(buffer.length||!start||!final)fail();return {...matcher.result(),source:final,sourceBinding:start,releaseAccepted:false};
}

function descriptor(file,maximum,withBytes=false){
 if(!path.isAbsolute(file)||path.normalize(file)!==file||fs.realpathSync(file)!==file)fail();const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const before=fs.fstatSync(fd,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size>BigInt(maximum))fail();const raw=Buffer.alloc(Number(before.size));let offset=0;while(offset<raw.length){const n=fs.readSync(fd,raw,offset,raw.length-offset,null);if(!n)fail();offset+=n;}if(fs.readSync(fd,Buffer.alloc(1),0,1,null)!==0)fail();const after=fs.fstatSync(fd,{bigint:true}),last=fs.lstatSync(file,{bigint:true});for(const k of ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'])if(before[k]!==after[k]||before[k]!==last[k])fail();const pin={path:file,sha256:hash(raw),bytes:raw.length,identity:['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].map(k=>String(before[k]))};return withBytes?{pin,raw}:pin;}finally{fs.closeSync(fd);}}
function fdIdentity(fd){const value=fs.fstatSync(fd,{bigint:true});if(!value.isDirectory())fail();return ['dev','ino','mode','uid','gid'].map(k=>String(value[k])).join(':');}
function directoryIdentity(dir){if(fs.realpathSync(dir)!==dir)fail();const value=fs.lstatSync(dir,{bigint:true});if(!value.isDirectory())fail();return ['dev','ino','mode','uid','gid'].map(k=>String(value[k])).join(':');}
async function resources(preflight=false){const memory=await observeHostedMemory();if(memory.availableBytes<768*2**20)fail();const disk=fs.statfsSync('/tmp',{bigint:true});const need=BigInt(1536*2**20+(preflight?450*2**20:0));if(disk.bavail*disk.bsize<need)fail();return memory;}
function ownedSession(sid){const rows=[];for(const name of fs.readdirSync('/proc')){if(!/^\d+$/.test(name))continue;let raw;try{raw=fs.readFileSync('/proc/'+name+'/stat','utf8');}catch(e){if(e.code==='ENOENT')continue;throw e;}const fields=raw.slice(raw.lastIndexOf(')')+2).trim().split(/\s+/);if(Number(fields[3])===sid)rows.push({pid:Number(name),start:fields[19],state:fields[0]});}return rows;}

export async function produce(args){
 const names=['--commit','--lock','--output','--git','--git-sha256','--python','--python-sha256','--mode'];
 if(!Array.isArray(args)||args.length!==names.length*2)fail();const options={};for(let i=0;i<args.length;i+=2){if(!names.includes(args[i])||Object.hasOwn(options,args[i]))fail();options[args[i]]=args[i+1];}
 if(!oid(options['--commit'])||!['probe','scan'].includes(options['--mode'])||!hex(options['--git-sha256'])||!hex(options['--python-sha256'])||options['--lock']!==path.join(ROOT,'package-lock.json'))fail();
 if(options['--mode']==='scan'&&!hex(REVIEWED_ACTUAL_ARCHIVE_PROFILE_SHA256))fail();
 const output=options['--output'];if(typeof output!=='string'||!path.isAbsolute(output)||path.normalize(output)!==output)fail();const parent=path.dirname(output),identity=directoryIdentity(parent),parentFD=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);const anchored='/proc/self/fd/'+parentFD+'/'+path.basename(output);let created;
 let child,timer,resourceFailure,closing,signalFailure=false,closed=false,pendingResource=Promise.resolve();
 const stop=()=>closing??=(async()=>{
  if(!child)return;if(!Number.isSafeInteger(child.pid)||child.pid<=1){if(!closed)fail();return;}
  const signal=name=>{const rows=ownedSession(child.pid);if(!closed||rows.length){try{process.kill(-child.pid,name);}catch(e){if(e.code!=='ESRCH')throw e;}}};
  const settled=()=>closed&&ownedSession(child.pid).length===0;
  if(!settled())signal('SIGTERM');let until=Date.now()+5000;
  while(!settled()&&Date.now()<until)await new Promise(r=>setTimeout(r,25));
  if(!settled()){signalFailure=true;signal('SIGKILL');until=Date.now()+2000;while(!settled()&&Date.now()<until)await new Promise(r=>setTimeout(r,25));}
  if(!settled())fail();
 })();
 const signals=new Map(['SIGTERM','SIGINT','SIGHUP'].map(sig=>[sig,()=>{signalFailure=true;void stop().catch(()=>{resourceFailure=true;});}]));
 try{
  await resources(true);
  const helper=path.join(ROOT,'scripts/npm-public-api-query/streaming_intake.py');const inputs=[options['--lock'],helper,fileURLToPath(import.meta.url),path.join(ROOT,'scripts/npm-public-api-query/cursor_component.py'),path.join(ROOT,'scripts/npm-public-api-query/git_tree_roster_component.py'),options['--git'],options['--python'],path.join(ROOT,'scripts/npm-public-corpus.mjs'),path.join(ROOT,'scripts/npm-public-corpus-semver.mjs'),path.join(ROOT,'scripts/npm-public-corpus-semver-pins.json'),path.join(ROOT,'scripts/hosted-memory-observation.mjs'),fs.realpathSync(process.execPath)].map((p,i)=>descriptor(p,i===0?4<<20:128<<20));
  if(inputs[5].sha256!==options['--git-sha256']||inputs[6].sha256!==options['--python-sha256'])fail();
  const {raw:lock,pin:consumedLock}=descriptor(options['--lock'],4<<20,true);if(JSON.stringify(consumedLock)!==JSON.stringify(inputs[0]))fail();const matcher=createMatcher(lock),work=fs.mkdtempSync('/tmp/official-npm-stream-v2-');fs.chmodSync(work,0o700);
  child=spawn(options['--python'],['-B',helper,options['--commit'],work,options['--git'],options['--git-sha256'],hash(lock),options['--mode']],{env:process.env,detached:true,stdio:['ignore','pipe','pipe']});
  let stderr=0;child.stderr.on('data',chunk=>{stderr+=chunk.length;if(stderr>65536){resourceFailure=true;void stop().catch(()=>{resourceFailure=true;});}});
  const completion=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(status,signal)=>{closed=true;resolve({status,signal});});});void completion.catch(()=>{});
  for(const [sig,handler] of signals)process.on(sig,handler);
  let checking=false;timer=setInterval(()=>{if(checking)return;checking=true;pendingResource=resources().catch(()=>{resourceFailure=true;void stop().catch(()=>{resourceFailure=true;});}).finally(()=>{checking=false;});},1000);
  const timeout=setTimeout(()=>{resourceFailure=true;void stop().catch(()=>{resourceFailure=true;});},600000);
  let result;
  try{result=await consumeFrames(child.stdout,matcher,{commit:options['--commit'],lockSHA256:hash(lock),mode:options['--mode']});const end=await completion;if(end.status!==0||end.signal||resourceFailure||signalFailure||stderr||ownedSession(child.pid).length)fail();}finally{clearTimeout(timeout);await stop();}
  clearInterval(timer);await pendingResource;if(resourceFailure||signalFailure)fail();await resources();for(const pin of inputs)if(JSON.stringify(descriptor(pin.path,pin.path===options['--lock']?4<<20:128<<20))!==JSON.stringify(pin))fail();
  loadPinnedSemver(ROOT);if(directoryIdentity(parent)!==identity||fdIdentity(parentFD)!==identity)fail();
  const raw=Buffer.from(JSON.stringify({...result,observedAt:new Date().toISOString(),sourceTools:inputs,actualMode:options['--mode'],actualArchiveProfileReviewed:options['--mode']==='scan',actualSelectedSourceClosureVerified:options['--mode']==='scan',snapshotFreshnessVerified:false,malwareClassCorrespondenceVerified:false,goFullMVSVerified:false,shippingImagesVerified:false,releaseAccepted:false},null,2)+'\n');if(raw.length>64*2**20)fail();
  const fd=fs.openSync(anchored,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);created=fs.fstatSync(fd,{bigint:true});try{fs.writeFileSync(fd,raw);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  if(directoryIdentity(parent)!==identity)fail();const published=fs.lstatSync(anchored,{bigint:true});if(published.ino!==created.ino||published.dev!==created.dev||published.nlink!==1n)fail();fs.fsyncSync(parentFD);if(resourceFailure||signalFailure)fail();return {output,sha256:hash(raw),bytes:raw.length,releaseAccepted:false};
 }catch{if(created){try{const st=fs.lstatSync(anchored,{bigint:true});if(st.ino===created.ino&&st.dev===created.dev){fs.unlinkSync(anchored);fs.fsyncSync(parentFD);}}catch{/* Refusal still propagates if owned partial-output cleanup fails. */}}throw Error('official npm source stream refused');}
 finally{clearInterval(timer);for(const [sig,handler] of signals)process.removeListener(sig,handler);await stop();fs.closeSync(parentFD);}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await produce(process.argv.slice(2));process.stdout.write(JSON.stringify(result)+'\n');}catch{process.stderr.write('official npm source stream refused\n');process.exitCode=1;}
}
