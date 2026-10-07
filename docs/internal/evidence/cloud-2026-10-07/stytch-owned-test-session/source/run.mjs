import {createHash, randomUUID} from 'node:crypto';
import {readFileSync, openSync, closeSync, writeSync, fsyncSync, mkdirSync} from 'node:fs';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

const ROOT='/workspace/zasp-sec';
const BASE='https://test.stytch.com';
const SOURCE=ROOT+'/proofs/stytch-b2b-test-session.mjs';
const EXPECTED='856a3c14a7810780abc2768cccbbf71013c3ec6e5d78466ccf74c5158161a29f';
const digest=()=>createHash('sha256').update(readFileSync(SOURCE)).digest('hex');
if (process.argv.length!==2 || digest()!==EXPECTED ||
    !/^project-test-[A-Za-z0-9-]+$/.test(process.env.STYTCH_PROJECT_ID??'') ||
    !(process.env.STYTCH_SECRET??'').startsWith('secret-test-') || /\s/.test(process.env.STYTCH_SECRET??'') ||
    process.env.STYTCH_PROOF_BASE_URL || process.env.STYTCH_PROOF_ALLOW_LOOPBACK) {
  throw new Error('Fixed TEST source/credential scope refused');
}
const require=createRequire(ROOT+'/node_modules/stytch/package.json');
const {fetch: wireFetch, EnvHttpProxyAgent}=require('undici');
// Undici honors inherited proxy settings. TLS trust remains verified.
const dispatcher=new EnvHttpProxyAgent();
const out='/tmp/zasp-stytch-disposable-'+randomUUID();
mkdirSync(out,{mode:0o700});
const ledgerFD=openSync(out+'/ownership.private.jsonl','wx',0o600);
for(const path of [out,'/tmp']){const fd=openSync(path,'r');fsyncSync(fd);closeSync(fd);}
function writeAll(fd, bytes) {
  let offset=0;
  while(offset<bytes.length){const n=writeSync(fd,bytes,offset,bytes.length-offset);if(n<=0)throw new Error('Journal refused');offset+=n;}
  fsyncSync(fd);
}
function record(value){writeAll(ledgerFD,Buffer.from(JSON.stringify(value)+'\n'));}
record({state:'START',scope:'disposable TEST password session; no messaging or project configuration'});
let intent=null, ownedID=null, createStarted=false, createResponseObserved=false, deleted=false, absent=false, absenceObserved=false;
let cancelled=false, terminal=false, proofPassed=false, failure=null;
const mainAbort=new AbortController();
const onSignal=()=>{cancelled=true;mainAbort.abort();if(terminal)process.exit(1);};
for(const name of ['SIGTERM','SIGINT','SIGHUP'])process.on(name,onSignal);
const mainTimer=setTimeout(onSignal,30_000);
const calls=[];
const testID=(value)=>/^organization-test-[A-Za-z0-9-]+$/.test(value??'');
async function bounded(response){
  if(Number(response.headers.get('content-length')??0)>65536)throw new Error('Body cap refused');
  const chunks=[];let count=0;
  for await(const chunk of response.body??[]){count+=chunk.length;if(count>65536)throw new Error('Body cap refused');chunks.push(Buffer.from(chunk));}
  const bytes=Buffer.concat(chunks);
  return {bytes,value:bytes.length?JSON.parse(bytes.toString('utf8')):null};
}
function ownedOrganization(value){
  const org=value?.organization;
  if(!intent||!testID(org?.organization_id)||org.organization_name!==intent.name||org.organization_slug!==intent.slug)throw new Error('Owned marker refused');
  if(ownedID&&ownedID!==org.organization_id)throw new Error('Owned ID mismatch');
  ownedID=org.organization_id;record({state:'OWNED',organizationId:ownedID,...intent});
}
async function request(path, options, cleanup=false){
  if(!cleanup&&cancelled)throw new Error('Cancelled');
  const signal=cleanup?AbortSignal.timeout(5000):AbortSignal.any([mainAbort.signal,AbortSignal.timeout(5000)]);
  const response=await wireFetch(BASE+path,{...options,dispatcher,redirect:'error',signal});
  const body=await bounded(response);
  calls.push({method:options.method,pathKind:path.includes('/passwords/')?'password':path==='/v1/b2b/organizations'?'organization-create':'owned-organization',httpStatus:response.status});
  return {response,...body};
}
globalThis.fetch=async(url,options)=>{
  const parsed=new URL(url);
  if(parsed.origin!==BASE||parsed.search||parsed.hash||parsed.username||parsed.password)throw new Error('Origin refused');
  const path=parsed.pathname;
  if(options.method==='POST'&&path==='/v1/b2b/organizations'){
    if(createStarted||cancelled)throw new Error('Duplicate create refused');
    const body=JSON.parse(options.body);
    const match=/^zasp-m0-02-proof-([0-9a-f-]{36})$/.exec(body.organization_slug??'');
    if(!match||body.organization_name!==`Zasp M0-02 Proof ${match[1]}`||body.email_invites!=='NOT_ALLOWED'||body.auth_methods!=='RESTRICTED'||JSON.stringify(body.allowed_auth_methods)!=='["password"]'||body.mfa_policy!=='OPTIONAL')throw new Error('Create scope refused');
    intent={slug:body.organization_slug,name:body.organization_name,marker:match[1]};
    record({state:'CREATE_INTENT',...intent});createStarted=true;
    const result=await request(path,options);
    createResponseObserved=true;
    if(result.response.ok)ownedOrganization(result.value);
    return new Response(result.bytes,{status:result.response.status,headers:result.response.headers});
  }
  if(options.method==='POST'&&['/v1/b2b/passwords/migrate','/v1/b2b/passwords/authenticate'].includes(path)){
    const body=JSON.parse(options.body);
    if(!ownedID||body.organization_id!==ownedID||body.email_address!==`zasp-m0-02-${intent.marker}@example.com`)throw new Error('Member scope refused');
    if(path.endsWith('/migrate')&&body.hash_type!=='sha_512')throw new Error('Migration scope refused');
    const result=await request(path,options);
    return new Response(result.bytes,{status:result.response.status,headers:result.response.headers});
  }
  if(options.method==='DELETE'&&ownedID&&path===`/v1/b2b/organizations/${ownedID}`){
    const result=await request(path,options,true);
    if(result.response.ok&&result.value?.organization_id===ownedID){deleted=true;record({state:'DELETE_ACK',organizationId:ownedID});}
    return new Response(result.bytes,{status:result.response.status,headers:result.response.headers});
  }
  throw new Error('Request allowlist refused');
};
const authorization='Basic '+Buffer.from(process.env.STYTCH_PROJECT_ID+':'+process.env.STYTCH_SECRET).toString('base64');
const headers={Authorization:authorization,Accept:'application/json','Content-Type':'application/json'};
try {
  const {createTestSession}=await import(pathToFileURL(SOURCE).href);
  await createTestSession({STYTCH_PROJECT_ID:process.env.STYTCH_PROJECT_ID,STYTCH_SECRET:process.env.STYTCH_SECRET});
  proofPassed=true;
} catch {failure='Disposable password/session proof refused';}
finally {
  clearTimeout(mainTimer);
  // Recover only the exact unique slug whose create intent was durably recorded.
  // Never search across, update or delete an unrelated organization.
  try {
    if(createStarted&&!ownedID){
      const result=await request('/v1/b2b/organizations/'+encodeURIComponent(intent.slug),{method:'GET',headers},true);
      if(result.response.status===404){absenceObserved=true;absent=createResponseObserved;}
      else if(result.response.ok)ownedOrganization(result.value);
      else throw new Error('Owned lookup unresolved');
    }
    if(ownedID&&!deleted){
      const result=await request('/v1/b2b/organizations/'+ownedID,{method:'DELETE',headers},true);
      if(result.response.status===404){absenceObserved=true;absent=true;}
      else if(result.response.ok&&result.value?.organization_id===ownedID){deleted=true;record({state:'RECOVERY_DELETE_ACK',organizationId:ownedID});}
      else throw new Error('Owned delete unresolved');
    }
    if(ownedID&&!absent){
      const result=await request('/v1/b2b/organizations/'+ownedID,{method:'GET',headers},true);
      if(result.response.status!==404)throw new Error('Owned absence unproved');
      absent=true;
      absenceObserved=true;
    }
  }catch{failure='Owned cleanup unresolved; retain private ownership journal';}
  terminal=true;
  if(createStarted&&!ownedID&&!createResponseObserved)failure='Create outcome uncertain; retain private slug for later parent recovery';
  if(digest()!==EXPECTED)failure='Source changed';
  const result={scope:'TEST password/session diagnostic; not email ownership, OAuth, SSO or product session acceptance',proofPassed,createStarted,createResponseObserved,absenceObserved,cleanupAbsent:absent,deletedAcknowledged:deleted,cancelled,calls,failure,completed:proofPassed&&absent&&!failure&&!cancelled};
  record({state:'FINAL',...result});
  const resultFD=openSync(out+'/result.json','wx',0o600);writeAll(resultFD,Buffer.from(JSON.stringify(result,null,2)+'\n'));closeSync(resultFD);
  const directoryFD=openSync(out,'r');fsyncSync(directoryFD);closeSync(directoryFD);
  closeSync(ledgerFD);
  await dispatcher.destroy();
  console.log(JSON.stringify({resultPath:out+'/result.json',completed:result.completed,cleanupAbsent:absent}));
  process.exitCode=result.completed?0:1;
}
