import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { openSync, closeSync, readSync, fstatSync, lstatSync, constants } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { isUtf8 } from 'node:buffer';
import { loadPinnedSemver } from './npm-public-corpus-semver.mjs';
const {semver,provenance:semverSource}=loadPinnedSemver();

const repository = 'https://github.com/github/advisory-database';
const corpusRoots = ['advisories/github-reviewed', 'advisories/unreviewed'];
const fail = () => { throw new Error('npm advisory component refused'); };
const sha = b => createHash('sha256').update(b).digest('hex');
const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v, names) => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v,n));
const time = v => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const version = v => { if(typeof v!=='string')return false;const parsed=semver.parse(v,{loose:false});return parsed!==null && parsed.version+(parsed.build.length?'+'+parsed.build.join('.'):'')===v; };

// Preserve duplicate-member and UTF-8 refusals before JSON.parse can erase them.
export function exactJSON(raw, cap = 1 << 20) {
  if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > cap || !isUtf8(raw)) fail();
  const s=raw.toString('utf8');let i=0;
  const ws=()=>{while (/\s/.test(s[i] ?? '') && i<s.length) i++;};
  const str=()=>{const start=i;if(s[i++]!=='"')fail();while(i<s.length){const c=s[i++];if(c==='"'){try{return JSON.parse(s.slice(start,i));}catch{fail();}}if(c==='\\')i++;}fail();};
  const value=depth=>{if(depth>64)fail();ws();const c=s[i];
    if(c==='"')return str();
    if(c==='{' || c==='['){i++;ws();const end=c==='{'?'}':']';const seen=new Set();if(s[i]===end){i++;return;}
      while(i<s.length){if(c==='{'){const k=str();if(seen.has(k))fail();seen.add(k);ws();if(s[i++]!==':')fail();}value(depth+1);ws();if(s[i]===end){i++;return;}if(s[i++]!==',')fail();ws();}fail();}
    const m=/^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(s.slice(i));if(!m)fail();i+=m[0].length;
  };value(0);ws();if(i!==s.length)fail();try{return JSON.parse(s);}catch{fail();}
}

export function lockedProductionInventory(raw) {
  const lock=exactJSON(raw,4<<20);
  if(lock.lockfileVersion!==3 || !object(lock.packages) || !Object.hasOwn(lock.packages,''))fail();
  const rows=[];
  for(const [location,p] of Object.entries(lock.packages)) {
    if(!object(p) || location.includes('..') || location.includes('\\') || location.startsWith('/'))fail();
    if(!location || !location.includes('node_modules/'))continue; // Project/workspace source remains bound by full lock hash.
    if(p.dev===true)continue;
    if(p.link===true)fail(); // Linked/workspace installed nodes require their own physical source resolver.
    const tail=location.slice(location.lastIndexOf('node_modules/')+13);
    const name=p.name ?? tail;
    if(typeof name!=='string' || name.length>214 || location.length>4096 || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) || !version(p.version) || typeof p.integrity!=='string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(p.integrity))fail();
    // Nonregistry/git/file dependencies require a separate source resolver.
    if(typeof p.resolved!=='string')fail();let u;try{u=new URL(p.resolved);}catch{fail();}
    if(u.protocol!=='https:' || u.hostname!=='registry.npmjs.org' || u.username || u.password || u.search || u.hash)fail();
    rows.push({location,name,version:p.version,integrity:p.integrity,resolved:p.resolved});
  }
  if(!rows.length || rows.length>10000)fail();
  return {lockSHA256:sha(raw),components:rows.sort((a,b)=>a.location.localeCompare(b.location))};
}

function affectedBy(a, v) {
  if(!object(a) || !object(a.package) || a.package.ecosystem!=='npm' || typeof a.package.name!=='string')fail();
  let hit=false,coverage=false;
  if(a.versions!==undefined){if(!Array.isArray(a.versions) || !a.versions.every(version))fail();coverage ||= a.versions.length>0;hit ||= a.versions.includes(v);}
  if(a.ranges!==undefined){if(!Array.isArray(a.ranges))fail();
    for(const range of a.ranges){if(!object(range) || range.type!=='SEMVER' || !Array.isArray(range.events) || !range.events.length)fail();coverage=true;let start=null,previous=null;
      for(const event of range.events){if(!object(event) || Object.keys(event).length!==1)fail();const [kind,bound]=Object.entries(event)[0];
        if(kind==='introduced'){if(start!==null || (bound!=='0' && !version(bound)) || (previous!==null && (bound==='0' || semver.lt(bound,previous))))fail();start=bound;}
        else if(['fixed','last_affected','limit'].includes(kind)){if(start===null || !version(bound) || (start!=='0' && semver.gt(start,bound)))fail();const after=start==='0'||semver.gte(v,start);hit ||= after && (kind==='last_affected'?semver.lte(v,bound):semver.lt(v,bound));start=null;previous=bound;}
        else fail();
      }
      if(start!==null)hit ||= start==='0'||semver.gte(v,start);
    }
  }
  if(!coverage)fail();return hit;
}

function recordMatches(raw, inventory, observedAt, budget) {
  const r=exactJSON(raw);
  if(!object(r) || typeof r.id!=='string' || !/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(r.id) || !time(r.modified) || !time(r.published) || Date.parse(r.modified)>observedAt || !Array.isArray(r.affected) || !r.affected.length)fail();
  if(r.withdrawn!==undefined && (!time(r.withdrawn)||Date.parse(r.withdrawn)>observedAt))fail();
  const matches=[];
  for(const a of r.affected){ // Validate every range even when this package isn't installed.
    if(!object(a)||!object(a.package)||a.package.ecosystem!=='npm')fail();
    affectedBy(a,'0.0.0');
    for(const c of inventory.components)if(c.name===a.package.name && affectedBy(a,c.version)){if(++budget.matches>100000)fail();const match={location:c.location,name:c.name,version:c.version};budget.bytes.reserve('matches',Buffer.byteLength(JSON.stringify(match)));matches.push(match);}
  }
  const severity=typeof r.database_specific?.severity==='string' && ['LOW','MODERATE','HIGH','CRITICAL'].includes(r.database_specific.severity)?r.database_specific.severity:'UNKNOWN';
  return {id:r.id,advisorySHA256:sha(raw),withdrawn:r.withdrawn??null,severity,matches};
}

export function scanNpmAdvisoryComponent({lock,records,authority,evaluatedAt}) {
  if(!keys(authority,['repository','commit','observedAt','manifestSHA256']) || authority.repository!==repository || !/^[a-f0-9]{40}$/.test(authority.commit) || !time(authority.observedAt) || !hex(authority.manifestSHA256) || !Number.isFinite(evaluatedAt))fail();
  const observed=Date.parse(authority.observedAt);if(observed>evaluatedAt || evaluatedAt-observed>24*60*60*1000)fail();
  if(!Array.isArray(records)||!records.length||records.length>100000)fail();
  const inventory=lockedProductionInventory(lock),rows=[],observations=[],ids=new Set(),paths=new Set();let bytes=0;const matchBudget={matches:0,bytes:createEvidenceByteBudget()};
  for(const r of records){if(!keys(r,['path','raw']) || !Buffer.isBuffer(r.raw) || typeof r.path!=='string' || r.path.length>4096 || !/^advisories\/(?:github-reviewed|unreviewed)\/[a-zA-Z0-9_./-]+\.json$/.test(r.path) || r.path.includes('..') || paths.has(r.path))fail();paths.add(r.path);bytes+=r.raw.length;if(bytes>(512<<20))fail();const value=recordMatches(r.raw,inventory,observed,matchBudget);if(ids.has(value.id))fail();ids.add(value.id);const row={path:r.path,bytes:r.raw.length,sha256:sha(r.raw)};matchBudget.bytes.reserve('rows',Buffer.byteLength(JSON.stringify(row)));rows.push(row);observations.push(value);}
  rows.sort((a,b)=>a.path.localeCompare(b.path));if(sha(Buffer.from(JSON.stringify(rows)))!==authority.manifestSHA256)fail();
  return {format:'npm-official-public-corpus-component-v1',semverSource,source:{...authority,records:rows},lockSHA256:inventory.lockSHA256,components:inventory.components,findings:observations.filter(r=>r.matches.length),coverage:{npmRegistryProductionLockEntries:true,physicalInstalledSBOM:false,goFullMVSRoots:0,shippingImages:0,renderedThirdPartyImages:false},releaseAccepted:false};
}

export function createEvidenceByteBudget(){
 const totals={rows:0,matches:0};
 return {reserve(kind,bytes){if(!Object.hasOwn(totals,kind)||!Number.isSafeInteger(bytes)||bytes<1||bytes>(1<<20)||totals[kind]+bytes>(32<<20))fail();totals[kind]+=bytes;}};
}

export function createCorpusBudget() {
  let files=0,fullBytes=0,npmFiles=0,npmBytes=0;
  return { reserve(bytes,isNpm) {
    if(!Number.isSafeInteger(bytes)||bytes<1||bytes>(1<<20)||typeof isNpm!=='boolean')fail();
    if(files+1>100000 || fullBytes+bytes>(1<<30) || (isNpm && (npmFiles+1>100000 || npmBytes+bytes>(512<<20))))fail();
    files++;fullBytes+=bytes;if(isNpm){npmFiles++;npmBytes+=bytes;}
  }};
}

// Actual producer: read-only official Git corpus lookup. No npm audit or network request.
function same(a,b){return ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].every(k=>a[k]===b[k]);}
function readBound(file,cap){const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const before=fstatSync(fd,{bigint:true});if(!before.isFile() || before.size>BigInt(cap) || !same(before,lstatSync(file,{bigint:true})))fail();const b=Buffer.alloc(Number(before.size));let n=0;while(n<b.length){const got=readSync(fd,b,n,b.length-n,null);if(got<=0)fail();n+=got;}if(readSync(fd,Buffer.alloc(1),0,1,null)!==0 || !same(before,fstatSync(fd,{bigint:true}))||!same(before,lstatSync(file,{bigint:true})))fail();return b;}finally{closeSync(fd);}}
export function collectPinnedNpmAdvisoryComponent({corpusRoot,authority,lockPath,evaluatedAt}) {
  if(typeof corpusRoot!=='string'||!path.isAbsolute(corpusRoot)||typeof lockPath!=='string'||!path.isAbsolute(lockPath)||!object(authority)||!/^[a-f0-9]{40}$/.test(authority.commit))fail();
  const git=args=>execFileSync('/usr/bin/git',['--no-replace-objects','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-C',corpusRoot,...args],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_OPTIONAL_LOCKS:'0',GIT_NO_LAZY_FETCH:'1'},stdio:['ignore','pipe','pipe'],maxBuffer:32<<20,timeout:30000});
  const localOnly=()=>{
    const raw=git(['config','--local','--no-includes','--name-only','--null','--list']);
    if(!isUtf8(raw)||raw.length>(1<<20))fail();
    const names=raw.toString('utf8').split('\0').filter(Boolean);if(names.length>10000)fail();
    if(names.some(name=>/^(?:extensions\.(?:partialclone|worktreeconfig)|remote\..*\.promisor|include\.path|includeif\..*)$/i.test(name)))fail();
  };
  const roster=()=>{localOnly();return git(['ls-tree','-r','-z',authority.commit,'--',...corpusRoots]);};const before=roster();const records=[];const full=[];const budget=createCorpusBudget();
  for(const line of before.toString('utf8').split('\0').filter(Boolean)){const match=/^100644 blob ([a-f0-9]{40})\t(.+)$/.exec(line);if(!match)fail();const [,oid,relative]=match;if(relative.includes('..')||!corpusRoots.some(root=>relative.startsWith(root+'/')))fail();const raw=readBound(path.join(corpusRoot,relative),1<<20);if(createHash('sha1').update(Buffer.from(`blob ${raw.length}\0`)).update(raw).digest('hex')!==oid)fail();let npm=false;if(relative.endsWith('.json')){const record=exactJSON(raw);if(!Array.isArray(record.affected))fail();npm=record.affected.some(a=>a?.package?.ecosystem==='npm');}budget.reserve(raw.length,npm);full.push({path:relative,bytes:raw.length,sha256:sha(raw)});if(npm)records.push({path:relative,raw});}
  assert.deepEqual(before,roster());const result=scanNpmAdvisoryComponent({lock:readBound(lockPath,4<<20),records,authority,evaluatedAt});
  result.source.fullOfficialCorpusRosterSHA256=sha(Buffer.from(JSON.stringify(full)));result.source.fullOfficialCorpusFiles=full.length;result.source.upstreamAdmission='Caller must bind issued official public Git intake receipt; local Git objects alone do not prove upstream provenance.';
  return result;
}

export const readBoundedInput=readBound;
