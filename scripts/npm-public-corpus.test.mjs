import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { scanNpmAdvisoryComponent,collectPinnedNpmAdvisoryComponent,lockedProductionInventory,exactJSON,createCorpusBudget } from './npm-public-corpus.mjs';
const now=Date.parse('2026-10-07T12:00:00Z');
const hash=b=>createHash('sha256').update(b).digest('hex');
const json=v=>Buffer.from(JSON.stringify(v));
const lock=(v='1.2.0')=>json({lockfileVersion:3,packages:{'':{name:'private-project'},'node_modules/example':{version:v,integrity:'sha512-YQ==',resolved:'https://registry.npmjs.org/example/-/example-1.2.0.tgz'},'node_modules/dev-only':{version:'1.0.0',dev:true}}});
const record=(events=[{introduced:'1.0.0'},{fixed:'2.0.0'}])=>({id:'GHSA-2345-6789-cfgh',modified:'2026-10-07T10:00:00Z',published:'2026-10-06T10:00:00Z',affected:[{package:{ecosystem:'npm',name:'example'},ranges:[{type:'SEMVER',events}]}],database_specific:{severity:'HIGH'}});
function input(r=record(),v='1.2.0'){const raw=json(r),records=[{path:'advisories/github-reviewed/2026/10/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json',raw}];const rows=records.map(x=>({path:x.path,bytes:x.raw.length,sha256:hash(x.raw)}));return {lock:lock(v),records,authority:{repository:'https://github.com/github/advisory-database',commit:'a'.repeat(40),observedAt:'2026-10-07T11:00:00Z',manifestSHA256:hash(json(rows))},evaluatedAt:now};}

test('materializes exact-lock npm findings from full pinned record bytes',()=>{
 const i=input(),before=hash(i.records[0].raw),r=scanNpmAdvisoryComponent(i);
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].matches[0].version,'1.2.0');assert.equal(r.findings[0].severity,'HIGH');assert.equal(r.findings[0].advisorySHA256,before);assert.equal(r.lockSHA256,hash(i.lock));assert.equal(r.components.length,1);assert.equal(r.releaseAccepted,false);assert.equal(r.coverage.goFullMVSRoots,0);assert.equal(r.coverage.shippingImages,0);assert.equal(hash(i.records[0].raw),before);
});

test('real npm semver boundaries remain sensitive',async t=>{
 for(const [name,r,v,count] of [
 ['introduced inclusive',record(),'1.0.0',1],['fixed exclusive',record(),'2.0.0',0],['below introduced',record(),'0.9.9',0],['build metadata preserved',record(),'1.2.0+build.7',1],
 ['last affected inclusive',record([{introduced:'1.0.0'},{last_affected:'1.2.0'}]),'1.2.0',1],
 ['limit exclusive',record([{introduced:'1.0.0'},{limit:'1.2.0'}]),'1.2.0',0],
 ['reopened interval',record([{introduced:'1.0.0'},{fixed:'1.1.0'},{introduced:'1.2.0'}]),'1.3.0',1],
 ['prerelease ordered',record([{introduced:'1.0.0-beta.1'},{fixed:'1.0.0'}]),'1.0.0-beta.2',1],
 ['explicit versions',{...record(),affected:[{package:{ecosystem:'npm',name:'example'},versions:['1.2.0']}]},'1.2.0',1],
 ])await t.test(name,()=>assert.equal(scanNpmAdvisoryComponent(input(r,v)).findings.length,count));
 const withdrawn={...record(),withdrawn:'2026-10-07T10:00:00Z'};assert.equal(scanNpmAdvisoryComponent(input(withdrawn)).findings[0].withdrawn,withdrawn.withdrawn);
 const unknown=record();delete unknown.database_specific;assert.equal(scanNpmAdvisoryComponent(input(unknown)).findings[0].severity,'UNKNOWN');
});

test('missing stale corrupt unsupported or ambiguous inputs refuse instead of zero clearance',async t=>{
 for(const [name,change] of [
 ['missing corpus',x=>x.records=[]],['stale corpus',x=>x.authority.observedAt='2026-10-05T11:00:00Z'],['future corpus',x=>x.authority.observedAt='2026-10-08T11:00:00Z'],
 ['wrong corpus digest',x=>x.authority.manifestSHA256='0'.repeat(64)],['duplicate advisory',x=>x.records.push({...x.records[0]})],['wrong repository',x=>x.authority.repository='https://other.example/advisories'],
 ['unsupported ecosystem',x=>{const r=record();r.affected[0].package.ecosystem='Go';x.records[0].raw=json(r);}],
 ['unsupported range',x=>{const r=record();r.affected[0].ranges[0].type='ECOSYSTEM';x.records[0].raw=json(r);}],
 ['invalid version',x=>x.lock=lock('latest')],['linked production alias cannot omit dev target',x=>{const l=JSON.parse(lock());l.packages['node_modules/example']={link:true,resolved:'node_modules/dev-only'};x.lock=json(l);}],['overlapping events',x=>x.records[0].raw=json(record([{introduced:'1.0.0'},{introduced:'1.1.0'}]))],
 ['unknown range event',x=>x.records[0].raw=json(record([{introduced:'0'},{future:'1.2.0'}]))],
 ['duplicate raw JSON key',x=>x.records[0].raw=Buffer.from('{"id":"a","id":"b"}')],
 ])await t.test(name,()=>{const x=input();change(x);assert.throws(()=>scanNpmAdvisoryComponent(x),/component refused/);});
 assert.throws(()=>exactJSON(Buffer.from([0xff])),/component refused/);assert.throws(()=>exactJSON(Buffer.from('{} {}')),/component refused/);
 assert.throws(()=>lockedProductionInventory(json({lockfileVersion:3,packages:{'':{},'node_modules/example':{version:'1.2.0',integrity:'sha512-YQ==',resolved:'file:../secret'}}})),/component refused/);
});

test('actual read-only producer binds complete local Git corpus without network',()=>{
 const dir=mkdtempSync(path.join(tmpdir(),'npm-osv-own-fixture-'));
 try{const i=input(),relative=i.records[0].path;mkdirSync(path.dirname(path.join(dir,relative)),{recursive:true});writeFileSync(path.join(dir,relative),i.records[0].raw);writeFileSync(path.join(dir,'fixture-lock.json'),i.lock);
 const git=args=>execFileSync('/usr/bin/git',['-C',dir,...args],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'},stdio:['ignore','pipe','pipe']});
 git(['init','-q']);git(['add','advisories']);git(['-c','user.name=Owned Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Owned fixture']);i.authority.commit=git(['rev-parse','HEAD']).toString().trim();
 const args={corpusRoot:dir,authority:i.authority,lockPath:path.join(dir,'fixture-lock.json'),evaluatedAt:now};const r=collectPinnedNpmAdvisoryComponent(args);assert.equal(r.findings.length,1);assert.equal(r.source.fullOfficialCorpusFiles,1);assert.equal(r.releaseAccepted,false);assert.match(r.source.upstreamAdmission,/do not prove upstream/);
 writeFileSync(path.join(dir,relative),json({...record(),affected:[]}));assert.throws(()=>collectPinnedNpmAdvisoryComponent(args),/component refused/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('current product lock inventory is consumed without disclosure',()=>{
 const raw=readFileSync(new URL('../package-lock.json',import.meta.url));const r=lockedProductionInventory(raw);assert.equal(r.lockSHA256,hash(raw));assert.ok(r.components.length>100);assert.ok(r.components.every(x=>x.location.includes('node_modules/')&&typeof x.integrity==='string'));
});

test('actual producer reservation helper refuses before raw retention',async t=>{
 await t.test('complete corpus row bound',()=>{const b=createCorpusBudget();for(let i=0;i<100000;i++)b.reserve(1,false);assert.throws(()=>b.reserve(1,false),/component refused/);});
 await t.test('selected npm byte bound',()=>{const b=createCorpusBudget();for(let i=0;i<512;i++)b.reserve(1<<20,true);assert.throws(()=>b.reserve(1,true),/component refused/);});
});

import { createEvidenceByteBudget } from './npm-public-corpus.mjs';
test('evidence byte reservations refuse before row or match retention',async t=>{
 for(const kind of ['rows','matches'])await t.test(kind,()=>{const b=createEvidenceByteBudget();for(let i=0;i<32;i++)b.reserve(kind,1<<20);assert.throws(()=>b.reserve(kind,1),/component refused/);});
 const raw=json({lockfileVersion:3,packages:{'':{},['node_modules/'+'x'.repeat(215)]:{version:'1.2.0',integrity:'sha512-YQ==',resolved:'https://registry.npmjs.org/example/-/example.tgz'}}});assert.throws(()=>lockedProductionInventory(raw),/component refused/);
});
