import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { loadPinnedSemver } from './npm-public-corpus-semver.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const pins=JSON.parse(readFileSync(new URL('./npm-public-corpus-semver-pins.json',import.meta.url)));
const hash=b=>createHash('sha256').update(b).digest('hex');
const serialize=v=>Buffer.from(JSON.stringify(v));
test('portable locked semver source refuses drift',async t=>{
 for(const mode of ['valid','version','integrity','file-hash','membership','symlink'])await t.test(mode,()=>{
  const dir=mkdtempSync(path.join(tmpdir(),'own-semver-source-'));
  try{
   const dest=path.join(dir,pins.lockLocation);mkdirSync(path.dirname(dest),{recursive:true});cpSync(path.join(root,pins.lockLocation),dest,{recursive:true});
   const lock={lockfileVersion:3,packages:{'':{},[pins.lockLocation]:{version:pins.version,integrity:pins.integrity}}};
   if(mode==='version')lock.packages[pins.lockLocation].version='7.7.4';
   if(mode==='integrity')lock.packages[pins.lockLocation].integrity='sha512-YQ==';
   writeFileSync(path.join(dir,'package-lock.json'),serialize(lock));
   if(mode==='file-hash'){const p=path.join(dest,'index.js');chmodSync(p,0o600);writeFileSync(p,Buffer.concat([readFileSync(p),Buffer.from('\n// own mutation\n')]));}
   if(mode==='membership')writeFileSync(path.join(dest,'own-extra.js'),'module.exports={}');
   if(mode==='symlink'){const p=path.join(dest,'index.js');rmSync(p);symlinkSync(path.join(root,pins.lockLocation,'index.js'),p);}
   if(mode==='valid'){const {semver,provenance}=loadPinnedSemver(dir);assert.equal(semver.compare('1.2.0','1.3.0'),-1);assert.equal(provenance.version,'7.8.5');assert.equal(provenance.files.length,53);}
   else assert.throws(()=>loadPinnedSemver(dir));
  }finally{rmSync(dir,{recursive:true,force:true});}
 });
});

test('callable public npm producer boundaries stay closed',async t=>{
 for(const mode of ['valid-deterministic','unknown-arg','duplicate-arg','relative-arg','missing-receipt','unknown-receipt','duplicate-receipt','wrong-repository','wrong-full-roster','wrong-lock','existing-output','mixed-corpus-record','local-promisor-missing-object','local-promisor-config','local-partial-config','local-include-config','local-worktree-config'])await t.test(mode,()=>{
  const dir=mkdtempSync(path.join(tmpdir(),'own-public-cli-'));
  try{
   const corpus=path.join(dir,'corpus');mkdirSync(corpus);const relative='advisories/github-reviewed/2026/10/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json';mkdirSync(path.dirname(path.join(corpus,relative)),{recursive:true});
   const observedAt=new Date().toISOString();let record={id:'GHSA-2345-6789-cfgh',published:observedAt,modified:observedAt,affected:[{package:{ecosystem:'npm',name:'example'},ranges:[{type:'SEMVER',events:[{introduced:'1.0.0'},{fixed:'2.0.0'}]}]}],database_specific:{severity:'HIGH'}};
   if(mode==='mixed-corpus-record')record.affected.push({package:{ecosystem:'PyPI',name:'example'},versions:['1.0.0']});
   const raw=serialize(record);writeFileSync(path.join(corpus,relative),raw);
   const git=args=>execFileSync('/usr/bin/git',['-C',corpus,...args],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'},timeout:10000,maxBuffer:1<<20});
   git(['init','-q']);git(['add','advisories']);git(['-c','user.name=Owned Fixture','-c','user.email=fixture@example.invalid','commit','-qm','owned public fixture']);
   const commit=git(['rev-parse','HEAD']).toString().trim();
   const lock=serialize({lockfileVersion:3,packages:{'':{},'node_modules/example':{version:'1.2.0',integrity:'sha512-YQ==',resolved:'https://registry.npmjs.org/example/-/example-1.2.0.tgz'}}});
   const lockPath=path.join(dir,'lock.json');writeFileSync(lockPath,lock);
   const rows=[{path:relative,bytes:raw.length,sha256:hash(raw)}];const receipt={format:'github-advisory-database-public-intake-v1',repository:'https://github.com/github/advisory-database',commit,observedAt,manifestSHA256:hash(serialize(rows)),fullOfficialCorpusRosterSHA256:hash(serialize(rows)),fullOfficialCorpusFiles:1,lockSHA256:hash(lock)};
   if(mode==='unknown-receipt')receipt.unissuedApproval=true;
   if(mode==='wrong-repository')receipt.repository='https://example.invalid/advisories';
   if(mode==='wrong-full-roster')receipt.fullOfficialCorpusRosterSHA256='0'.repeat(64);
   if(mode==='wrong-lock')receipt.lockSHA256='0'.repeat(64);
   const receiptPath=path.join(dir,'receipt.json');writeFileSync(receiptPath,mode==='duplicate-receipt'?Buffer.from(serialize(receipt).toString().replace('"format":','"format":"shadow","format":')):serialize(receipt));
   if(mode==='missing-receipt')rmSync(receiptPath);
   const output=path.join(dir,'output.json');if(mode==='existing-output')writeFileSync(output,'own existing bytes');
   const forbiddenConfig={
    'local-promisor-config':'remote.origin.promisor',
    'local-partial-config':'extensions.partialClone',
    'local-include-config':'include.path',
    'local-worktree-config':'extensions.worktreeConfig',
   };
   if(Object.hasOwn(forbiddenConfig,mode))git(['config',forbiddenConfig[mode],mode==='local-include-config'?path.join(dir,'not-read.conf'):'true']);
   let trap;
   if(mode==='local-promisor-missing-object'){
    // The only SSH command is an owned trap that writes a marker and exits;
    // neither the baseline nor candidate fixture performs a network request.
    trap=path.join(dir,'own-helper-trigger');const helper=path.join(dir,'own-ssh-trap');
    writeFileSync(helper,`#!/bin/sh\nprintf triggered > '${trap}'\nexit 1\n`,{mode:0o700});
    const tree=git(['rev-parse',`${commit}^{tree}`]).toString().trim();assert.match(tree,/^[a-f0-9]{40}$/);
    git(['config','core.repositoryformatversion','1']);git(['config','extensions.partialClone','origin']);
    git(['config','remote.origin.promisor','true']);git(['config','remote.origin.partialclonefilter','blob:none']);
    git(['config','remote.origin.url','ssh://fixture.invalid/owned']);git(['config','core.sshCommand',helper]);
    rmSync(path.join(corpus,'.git','objects',tree.slice(0,2),tree.slice(2)));
    const baseline=spawnSync('/usr/bin/git',['--no-replace-objects','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',corpus,'ls-tree','-r','-z',commit,'--','advisories/github-reviewed','advisories/unreviewed'],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_OPTIONAL_LOCKS:'0'},timeout:10000,maxBuffer:1<<20,encoding:'utf8'});
    assert.equal(baseline.signal,null);assert.equal(baseline.error,undefined);assert.notEqual(baseline.status,0);
    assert.equal(readFileSync(trap,'utf8'),'triggered','unguarded own lookup must reach the owned trap');rmSync(trap);
   }
   const args=['--corpus-dir',corpus,'--public-intake-receipt',receiptPath,'--lock',lockPath,'--output',output];
   if(mode==='unknown-arg')args[0]='--unknown';
   if(mode==='duplicate-arg')args[2]='--corpus-dir';
   if(mode==='relative-arg')args[1]='relative';
   const call=a=>spawnSync(process.execPath,[fileURLToPath(new URL('./produce-public-npm-advisory-component.mjs',import.meta.url)),...a],{env:{PATH:'/usr/bin:/bin',TMPDIR:dir},timeout:15000,maxBuffer:1<<20,encoding:'utf8'});
   const result=call(args);assert.equal(result.signal,null);assert.equal(result.error,undefined);
   if(mode==='local-promisor-missing-object')assert.throws(()=>readFileSync(trap),{code:'ENOENT'},'guarded producer must never trigger the owned helper');
   if(mode==='valid-deterministic'){
    assert.equal(result.status,0);const bytes=readFileSync(output),evidence=JSON.parse(bytes);assert.equal(evidence.findings.length,1);assert.equal(evidence.semverSource.version,'7.8.5');assert.equal(evidence.releaseAccepted,false);assert.equal(evidence.coverage.goFullMVSRoots,0);assert.match(evidence.sourceAuthority,/independent upstream admission review remains required/);
    const other=path.join(dir,'other.json'),second=call([...args.slice(0,-1),other]);assert.equal(second.status,0);assert.deepEqual(readFileSync(other),bytes);
   }else{assert.equal(result.status,1);assert.equal(result.stderr,'public npm producer refused\n');assert.equal(result.stdout,'');if(mode==='existing-output')assert.equal(readFileSync(output,'utf8'),'own existing bytes');}
  }finally{rmSync(dir,{recursive:true,force:true});}
 });
});
