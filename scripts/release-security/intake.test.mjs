import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { checkIntake, hashTree, mirrorPublicSources, origins, toolNames } from './intake.mjs';
import { sha256 } from './trust.mjs';

const now = Date.UTC(2026,9,23);
const date = t => new Date(t).toISOString();
function record() {
  const npm = 'a'.repeat(40);
  const urls={npm:'https://codeload.github.com/github/advisory-database/tar.gz/'+npm,go:'https://vuln.go.dev/vulndb.zip',
    grype:'https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.3_2026-10-23T03:15:00Z_1.tar.zst'};
  return {format:'zasp.release.intake.v1',observedAt:date(now),sources:Object.entries(origins).map(([id,origin])=>({
    id,origin,version:id==='npm'?npm:'v1',sha256:sha256(id),refreshedAt:date(now-1000),
    ...(id==='npm'?{npmManifestSha256:sha256('records')}:{}),transfer:{url:urls[id],sha256:sha256(id),bytes:id.length}})),
    tools:toolNames.map(id=>({id,sha256:sha256(id),version:'v1'}))};
}
test('advisory intake refuses untrusted hosts, future refreshes, wrong rosters and unsigned substitutes',()=>{
  assert.ok(checkIntake(record(),now));
  const bad = [
    v=>{v.sources[2].transfer.url='https://unapproved.invalid/databases/v6/db.tar.zst';},
    v=>{v.sources[1].transfer.url+='?package=private';},
    v=>{v.sources[0].refreshedAt=date(now-25*3600000);},
    v=>{v.sources[0].refreshedAt=date(now+1000);},
    v=>{v.sources[0].origin=v.sources[1].origin;},
    v=>{delete v.sources[0].npmManifestSha256;},
    v=>{v.tools[1].id=v.tools[0].id;},
    v=>{v.tools[0].sha256='unbound';},
    v=>{v.tools=[];}
  ];
  for(const change of bad) {const v=record();change(v);assert.throws(()=>checkIntake(v,now));}
});
test('public-only transfers bind the source, exact bytes, and leave failed transfers unpublished',async t=>{
  const target=await mkdtemp(path.join(os.tmpdir(),'zasp-intake-'));t.after(()=>rm(target,{recursive:true,force:true}));
  const intake=record(),seen=[];
  async function fetchPublic(url, opts) {
    assert.equal(opts.credentials,'omit');assert.equal(opts.redirect,'error');assert.equal(url.search,'');
    const source=intake.sources.find(x=>x.transfer.url===url.href);seen.push(source.id);
    return new Response(source.id);
  }
  await mirrorPublicSources(intake,target,{fetchPublic,now});await mirrorPublicSources(intake,target,{fetchPublic,now});
  assert.equal((await readdir(target)).length,3);assert.equal(seen.length,6);
  const failed=path.join(target,'failed');
  await assert.rejects(mirrorPublicSources(intake,failed,{fetchPublic:async()=>new Response('BAD'),now}),/digest differs/);
  assert.deepEqual(await readdir(failed),[]);
});
test('database digest binds every relative name and its bytes and rejects symlinks',async t=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'zasp-db-'));t.after(()=>rm(root,{recursive:true,force:true}));
  await mkdir(path.join(root,'ID'));await writeFile(path.join(root,'ID','A.json'),'{}');
  const hash=await hashTree(root);assert.equal(await hashTree(root),hash);
  await writeFile(path.join(root,'ID','A.json'),'[]');assert.notEqual(await hashTree(root),hash);
  await symlink('A.json',path.join(root,'ID','B.json'));await assert.rejects(hashTree(root),/Invalid/);
});
