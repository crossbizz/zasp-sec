import { constants } from 'node:fs';
import { link, mkdir, open, readFile, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireThat, sha256, stamp } from './trust.mjs';

export const refreshEndpoints = {
  npm: 'https://api.github.com/repos/github/advisory-database/git/ref/heads/main',
  go: 'https://vuln.go.dev/index/db.json',
  grype: 'https://grype.anchore.io/databases/v6/latest.json'
};
function parseSource(id, record) {
  requireThat(record?.url === refreshEndpoints[id] && typeof record.raw === 'string' && record.raw.length < 2 ** 21, 'Wrong public refresh source');
  const raw = Buffer.from(record.raw,'base64');
  requireThat(raw.toString('base64') === record.raw, 'Corrupt public refresh evidence');
  const data = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  if (id === 'npm') {
    requireThat(data.ref === 'refs/heads/main' && data.object?.type === 'commit' && /^[a-f0-9]{40}$/.test(data.object.sha), 'Unknown public npm revision');
    return {version:data.object.sha};
  }
  if (id === 'go') { stamp(data.modified); return {version:data.modified}; }
  requireThat(data.status === 'active' && /^v6\.[0-9]+\.[0-9]+$/.test(data.schemaVersion) && /^vulnerability-db_v6\.[0-9]+\.[0-9]+_[A-Za-z0-9._:-]+\.tar\.zst$/.test(data.path) && /^sha256:[a-f0-9]{64}$/.test(data.checksum), 'Unsupported Grype database listing');
  stamp(data.built);
  return {version:data.path.slice(0,-8),url:'https://grype.anchore.io/databases/v6/'+data.path,sha256:data.checksum.slice(7)};
}
export function checkRefresh(raw, intake) {
  requireThat(sha256(raw) === intake.refreshSha256, 'Public refresh digest differs from signed intake');
  const refresh = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  requireThat(refresh.format === 'zasp.release.public-refresh.v1' && Object.keys(refresh.sources ?? {}).length === 3, 'Incomplete upstream observations');
  const observed = stamp(refresh.observedAt);
  for (const s of intake.sources) {
    const expected = parseSource(s.id,refresh.sources[s.id]);
    requireThat(s.version === expected.version && stamp(s.refreshedAt) === observed, 'Approved source revision or update time differs from upstream observation');
    if(s.id === 'grype') requireThat(s.transfer?.url === expected.url && s.transfer?.sha256 === expected.sha256, 'Grype archive differs from the upstream checksum');
  }
}
export async function observePublicSources({fetchPublic=fetch,clock=()=>new Date()}={}) {
  const sources={};
  await Promise.all(Object.entries(refreshEndpoints).map(async ([id,url])=>{
    const r=await fetchPublic(url,{redirect:'error',credentials:'omit',headers:{accept:'application/json','user-agent':'zasp-public-advisory-intake'},signal:AbortSignal.timeout(30000)});
    requireThat(r.status===200 && r.body,'Public advisory source unavailable');
    const chunks=[];let size=0;
    for await(const c of r.body){size+=c.length;requireThat(size<=1024**2,'Public refresh response exceeds limit');chunks.push(c);}
    const record={url,raw:Buffer.concat(chunks).toString('base64')};
    parseSource(id,record); sources[id]=record;
  }));
  return {format:'zasp.release.public-refresh.v1',observedAt:clock().toISOString(),sources:Object.fromEntries(Object.keys(refreshEndpoints).map(id=>[id,sources[id]]))};
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const target=process.argv[2];
    requireThat(process.argv.length===3 && path.isAbsolute(target),'Usage: refresh.mjs ABSOLUTE_PUBLIC_EVIDENCE_DIRECTORY');
    const record=await observePublicSources(), raw=Buffer.from(JSON.stringify(record)+'\n');
    await mkdir(target,{mode:0o700,recursive:true});
    const name=path.join(target,sha256(raw)+'.json'), tmp=path.join(target,'.partial-'+randomUUID());
    const fd=await open(tmp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o400);
    try {
      await fd.writeFile(raw); await fd.sync();
      try { await link(tmp,name); } catch(error) {
        if(error.code!=='EEXIST' || sha256(await readFile(name))!==sha256(raw)) throw error;
      }
    } finally {await fd.close();await unlink(tmp);}
    console.log('Public advisory refresh receipt SHA-256 '+sha256(raw));
  } catch(error) {console.error(error.message);process.exitCode=1;}
}
