import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { expectedHostedBinaries, imageRoles } from './candidate.mjs';
import { expectedScanSubjects } from './scan-common.mjs';
import { evidenceNames, verifyPromotion } from './verify.mjs';
import { sha256 } from './trust.mjs';
import { origins, toolNames } from './intake.mjs';
import { observePublicSources } from './refresh.mjs';

const now = Date.UTC(2026, 9, 23, 12);
const time = ms => new Date(ms).toISOString();
const keys = {candidate:'BUILD', scan:'SCANNER', exceptions:'APPSEC', intake:'INTAKE'};
async function fixture(t) {
  const temp = await mkdtemp(path.join(os.tmpdir(),'zasp-release-test-'));
  t.after(()=> rm(temp,{force:true,recursive:true}));
  const repo=path.join(temp,'repo'), dir=path.join(temp,'evidence');
  await mkdir(path.join(repo,'deploy'),{recursive:true}); await mkdir(dir);
  await mkdir(path.join(repo,'deploy/production'));
  for (const role of imageRoles) await cp(new URL('../../deploy/production/'+role+'.Dockerfile', import.meta.url),path.join(repo,'deploy/production',role+'.Dockerfile'));
  const lock=Buffer.from('{"lockfileVersion":3}\n'); await writeFile(path.join(repo,'package-lock.json'),lock);
  const git=(...args)=>execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','-q');git('add','.');git('-c','user.name=fixture','-c','user.email=fixture@invalid','-c','commit.gpgsign=false','commit','-qm','fixture');
  const commit=git('rev-parse','HEAD'), env={}, privates={};
  for (const [role,key] of Object.entries(keys)) {
    const pair=generateKeyPairSync('ed25519'); privates[role]=pair.privateKey; env['ZASP_RELEASE_'+key+'_PUBLIC_KEY']=pair.publicKey.export({format:'pem',type:'spki'});
  }
  async function seal(role, value) {
    const raw=Buffer.from(JSON.stringify(value)+'\n');
    await writeFile(path.join(dir,role+'.json'),raw);
    await writeFile(path.join(dir,role+'.json.sig'),sign(null,raw,privates[role]).toString('base64')+'\n');
    return sha256(raw);
  }
  const intake={format:'zasp.release.intake.v1',observedAt:time(now-1000),
    sources:Object.entries(origins).map(([id,origin])=>({id,origin,version:id==='npm'?'a'.repeat(40):'v1',refreshedAt:time(now-2000),sha256:sha256(id),...(id==='npm'?{npmManifestSha256:sha256('records')}:{})})),
    tools:toolNames.map(id=>({id,version:'v1',sha256:sha256(id)}))};
  const grypeFile='vulnerability-db_v6.1.1_2026-10-22T02:00:00Z_1.tar.zst';
  const payloads={
    'api.github.com':{ref:'refs/heads/main',object:{type:'commit',sha:'a'.repeat(40)}},
    'vuln.go.dev':{modified:time(now-50000)},
    'grype.anchore.io':{status:'active',schemaVersion:'v6.1.1',built:time(now-50000),path:grypeFile,checksum:'sha256:'+sha256('grype')}
  };
  const refresh=await observePublicSources({clock:()=>new Date(now-2000),fetchPublic:async url=>Response.json(payloads[new URL(url).hostname])});
  const refreshBytes=Buffer.from(JSON.stringify(refresh)+'\n');
  await writeFile(path.join(dir,'refresh.json'),refreshBytes);
  intake.refreshSha256=sha256(refreshBytes);
  intake.sources.find(s=>s.id==='go').version=payloads['vuln.go.dev'].modified;
  Object.assign(intake.sources.find(s=>s.id==='grype'),{version:grypeFile.slice(0,-8),transfer:{url:'https://grype.anchore.io/databases/v6/'+grypeFile,bytes:5,sha256:sha256('grype')}});
  const image={ref:'registry.invalid/vendor/base',digest:'sha256:'+sha256('vendor'),platform:'linux/amd64'};
  const images=[image,...imageRoles.map(role=>({ref:'registry.invalid/zasp/'+role,digest:'sha256:'+sha256(role),platform:'linux/amd64'}))];
  const rendered=Buffer.from('kind: Pod\nspec:\n  containers:\n'+images.map(i=>'    - image: '+i.ref+'@'+i.digest).join('\n')+'\n');
  await writeFile(path.join(dir,'rendered.yaml'),rendered);
  const hosted=await expectedHostedBinaries(repo);
  const binaries=[...hosted].map(([name,root])=>({name,root,platform:'linux/amd64',sha256:sha256(name)}));
  for (const [name,root,targets] of [['zaspctl','cmd/zaspctl',['linux/amd64','windows/amd64','darwin/arm64']],['zasp-endpoint','services/endpoint-agent',['darwin/arm64']],['zasp-device-windows','services/endpoint-agent',['windows/amd64']]]) {
    for(const platform of targets) binaries.push({name,root,platform,sha256:sha256(name+platform)});
  }
  const candidate={format:'zasp.release.candidate.v1',commit,lockSha256:sha256(lock),renderedSha256:sha256(rendered),deploymentPlatforms:['linux/amd64'], images,binaries,
    productImages:Object.fromEntries(imageRoles.map((role,i)=>[role,images[i+1].ref+'@'+images[i+1].digest])),npmInstalls:[{platform:'linux/amd64',libc:'glibc',inventorySha256:sha256('packages')}]};
  const candidateSha256=await seal('candidate',candidate),intakeSha256=await seal('intake',intake);
  const subjects=await Promise.all(expectedScanSubjects(candidate).map(async id=>{
    const artifacts=await Promise.all(evidenceNames(id).map(async file=>{
      const raw=Buffer.from(JSON.stringify({subject:id})+'\n');
      await writeFile(path.join(dir,file),raw);
      return {file,sha256:sha256(raw)};
    }));
    return {id,findings:[],coverageGaps:[],artifacts};
  }));
  const scan={format:'zasp.release.scan.v1',candidateSha256,intakeSha256,observedAt:time(now),subjects};
  await seal('scan',scan);
  return {repo,dir,env,now,seal,scan,candidate,intake};
}

test('real signatures admit complete evidence and policy exceptions bind the exact finding and candidate',async t=>{
  const f=await fixture(t);
  assert.equal((await verifyPromotion(f)).appliedExceptions,0);
  const source=f.scan.subjects.find(s=>s.id==='npm:production');
  const finding={advisory:'GHSA-example',ecosystem:'npm',package:'sample',version:'1.0.0',severity:'high',fix:'1.0.1',withdrawn:false};
  for(const severity of ['high','critical','unknown']){
    source.findings=[{...finding,severity}];await f.seal('scan',f.scan);
    await assert.rejects(verifyPromotion(f),/requires AppSec review/);
  }
  source.findings=[finding];await f.seal('scan',f.scan);
  const record={subject:source.id,advisory:finding.advisory,ecosystem:finding.ecosystem,package:finding.package,version:finding.version,severity:'high',owner:'appsec',reason:'time-bound staged replacement',approvedAt:time(now-500),expiresAt:time(now+60000)};
  const exceptions={format:'zasp.release.exceptions.v1',candidateSha256:f.scan.candidateSha256,exceptions:[record]};
  await f.seal('exceptions',exceptions);
  assert.equal((await verifyPromotion(f)).appliedExceptions,1);
  await f.seal('exceptions',{...exceptions,exceptions:[{...record,version:'2.0.0'}]});
  await assert.rejects(verifyPromotion(f),/requires AppSec review/);
  await f.seal('exceptions',{...exceptions,exceptions:[{...record,expiresAt:time(now)}]});
  await assert.rejects(verifyPromotion(f),/expired/);
  await rm(path.join(f.dir,'exceptions.json'));await rm(path.join(f.dir,'exceptions.json.sig'));
  source.findings=[{...finding,withdrawn:true}];await f.seal('scan',f.scan);
  assert.equal((await verifyPromotion(f)).withdrawnFindings,1);
});

test('refuses unsigned, stale, tampered, skipped or mismatched evidence',async t=>{
  const f=await fixture(t);
  await assert.rejects(verifyPromotion({...f,now:now+25*3600000}),/stale/);
  await assert.rejects(verifyPromotion({...f,env:{...f.env,ZASP_RELEASE_SCANNER_PUBLIC_KEY:f.env.ZASP_RELEASE_BUILD_PUBLIC_KEY}}),/separate/);
  const original=await readFile(path.join(f.dir,'scan.json'));
  await writeFile(path.join(f.dir,'scan.json'),Buffer.concat([original,Buffer.from(' ')]));
  await assert.rejects(verifyPromotion(f),/Invalid signed/);
  await f.seal('scan',{...f.scan,subjects:f.scan.subjects.slice(1)});
  await assert.rejects(verifyPromotion(f),/subject coverage/);
  f.scan.subjects[0].coverageGaps=['missing advisory evidence'];await f.seal('scan',f.scan);
  await assert.rejects(verifyPromotion(f),/Incomplete scan/);
  f.scan.subjects[0].coverageGaps=[];await f.seal('scan',f.scan);
  await writeFile(path.join(f.dir,f.scan.subjects[0].artifacts[0].file),'altered');
  await assert.rejects(verifyPromotion(f),/digest mismatch/);
  await rm(path.join(f.dir,'scan.json.sig'));
  await assert.rejects(verifyPromotion(f),/ENOENT/);
});

test('signed candidate must reconcile actual render, lock, platform and native V2 artifacts',async t=>{
  const f=await fixture(t);
  async function rejects(candidate,match){await f.seal('candidate',candidate);await assert.rejects(verifyPromotion(f),match);}
  await rejects({...f.candidate,lockSha256:sha256('another lock')},/lock or rendered/);
  await rejects({...f.candidate,binaries:f.candidate.binaries.filter(b=>b.name!=='zasp-device-windows')},/omitted required/);
  await rejects({...f.candidate,images:f.candidate.images.slice(1)},/missing or substituted/);
  await rejects({...f.candidate,deploymentPlatforms:['linux/amd64','linux/arm64']},/target platform/);
});
