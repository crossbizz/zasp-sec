import { execFileSync } from 'node:child_process';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCandidate, sameSet } from './candidate.mjs';
import { checkIntake } from './intake.mjs';
import { checkRefresh } from './refresh.mjs';
import { expectedScanSubjects } from './scan-common.mjs';
import { bundleFile, fileHash, hex, object, publicKey, readBound, requireThat, sha256, stamp, unique, verifySigned } from './trust.mjs';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const keyNames = {candidate:'BUILD',intake:'INTAKE',scan:'SCANNER',exceptions:'APPSEC'};
const day = 24 * 60 * 60 * 1000;
const textField = (x, limit) => typeof x === 'string' && x.trim().length > 0 && x.length <= limit && [...x].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127);
const findingKey = x => JSON.stringify([x.subject,x.advisory,x.ecosystem,x.package,x.version,x.severity]);

function exceptionIndex(document, candidateHash, at) {
  const index = new Map();
  if (!document) return index;
  requireThat(document.format === 'zasp.release.exceptions.v1' && document.candidateSha256 === candidateHash &&
    Array.isArray(document.exceptions) && document.exceptions.length <= 2048, 'Exception scope mismatch');
  for (const x of document.exceptions) {
    const issued = stamp(x.approvedAt), expires = stamp(x.expiresAt);
    requireThat(issued <= at && at < expires && issued < expires && textField(x.owner,160) && textField(x.reason,1024),
      'Invalid, expired or unowned release exception');
    requireThat(['high','critical','unknown'].includes(x.severity) && ['subject','advisory','ecosystem','package','version'].every(k => textField(x[k],512)),
      'Invalid exact exception subject or advisory');
    const key = findingKey(x);
    requireThat(!index.has(key), 'Duplicate release exception'); index.set(key,x);
  }
  return index;
}
export function evidenceNames(id) {
  const labels = id === 'npm:production' ? ['npm-lock-report','npm-installed']
    : id.startsWith('go:') ? ['go-build','go-selected','go-reachability']
      : ['image-syft','image-spdx','image-grype'];
  return labels.map(label => sha256(id).slice(0,32)+'-'+label+'.json');
}
export async function verifyScan({scan, candidate, candidateHash, intakeHash, dir, exceptions, now, intake}) {
  requireThat(scan?.format === 'zasp.release.scan.v1' && scan.candidateSha256 === candidateHash && scan.intakeSha256 === intakeHash, 'Scan is for another candidate or advisory snapshot');
  const finished = stamp(scan.observedAt);
  requireThat(finished <= now && now - finished <= day && finished >= stamp(intake.observedAt), 'Stale or misordered scan');
  unique(scan.subjects, s => s.id, 'scan subjects');
  sameSet(scan.subjects.map(s=>s.id), expectedScanSubjects(candidate),'Candidate scan subject coverage differs');
  const approved = exceptionIndex(exceptions, candidateHash, now);
  const used = new Set(), artifacts = new Set();
  let reviewed = 0, withdrawn = 0;
  for (const s of scan.subjects) {
    requireThat(Array.isArray(s.coverageGaps) && s.coverageGaps.length === 0 && Array.isArray(s.findings), 'Incomplete scan subject');
    requireThat(Array.isArray(s.artifacts) && s.artifacts.length > 0 && s.artifacts.length <= 256, 'Missing retained scan evidence');
    sameSet(s.artifacts.map(a=>a?.file),evidenceNames(s.id),'Incomplete raw evidence for a scanned subject');
    for (const a of s.artifacts) {
      requireThat(object(a) && hex(a.sha256) && !artifacts.has(a.file), 'Duplicate or invalid source evidence');
      artifacts.add(a.file);
      requireThat(await fileHash(await bundleFile(dir,a.file)) === a.sha256, 'Retained scan artifact digest mismatch');
    }
    for (const f of s.findings) {
      requireThat(object(f) && ['advisory','ecosystem','package','version'].every(k => textField(f[k],512)) &&
        ['unknown','low','medium','high','critical','negligible'].includes(f.severity) && typeof f.withdrawn === 'boolean' &&
        (f.fix === null || textField(f.fix,512)), 'Malformed vulnerability result');
      requireThat(s.id === 'npm:production' ? f.ecosystem === 'npm' : !s.id.startsWith('go:') || f.ecosystem === 'Go', 'Advisory ecosystem differs from the scan subject');
      if (f.withdrawn) { withdrawn++; continue; }
      if (['critical','high','unknown'].includes(f.severity)) {
        const key = findingKey({...f,subject:s.id});
        requireThat(approved.has(key), 'Unresolved ' + f.severity + ' finding requires AppSec review: ' + f.advisory);
        used.add(key);
      }
      reviewed++;
    }
  }
  requireThat(approved.size === used.size, 'An approved exception does not match an active finding');
  return {subjects:scan.subjects.length, artifacts:artifacts.size, reviewedFindings:reviewed, withdrawnFindings:withdrawn, appliedExceptions:used.size};
}
export async function verifyPromotion({dir, repo=repoRoot, env=process.env, now=Date.now()}={}) {
  requireThat(typeof dir === 'string' && path.isAbsolute(dir), 'Production dependency audit evidence unavailable: configure an absolute signed evidence directory');
  const commit = execFileSync('git',['rev-parse','HEAD'],{cwd:repo,encoding:'utf8'}).trim();
  execFileSync('git',['diff','--quiet','HEAD','--'],{cwd:repo,stdio:'ignore'});
  const usedKeys = new Set();
  const signed = async role => {
    const pem = env['ZASP_RELEASE_'+keyNames[role]+'_PUBLIC_KEY'];
    const identity = publicKey(pem).export({type:'spki',format:'der'}).toString('hex');
    requireThat(!usedKeys.has(identity),'Release authority roles require separate public keys'); usedKeys.add(identity);
    const file = await bundleFile(dir, role+'.json');
    await bundleFile(dir,role+'.json.sig');
    return verifySigned(file,pem,'zasp.release.'+role+'.v1');
  };
  const build = await signed('candidate'), source = await signed('intake'), scanner = await signed('scan');
  const intake = checkIntake(source.value,now);
  checkRefresh(await readBound(await bundleFile(dir,'refresh.json'),6*1024**2),intake);
  await validateCandidate(build.value,{commit,lock:await readFile(path.join(repo,'package-lock.json')),rendered:await readBound(await bundleFile(dir,'rendered.yaml'),32*1024**2),repo});
  let exceptions;
  try { await access(path.join(dir,'exceptions.json')); exceptions = (await signed('exceptions')).value; }
  catch (error) { if (error.code !== 'ENOENT') throw error;
    // A missing signature for a present exception file is an error.
    try { await access(path.join(dir,'exceptions.json')); throw Error('Signed exception evidence missing'); }
    catch (check) { if (check.code !== 'ENOENT') throw check; }
  }
  const summary = await verifyScan({scan:scanner.value,candidate:build.value,candidateHash:build.sha256,intakeHash:source.sha256,dir,exceptions,now,intake});
  return {format:'zasp.release.promotion.v1',commit,candidateSha256:build.sha256,intakeSha256:source.sha256,scanSha256:scanner.sha256,...summary};
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await verifyPromotion({dir:process.env.ZASP_RELEASE_EVIDENCE_DIR}))); }
  catch (err) { console.error(err.message); process.exitCode=1; }
}
