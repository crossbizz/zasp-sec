import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir, lstat, link, mkdir, mkdtemp, open, rename, rm, unlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireThat, stamp, hex, unique, verifySigned, fileHash } from './trust.mjs';

export const origins = Object.freeze({
  npm:'https://github.com/github/advisory-database',
  go:'https://vuln.go.dev',
  grype:'https://grype.anchore.io/databases'
});
export const toolNames = ['go','govulncheck','grype','syft'];
const day = 24 * 60 * 60 * 1000;

function exactSet(actual, expected) {
  return actual.length === expected.length && expected.every(x => actual.includes(x));
}
function transferURL(source) {
  const transfer = source.transfer;
  requireThat(transfer && hex(transfer.sha256) && Number.isSafeInteger(transfer.bytes) && transfer.bytes > 0 && transfer.bytes <= 8 * 1024 ** 3, 'Missing approved archive digest and byte length');
  const url = new URL(transfer.url);
  requireThat(url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash && !url.href.includes('%'), 'Invalid public mirror URL');
  const allowed = (source.id === 'npm' && url.hostname === 'codeload.github.com' && url.pathname === '/github/advisory-database/tar.gz/' + source.version)
    || (source.id === 'go' && url.href === 'https://vuln.go.dev/vulndb.zip')
    || (source.id === 'grype' && ['grype.anchore.io','toolbox-data.anchore.io'].includes(url.hostname) && /^\/(?:grype\/)?databases\/v6\/[A-Za-z0-9._:-]+\.tar\.(?:zst|gz)$/.test(url.pathname));
  requireThat(allowed, 'Archive is outside the approved public source');
  return url;
}
export function checkIntake(value, now = Date.now()) {
  requireThat(value?.format === 'zasp.release.intake.v1', 'Unknown advisory intake format');
  const observed = stamp(value.observedAt);
  requireThat(observed <= now && now - observed <= day, 'Advisory approval is stale or from the future');
  unique(value.sources, x => x.id, 'advisory sources');
  unique(value.tools, x => x.id, 'scanner tools');
  requireThat(exactSet(value.sources.map(s => s.id), Object.keys(origins)) && exactSet(value.tools.map(t => t.id), toolNames), 'Incomplete advisory sources or scanner tools');
  for (const source of value.sources) {
    const refreshed = stamp(source.refreshedAt);
    requireThat(source.origin === origins[source.id] && hex(source.sha256) && refreshed <= observed && now - refreshed <= day, 'Unapproved or stale advisory source');
    requireThat(typeof source.version === 'string' && /^[\w.+:-]{1,128}$/.test(source.version), 'Missing advisory source revision');
    if (source.id === 'npm') requireThat(/^[a-f\d]{40}$/.test(source.version) && hex(source.npmManifestSha256), 'Unbound npm commit or advisory record roster');
    if (source.transfer !== undefined) transferURL(source);
  }
  for (const tool of value.tools) {
    requireThat(hex(tool.sha256) && typeof tool.version === 'string' && /^[\w.+:-]{1,128}$/.test(tool.version), 'Unpinned scanner tool');
  }
  return value;
}

// Tree identity is SHA-256 over sorted relative UTF-8 names, byte lengths and
// content hashes. The tuple encoding remains unambiguous for nested DB shards.
export async function hashTree(directory) {
  requireThat((await lstat(directory)).isDirectory(), 'Invalid advisory DB directory');
  const hash = createHash('sha256');
  const files = [];
  let bytes = 0;
  async function visit(relative) {
    const entries = await readdir(path.join(directory, relative), {withFileTypes:true});
    for (const entry of entries) {
      requireThat(/^[A-Za-z0-9@_!+.,=-]+$/.test(entry.name), 'Unsupported advisory DB entry');
      const name = path.posix.join(relative, entry.name);
      requireThat(name.length <= 1024, 'Advisory DB path limit');
      if (entry.isDirectory()) await visit(name);
      else {
        requireThat(entry.isFile() && files.length < 200000, 'Invalid advisory DB tree');
        files.push(name);
      }
    }
  }
  await visit('');
  requireThat(files.length > 0, 'Empty advisory DB');
  for (const file of files.sort()) {
    const absolute = path.join(directory, file);
    const size = (await lstat(absolute)).size;
    bytes += size;
    requireThat(bytes <= 16 * 1024 ** 3, 'Advisory DB byte limit');
    hash.update(JSON.stringify([file, size, await fileHash(absolute)]) + '\n');
  }
  return hash.digest('hex');
}

// Runs only in the public ingress zone. No release inventory is an argument.
// Completed files are immutable and content addressed. An interrupted copy is
// removed; concurrent identical acquisition safely reuses the verified file.
export async function mirrorPublicSources(intake, target, {now = Date.now(), fetchPublic = fetch} = {}) {
  checkIntake(intake, now);
  const entries = intake.sources.map(source => ({source, url:transferURL(source)}));
  await mkdir(target, {recursive:true,mode:0o700});
  for (const {source, url} of entries) {
    const {bytes, sha256} = source.transfer;
    const destination = path.join(target, source.id + '-' + sha256);
    const tmp = path.join(target, '.partial-' + randomUUID());
    const fd = await open(tmp, 'wx', 0o400);
    try {
      const response = await fetchPublic(url, {redirect:'error',credentials:'omit',signal:AbortSignal.timeout(600000)});
      requireThat(response.status === 200 && response.body, 'Public upstream unavailable');
      const hash = createHash('sha256');
      let received = 0;
      for await (const chunk of response.body) {
        received += chunk.length;
        requireThat(received <= bytes, 'Public archive exceeds its approved size');
        hash.update(chunk);
        await fd.writeFile(chunk);
      }
      requireThat(received === bytes && hash.digest('hex') === sha256, 'Public archive digest differs from approval');
      await fd.sync();
      try { await link(tmp, destination); }
      catch (err) {
        if (err.code !== 'EEXIST') throw err;
        requireThat(await fileHash(destination) === sha256, 'Existing mirror content mismatch');
      }
    } finally { await fd.close(); await unlink(tmp); }
  }
}
// The exact-lock npm collector needs local Git objects for the upstream
// commit. Fetch from a fixed public URL in an empty directory. Credentials,
// user config, hooks and submodule recursion are excluded.
export async function checkoutNpmMirror(intake, target) {
  checkIntake(intake);
  const revision = intake.sources.find(s => s.id === 'npm').version;
  await mkdir(target,{mode:0o700,recursive:true});
  const tmp = await mkdtemp(path.join(target,'.npm-checkout-'));
  const destination = path.join(target,'npm-'+revision);
  const env = {PATH:process.env.PATH, HOME:tmp, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:'/dev/null', GIT_TERMINAL_PROMPT:'0', GIT_ALLOW_PROTOCOL:'https', GCM_INTERACTIVE:'never'};
  const git = args => promisify(execFile)('git',['-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never',...args],{cwd:tmp,env,timeout:600000,maxBuffer:4*1024**2});
  try {
    await git(['init','--quiet']);
    await git(['fetch','--no-tags','--depth=1','--no-recurse-submodules',origins.npm,revision]);
    await git(['checkout','--quiet','--detach','FETCH_HEAD']);
    requireThat((await git(['rev-parse','HEAD'])).stdout.trim() === revision, 'Public npm mirror commit mismatch');
    try { await rename(tmp,destination); }
    catch (err) {
      if (!['ENOTEMPTY','EEXIST'].includes(err.code)) throw err;
      const existing = await promisify(execFile)('git',['--no-replace-objects','-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-C',destination,'rev-parse','HEAD'],{env:{...env,GIT_ALLOW_PROTOCOL:'',GIT_NO_LAZY_FETCH:'1'},timeout:10000});
      requireThat(existing.stdout.trim() === revision,'Existing npm mirror revision mismatch');
    }
    return destination;
  } finally { await rm(tmp,{recursive:true,force:true}); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , command, approvedFile, mirror] = process.argv;
  try {
    requireThat(process.argv.length === 5 && ['mirror','checkout-npm'].includes(command), 'Usage: intake.mjs mirror|checkout-npm SIGNED_INTAKE_JSON PUBLIC_MIRROR_DIRECTORY');
    const {value} = await verifySigned(approvedFile, process.env.ZASP_RELEASE_INTAKE_PUBLIC_KEY, 'zasp.release.intake.v1');
    if (command === 'checkout-npm') {
      await checkoutNpmMirror(value, mirror);
      console.log('Verified the exact public npm advisory commit.');
    } else {
      await mirrorPublicSources(value, mirror);
      console.log('Verified three public archives in the mirror.');
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
