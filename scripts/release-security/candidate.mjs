import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { loadAll, JSON_SCHEMA } from 'js-yaml';
import { hex, object, requireThat, sha256, unique } from './trust.mjs';

export const imageRoles = ['web','api','worker','redteam-worker','attack-lab-runner','event-ingest','gateway-control','runtime-gateway','sensor-agent'];
const native = [
  ['zaspctl','cmd/zaspctl',['linux/amd64','darwin/arm64','windows/amd64']],
  ['zasp-endpoint','services/endpoint-agent',['darwin/arm64']],
  ['zasp-device-windows','services/endpoint-agent',['windows/amd64']]
];
const distroDigest = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const validRepo = value => typeof value === 'string' && value.length < 256 && /^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/.test(value);
export const linuxPlatform = value => ['linux/amd64','linux/arm64'].includes(value);
export function sameSet(actual, expected, message) {
  const a = new Set(actual), b = new Set(expected);
  requireThat(a.size === b.size && [...a].every(x => b.has(x)), message);
}
function renderedImages(bytes) {
  const result = new Set();
  let visited = 0;
  function walk(value, depth = 0) {
    if (!value || typeof value !== 'object') return;
    requireThat(++visited < 500000 && depth <= 80, 'Rendered manifest exceeds limit');
    for (const [key, children] of Object.entries(value)) {
      if (['containers','initContainers','ephemeralContainers'].includes(key) && Array.isArray(children)) {
        for (const c of children) {
          requireThat(typeof c?.image === 'string' && /^.+@sha256:[a-f0-9]{64}$/.test(c.image), 'Rendered container requires its immutable digest');
          result.add(c.image);
        }
      } else walk(children, depth + 1);
    }
  }
  for (const doc of loadAll(bytes.toString('utf8'), {schema:JSON_SCHEMA})) walk(doc);
  requireThat(result.size > 0, 'Empty rendered inventory');
  return result;
}
export async function expectedHostedBinaries(repo) {
  const result = new Map();
  for (const role of imageRoles) {
    const dockerfile = await readFile(path.join(repo,'deploy/production',role + '.Dockerfile'),'utf8');
    for (const match of dockerfile.matchAll(/\bgo build\b[^\n]*? -o \/out\/([a-z][a-z0-9-]*)\s/g)) {
      const name = match[1];
      const root = ['event-ingest','gateway-control','runtime-gateway','sensor-agent'].includes(name) ? 'services/' + name : 'services/platform';
      result.set(name,root);
    }
  }
  requireThat(result.has('agentsec-api') && result.has('sensor-agent'), 'Unknown hosted build format');
  return result;
}
export async function validateCandidate(c, {commit, lock, rendered, repo}) {
  requireThat(c?.format === 'zasp.release.candidate.v1' && /^[a-f0-9]{40}$/.test(commit) && c.commit === commit, 'Candidate commit differs from checkout');
  requireThat(c.lockSha256 === sha256(lock) && c.renderedSha256 === sha256(rendered), 'Candidate lock or rendered digest mismatch');
  const platforms = c.deploymentPlatforms;
  requireThat(Array.isArray(platforms) && platforms.length > 0 && platforms.every(linuxPlatform) && new Set(platforms).size === platforms.length, 'Invalid target platforms');
  requireThat(object(c.productImages), 'Missing product image inventory');
  sameSet(Object.keys(c.productImages), imageRoles, 'Incomplete product build inventory');
  requireThat(new Set(Object.values(c.productImages)).size === imageRoles.length, 'Duplicate product image role');
  unique(c.images, i => [i.ref,i.digest,i.platform].join('#'), 'platform images');
  const platformRefs = new Set(), deploymentRefs = new Map();
  for (const i of c.images) {
    requireThat(validRepo(i.ref) && distroDigest(i.digest) && platforms.includes(i.platform), 'Invalid image subject');
    requireThat(i.deploymentDigest === undefined || distroDigest(i.deploymentDigest), 'Invalid rendered index digest');
    const ref = i.ref + '@' + (i.deploymentDigest ?? i.digest);
    requireThat(!platformRefs.has(ref + '#' + i.platform), 'Multiple image descriptors for one platform');
    platformRefs.add(ref + '#' + i.platform);
    if (!deploymentRefs.has(ref)) deploymentRefs.set(ref,[]);
    deploymentRefs.get(ref).push(i.platform);
  }
  const actualRendered = renderedImages(rendered);
  // Some release images (e.g. a per-job runner) are referenced by control
  // plane configuration and start on demand. The signed product build roster
  // covers those artifacts even when there is no steady-state Pod template.
  sameSet(deploymentRefs.keys(), [...actualRendered, ...Object.values(c.productImages)], 'Rendered or product image is missing or substituted');
  for (const platformsFound of deploymentRefs.values()) sameSet(platformsFound, platforms, 'An image target platform is missing');
  unique(c.npmInstalls, p => p.platform, 'npm installations');
  for (const p of c.npmInstalls) requireThat(platforms.includes(p.platform) && ['glibc','musl'].includes(p.libc) && hex(p.inventorySha256), 'Invalid npm installation binding');
  sameSet(c.npmInstalls.map(p => p.platform), platforms, 'Candidate lacks a platform npm inventory');
  unique(c.binaries, b => [b.name,b.platform].join('@'), 'binaries');
  const required = new Map();
  for (const [name,root] of await expectedHostedBinaries(repo)) for (const platform of platforms) required.set(name+'@'+platform, root);
  for (const [name,root,targets] of native) for (const target of targets) required.set(name+'@'+target, root);
  for (const b of c.binaries) {
    requireThat(typeof b.name === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(b.name) && /^[a-z]+\/(?:amd64|arm64)$/.test(b.platform) && hex(b.sha256), 'Invalid Go binary subject');
    requireThat(typeof b.root === 'string' && /^(?:services|cmd|sdks)\/[a-zA-Z0-9_-]+$/.test(b.root), 'Invalid Go module root');
    const key = b.name+'@'+b.platform;
    if (required.has(key)) {
      requireThat(required.get(key) === b.root, 'Binary build root mismatch'); required.delete(key);
    }
  }
  requireThat(required.size === 0, 'Candidate omitted required shipping binaries');
}
