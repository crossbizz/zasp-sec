import { appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { loadAll, JSON_SCHEMA } from 'js-yaml';
import { requireThat } from './trust.mjs';

// Only the namespace-scoped kinds used by the Zasp product release. New
// cluster-wide prerequisites have their own installation and authorization.
const allowed = new Set([
  'v1/Service', 'v1/ServiceAccount', 'v1/ConfigMap',
  'apps/v1/Deployment', 'batch/v1/Job', 'batch/v1/CronJob',
  'autoscaling/v2/HorizontalPodAutoscaler', 'networking.k8s.io/v1/Ingress',
  'networking.k8s.io/v1/NetworkPolicy', 'policy/v1/PodDisruptionBudget',
  'monitoring.coreos.com/v1/ServiceMonitor', 'monitoring.coreos.com/v1/PrometheusRule',
  'secrets-store.csi.x-k8s.io/v1/SecretProviderClass', 'vpcresources.k8s.aws/v1beta1/SecurityGroupPolicy',
]);
const shared = /(?:^|[-_/])(?:nango|opensearch)(?:$|[-_:./@])/i;

function releaseDocuments(manifest, hooks = []) {
  requireThat((typeof manifest === 'string' || Buffer.isBuffer(manifest)) && Array.isArray(hooks), 'Missing production release manifest');
  return [manifest.toString(), ...hooks.map(h => {
    requireThat(typeof h?.manifest === 'string', 'Unreadable previous release hook');
    return h.manifest;
  })].flatMap(raw => loadAll(raw, {schema: JSON_SCHEMA}).filter(Boolean));
}

export function validateProductionResources(manifest, hooks = []) {
  const documents = releaseDocuments(manifest, hooks);
  requireThat(documents.length > 0, 'Empty production release');
  for (const doc of documents) {
    const metadata = doc.metadata;
    requireThat(allowed.has(doc.apiVersion + '/' + doc.kind) && metadata?.name && (!metadata.namespace || metadata.namespace === 'zasp'),
      'Product release contains a cluster-wide or foreign-namespace resource');
    const pod = doc.spec?.template?.spec ?? doc.spec?.jobTemplate?.spec?.template?.spec;
    if (pod) {
      const containers = [...(pod.containers ?? []), ...(pod.initContainers ?? []), ...(pod.ephemeralContainers ?? [])];
      requireThat(!shared.test(metadata.name) && containers.every(c => !shared.test(c.name) && !shared.test(c.image)),
        'Product release contains a shared dependency workload');
    }
  }
}

function overlappingIngress(product, existing) {
  if (product.spec?.ingressClassName && existing.spec?.ingressClassName && product.spec.ingressClassName !== existing.spec.ingressClassName) return false;
  if (product.spec?.defaultBackend || existing.spec?.defaultBackend) return true;
  const rewrites = [product, existing].some(doc => Object.keys(doc.metadata.annotations ?? {}).some(name => /use-regex|rewrite-target/.test(name)));
  for (const a of product.spec?.rules ?? []) for (const b of existing.spec?.rules ?? []) {
    const hostsMatch = !a.host || !b.host || a.host === b.host || (a.host.startsWith('*.') && b.host.endsWith(a.host.slice(1))) || (b.host.startsWith('*.') && a.host.endsWith(b.host.slice(1)));
    if (!hostsMatch) continue;
    if (rewrites) return true;
    for (const left of a.http?.paths ?? []) for (const right of b.http?.paths ?? []) {
      if (left.pathType === 'ImplementationSpecific' || right.pathType === 'ImplementationSpecific') return true;
      const leftPath = (left.path || '/').replace(/\/$/, ''), rightPath = (right.path || '/').replace(/\/$/, '');
      if (leftPath === rightPath || (left.pathType === 'Prefix' && rightPath.startsWith(leftPath + '/')) || (right.pathType === 'Prefix' && leftPath.startsWith(rightPath + '/'))) return true;
    }
  }
  return false;
}

// The two releases share a namespace. Helm hooks can run before Helm's
// ordinary ownership validation, so collisions must be excluded beforehand.
export function protectEvaluationRelease(manifest, hooks, evaluation) {
  const seen = releaseDocuments(evaluation.manifest, evaluation.hooks);
  const id = doc => [doc.apiVersion.split('/').length === 1 ? '' : doc.apiVersion.split('/')[0], doc.kind, doc.metadata.namespace || 'zasp', doc.metadata.name].join('/');
  const reserved = new Set(seen.map(id));
  const labels = seen.map(doc => doc.spec?.template?.metadata?.labels).filter(Boolean);
  for (const doc of releaseDocuments(manifest, hooks)) {
    if (doc.kind === 'Ingress') requireThat(!seen.some(existing => existing.kind === 'Ingress' && overlappingIngress(doc, existing)),
      'Product Ingress overlaps existing evaluation routing');
    requireThat(!reserved.has(id(doc)), 'Product resource collides with the existing evaluation release');
    const selector = doc.kind === 'NetworkPolicy' ? doc.spec?.podSelector
      : doc.kind === 'PodDisruptionBudget' ? doc.spec?.selector
      : doc.kind === 'Service' && doc.spec?.selector ? {matchLabels:doc.spec.selector} : null;
    if (!selector) continue;
    for (const pod of labels) {
      const labelsMatch = Object.entries(selector.matchLabels ?? {}).every(([key,value]) => pod[key] === value);
      const expressionsMatch = (selector.matchExpressions ?? []).every(({key,operator,values}) => {
        if (operator === 'In') return values.includes(pod[key]);
        if (operator === 'NotIn') return !values.includes(pod[key]);
        if (operator === 'Exists') return Object.hasOwn(pod,key);
        if (operator === 'DoesNotExist') return !Object.hasOwn(pod,key);
        throw Error('Unsupported product pod selector');
      });
      requireThat(!(labelsMatch && expressionsMatch), 'Product resource selects the existing evaluation pod');
    }
  }
}

export const pushChecks = [
  ['runnable-ui.yml', ['Verify runnable UI', 'Platform Go packages']],
  ['feature-v2.yml', ['local-runtime', 'skill-scanner-benchmark', 'browser-upload-routes', 'macos-endpoint', 'windows-inventory']],
  ['infrastructure-providers.yml', ['provider-contracts', 'backup-and-recovery', 'vps-operations', 'release-rendering', 'nango-kubernetes-runtime', 'nango-vps-runtime', 'opensearch-vps-runtime']],
];

export async function checkTestedMain({env = process.env, request = fetch, wait = false, sleep = delay, now = Date.now} = {}) {
  const {GITHUB_SHA: sha, GITHUB_REPOSITORY: repo, GH_TOKEN: token} = env;
  requireThat(/^[a-f0-9]{40}$/.test(sha) && repo === 'crossbizz/zasp-sec' && token && env.GITHUB_REF === 'refs/heads/main', 'Production requires a main commit and read-only Actions credentials');
  const api = async path => {
    const response = await request('https://api.github.com/repos/' + repo + path, {
      headers: {Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'},
      signal: AbortSignal.timeout(15000), redirect: 'error',
    });
    requireThat(response.ok, 'Could not verify main CI evidence (HTTP ' + response.status + ')');
    return response.json();
  };
  const expires = now() + 100*60_000;
  while (true) {
    if ((await api('/git/ref/heads/main')).object?.sha !== sha) return false;
    const passing = await Promise.all(pushChecks.map(async ([workflow, names]) => {
      const {workflow_runs: runs} = await api('/actions/workflows/' + workflow + '/runs?branch=main&event=push&head_sha=' + sha + '&per_page=100');
      const run = runs.filter(r => r.head_sha === sha && r.head_branch === 'main' && r.event === 'push' && r.head_repository?.full_name === repo)
        .sort((a,b) => b.run_number - a.run_number)[0];
      if (!run || run.status !== 'completed') return false;
      requireThat(run.conclusion === 'success', 'Push workflow did not pass: ' + workflow);
      const {jobs, total_count: count} = await api('/actions/runs/' + run.id + '/attempts/' + run.run_attempt + '/jobs?per_page=100');
      requireThat(jobs.length === count && names.every(name => jobs.some(job => job.name === name && job.conclusion === 'success')),
        'Required push tests were missing or skipped: ' + workflow);
      return true;
    }));
    if (passing.every(Boolean)) return (await api('/git/ref/heads/main')).object?.sha === sha;
    requireThat(wait && now() < expires, 'Main CI is incomplete for the exact candidate');
    await sleep(30000);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const current = await checkTestedMain({wait:true});
    await appendFile(process.env.GITHUB_OUTPUT, 'current=' + current + '\n');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
