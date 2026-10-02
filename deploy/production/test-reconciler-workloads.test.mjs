import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { loadAll } from 'js-yaml';
import { renderRelease } from './release-contract.mjs';
import { productionReleaseFixture } from './release-fixture.mjs';
import { validateTestReconcilerNetwork } from './test-reconciler-network.mjs';

const exec = promisify(execFile);
const name = 'zasp-test-reconciler';
function fixture() {
  return { profile: 'control_plane', schema: { expectedVersion: 55 },
    monitoring: { enabled: true, namespace: 'monitoring' },
    global: { terminationGracePeriodSeconds: 30, productImages: { agentsecWorker: `registry.example/worker@sha256:${'a'.repeat(64)}` } },
    testReconciler: { enabled: true, awsRegion: 'us-west-2', roleArn: 'arn:aws:iam::123456789012:role/test-reconciler',
      databaseSecretArn: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:reconciler-dsn',
      evidenceBucket: 'zasp-production-evidence', evidenceOwner: '123456789012',
      evidenceKMSKeyArn: 'arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111',
      databaseCIDRs: ['10.30.0.0/24'], stsCIDRs: ['10.31.0.0/28'], s3CIDRs: ['10.32.0.0/28'], kmsCIDRs: ['10.33.0.0/28'] } };
}
async function render(values) {
  const directory = await mkdtemp(path.join(tmpdir(), 'zasp-reconciler-chart-'));
  try {
    await mkdir(path.join(directory, 'templates'));
    await writeFile(path.join(directory, 'Chart.yaml'), 'apiVersion: v2\nname: reconciler-test\nversion: 0.1.0\n');
    await writeFile(path.join(directory, 'templates/reconciler.yaml'), await readFile(new URL('../staging/product/templates/test-reconciler.yaml', import.meta.url)));
    await writeFile(path.join(directory, 'values.json'), JSON.stringify(values));
    const { stdout } = await exec('helm', ['template', 'owned', directory, '-n', 'agentsec', '-f', path.join(directory, 'values.json')], { timeout: 20000 });
    return loadAll(stdout).filter(Boolean);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
const one = (resources, kind) => { const found = resources.filter(r => r.kind === kind); assert.equal(found.length, 1, kind); return found[0]; };

test('reconciler network validator rejects widened dependencies and additive policies', async () => {
  const values = fixture();
  const rows = [...await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: 'precision-intake' }), ...await render(values)];
  const network = r => r.find(x => x.kind === 'NetworkPolicy' && x.metadata.name === `${name}-dependencies`);
  const deployment = r => r.find(x => x.kind === 'Deployment' && x.metadata.name === name);
  assert.doesNotThrow(() => validateTestReconcilerNetwork(rows, values.testReconciler));
  for (const mutate of [
    r => network(r).spec.egress[0].ports[0].port = 443,
    r => network(r).spec.egress[1].to.push({ ipBlock: { cidr: '0.0.0.0/0' } }),
    r => delete network(r).spec.egress[2].to[0].podSelector,
    r => network(r).spec.ingress.push({}),
    r => network(r).spec.podSelector = {},
    r => network(r).metadata.namespace = 'other',
    r => r.push(structuredClone(network(r))),
    r => r.splice(r.indexOf(network(r)), 1),
    r => delete deployment(r).spec.template.metadata.labels['app.kubernetes.io/part-of'],
    r => r.find(x => x.kind === 'NetworkPolicy' && x.metadata.name === 'default-deny').spec.egress = [{}],
    r => delete r.find(x => x.kind === 'NetworkPolicy' && x.metadata.name === 'dns-egress').spec.podSelector.matchExpressions,
  ]) {
    const changed = structuredClone(rows); mutate(changed);
    assert.throws(() => validateTestReconcilerNetwork(changed, values.testReconciler), /release rejected/);
  }
  for (const podSelector of [
    {}, { matchLabels: { 'app.kubernetes.io/part-of': 'zasp' } },
    { matchExpressions: [{ key: 'app.kubernetes.io/name', operator: 'In', values: [name] }] },
    { matchExpressions: [{ key: 'absent', operator: 'NotIn', values: ['other'] }] },
    { matchExpressions: [{ key: 'app.kubernetes.io/name', operator: 'Exists' }] },
    { matchExpressions: [{ key: 'absent', operator: 'DoesNotExist' }] },
    { matchExpressions: [{ key: 'absent', operator: 'Unknown' }] },
    { matchExpressions: [{ key: 'absent', operator: 'NotIn' }] },
  ]) {
    const changed = structuredClone(rows);
    changed.push({ apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'unrelated-looking-policy' }, spec: { podSelector, policyTypes: ['Egress'], egress: [{}] } });
    assert.throws(() => validateTestReconcilerNetwork(changed, values.testReconciler), /release rejected/);
  }
  const unrelated = structuredClone(rows);
  unrelated.push({ kind: 'NetworkPolicy', metadata: { name: 'other-workload' }, spec: { podSelector: { matchLabels: { 'app.kubernetes.io/name': 'other' } }, policyTypes: ['Egress'], egress: [{}] } });
  assert.doesNotThrow(() => validateTestReconcilerNetwork(unrelated, values.testReconciler));
});

function selects(selector, labels) {
  if (!Object.entries(selector.matchLabels ?? {}).every(([key, value]) => labels[key] === value)) return false;
  return (selector.matchExpressions ?? []).every(({ key, operator, values }) => {
    if (operator === 'NotIn') return !values.includes(labels[key]);
    if (operator === 'In') return values.includes(labels[key]);
    if (operator === 'Exists') return key in labels;
    if (operator === 'DoesNotExist') return !(key in labels);
    throw new Error('unknown selector operator');
  });
}

test('shared chart policies cannot broaden the reconciler DNS-only allowance', async () => {
  // Render the real shared chart in its supported phase, then evaluate additive
  // policies against the candidate pod. This is not schema55 activation proof.
  const shared = await renderRelease(productionReleaseFixture);
  const candidate = await render(fixture());
  const labels = one(candidate, 'Deployment').spec.template.metadata.labels;
  const selected = [...shared, ...candidate].filter(r => r.kind === 'NetworkPolicy' && selects(r.spec.podSelector, labels));
  const rules = selected.flatMap(p => p.spec.egress ?? []);
  const dns = rules.filter(r => r.ports?.some(p => p.port === 53));
  assert.equal(dns.length, 1, 'shared policy adds broader DNS access');
  assert.equal(dns[0].to[0].podSelector.matchLabels['k8s-app'], 'kube-dns');
  assert.equal(rules.length, 3, 'unexpected additive dependency access');
});

test('reconciler is opt-in and refuses incompatible deployment authority', async () => {
  assert.deepEqual(await render({ testReconciler: { enabled: false } }), []);
  assert.deepEqual(await render({}), []);
  for (const mutate of [v => v.testReconciler.enabled = 'true', v => v.schema.expectedVersion = 54,
    v => v.profile = 'customer_edge', v => v.global.terminationGracePeriodSeconds = 20,
    v => v.global.productImages.agentsecWorker = 'registry.example/worker:latest',
    v => v.testReconciler.evidenceOwner = '999999999999', v => v.testReconciler.evidenceKMSKeyArn = 'alias/key',
    v => v.testReconciler.databaseSecretArn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret/other',
    v => v.testReconciler.roleArn = '', v => v.testReconciler.evidenceBucket = '',
  ]) { const v = fixture(); mutate(v); await assert.rejects(render(v)); }
});

test('reconciler renders isolated credentials, fixed runtime and bounded shutdown', async () => {
  const v = fixture(), resources = await render(v), deployment = one(resources, 'Deployment');
  const pod = deployment.spec.template.spec, container = pod.containers[0];
  assert.equal(deployment.spec.replicas, 2);
  assert.equal(pod.serviceAccountName, name);
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(one(resources, 'ServiceAccount').metadata.annotations['eks.amazonaws.com/role-arn'], v.testReconciler.roleArn);
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.equal(container.securityContext.allowPrivilegeEscalation, false);
  assert.deepEqual(container.securityContext.capabilities.drop, ['ALL']);
  assert.equal(container.readinessProbe.httpGet.path, '/readyz');
  const env = Object.fromEntries(container.env.map(e => [e.name, e.value ?? e.valueFrom]));
  assert.deepEqual(env, {
    ZASP_WORKER_MODE: 'security-agent-test-reconciler', ZASP_DATABASE_AUTHORITY: 'zasp_security_agent_worker',
    ZASP_WORKER_ID: { fieldRef: { fieldPath: 'metadata.name' } }, ZASP_POLL_INTERVAL: '1s', ZASP_LEASE_DURATION: '60s', ZASP_BATCH_SIZE: '1', ZASP_SHUTDOWN_TIMEOUT: '20s',
    ZASP_AWS_REGION: 'us-west-2', ZASP_EVIDENCE_BUCKET: v.testReconciler.evidenceBucket, ZASP_EVIDENCE_BUCKET_OWNER: '123456789012', ZASP_EVIDENCE_KMS_KEY_ARN: v.testReconciler.evidenceKMSKeyArn,
    ZASP_TEST_RECONCILER_ROLE_ARN: v.testReconciler.roleArn, ZASP_TEST_RECONCILER_WEB_IDENTITY_TOKEN_FILE: '/var/run/secrets/eks.amazonaws.com/serviceaccount/token',
  });
  assert.equal(pod.volumes.length, 2);
  assert.equal(pod.volumes[1].projected.sources[0].serviceAccountToken.audience, 'sts.amazonaws.com');
  assert.match(one(resources, 'SecretProviderClass').spec.parameters.objects, /objectAlias: postgres-dsn/);
  assert.match(container.args[0], /exec \/app\/agentsec-worker/);
  assert.equal(one(resources, 'PodDisruptionBudget').spec.minAvailable, 1);
  assert.equal(one(resources, 'HorizontalPodAutoscaler').spec.maxReplicas, 6);
});

test('turning chart monitoring off removes scrape resources and closes ingress', async () => {
  const values = fixture(); values.monitoring.enabled = false;
  const resources = await render(values);
  assert.equal(resources.some(r => ['Service', 'ServiceMonitor', 'PrometheusRule'].includes(r.kind)), false);
  assert.deepEqual(one(resources, 'NetworkPolicy').spec.ingress, []);
  assert.equal(one(resources, 'Deployment').spec.replicas, 2);
  assert.equal(one(resources, 'HorizontalPodAutoscaler').spec.maxReplicas, 6);
});

test('reconciler egress is closed to declared database and cloud ranges plus cluster DNS', async () => {
  const resources = await render(fixture()), policy = one(resources, 'NetworkPolicy');
  assert.deepEqual(policy.spec.policyTypes, ['Ingress', 'Egress']);
  assert.deepEqual(policy.spec.ingress, [{ from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'monitoring' } } }], ports: [{ protocol: 'TCP', port: 8081 }] }]);
  const rules = policy.spec.egress;
  assert.equal(rules.length, 3);
  assert.deepEqual(rules[0].ports, [{ protocol: 'TCP', port: 5432 }]);
  assert.deepEqual(rules[1].ports, [{ protocol: 'TCP', port: 443 }]);
  assert.deepEqual(rules[1].to.map(p => p.ipBlock.cidr), ['10.31.0.0/28', '10.32.0.0/28', '10.33.0.0/28']);
  assert.equal(rules[2].to[0].namespaceSelector.matchLabels['kubernetes.io/metadata.name'], 'kube-system');
  for (const key of ['databaseCIDRs', 'stsCIDRs', 's3CIDRs', 'kmsCIDRs']) {
    for (const ranges of [[], ['0.0.0.0/0'], ['127.0.0.1/32'], ['169.254.169.254/32'], ['10.30.0.1/24'], ['010.30.0.0/24'], ['10.30.0.0/24', '10.30.0.0/25'], [true]]) {
      const v = fixture(); v.testReconciler[key] = ranges; await assert.rejects(render(v));
    }
  }
});
