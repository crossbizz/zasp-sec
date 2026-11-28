import {strict as assert} from 'node:assert';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {load, loadAll} from 'js-yaml';
import {renderChart, renderVpsFixture} from './test-fixture.mjs';

test('the PostHog project key and ingestion egress belong only to the enabled product API', async () => {
  const host = 'https://analytics.example.test:8443';
  const cidr = '192.0.2.71/32';
  const args = ['--set', `posthog.host=${host},posthog.existingSecret=ingestion`];
  const enabled = ['--set', 'posthog.enabled=true'];
  const ranges = ['--set-string', `posthog.egressCIDRs[0]=${cidr}`];
  const off = await renderVpsFixture('compatibility', [...args, ...ranges]);
  assert.ok(!JSON.stringify(off).includes('ZASP_POSTHOG_'));
  assert.ok(!JSON.stringify(off).includes(cidr));
  await assert.rejects(renderVpsFixture('compatibility', [...args, ...enabled]), /posthog\.egressCIDRs is required/);

  const rows = await renderVpsFixture('compatibility', [...args, ...enabled, ...ranges]);
  const api = rows.find(r => r.kind === 'Deployment' && r.metadata.name === 'agentsec-api');
  const vars = api.spec.template.spec.containers[0].env.filter(e => e.name.startsWith('ZASP_POSTHOG_'));
  assert.deepEqual(vars, [
    {name: 'ZASP_POSTHOG_HOST', value: host},
    {name: 'ZASP_POSTHOG_PROJECT_KEY', valueFrom: {secretKeyRef: {name: 'ingestion', key: 'project-key'}}},
  ]);
  assert.ok(rows.filter(r => r !== api).every(r => !JSON.stringify(r).includes('ZASP_POSTHOG_')));
  const policies = rows.filter(r => r.kind === 'NetworkPolicy' && JSON.stringify(r.spec).includes(cidr));
  assert.equal(policies.length, 1);
  assert.equal(policies[0].spec.podSelector.matchLabels['app.kubernetes.io/name'], 'agentsec-api');
  assert.deepEqual(policies[0].spec.egress.find(rule => JSON.stringify(rule).includes(cidr)), {
    to: [{ipBlock: {cidr}}], ports: [{protocol: 'TCP', port: 8443}],
  });
});

test('reserves the four peer namespaces independently of product Helm releases', async () => {
  const objects = loadAll(await readFile(new URL('./namespaces.yaml', import.meta.url), 'utf8'));
  assert.deepEqual(objects.map(o => o.kind), Array(4).fill('Namespace'));
  assert.deepEqual(objects.map(o => o.metadata.name).sort(), ['connectors', 'opensearch', 'staging', 'zasp']);
});

test('OpenSearch persists data independently and restricts ingress and index permissions', async () => {
  const resources = await renderChart('opensearch', 'deploy/vps/opensearch', 'opensearch');
  const kind = k => resources.filter(r => r.kind === k);
  const state = kind('StatefulSet')[0];
  assert.equal(state.spec.persistentVolumeClaimRetentionPolicy.whenDeleted, 'Retain');
  assert.deepEqual(state.spec.volumeClaimTemplates[0].spec.accessModes, ['ReadWriteOnce']);
  assert.equal(state.spec.template.spec.automountServiceAccountToken, false);
  assert.match(state.spec.template.spec.containers[0].image, /@sha256:[a-f0-9]{64}$/);
  assert.equal(kind('Ingress').length + kind('Secret').length, 0);
  for (const service of kind('Service')) assert.equal(service.spec.type ?? 'ClusterIP', 'ClusterIP');
  const files = kind('ConfigMap').find(r => r.metadata.name === 'opensearch-security-configuration').data;
  const config = load(kind('ConfigMap').find(r => r.metadata.name === 'opensearch-node').data['opensearch.yml']);
  assert.equal(config['plugins.security.ssl.http.clientauth_mode'], 'REQUIRE');
  assert.equal(config['plugins.security.allow_default_init_securityindex'], false);
  const roles = load(files['roles.yml']);
  const mappings = load(files['roles_mapping.yml']);
  for (const [role, name] of [['zasp_api','api'], ['zasp_inventory','inventory'], ['zasp_runtime','runtime'], ['zasp_schema','schema']]) {
    assert.deepEqual(mappings[role].users, ['zasp-search-' + name]);
    assert.ok(!roles[role].index_permissions[0].index_patterns.includes('*'));
  }
  assert.ok(roles.zasp_api.index_permissions[0].allowed_actions.every(a => !a.includes('write')));
  const ingress = kind('NetworkPolicy').find(r => r.metadata.name === 'opensearch').spec.ingress[0];
  assert.equal(ingress.from[0].namespaceSelector.matchLabels['kubernetes.io/metadata.name'], 'zasp');
  assert.deepEqual(ingress.ports, [{protocol:'TCP', port:9200}]);
  await assert.rejects(renderChart('opensearch', 'deploy/vps/opensearch', 'staging'));
});

test('a full product render is namespace-local and references its private broker and search services', async () => {
  const rows = await renderVpsFixture();
  assert.ok(rows.length > 50);
  for (const row of rows) {
    assert.equal(row.metadata.namespace ?? 'zasp', 'zasp', row.metadata.name);
    assert.ok(!/^(Namespace|ClusterRole|ClusterRoleBinding|ValidatingAdmissionPolicy|ValidatingAdmissionPolicyBinding|CustomResourceDefinition)$/.test(row.kind), row.kind);
    if (['Deployment','StatefulSet','Service'].includes(row.kind)) {
      assert.ok(!['nango','opensearch'].includes(row.metadata.name));
    }
  }
  for (const name of ['agentsec-api','agentsec-discovery-worker']) {
    const pod = rows.find(r => r.kind === 'Deployment' && r.metadata.name === name).spec.template.spec;
    const env = Object.fromEntries(pod.containers[0].env.map(e => [e.name, e.value]));
    assert.equal(env.ZASP_NANGO_BASE_URL, 'https://nango.connectors.svc.cluster.local:8443');
    assert.equal(env.ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION, 'collector_v1');
    assert.equal(env.SSL_CERT_DIR, '/etc/ssl/certs:/var/run/secrets/zasp-nango/ca');
    const secret = pod.volumes.find(v => v.name === 'nango-service-key').secret;
    assert.equal(secret.secretName, 'nango-client');
    assert.deepEqual(secret.items.map(v => v.key).sort(), ['ca.crt','service-key']);
  }
});

function selectsPod(selector, labels) {
  if (!Object.entries(selector.matchLabels ?? {}).every(([key, value]) => labels[key] === value)) return false;
  return (selector.matchExpressions ?? []).every(({key, operator, values}) => {
    if (operator === 'In') return values.includes(labels[key]);
    if (operator === 'NotIn') return !values.includes(labels[key]);
    if (operator === 'Exists') return Object.hasOwn(labels, key);
    if (operator === 'DoesNotExist') return !Object.hasOwn(labels, key);
    assert.fail('unexpected Kubernetes selector operator ' + operator);
  });
}

test('agentsec coexists with the evaluation release and leaves its service, pods and storage available', async () => {
  const [product, evaluation] = await Promise.all([
    renderVpsFixture(),
    renderChart('zasp', 'deploy/kubernetes/zasp', 'zasp', [
      '--set-string', 'publicOrigin=https://zasp.example.test:8443',
      '--set-string', 'images.api=fixture/api,images.web=fixture/web,images.worker=fixture/worker',
      '--set-string', 'secrets.existingSecret=zasp-secrets,nango.existingSecret=zasp-nango',
      '--set', 'nango.enabled=true,ingress.enabled=true', '--set-string', 'ingress.tlsSecretName=zasp-front-tls',
    ]),
  ]);
  const id = object => object.kind + '/' + object.metadata.name;
  const protectedIds = new Set(evaluation.map(id));
  const state = evaluation.find(object => id(object) === 'StatefulSet/zasp');
  const evalPod = state.spec.template.metadata.labels;
  const evalService = evaluation.find(object => id(object) === 'Service/zasp');
  protectedIds.add('Endpoints/' + evalService.metadata.name);
  for (const claim of state.spec.volumeClaimTemplates) protectedIds.add('PersistentVolumeClaim/' + claim.metadata.name + '-zasp-0');
  for (const volume of state.spec.template.spec.volumes) {
    if (volume.secret) protectedIds.add('Secret/' + volume.secret.secretName);
  }
  const deny = product.find(object => object.kind === 'NetworkPolicy' && object.metadata.name === 'agentsec-default-deny');
  assert.ok(deny, 'product workloads require default ingress and egress isolation');
  for (const row of product) {
    assert.ok(!protectedIds.has(id(row)), id(row) + ' would take ownership of existing resources');
    assert.notEqual(row.kind, 'Ingress', 'coexistence installation must leave the current route available');
    if (row.kind === 'NetworkPolicy') assert.ok(!selectsPod(row.spec.podSelector, evalPod), id(row) + ' would change evaluation connectivity');
    if (row.kind === 'Service' && row.spec.selector) assert.ok(!selectsPod({matchLabels: row.spec.selector}, evalPod), id(row) + ' selects evaluation pods');
    const pod = row.spec?.template ?? row.spec?.jobTemplate?.spec.template;
    if (pod) {
      assert.ok(selectsPod(deny.spec.podSelector, pod.metadata.labels), id(row) + ' must be covered by production isolation');
      assert.ok(!selectsPod({matchLabels: evalService.spec.selector}, pod.metadata.labels), id(row) + ' would receive evaluation traffic');
      assert.ok((pod.spec.volumes ?? []).every(v => !protectedIds.has('PersistentVolumeClaim/' + v.persistentVolumeClaim?.claimName)));
    }
  }
});
