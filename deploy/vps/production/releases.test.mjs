import {strict as assert} from 'node:assert';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {load, loadAll} from 'js-yaml';
import {renderChart, renderVpsFixture} from './test-fixture.mjs';

test('reserves the four peer namespaces independently of product Helm releases', async () => {
  const objects = loadAll(await readFile(new URL('./namespaces.yaml', import.meta.url), 'utf8'));
  assert.deepEqual(objects.map(o => o.kind), Array(4).fill('Namespace'));
  assert.deepEqual(objects.map(o => o.metadata.name).sort(), ['agentsec', 'connectors', 'opensearch', 'staging']);
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
  assert.equal(ingress.from[0].namespaceSelector.matchLabels['kubernetes.io/metadata.name'], 'agentsec');
  assert.deepEqual(ingress.ports, [{protocol:'TCP', port:9200}]);
  await assert.rejects(renderChart('opensearch', 'deploy/vps/opensearch', 'staging'));
});

test('a full product render is namespace-local and references its private broker and search services', async () => {
  const rows = await renderVpsFixture();
  assert.ok(rows.length > 50);
  for (const row of rows) {
    assert.equal(row.metadata.namespace ?? 'agentsec', 'agentsec', row.metadata.name);
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
