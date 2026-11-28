import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import {renderVpsFixture} from './test-fixture.mjs';

const searchDir = '/var/run/secrets/zasp-opensearch';
const operatorDir = '/var/run/secrets/zasp-deployment-admin';
const tokenFile = '/var/run/secrets/eks.amazonaws.com/serviceaccount/token';

function podOf(resource) {
  return resource.spec?.jobTemplate?.spec?.template?.spec ?? resource.spec?.template?.spec;
}

function mountedVolume(pod, container, directory) {
  const mount = container.volumeMounts?.find(item => item.mountPath === directory);
  assert.equal(mount?.readOnly, true, container.name + ' must mount ' + directory + ' read-only');
  assert.equal(mount.subPath, undefined);
  assert.equal(mount.subPathExpr, undefined);
  const volume = pod.volumes.find(item => item.name === mount.name);
  assert.ok(volume, container.name + ' must mount a declared volume');
  return volume;
}

function assertToken(pod, container, settings) {
  for (const [key, location] of settings) {
    if (!key.endsWith('_WEB_IDENTITY_TOKEN_FILE')) continue;
    assert.equal(location, tokenFile, key);
    assert.equal(pod.automountServiceAccountToken, false);
    assert.ok(pod.serviceAccountName && pod.serviceAccountName !== 'default');
    assert.ok(!settings.has('AWS_ACCESS_KEY_ID') && !settings.has('AWS_SECRET_ACCESS_KEY'));
    const projected = mountedVolume(pod, container, path.posix.dirname(location)).projected;
    assert.ok(projected, key + ' must select a rotating projected token');
    assert.equal(projected.sources.length, 1);
    const token = projected.sources[0].serviceAccountToken;
    assert.ok(token && token.expirationSeconds >= 600 && token.expirationSeconds <= 3600);
    assert.equal(token.audience, 'sts.amazonaws.com');
    assert.equal(token.path, 'token');
  }
}

for (const phase of ['compatibility', 'precision-intake']) {
  test('VPS ' + phase + ' binds workload credentials to the intended containers', async () => {
    const resources = await renderVpsFixture(phase);
    const searchRoles = new Map([
      ['agentsec-api', 'api'], ['agentsec-projection-search', 'inventory'],
      ['agentsec-runtime-index', 'runtime'], ['agentsec-projection-search-init-v1', 'schema'],
    ]);
    if (phase !== 'compatibility') {
      searchRoles.set('agentsec-runtime-session-index-v2', 'runtime');
      searchRoles.set('agentsec-projection-search-init-v2', 'schema');
    }
    const searchHolders = [];
    const deploymentAdminHolders = [];
    const tokenHolders = [];
    for (const resource of resources) {
      const pod = podOf(resource);
      if (!pod) continue;
      const name = resource.metadata.name;
      for (const container of [...(pod.initContainers ?? []), ...pod.containers]) {
        const env = new Map((container.env ?? []).map(entry => [entry.name, entry.value]));
        assertToken(pod, container, env);
        if ([...env.keys()].some(key => key.endsWith('_WEB_IDENTITY_TOKEN_FILE'))) tokenHolders.push(name);
        const mounts = container.volumeMounts ?? [];
        const secretNames = mounts.map(mount => pod.volumes?.find(vol => vol.name === mount.name)?.secret?.secretName).filter(Boolean);
        if (env.has('ZASP_OPENSEARCH_AUTH_MODE') || secretNames.some(secret => /^opensearch-.*-client$/.test(secret))) {
          const role = searchRoles.get(name);
          assert.ok(role, 'unexpected search credential in ' + name + '/' + container.name);
          assert.equal(env.get('ZASP_OPENSEARCH_AUTH_MODE'), 'mtls');
          const secret = mountedVolume(pod, container, searchDir).secret;
          assert.equal(secret.secretName, 'opensearch-' + role + '-client');
          assert.equal(secret.defaultMode, 0o440);
          assert.deepEqual(secret.items.map(item => [item.key, item.path]).sort(), [
            ['ca.crt','ca.crt'], ['tls.crt','tls.crt'], ['tls.key','tls.key'],
          ]);
          assert.equal(pod.securityContext.fsGroup, 65532);
          assert.equal(pod.securityContext.runAsNonRoot, true);
          searchHolders.push(name);
        }
        if ([...env.keys()].some(key => key.startsWith('ZASP_DEPLOYMENT_ADMIN_')) || secretNames.includes('deployment-admin')) {
          assert.equal(name, 'agentsec-api');
          assert.equal(container.name, 'agentsec-api');
          assert.equal(env.get('ZASP_DEPLOYMENT_ADMIN_ID'), 'fixture-deployment');
          assert.equal(env.get('ZASP_DEPLOYMENT_ADMIN_PASSWORD_FILE'), operatorDir + '/password');
          assert.equal(env.get('ZASP_DEPLOYMENT_ADMIN_DSN_FILE'), operatorDir + '/database-url');
          const secret = mountedVolume(pod, container, operatorDir).secret;
          assert.equal(secret.secretName, 'deployment-admin');
          assert.equal(secret.defaultMode, 0o440);
          assert.ok(['database-url','password'].every(key => secret.items.some(item => item.key === key && item.path === key)));
          deploymentAdminHolders.push(name);
        }
      }
    }
    assert.deepEqual(searchHolders.sort(), [...searchRoles.keys()].sort());
    assert.deepEqual(deploymentAdminHolders, ['agentsec-api']);
    for (const expected of ['agentsec-api', 'agentsec-discovery-worker', 'agentsec-runtime-index', 'agentsec-outbox-publisher']) {
      assert.ok(tokenHolders.includes(expected), 'missing projected STS token for ' + expected);
    }
  });
}
