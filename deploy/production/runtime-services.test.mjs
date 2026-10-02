import test from 'node:test';
import assert from 'node:assert/strict';
import { renderRelease } from './release-contract.mjs';
import { productionReleaseFixture } from './release-fixture.mjs';

test('release entrypoint connects API and scheduler credentials to enabled runtime services', async () => {
  const runtimeServices = { enabled: true, timeout: '5s', temporalAddress: 'temporal-frontend.zasp-runtime.svc.cluster.local:7233', namespace: 'zasp-staging', taskQueue: 'zasp-security-agent', discoveryTaskQueue: 'zasp-discovery', openfgaURL: 'https://openfga.zasp-runtime.svc.cluster.local:8080', storeID: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelID: '01ARZ3NDEKTSV4RRFFQ69G5FAW', clientSecret: 'zasp-runtime-services-client' };
  const resources = await renderRelease(productionReleaseFixture, { schemaVersion: 49, runtimeServices });
  for (const name of ['agentsec-api', 'agentsec-discovery-scheduler']) {
    const pod = resources.find(r => r.kind === 'Deployment' && r.metadata.name === name).spec.template.spec;
    const env = Object.fromEntries(pod.containers[0].env.map(e => [e.name,e.value]));
    assert.equal(env.ZASP_RUNTIME_SERVICES_ENABLED, 'true');
    assert.equal(env.ZASP_OPENFGA_MODEL_ID, '01ARZ3NDEKTSV4RRFFQ69G5FAW');
    assert.equal(env.ZASP_ENVIRONMENT, 'production');
    assert.equal(pod.volumes.find(v => v.name === 'runtime-services').secret.secretName, 'zasp-runtime-services-client');
    assert.equal(pod.containers[0].volumeMounts.find(v => v.name === 'runtime-services').readOnly, true);
  }
});
