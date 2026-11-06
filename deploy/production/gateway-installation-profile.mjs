const reject = () => { throw new Error('gateway installation deployment rejected'); };
export function normalizeGatewayInstallation(value, profile, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'enabled,profileChecksum' || typeof value.enabled !== 'boolean' || typeof value.profileChecksum !== 'string') reject();
  if (value.enabled ? profile?.profile !== 'canonical61-temporal78-authorization79-80-worker-v1' || runtime?.enabled !== true || !/^[a-f0-9]{64}$/.test(value.profileChecksum) : value.profileChecksum !== '') reject();
  return Object.freeze({...value});
}
export function normalizeGatewayInstallationProducer(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join(',') !== 'enabled' || typeof value.enabled !== 'boolean') reject();
  return Object.freeze({...value});
}
// These flags select an already-installed application profile. No credentials,
// grants, cache storage or original policy/decision readiness are changed.
function validateResources(resources, selected, producer, checksum) {
  const targetName = producer ? 'runtime-gateway' : 'agentsec-gateway-control';
  const containerName = producer ? 'runtime-gateway' : 'gateway-control';
  const workloads = resources.filter(r => ['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
  const targets = workloads.filter(r => r.kind === 'Deployment' && r.metadata?.name === targetName);
  if (selected && targets.length !== 1) reject();
  for (const resource of workloads) {
    const pod = resource.kind === 'Pod' ? resource.spec : resource.kind === 'CronJob' ? resource.spec?.jobTemplate?.spec?.template?.spec : resource.spec?.template?.spec;
    if (selected && targets.includes(resource) && (pod?.containers?.length !== 1 || pod.containers[0].name !== containerName)) reject();
    for (const [index,container] of [...(pod?.containers ?? []),...(pod?.initContainers ?? [])].entries()) {
      // Selected flags must never be hidden by bulk environment imports. The
      // actual consumer is guarded even when the release selects default off.
      if ((selected || resource.metadata?.name === targetName) && container.envFrom !== undefined) reject();
      const entries = (container.env ?? []).filter(e => e.name?.startsWith('ZASP_GATEWAY_INSTALLATION_'));
      const expected = selected && targets.includes(resource) && index === 0;
      if (!expected) { if (entries.length) reject(); continue; }
      const names = producer ? ['ZASP_GATEWAY_INSTALLATION_ACK_ENABLED'] : ['ZASP_GATEWAY_INSTALLATION_ACK_ENABLED','ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM'];
      if (entries.length !== names.length || new Set(entries.map(e=>e.name)).size !== names.length || entries.some(e=>e.valueFrom !== undefined || !names.includes(e.name)) || entries.find(e=>e.name===names[0])?.value !== 'true' || !producer && entries.find(e=>e.name===names[1])?.value !== checksum) reject();
    }
  }
}
export function validateGatewayInstallationResources(resources, config) {
  validateResources(resources, config?.enabled === true, false, config?.profileChecksum);
}
export function validateGatewayInstallationProducerResources(resources, configuration) {
  const config = normalizeGatewayInstallationProducer(configuration);
  validateResources(resources, config?.enabled === true, true);
}
