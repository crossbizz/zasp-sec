const reject = () => { throw new Error('agent read deployment rejected'); };
export function normalizeAgentRead(value, profile, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join(',') !== 'profileChecksum' || typeof value.profileChecksum !== 'string') reject();
  if (value.profileChecksum !== '' && (profile?.profile !== 'canonical61-temporal78-authorization79-80-worker-v1' || runtime?.enabled !== true || !/^[a-f0-9]{64}$/.test(value.profileChecksum))) reject();
  return Object.freeze({...value});
}

// Only the API consumes a previously installed profile. This never installs SQL
// or grants any worker the parent-agent read contract.
export function validateAgentReadResources(resources, config) {
  const selected = Boolean(config?.profileChecksum);
  const workloads = resources.filter(r => ['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
  const targets = workloads.filter(r => r.kind === 'Deployment' && r.metadata?.name === 'agentsec-api');
  if (selected && targets.length !== 1) reject();
  for (const resource of workloads) {
    const pod = resource.kind === 'Pod' ? resource.spec : resource.kind === 'CronJob' ? resource.spec?.jobTemplate?.spec?.template?.spec : resource.spec?.template?.spec;
    const containers = [...(pod?.containers ?? []),...(pod?.initContainers ?? [])];
    if (selected && targets.includes(resource) && pod?.containers?.length !== 1) reject();
    for (const [index,container] of containers.entries()) {
      if ((selected || resource.metadata?.name === 'agentsec-api') && container.envFrom !== undefined) reject();
      const entries = container.env?.filter(e => e.name?.startsWith('ZASP_AGENT_READ_')) ?? [];
      const expected = selected && targets.includes(resource) && index === 0;
      if (!expected) { if (entries.length) reject(); continue; }
      if (entries.length !== 1 || entries[0].name !== 'ZASP_AGENT_READ_PROFILE_CHECKSUM' || entries[0].value !== config.profileChecksum || entries[0].valueFrom !== undefined) reject();
    }
  }
}
