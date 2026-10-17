const reject = () => { throw new Error('environment class deployment rejected'); };
export function normalizeEnvironmentClass(value, profile, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'enabled,profileChecksum' || typeof value.enabled !== 'boolean' || typeof value.profileChecksum !== 'string') reject();
  if (value.enabled) {
    if (profile?.profile !== 'canonical61-temporal78-authorization79-80-worker-v1' || runtime?.enabled !== true || !/^[a-f0-9]{64}$/.test(value.profileChecksum)) reject();
  } else if (value.profileChecksum !== '') reject();
  return Object.freeze({...value});
}

// Consumers only; supplementary SQL installation and native admission remain
// explicit operator prerequisites. No worker gains this capability.
export function validateEnvironmentClassResources(resources, config) {
  const enabled = config?.enabled === true;
  const workloads = resources.filter(r => ['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
  const targets = workloads.filter(r => r.kind === 'Deployment' && r.metadata?.name === 'agentsec-api');
  if (enabled && targets.length !== 1) reject();
  for (const resource of workloads) {
    const pod = resource.kind === 'Pod' ? resource.spec : resource.kind === 'CronJob' ? resource.spec?.jobTemplate?.spec?.template?.spec : resource.spec?.template?.spec;
    const containers = [...(pod?.containers ?? []),...(pod?.initContainers ?? [])];
    if (enabled && targets.includes(resource) && pod?.containers?.length !== 1) reject();
    for (const [index,container] of containers.entries()) {
      // Inherited values cannot prove this reserved opt-in is absent. In legacy
      // mode constrain only the API consumer; selected mode closes every
      // workload so another pod cannot silently inherit the capability flags.
      if ((enabled || resource.metadata?.name === 'agentsec-api') && container.envFrom !== undefined) reject();
      const entries = container.env?.filter(e => e.name?.startsWith('ZASP_ENVIRONMENT_CLASS_')) ?? [];
      const expected = enabled && targets.includes(resource) && index === 0;
      if (!expected) { if (entries.length) reject(); continue; }
      if (entries.length !== 2 || container.envFrom !== undefined) reject();
      for (const [name,value] of [['ZASP_ENVIRONMENT_CLASS_ENABLED','true'],['ZASP_ENVIRONMENT_CLASS_PROFILE_CHECKSUM',config.profileChecksum]]) {
        const rows = entries.filter(e=>e.name===name);
        if (rows.length!==1 || rows[0].value!==value || rows[0].valueFrom!==undefined) reject();
      }
    }
  }
}
