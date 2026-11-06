const reject = () => { throw new Error('sensor node coverage deployment rejected'); };
export function normalizeSensorNodeCoverage(value, profile, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'enabled,profileChecksum' || typeof value.enabled !== 'boolean' || typeof value.profileChecksum !== 'string') reject();
  if (!value.enabled && value.profileChecksum !== '') reject();
  if (value.enabled && (profile?.profile !== 'canonical61-temporal78-authorization79-80-worker-v1' || runtime?.enabled !== true || !/^[a-f0-9]{64}$/.test(value.profileChecksum))) reject();
  return Object.freeze({...value});
}

// Exact API reader and event-ingest writer consumers; installation is separate.
export function validateSensorNodeCoverageResources(resources, config) {
  const selected = Boolean(config?.enabled);
  const workloads = resources.filter(r => ['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
  const targets = workloads.filter(r => r.kind === 'Deployment' && ['agentsec-api','agentsec-event-ingest'].includes(r.metadata?.name));
  if (selected && (targets.length !== 2 || new Set(targets.map(r=>r.metadata?.name)).size !== 2)) reject();
  for (const resource of workloads) {
    const pod = resource.kind === 'Pod' ? resource.spec : resource.kind === 'CronJob' ? resource.spec?.jobTemplate?.spec?.template?.spec : resource.spec?.template?.spec;
    const containers = [...(pod?.containers ?? []),...(pod?.initContainers ?? [])];
    if (selected && targets.includes(resource) && pod?.containers?.length !== 1) reject();
    for (const [index,container] of containers.entries()) {
      if ((selected || ['agentsec-api','agentsec-event-ingest'].includes(resource.metadata?.name)) && container.envFrom !== undefined) reject();
      const entries = container.env?.filter(e => e.name?.startsWith('ZASP_SENSOR_NODE_COVERAGE_')) ?? [];
      const expected = selected && targets.includes(resource) && index === 0;
      if (expected && container.name !== (resource.metadata?.name === 'agentsec-api' ? 'agentsec-api' : 'event-ingest')) reject();
      if (!expected) { if (entries.length) reject(); continue; }
      if (entries.length !== 2 || entries.some(e=>e.valueFrom !== undefined) || entries.find(e=>e.name==='ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED')?.value !== 'true' || entries.find(e=>e.name==='ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM')?.value !== config.profileChecksum) reject();
    }
  }
}

const sensorIDPattern=/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function normalizeSensorNodeCoverageProducer(value){
 if(value===undefined)return undefined;
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='enabled,sensorID'||typeof value.enabled!=='boolean'||typeof value.sensorID!=='string'||(value.enabled?!sensorIDPattern.test(value.sensorID):value.sensorID!==''))reject();
 return Object.freeze({...value});
}
// This ID is an enrollment constraint, never authentication or a SQL checksum.
export function validateSensorNodeCoverageProducerResources(resources,configuration){
 const config=normalizeSensorNodeCoverageProducer(configuration),selected=config?.enabled===true;
 const workloads=resources.filter(r=>['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
 const targets=workloads.filter(r=>r.kind==='DaemonSet'&&r.metadata?.name==='sensor-agent');
 if(selected&&targets.length!==1)reject();
 for(const resource of workloads){
  const pod=resource.kind==='Pod'?resource.spec:resource.kind==='CronJob'?resource.spec?.jobTemplate?.spec?.template?.spec:resource.spec?.template?.spec;
  const consumers=(pod?.containers??[]).filter(c=>c.name==='sensor-agent');
  if(selected&&targets.includes(resource)&&consumers.length!==1)reject();
  for(const [index,container]of [...(pod?.containers??[]),...(pod?.initContainers??[])].entries()){
   if(container.envFrom!==undefined)reject();
   const entries=(container.env??[]).filter(e=>e.name?.startsWith('ZASP_SENSOR_NODE_COVERAGE_')||e.name==='ZASP_SENSOR_ID');
   const expected=selected&&targets.includes(resource)&&index<(pod?.containers?.length??0)&&container.name==='sensor-agent';
   if(!expected){if(entries.length)reject();continue;}
   if(entries.length!==2||entries.some(e=>e.valueFrom!==undefined)||entries.find(e=>e.name==='ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED')?.value!=='true'||entries.find(e=>e.name==='ZASP_SENSOR_ID')?.value!==config.sensorID)reject();
  }
 }
}
