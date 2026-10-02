import { normalizeAuthorizationTemporalProfile } from './authorization-temporal-profile.mjs';

const consumers = ['agentsec-api', 'agentsec-discovery-scheduler', 'agentsec-discovery-worker', 'agentsec-red-team-adapter', 'agentsec-red-team-worker', 'agentsec-security-agent', 'zasp-authorization-projector'];
const fail = () => { throw new Error('authorization temporal resources rejected'); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function validateAuthorizationTemporalResources(resources, profile, accountID) {
  if (!profile) return;
  const one = (kind, name) => { const rows = resources.filter(r => r.kind === kind && r.metadata?.name === name); if (rows.length !== 1) fail(); return rows[0]; };
  const pod = r => r.kind === 'CronJob' ? r.spec?.jobTemplate?.spec?.template?.spec : r.spec?.template?.spec;
  const container = r => { const p = pod(r); if (p?.containers?.length !== 1 || p.containers[0].envFrom !== undefined) fail(); return p.containers[0]; };
  const entry = (r, name) => { const rows = container(r).env?.filter(e => e.name === name); if (rows?.length !== 1) fail(); return rows[0]; };
  const expect = (r, name, value) => { const e = entry(r, name); if (e.value !== value || e.valueFrom !== undefined) fail(); };
  const secret = (r, name, source) => { const e = entry(r, name); if (e.value !== undefined || !same(e.valueFrom, {secretKeyRef:{name:source,key:'postgres-dsn'}})) fail(); };
  const api = one('Deployment', 'agentsec-api');
  const fields = {timeout:'TIMEOUT',temporalAddress:'TEMPORAL_ADDRESS',namespace:'TEMPORAL_NAMESPACE',taskQueue:'TEMPORAL_TASK_QUEUE',discoveryTaskQueue:'TEMPORAL_DISCOVERY_TASK_QUEUE',openfgaURL:'OPENFGA_URL',storeID:'OPENFGA_STORE_ID',modelID:'OPENFGA_MODEL_ID'};
  const key = field => field === 'TIMEOUT' ? 'ZASP_RUNTIME_SERVICES_TIMEOUT' : `ZASP_${field}`;
  const runtime = {enabled:true, ...Object.fromEntries(Object.entries(fields).map(([field,suffix]) => [field,entry(api,key(suffix)).value])), clientSecret: pod(api).volumes?.find(v=>v.name==='runtime-services')?.secret?.secretName};
  normalizeAuthorizationTemporalProfile(profile, {schemaVersion:61,runtimeServices:runtime}, accountID);
  expect(one('Deployment', 'agentsec-event-ingest'), 'ZASP_RUNTIME_DATABASE_PROFILE', 'canonical61-temporal78-authorization79-80-runtime-v1');
  for (const suffix of ['outbox', 'coordinator', 'archive', 'index', 'correlation', 'projection', 'complete', 'session-index-v2']) {
    const worker = one('Deployment', `agentsec-runtime-${suffix}`);
    expect(worker, 'ZASP_RUNTIME_DATABASE_PROFILE', 'canonical61-temporal78-authorization79-80-runtime-v1');
    // These workers consume registered SQL authorities, not FGA or Temporal.
    if (container(worker).env.some(e => /^ZASP_(RUNTIME_SERVICES_|TEMPORAL_|OPENFGA_)/.test(e.name)) || pod(worker).volumes?.some(v => v.name === 'runtime-services' || v.secret?.secretName === runtime.clientSecret)) fail();
  }
  for (const name of consumers) {
    const r = one(name === 'zasp-authorization-projector' ? 'CronJob' : 'Deployment', name);
    expect(r, 'ZASP_RUNTIME_SERVICES_ENABLED', 'true');
    for (const suffix of Object.values(fields)) expect(r,key(suffix),entry(api,key(suffix)).value);
    const volume=pod(r).volumes?.find(v=>v.name==='runtime-services'), mount=container(r).volumeMounts?.find(v=>v.name==='runtime-services');
    if (volume?.secret?.secretName !== runtime.clientSecret || mount?.mountPath !== '/var/run/secrets/runtime-services' || mount.readOnly !== true) fail();
  }
  const worker=one('Deployment','agentsec-security-agent'), adapter=one('Deployment','agentsec-red-team-adapter'), migration=one('Job','agentsec-schema-v61');
  expect(worker,'ZASP_GATEWAY_POLICY_KEYS_FILE','/var/run/zasp-policy-verifier/policy-keys.json');
  const verifier=pod(worker).initContainers?.filter(c=>c.name==='materialize-policy-verifier');
  if (verifier?.length !== 1 || verifier[0].image !== container(worker).image || !same(verifier[0].command,['/bin/sh','-ec']) || !same(verifier[0].args,['umask 077; cp /public-keys/policy-keys.json /keys/policy-keys.json; chmod 0400 /keys/policy-keys.json']) || verifier[0].securityContext?.runAsUser !== 65532 || verifier[0].securityContext?.runAsGroup !== 65532 || verifier[0].securityContext?.runAsNonRoot !== true || verifier[0].securityContext?.allowPrivilegeEscalation !== false || verifier[0].securityContext?.readOnlyRootFilesystem !== true || !same(verifier[0].securityContext?.capabilities,{drop:['ALL']})) fail();
  if (!same(verifier[0].volumeMounts,[{name:'policy-verifier-source',mountPath:'/public-keys',readOnly:true},{name:'policy-verifier',mountPath:'/keys'}])) fail();
  if (!same(pod(worker).volumes?.find(v=>v.name==='policy-verifier-source')?.configMap,{name:profile.gatewayPolicyKeysConfigMap,defaultMode:288,items:[{key:'policy-keys.json',path:'policy-keys.json'}]}) || !same(pod(worker).volumes?.find(v=>v.name==='policy-verifier')?.emptyDir,{medium:'Memory',sizeLimit:'64Ki'})) fail();
  if (!same(container(worker).volumeMounts?.filter(v=>v.name==='policy-verifier'),[{name:'policy-verifier',mountPath:'/var/run/zasp-policy-verifier',readOnly:true}]) || container(worker).volumeMounts?.some(v=>v.name==='policy-verifier-source')) fail();
  const authorityPods = new Set([worker,adapter,migration]);
  const restrictedSecrets = [profile.executorDSNSecret,profile.compensationDSNSecret,profile.forwardKey.secretName,profile.compensationKey.secretName];
  for (const r of resources.filter(r=>['Deployment','Job','CronJob'].includes(r.kind))) {
    const p=pod(r);
    if (r !== worker && (p?.volumes?.some(v=>v.configMap?.name===profile.gatewayPolicyKeysConfigMap) || p?.containers?.some(c=>c.env?.some(e=>e.name==='ZASP_GATEWAY_POLICY_KEYS_FILE')))) fail();
    if (!authorityPods.has(r) && (p?.volumes?.some(v=>restrictedSecrets.includes(v.secret?.secretName)) || p?.containers?.some(c=>c.env?.some(e=>restrictedSecrets.includes(e.valueFrom?.secretKeyRef?.name) || /^ZASP_(AUTHORIZATION_(WORKER|COMPENSATION)_KEY_FILE|TEMPORAL_(EXECUTOR|COMPENSATION)_POSTGRES_DSN)$/.test(e.name))))) fail();
  }
  expect(worker,'ZASP_WORKER_MODE','security-agent');
  if (!same(container(worker).command,['/bin/sh','-ec']) || !same(container(worker).args,['export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-security-agent/postgres-dsn)"; exec /app/agentsec-worker'])) fail();
  expect(worker,'ZASP_RED_TEAM_ROLE_ARN',profile.workerRoleArn);
  if (!/@sha256:[0-9a-f]{64}$/.test(entry(worker,'ZASP_RED_TEAM_RUNNER_IMAGE').value) || entry(worker,'ZASP_RED_TEAM_RUNNER_IMAGE').value !== container(worker).image) fail();
  secret(worker,'ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN',profile.executorDSNSecret);
  secret(worker,'ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN',profile.compensationDSNSecret);
  secret(adapter,'ZASP_DATABASE_URL',profile.adapterDSNSecret);
  secret(adapter,'ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN',profile.compensationDSNSecret);
  if (container(adapter).env.some(e=>e.name==='ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN') || !same(container(adapter).args,['exec /app/red-team-adapter'])) fail();
  for (const [r,uid] of [[worker,65532],[adapter,1000],[migration,65532]]) {
    const p=pod(r), c=container(r), init=p.initContainers?.filter(c=>c.name==='materialize-worker-keys');
    if (p.initContainers?.length !== (r === migration ? 1 : r === worker ? 3 : 2)) fail();
    expect(r,'ZASP_AUTHORIZATION_WORKER_KEY_FILE','/var/run/zasp-authority/forward.seed');
    expect(r,'ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE','/var/run/zasp-authority/compensation.seed');
    const script='umask 077; cp /forward/seed /keys/forward.seed; cp /compensation/seed /keys/compensation.seed; chmod 0400 /keys/forward.seed /keys/compensation.seed';
    if (p.securityContext?.runAsUser !== uid || p.securityContext?.fsGroup !== uid || c.securityContext?.runAsUser !== uid || init?.length !== 1 || init[0].securityContext?.runAsUser !== uid || !same(init[0].command,['/bin/sh','-ec']) || !same(init[0].args,[script])) fail();
    if (init[0].securityContext.allowPrivilegeEscalation !== false || init[0].securityContext.runAsNonRoot !== true) fail();
    if (!same(p.volumes?.find(v=>v.name==='worker-keys')?.emptyDir,{medium:'Memory',sizeLimit:'64Ki'})) fail();
    for (const [name,source] of [['forward-key-source',profile.forwardKey.secretName],['compensation-key-source',profile.compensationKey.secretName]]) {
      const v=p.volumes?.find(v=>v.name===name);
      if (!same(v?.secret,{secretName:source,defaultMode:288,items:[{key:'seed',path:'seed'}]})) fail();
    }
    const mount=c.volumeMounts?.filter(v=>v.name==='worker-keys');
    if (mount?.length !== 1 || mount[0].readOnly !== true || mount[0].mountPath !== '/var/run/zasp-authority') fail();
  }
  expect(migration,'ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL',profile.executorPrincipal);
  expect(migration,'ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL',profile.compensationPrincipal);
  expect(migration,'ZASP_OUTBOX_WORKER_DB_PRINCIPAL',profile.projectorPrincipal);
  expect(migration,'ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL',profile.adapterPrincipal);
  const projector=one('CronJob','zasp-authorization-projector'), pc=container(projector);
  secret(projector,'ZASP_POSTGRES_DSN',profile.projectorDSNSecret);
  if (projector.spec.concurrencyPolicy !== 'Forbid' || projector.spec.jobTemplate.spec.backoffLimit !== 0 || projector.spec.jobTemplate.spec.activeDeadlineSeconds !== 150 || !same(pc.command,['/app/zasp-authorization-reconcile']) || !same(pc.args,['--mode','reconcile','--limit','20','--timeout','2m']) || pc.readinessProbe !== undefined || pc.livenessProbe !== undefined) fail();
  const network=one('NetworkPolicy','runtime-services-egress').spec;
  if (!same(network.podSelector,{matchExpressions:[{key:'app.kubernetes.io/name',operator:'In',values:consumers.filter(n=>n!=='agentsec-red-team-adapter')}]})) fail();
  if (network.egress?.length !== 2) fail();
  for (const [i,service,port] of [[0,'temporal',7233],[1,'openfga',8080]]) {
    if (!same(network.egress[i],{to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'zasp-runtime'}},podSelector:{matchLabels:{'app.kubernetes.io/name':service}}}],ports:[{protocol:'TCP',port}]})) fail();
  }
  const adapterNetwork=one('NetworkPolicy','authorization-adapter-fga-egress').spec;
  if (!same(adapterNetwork.podSelector,{matchLabels:{'app.kubernetes.io/name':'agentsec-red-team-adapter'}}) || !same(adapterNetwork.egress,[network.egress[1]])) fail();
}
