const reject = () => { throw new Error('optional egress deployment rejected'); };
const dns = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const prefix = 'ZASP_OPTIONAL_EGRESS_';

// References only: the runtime validates the selected compiled normal/audit
// recipe and registered purposes. Deployment never installs or approves it.
export function normalizeOptionalEgress(value, profile, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'enabled,profileChecksum,settlementDSNSecret' || typeof value.enabled !== 'boolean' || typeof value.profileChecksum !== 'string' || typeof value.settlementDSNSecret !== 'string') reject();
  if (!value.enabled) {
    if (value.profileChecksum !== '' || value.settlementDSNSecret !== '') reject();
  } else {
    if (profile?.profile !== 'canonical61-temporal78-authorization79-80-worker-v1' || runtime?.enabled !== true || !/^[a-f0-9]{64}$/.test(value.profileChecksum) || !dns.test(value.settlementDSNSecret)) reject();
    const refs = ['zasp-runtime-secrets',profile.executorDSNSecret,profile.compensationDSNSecret,profile.projectorDSNSecret,profile.adapterDSNSecret,runtime.clientSecret,...Object.values(profile.maintenance ?? {}).filter(v=>typeof v==='string')];
    if (refs.includes(value.settlementDSNSecret)) reject();
  }
  return Object.freeze({...value});
}

export function validateOptionalEgressResources(resources, config, plannerCIDRs) {
  const enabled = config?.enabled === true;
  const workloads = resources.filter(r=>['Deployment','Job','CronJob'].includes(r.kind));
  const pod = r=>r.kind==='CronJob'?r.spec?.jobTemplate?.spec?.template?.spec:r.spec?.template?.spec;
  const targets = ['agentsec-api','agentsec-security-agent'];
  if (enabled) for (const name of targets) {
    const rows=workloads.filter(r=>r.kind==='Deployment'&&r.metadata?.name===name);
    if (rows.length!==1 || pod(rows[0])?.containers?.length!==1) reject();
  }
  for (const resource of workloads) {
    const p=pod(resource), target=enabled&&resource.kind==='Deployment'&&targets.includes(resource.metadata?.name);
    for (const [index,c] of [...(p?.containers??[]),...(p?.initContainers??[])].entries()) {
      const expected=target&&index===0;
      const entries=c.env?.filter(e=>e.name?.startsWith(prefix))??[];
      if (!expected) { if(entries.length) reject(); }
      else {
        const api=resource.metadata.name==='agentsec-api';
        if(entries.length!==(api?3:2) || c.envFrom!==undefined) reject();
        for (const [name,value] of [['ZASP_OPTIONAL_EGRESS_ENABLED','true'],['ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM',config.profileChecksum]]) {
          const rows=entries.filter(e=>e.name===name);
          if(rows.length!==1 || rows[0].value!==value || rows[0].valueFrom!==undefined) reject();
        }
        if(api) {
          const rows=entries.filter(e=>e.name==='ZASP_OPTIONAL_EGRESS_SETTLEMENT_POSTGRES_DSN');
          if(rows.length!==1 || rows[0].value!==undefined || !same(rows[0].valueFrom,{secretKeyRef:{name:config.settlementDSNSecret,key:'postgres-dsn'}})) reject();
        }
      }
      if(enabled && !(target&&index===0&&resource.metadata.name==='agentsec-api') && (c.env?.some(e=>e.valueFrom?.secretKeyRef?.name===config.settlementDSNSecret) || c.envFrom?.some(e=>e.secretRef?.name===config.settlementDSNSecret))) reject();
    }
    if(enabled&&p?.volumes?.some(v=>v.secret?.secretName===config.settlementDSNSecret || v.projected?.sources?.some(s=>s.secret?.name===config.settlementDSNSecret))) reject();
  }
  const policies=resources.filter(r=>r.kind==='NetworkPolicy'&&r.metadata?.name==='api-optional-openrouter-egress');
  if(!enabled) {if(policies.length)reject();return;}
  if(!Array.isArray(plannerCIDRs)||plannerCIDRs.length===0||new Set(plannerCIDRs).size!==plannerCIDRs.length||policies.length!==1)reject();
  const expected={podSelector:{matchLabels:{'app.kubernetes.io/name':'agentsec-api'}},policyTypes:['Egress'],egress:plannerCIDRs.map(cidr=>({to:[{ipBlock:{cidr}}],ports:[{protocol:'TCP',port:443}]}))};
  if(!same(policies[0].spec,expected))reject();
}
