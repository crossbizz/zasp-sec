// Runtime wiring only. This profile never installs authority, activates an
// organization, withdraws credentials, or asserts that fleet cutover is safe.
const fields = ['profile','connectorProfileChecksum','approvalProfileChecksum','activationProfileChecksum','connectorDSNSecret','approvalDSNSecret','connectorKeySecret','approvalKeySecret'];
const references = ['connectorDSNSecret','approvalDSNSecret','connectorKeySecret','approvalKeySecret'];
const reject = () => { throw new Error('maintenance runtime profile rejected'); };
export function normalizeMaintenanceRuntime(value, parent, runtime) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length || fields.some(k=>!Object.hasOwn(value,k)) || value.profile !== 'registered-dual-maintenance-runtime-v1') reject();
  for (const k of ['connectorProfileChecksum','approvalProfileChecksum','activationProfileChecksum']) if (typeof value[k] !== 'string' || !/^[0-9a-f]{64}$/.test(value[k])) reject();
  if (references.some(k=>typeof value[k] !== 'string' || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(value[k]))) reject();
  const all=[...references.map(k=>value[k]),parent.executorDSNSecret,parent.compensationDSNSecret,parent.projectorDSNSecret,parent.adapterDSNSecret,parent.forwardKey.secretName,parent.compensationKey.secretName,parent.pricingBindingsConfigMap,parent.gatewayPolicyKeysConfigMap,runtime.clientSecret];
  if (new Set(all).size !== all.length) reject();
  return Object.freeze({...value});
}

export function validateMaintenanceRuntimeResources(resources, profile) {
  const m=profile.maintenance;
  const fail=()=>{throw new Error('maintenance runtime resources rejected');};
  const pod=r=>r.kind==='CronJob'?r.spec?.jobTemplate?.spec?.template?.spec:r.spec?.template?.spec;
  const targets=new Set(['agentsec-api','agentsec-security-agent','zasp-authorization-projector']);
  const pins={ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM:m?.connectorProfileChecksum,ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM:m?.approvalProfileChecksum,ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM:m?.activationProfileChecksum};
  const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  for(const r of resources.filter(r=>['Deployment','CronJob','Job'].includes(r.kind))){
    const p=pod(r),c=p?.containers?.[0],active=m&&targets.has(r.metadata.name),api=active&&r.metadata.name==='agentsec-api';
    const env=c?.env??[];
    const expect=(name,value)=>{const entries=env.filter(e=>e.name===name);if(entries.length!==1||!same(entries[0],{name,...value}))fail();};
    for(const [name,value] of Object.entries(pins)){if(active)expect(name,{value});else if(env.some(e=>e.name===name))fail();}
    const authority=/^ZASP_(CONNECTOR_MAINTENANCE|APPROVAL_MAINTENANCE)_(POSTGRES_DSN|KEY_FILE)$/;
    if(!api && env.some(e=>authority.test(e.name)))fail();
    const refs=m?[m.connectorDSNSecret,m.approvalDSNSecret,m.connectorKeySecret,m.approvalKeySecret]:[];
    // Inspect every Kubernetes-native secret access path. Only the API's exact
    // key initializer may see raw seeds; only its main process sees private
    // copies and the two DSN env entries. Other containers get no maintenance
    // authority, including sidecars, debug containers and unrelated initializers.
    const sensitiveVolumes=new Set(['connector-maintenance-source','approval-maintenance-source','maintenance-keys']);
    for(const v of p?.volumes??[]){
      if(v.projected?.sources?.some(source=>refs.includes(source.secret?.name)))fail();
      if(refs.includes(v.secret?.secretName)){
        if(!api || !((v.name==='connector-maintenance-source'&&v.secret.secretName===m.connectorKeySecret)||(v.name==='approval-maintenance-source'&&v.secret.secretName===m.approvalKeySecret)))fail();
        sensitiveVolumes.add(v.name);
      }
      if(!api&&sensitiveVolumes.has(v.name))fail();
    }
    if(p?.imagePullSecrets?.some(ref=>refs.includes(ref.name)))fail();
    for(const actor of [...(p?.containers??[]),...(p?.initContainers??[]),...(p?.ephemeralContainers??[])]){
      const main=actor===c,materializer=api&&(p.initContainers??[]).includes(actor)&&actor.name==='materialize-maintenance-keys';
      for(const e of actor.env??[]){
        if(Object.hasOwn(pins,e.name)&&(!active||!main))fail();
        if(authority.test(e.name)&&(!api||!main))fail();
        const ref=e.valueFrom?.secretKeyRef?.name;
        if(refs.includes(ref)&&!(api&&main&&((e.name==='ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN'&&ref===m.connectorDSNSecret)||(e.name==='ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN'&&ref===m.approvalDSNSecret))))fail();
      }
      if(actor.envFrom?.some(source=>refs.includes(source.secretRef?.name)))fail();
      for(const mount of actor.volumeMounts??[]){
        if(!sensitiveVolumes.has(mount.name))continue;
        if(!(materializer||(api&&main&&mount.name==='maintenance-keys')))fail();
      }
      if(actor.volumeDevices?.some(device=>sensitiveVolumes.has(device.name)))fail();
    }
    if(!api)continue;
    for(const [family,secret] of [['CONNECTOR',m.connectorDSNSecret],['APPROVAL',m.approvalDSNSecret]])expect(`ZASP_${family}_MAINTENANCE_POSTGRES_DSN`,{valueFrom:{secretKeyRef:{name:secret,key:'postgres-dsn'}}});
    for(const family of ['connector','approval'])expect(`ZASP_${family.toUpperCase()}_MAINTENANCE_KEY_FILE`,{value:`/var/run/zasp-maintenance/${family}.seed`});
    const init=p.initContainers?.filter(c=>c.name==='materialize-maintenance-keys');
    if(init?.length!==1 || init[0].image!==c.image || !same(init[0].command,['/bin/sh','-ec']) || !same(init[0].args,['umask 077; cp /connector/seed /keys/connector.seed; cp /approval/seed /keys/approval.seed; chmod 0400 /keys/connector.seed /keys/approval.seed']))fail();
    const security={runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}};
    if(!same(init[0].securityContext,security)||!same(init[0].volumeMounts,[{name:'connector-maintenance-source',mountPath:'/connector',readOnly:true},{name:'approval-maintenance-source',mountPath:'/approval',readOnly:true},{name:'maintenance-keys',mountPath:'/keys'}]))fail();
    if(!same(p.volumes?.find(v=>v.name==='maintenance-keys')?.emptyDir,{medium:'Memory',sizeLimit:'64Ki'}))fail();
    for(const [name,secretName] of [['connector-maintenance-source',m.connectorKeySecret],['approval-maintenance-source',m.approvalKeySecret]])if(!same(p.volumes?.find(v=>v.name===name)?.secret,{secretName,defaultMode:288,items:[{key:'seed',path:'seed'}]}))fail();
    if(!same(c.volumeMounts?.filter(v=>v.name==='maintenance-keys'),[{name:'maintenance-keys',mountPath:'/var/run/zasp-maintenance',readOnly:true}])||c.volumeMounts?.some(v=>['connector-maintenance-source','approval-maintenance-source'].includes(v.name)))fail();
  }
}
