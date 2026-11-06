import test from 'node:test';
import assert from 'node:assert/strict';
import { renderRelease, validateRenderedRelease } from './release-contract.mjs';
import { normalizeAuthorizationTemporalProfile } from './authorization-temporal-profile.mjs';
import { productionReleaseFixture as release } from './release-fixture.mjs';
const config = () => ({
  schemaVersion: 61,
  authorizationTemporal: {
    profile: 'canonical61-temporal78-authorization79-80-worker-v1',
    executorPrincipal: 'temporal_executor_login', compensationPrincipal: 'temporal_compensation_login',
    projectorPrincipal: 'outbox_login', adapterPrincipal: 'red_team_adapter_login',
    executorDSNSecret: 'zasp-temporal-executor', compensationDSNSecret: 'zasp-temporal-compensation',
    projectorDSNSecret: 'zasp-authorization-projector', adapterDSNSecret: 'zasp-authorization-adapter',
    forwardKey: { purpose: 'worker-forward', secretName: 'zasp-worker-forward-key', key: 'seed' },
    compensationKey: { purpose: 'captured-compensation', secretName: 'zasp-worker-compensation-key', key: 'seed' },
    pricingBindingsConfigMap: 'zasp-temporal-pricing',
    gatewayPolicyKeysConfigMap: 'zasp-gateway-policy-verifiers',
    workerRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-temporal-worker',
    projectorRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-authorization-projector',
    adapterRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-red-team-adapter',
  },
  runtimeServices: { enabled: true, timeout: '5s', temporalAddress: 'temporal-frontend.zasp-runtime.svc.cluster.local:7233', namespace: 'zasp-staging', taskQueue: 'zasp-security-agent', discoveryTaskQueue: 'zasp-discovery', openfgaURL: 'https://openfga.zasp-runtime.svc.cluster.local:8080', storeID: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelID: '01ARZ3NDEKTSV4RRFFQ69G5FAW', clientSecret: 'zasp-runtime-services-client' },
});

const maintenance = () => ({
  profile: 'registered-dual-maintenance-runtime-v1',
  connectorProfileChecksum: '1'.repeat(64), approvalProfileChecksum: '2'.repeat(64), activationProfileChecksum: '3'.repeat(64),
  connectorDSNSecret: 'zasp-connector-maintenance-dsn', approvalDSNSecret: 'zasp-approval-maintenance-dsn',
  connectorKeySecret: 'zasp-connector-maintenance-seed', approvalKeySecret: 'zasp-approval-maintenance-seed',
});
const options = () => { const o=config();o.authorizationTemporal.maintenance=maintenance();return o; };
const pod = r => r.kind==='CronJob'?r.spec.jobTemplate.spec.template.spec:r.spec.template.spec;
const one = (r,k,n) => {const rows=r.filter(x=>x.kind===k&&x.metadata.name===n);assert.equal(rows.length,1);return rows[0];};
const env = r => Object.fromEntries(pod(r).containers[0].env.map(e=>[e.name,e.value??e.valueFrom]));
const validate = (r,o) => validateRenderedRelease(r,'123456789012',61,'precision-intake',undefined,undefined,undefined,undefined,undefined,'active',o.authorizationTemporal);

test('maintenance runtime admits a closed optional bundle and rejects partial, aliased and secret-value authority',()=>{
 const o=options();assert.equal(normalizeAuthorizationTemporalProfile(o.authorizationTemporal,o,'123456789012').maintenance.profile,maintenance().profile);
 for(const edit of [m=>delete m.connectorProfileChecksum,m=>m.connectorProfileChecksum='A'.repeat(64),m=>m.approvalDSNSecret=m.connectorDSNSecret,m=>m.connectorKeySecret=m.approvalKeySecret,m=>m.connectorDSNSecret=o.authorizationTemporal.executorDSNSecret,m=>m.activate=true,m=>m.profile='activate-production',m=>m.connectorKeySecret='raw secret bytes']){
   const x=options();edit(x.authorizationTemporal.maintenance);assert.throws(()=>normalizeAuthorizationTemporalProfile(x.authorizationTemporal,x,'123456789012'),/rejected/);
 }
});

test('maintenance runtime renders API authority plus the same three pins on executor and projector without activating',async()=>{
 const o=options(),rows=await renderRelease(release,o),m=maintenance();
 const api=one(rows,'Deployment','agentsec-api'),worker=one(rows,'Deployment','agentsec-security-agent'),projector=one(rows,'CronJob','zasp-authorization-projector');
 for(const r of [api,worker,projector]){
  assert.equal(env(r).ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM,m.connectorProfileChecksum);
  assert.equal(env(r).ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM,m.approvalProfileChecksum);
  assert.equal(env(r).ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM,m.activationProfileChecksum);
 }
 assert.deepEqual(env(api).ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN,{secretKeyRef:{name:m.connectorDSNSecret,key:'postgres-dsn'}});
 assert.deepEqual(env(api).ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN,{secretKeyRef:{name:m.approvalDSNSecret,key:'postgres-dsn'}});
 assert.equal(env(api).ZASP_CONNECTOR_MAINTENANCE_KEY_FILE,'/var/run/zasp-maintenance/connector.seed');
 assert.equal(env(api).ZASP_APPROVAL_MAINTENANCE_KEY_FILE,'/var/run/zasp-maintenance/approval.seed');
 const init=pod(api).initContainers.find(c=>c.name==='materialize-maintenance-keys');assert.equal(init.securityContext.runAsUser,65532);assert.match(init.args[0],/chmod 0400/);
 assert.equal(pod(api).containers[0].volumeMounts.find(v=>v.name==='maintenance-keys').readOnly,true);
 for(const r of [worker,projector])assert.equal(env(r).ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN,undefined);
 for(const r of rows.filter(r=>['Deployment','CronJob','Job'].includes(r.kind)))assert.doesNotMatch(JSON.stringify(pod(r).containers),/controlled-maintenance-cutover|maintenance-register|activate_controlled_organization/);
 assert.doesNotThrow(()=>validate(rows,o));
 for(const mutate of [r=>pod(one(r,'CronJob','zasp-authorization-projector')).containers[0].env.find(e=>e.name==='ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM').value='4'.repeat(64),r=>pod(one(r,'Deployment','agentsec-api')).initContainers[0].args=['chmod 0440 /keys/*'],r=>pod(one(r,'Deployment','web')).volumes=[{name:'leak',secret:{secretName:m.connectorKeySecret}}]]){const changed=structuredClone(rows);mutate(changed);assert.throws(()=>validate(changed,o),/rejected/);}
});

// These permission mutations exercise the rendered-resource validator directly;
// they need no Helm executable and do not stand in for actual chart rendering.
test('maintenance permissions reject indirect secret references and secondary-container authority', async t=>{
 const {validateMaintenanceRuntimeResources}=await import('./maintenance-runtime-profile.mjs');
 const m=maintenance(),profile=options().authorizationTemporal;
 const base=()=>[{kind:'Deployment',metadata:{name:'web'},spec:{template:{spec:{containers:[{name:'web',env:[]}],volumes:[]}}}}];
 const cases={
  projected_seed:p=>p.volumes.push({name:'leak',projected:{sources:[{secret:{name:m.connectorKeySecret}}]}}),
  projected_dsn:p=>p.volumes.push({name:'leak',projected:{sources:[{secret:{name:m.approvalDSNSecret}}]}}),
  envfrom_seed:p=>p.containers[0].envFrom=[{secretRef:{name:m.connectorKeySecret}}],
  init_envfrom_dsn:p=>p.initContainers=[{name:'leak',envFrom:[{secretRef:{name:m.connectorDSNSecret}}]}],
  secondary_pin:p=>p.containers.push({name:'leak',env:[{name:'ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM',value:m.activationProfileChecksum}]}),
  secondary_dsn:p=>p.containers.push({name:'leak',env:[{name:'ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN',value:'raw'}]}),
  init_authority:p=>p.initContainers=[{name:'leak',env:[{name:'ZASP_CONNECTOR_MAINTENANCE_KEY_FILE',value:'/keys/seed'}]}],
  ephemeral_seed:p=>p.ephemeralContainers=[{name:'leak',env:[{name:'SEED',valueFrom:{secretKeyRef:{name:m.connectorKeySecret,key:'seed'}}}]}],
 };
 for(const [name,mutate]of Object.entries(cases))await t.test(name,()=>{const rows=base();mutate(pod(rows[0]));assert.throws(()=>validateMaintenanceRuntimeResources(rows,profile),/rejected/);});
});

test('maintenance private copies and raw seeds stay exclusive to the API and exact materializer',async t=>{
 const {validateMaintenanceRuntimeResources}=await import('./maintenance-runtime-profile.mjs');
 const m=maintenance(),profile=options().authorizationTemporal;
 const base=()=>[{kind:'Deployment',metadata:{name:'agentsec-api'},spec:{template:{spec:{
  containers:[{name:'api',image:'reviewed-api',env:[
   {name:'ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM',value:m.connectorProfileChecksum},
   {name:'ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM',value:m.approvalProfileChecksum},
   {name:'ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM',value:m.activationProfileChecksum},
   {name:'ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:m.connectorDSNSecret,key:'postgres-dsn'}}},
   {name:'ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:m.approvalDSNSecret,key:'postgres-dsn'}}},
   {name:'ZASP_CONNECTOR_MAINTENANCE_KEY_FILE',value:'/var/run/zasp-maintenance/connector.seed'},
   {name:'ZASP_APPROVAL_MAINTENANCE_KEY_FILE',value:'/var/run/zasp-maintenance/approval.seed'},
  ],volumeMounts:[{name:'maintenance-keys',mountPath:'/var/run/zasp-maintenance',readOnly:true}]}],
  initContainers:[{name:'materialize-maintenance-keys',image:'reviewed-api',command:['/bin/sh','-ec'],args:['umask 077; cp /connector/seed /keys/connector.seed; cp /approval/seed /keys/approval.seed; chmod 0400 /keys/connector.seed /keys/approval.seed'],securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},volumeMounts:[{name:'connector-maintenance-source',mountPath:'/connector',readOnly:true},{name:'approval-maintenance-source',mountPath:'/approval',readOnly:true},{name:'maintenance-keys',mountPath:'/keys'}]}],
  volumes:[{name:'maintenance-keys',emptyDir:{medium:'Memory',sizeLimit:'64Ki'}},{name:'connector-maintenance-source',secret:{secretName:m.connectorKeySecret,defaultMode:288,items:[{key:'seed',path:'seed'}]}},{name:'approval-maintenance-source',secret:{secretName:m.approvalKeySecret,defaultMode:288,items:[{key:'seed',path:'seed'}]}}],
 }}}}];
 assert.doesNotThrow(()=>validateMaintenanceRuntimeResources(base(),profile));
 const cases={
  extra_init_raw:p=>p.initContainers.push({name:'other-init',volumeMounts:[{name:'connector-maintenance-source',mountPath:'/leak'}]}),
  extra_init_copy:p=>p.initContainers.push({name:'other-init',volumeMounts:[{name:'maintenance-keys',mountPath:'/leak'}]}),
  sidecar_copy:p=>p.containers.push({name:'sidecar',volumeMounts:[{name:'maintenance-keys',mountPath:'/leak'}]}),
  debug_copy:p=>p.ephemeralContainers=[{name:'debug',volumeMounts:[{name:'maintenance-keys',mountPath:'/leak'}]}],
  extra_init_envfrom:p=>p.initContainers.push({name:'other-init',envFrom:[{secretRef:{name:m.connectorKeySecret}}]}),
  api_envfrom:p=>p.containers[0].envFrom=[{secretRef:{name:m.approvalDSNSecret}}],
  alias_seed_volume:p=>p.volumes.push({name:'alias',secret:{secretName:m.connectorKeySecret}}),
  api_projected_seed:p=>p.volumes.push({name:'alias',projected:{sources:[{secret:{name:m.approvalKeySecret}}]}}),
 };
 for(const [name,mutate]of Object.entries(cases))await t.test(name,()=>{const rows=base();mutate(pod(rows[0]));assert.throws(()=>validateMaintenanceRuntimeResources(rows,profile),/rejected/);});
});
