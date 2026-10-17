import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
const reject=()=>{throw new Error('retention deployment rejected');};
const pinPattern=/^[a-f0-9]{64}$/;
const queuePattern=/^[a-z][a-z0-9._-]{1,127}$/;
// Every production consumer whose reads, index writes or completion writes
// depend on the supplementary profile must move together. Projection keeps its
// original stage authority; expiry protection is enforced at its actual writer.
export const retentionConsumers=Object.freeze(['agentsec-api','agentsec-runtime-coordinator','agentsec-runtime-complete','agentsec-runtime-index','agentsec-runtime-session-index-v2','agentsec-retention-reference-expiry']);
export function normalizeRetention(value,profile,runtime){
 if(value===undefined)return undefined;
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='enabled,indexStageVersion,profileChecksum,sessionIndex,taskQueue'||typeof value.enabled!=='boolean'||typeof value.profileChecksum!=='string'||typeof value.taskQueue!=='string'||typeof value.indexStageVersion!=='string'||typeof value.sessionIndex!=='string')reject();
 if(value.enabled){
  if(profile?.profile!=='canonical61-temporal78-authorization79-80-worker-v1'||runtime?.enabled!==true||!pinPattern.test(value.profileChecksum)||!queuePattern.test(value.taskQueue)||[runtime.taskQueue,runtime.discoveryTaskQueue].includes(value.taskQueue)||value.indexStageVersion!=='runtime-index-v2'||value.sessionIndex!=='zasp-runtime-sessions-v2')reject();
 }else if(value.profileChecksum!==''||value.taskQueue!==''||value.indexStageVersion!==''||value.sessionIndex!=='')reject();
 return Object.freeze({...value});
}
export function validateRetentionResources(resources,config,profile){
 const enabled=config?.enabled===true;
 const workloads=resources.filter(r=>['Deployment','Job','CronJob','DaemonSet','StatefulSet'].includes(r.kind));
 const pod=r=>r.kind==='CronJob'?r.spec?.jobTemplate?.spec?.template?.spec:r.spec?.template?.spec;
 if(enabled)for(const name of retentionConsumers){
  const matches=workloads.filter(r=>r.kind==='Deployment'&&r.metadata?.name===name);
  if(matches.length!==1||pod(matches[0])?.containers?.length!==1)reject();
 }
 for(const r of workloads){
  const p=pod(r),target=enabled&&r.kind==='Deployment'&&retentionConsumers.includes(r.metadata?.name);
  for(const [i,c]of [...(p?.containers??[]),...(p?.initContainers??[])].entries()){
   const entries=c.env?.filter(e=>e.name?.startsWith('ZASP_RETENTION_'))??[];
   if(!target||i!==0){if(entries.length)reject();continue;}
   const sweep=r.metadata.name==='agentsec-retention-reference-expiry';
   if(c.envFrom!==undefined||entries.length!==(sweep?2:1))reject();
   const exact=(name,value)=>{const rows=c.env?.filter(e=>e.name===name);if(rows?.length!==1||rows[0].value!==value||rows[0].valueFrom!==undefined)reject();};
   exact('ZASP_RETENTION_PROFILE_CHECKSUM',config.profileChecksum);
   if(['agentsec-runtime-index','agentsec-runtime-session-index-v2'].includes(r.metadata.name)){exact('ZASP_RUNTIME_STAGE_VERSION',config.indexStageVersion);exact('ZASP_RUNTIME_SESSION_INDEX',config.sessionIndex);}
   if(sweep){
    exact('ZASP_RETENTION_TASK_QUEUE',config.taskQueue);exact('ZASP_WORKER_MODE','retention-reference-expiry');exact('ZASP_DATABASE_AUTHORITY','zasp_temporal_executor');exact('ZASP_BATCH_SIZE','1');
    const dsns=c.env?.filter(e=>e.name==='ZASP_POSTGRES_DSN');
    if(dsns?.length!==1||dsns[0].value!==undefined||JSON.stringify(dsns[0].valueFrom)!==JSON.stringify({secretKeyRef:{name:profile.executorDSNSecret,key:'postgres-dsn'}}))reject();
   }
  }
 }
 const networks=resources.filter(r=>r.kind==='NetworkPolicy'&&r.metadata?.name==='retention-reference-expiry-egress');
 if(!enabled){if(networks.length)reject();}else{
  const parents=resources.filter(r=>r.kind==='NetworkPolicy'&&r.metadata?.name==='security-agent-database');
  const parentTarget=parents[0]?.spec?.egress?.[0]?.to?.[0],cidr=parentTarget?.ipBlock?.cidr;
  const parts=typeof cidr==='string'?cidr.split('/'):[],version=isIP(parts[0]??''),bits=Number(parts[1]);
  if(parents.length!==1||parents[0].spec.egress.length!==1||parents[0].spec.egress[0].to.length!==1||JSON.stringify(parents[0].spec.egress[0].ports)!==JSON.stringify([{protocol:'TCP',port:5432}])||parts.length!==2||!version||!Number.isInteger(bits)||bits<1||bits>(version===4?32:128))reject();
  const expected={podSelector:{matchLabels:{'app.kubernetes.io/name':'agentsec-retention-reference-expiry'}},policyTypes:['Egress'],egress:[{to:[{ipBlock:{cidr}}],ports:[{protocol:'TCP',port:5432}]},...[["temporal",7233],["openfga",8080]].map(([name,port])=>({to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'zasp-runtime'}},podSelector:{matchLabels:{'app.kubernetes.io/name':name}}}],ports:[{protocol:'TCP',port}]}))]};
  if(networks.length!==1||JSON.stringify(networks[0].spec)!==JSON.stringify(expected))reject();
 }
 if(!enabled&&workloads.some(r=>r.metadata?.name==='agentsec-retention-reference-expiry'))reject();
}
// A source/release guard result is a component artifact, never proof that the
// observed fleet has rolled or old credentials have been withdrawn.
export function retentionConsumerManifest(config){
 if(config?.enabled!==true||!pinPattern.test(config.profileChecksum)||!queuePattern.test(config.taskQueue)||config.indexStageVersion!=='runtime-index-v2'||config.sessionIndex!=='zasp-runtime-sessions-v2')reject();
 const manifest={version:1,profileChecksum:config.profileChecksum,taskQueue:config.taskQueue,indexStageVersion:config.indexStageVersion,sessionIndex:config.sessionIndex,consumers:retentionConsumers};
 return Object.freeze({...manifest,digest:createHash('sha256').update(JSON.stringify(manifest)).digest('hex')});
}

export function validateRetentionExecutorCapability(resource,profile,config,runtimeSecret){
 if(config?.enabled!==true||resource.kind!=='Deployment'||resource.metadata?.name!=='agentsec-retention-reference-expiry')reject();
 const p=resource.spec?.template?.spec,c=p?.containers?.[0];
 if(p?.containers?.length!==1||p.serviceAccountName!=='zasp-retention-reference-expiry'||p.automountServiceAccountToken!==false||p.initContainers!==undefined||p.hostNetwork===true||p.hostPID===true||p.hostIPC===true||c.lifecycle!==undefined||c.envFrom!==undefined||JSON.stringify(c.command)!==JSON.stringify(['/app/agentsec-worker'])||c.args!==undefined)reject();
 const allowed=new Set(['ZASP_ENVIRONMENT','ZASP_WORKER_MODE','ZASP_DATABASE_AUTHORITY','ZASP_WORKER_ID','ZASP_POLL_INTERVAL','ZASP_LEASE_DURATION','ZASP_SHUTDOWN_TIMEOUT','ZASP_BATCH_SIZE','ZASP_RETENTION_TASK_QUEUE','ZASP_POSTGRES_DSN','ZASP_RETENTION_PROFILE_CHECKSUM','ZASP_RUNTIME_SERVICES_ENABLED','ZASP_RUNTIME_SERVICES_TIMEOUT','ZASP_TEMPORAL_ADDRESS','ZASP_TEMPORAL_NAMESPACE','ZASP_TEMPORAL_TASK_QUEUE','ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE','ZASP_OPENFGA_URL','ZASP_OPENFGA_STORE_ID','ZASP_OPENFGA_MODEL_ID','ZASP_TEMPORAL_TLS_CA_FILE','ZASP_TEMPORAL_TLS_CERT_FILE','ZASP_TEMPORAL_TLS_KEY_FILE','ZASP_OPENFGA_TLS_CA_FILE','ZASP_OPENFGA_TOKEN_FILE']);
 const seen=new Set();
 for(const e of c.env??[]){
  if(!allowed.has(e.name)||seen.has(e.name))reject();seen.add(e.name);
  if(e.name==='ZASP_POSTGRES_DSN'){
   if(e.value!==undefined||JSON.stringify(e.valueFrom)!==JSON.stringify({secretKeyRef:{name:profile.executorDSNSecret,key:'postgres-dsn'}}))reject();
  }else if(e.valueFrom!==undefined&&!(e.name==='ZASP_WORKER_ID'&&JSON.stringify(e.valueFrom)===JSON.stringify({fieldRef:{apiVersion:'v1',fieldPath:'metadata.name'}})))reject();
 }
 for(const [name,value]of [['ZASP_WORKER_MODE','retention-reference-expiry'],['ZASP_DATABASE_AUTHORITY','zasp_temporal_executor'],['ZASP_BATCH_SIZE','1'],['ZASP_RETENTION_PROFILE_CHECKSUM',config.profileChecksum],['ZASP_RETENTION_TASK_QUEUE',config.taskQueue]])if(c.env?.find(e=>e.name===name)?.value!==value)reject();
 if(typeof runtimeSecret!=='string'||runtimeSecret.length===0||[profile.executorDSNSecret,profile.compensationDSNSecret,profile.forwardKey?.secretName,profile.compensationKey?.secretName].includes(runtimeSecret))reject();
 if(c.securityContext?.privileged===true||c.securityContext?.allowPrivilegeEscalation!==false||c.securityContext?.readOnlyRootFilesystem!==true||c.securityContext?.runAsNonRoot!==true||c.securityContext?.runAsUser!==65532||c.securityContext?.runAsGroup!==65532||JSON.stringify(c.securityContext?.capabilities)!==JSON.stringify({drop:['ALL']}))reject();
 if(!seen.has('ZASP_POSTGRES_DSN')||p.volumes?.length!==1||p.volumes[0].name!=='runtime-services'||JSON.stringify(p.volumes[0].secret)!==JSON.stringify({secretName:runtimeSecret,defaultMode:288})||JSON.stringify(c.volumeMounts)!==JSON.stringify([{name:'runtime-services',mountPath:'/var/run/secrets/runtime-services',readOnly:true}]))reject();
 return true;
}
