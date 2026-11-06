const reject=()=>{throw new Error('Agent device association deployment rejected');};
export function normalizeAgentDeviceAssociation(value,profile,runtime){
 if(value===undefined)return undefined;
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='enabled,profileChecksum'||typeof value.enabled!=='boolean'||typeof value.profileChecksum!=='string')reject();
 if(value.enabled?profile?.profile!=='canonical61-temporal78-authorization79-80-worker-v1'||runtime?.enabled!==true||!/^[a-f0-9]{64}$/.test(value.profileChecksum):value.profileChecksum!=='')reject();
 return Object.freeze({...value});
}
export function validateAgentDeviceAssociationResources(resources,config){
 const selected=config?.enabled===true;
 const workloads=resources.filter(r=>['Deployment','Job','CronJob','DaemonSet','StatefulSet','ReplicaSet','ReplicationController','Pod'].includes(r.kind));
 const consumers={'agentsec-api':'agentsec-api','agentsec-gateway-control':'gateway-control'};
 const targets=workloads.filter(r=>r.kind==='Deployment'&&Object.hasOwn(consumers,r.metadata?.name));
 if(selected&&(targets.length!==2||new Set(targets.map(r=>r.metadata.name)).size!==2))reject();
 for(const resource of workloads){
  const pod=resource.kind==='Pod'?resource.spec:resource.kind==='CronJob'?resource.spec?.jobTemplate?.spec?.template?.spec:resource.spec?.template?.spec;
  if(selected&&targets.includes(resource)&&(pod?.containers?.length!==1||pod.containers[0].name!==consumers[resource.metadata.name]))reject();
  for(const [index,container]of [...(pod?.containers??[]),...(pod?.initContainers??[])].entries()){
   if((selected||Object.hasOwn(consumers,resource.metadata?.name))&&container.envFrom!==undefined)reject();
   const entries=(container.env??[]).filter(v=>v.name?.startsWith('ZASP_AGENT_DEVICE_ASSOCIATION_'));
   const expected=selected&&targets.includes(resource)&&index===0;
   if(!expected){if(entries.length)reject();continue;}
   const api=resource.metadata.name==='agentsec-api',names=api?['ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM']:['ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED','ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM'];
   if(entries.length!==names.length||new Set(entries.map(v=>v.name)).size!==names.length||entries.some(v=>!names.includes(v.name)||v.valueFrom!==undefined))reject();
   if(api?entries[0].value!==config.profileChecksum:entries.find(v=>v.name===names[0])?.value!=='true'||entries.find(v=>v.name===names[1])?.value!==config.profileChecksum)reject();
  }
 }
}
