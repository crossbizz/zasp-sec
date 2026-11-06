import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAgentOwnerFilter, validateAgentOwnerFilterResources } from './agent-owner-filter-profile.mjs';
const pin = 'a'.repeat(64);
const enabled = {enabled:true,profileChecksum:pin};
const parent = {profile:'canonical61-temporal78-authorization79-80-worker-v1'};
const runtime = {enabled:true};
const workload = (name, env=[]) => ({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env}]}}}});
const env = [{name:'ZASP_AGENT_OWNER_FILTER_ENABLED',value:'true'},{name:'ZASP_AGENT_OWNER_FILTER_CHECKSUM',value:pin}];
test('agent owner filter consumers preserve disabled compatibility and explicit current profile admission', () => {
 assert.equal(normalizeAgentOwnerFilter(undefined),undefined);
 assert.deepEqual(normalizeAgentOwnerFilter({enabled:false,profileChecksum:''}),{enabled:false,profileChecksum:''});
 assert.deepEqual(normalizeAgentOwnerFilter(enabled,parent,runtime),enabled);
 for(const value of [{enabled:false,profileChecksum:pin},{enabled:true,profileChecksum:''},{...enabled,extra:true},{enabled:'true',profileChecksum:pin},null]) assert.throws(()=>normalizeAgentOwnerFilter(value,parent,runtime));
 assert.throws(()=>normalizeAgentOwnerFilter(enabled,undefined,runtime));
 assert.throws(()=>normalizeAgentOwnerFilter(enabled,parent,{enabled:false}));
 validateAgentOwnerFilterResources([workload('agentsec-api')],undefined);
 validateAgentOwnerFilterResources([workload('agentsec-api',env),workload('agentsec-worker')],enabled);
 for(const resources of [[],[workload('agentsec-api',env.slice(1))],[workload('agentsec-api',[...env,env[0]])],[workload('agentsec-api',env),workload('agentsec-worker',env)], [workload('agentsec-api',env),workload('agentsec-api',env)], [workload('agentsec-api',env.map(e=>({...e,valueFrom:{secretKeyRef:{name:'wrong',key:'pin'}}})))]]) assert.throws(()=>validateAgentOwnerFilterResources(resources,enabled));
 assert.throws(()=>validateAgentOwnerFilterResources([workload('agentsec-api',env)],undefined));
 const inherited=workload('agentsec-api',env);inherited.spec.template.spec.containers[0].envFrom=[];
 assert.throws(()=>validateAgentOwnerFilterResources([inherited],enabled));
 const legacyInherited=workload('agentsec-api');legacyInherited.spec.template.spec.containers[0].envFrom=[{secretRef:{name:'unknown'}}];
 assert.throws(()=>validateAgentOwnerFilterResources([legacyInherited],undefined));
 for(const kind of ['DaemonSet','StatefulSet','Pod','CronJob','Job']) {
  const pod={containers:[{env:[...env]}]};
  const resource={kind,metadata:{name:'other'},spec:kind==='Pod'?pod:kind==='CronJob'?{jobTemplate:{spec:{template:{spec:pod}}}}:{template:{spec:pod}}};
  assert.throws(()=>validateAgentOwnerFilterResources([workload('agentsec-api',env),resource],enabled));
  pod.containers[0]={envFrom:[{secretRef:{name:'unknown'}}]};
  assert.throws(()=>validateAgentOwnerFilterResources([workload('agentsec-api',env),resource],enabled));
 }
 const init=workload('agentsec-api',env);init.spec.template.spec.initContainers=[{env:[...env]}];
 assert.throws(()=>validateAgentOwnerFilterResources([init],enabled));
});
