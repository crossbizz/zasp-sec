import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAgentRead, validateAgentReadResources } from './agent-read-profile.mjs';
const pin = 'a'.repeat(64);
const selected = {profileChecksum:pin};
const parent = {profile:'canonical61-temporal78-authorization79-80-worker-v1'};
const runtime = {enabled:true};
const workload = (name, env=[]) => ({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env}]}}}});
const env = [{name:'ZASP_AGENT_READ_PROFILE_CHECKSUM',value:pin}];
test('Agent read deployment requires explicit current API consumer and closes inherited or worker configuration', () => {
 assert.equal(normalizeAgentRead(undefined),undefined);
 assert.deepEqual(normalizeAgentRead({profileChecksum:''}),{profileChecksum:''});
 assert.deepEqual(normalizeAgentRead(selected,parent,runtime),selected);
 for (const value of [null,{},{profileChecksum:1},{profileChecksum:'invalid'},{...selected,enabled:true}]) assert.throws(()=>normalizeAgentRead(value,parent,runtime));
 assert.throws(()=>normalizeAgentRead(selected,undefined,runtime));
 assert.throws(()=>normalizeAgentRead(selected,parent,{enabled:false}));
 validateAgentReadResources([workload('agentsec-api')],undefined);
 validateAgentReadResources([workload('agentsec-api',env),workload('agentsec-worker')],selected);
 for (const resources of [[],[workload('agentsec-api')],[workload('agentsec-api',[...env,...env])],[workload('agentsec-api',env),workload('agentsec-worker',env)],[workload('agentsec-api',env),workload('agentsec-api',env)],[workload('agentsec-api',env.map(e=>({...e,valueFrom:{secretKeyRef:{name:'wrong',key:'pin'}}})))]]) assert.throws(()=>validateAgentReadResources(resources,selected));
 assert.throws(()=>validateAgentReadResources([workload('agentsec-api',env)],undefined));
 for (const kind of ['DaemonSet','StatefulSet','Pod','CronJob','Job']) {
  const pod={containers:[{env:[...env]}]};
  const resource={kind,metadata:{name:'other'},spec:kind==='Pod'?pod:kind==='CronJob'?{jobTemplate:{spec:{template:{spec:pod}}}}:{template:{spec:pod}}};
  assert.throws(()=>validateAgentReadResources([workload('agentsec-api',env),resource],selected));
  pod.containers[0]={envFrom:[{secretRef:{name:'unknown'}}]};
  assert.throws(()=>validateAgentReadResources([workload('agentsec-api',env),resource],selected));
 }
 const inherited=workload('agentsec-api');inherited.spec.template.spec.containers[0].envFrom=[];
 assert.throws(()=>validateAgentReadResources([inherited],undefined));
 const init=workload('agentsec-api',env);init.spec.template.spec.initContainers=[{env:[...env]}];
 assert.throws(()=>validateAgentReadResources([init],selected));
});
