import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAgentOwnershipWrite, validateAgentOwnershipWriteResources } from './agent-ownership-write-profile.mjs';
const pin = 'a'.repeat(64);
const selected = {profileChecksum:pin};
const parent = {profile:'canonical61-temporal78-authorization79-80-worker-v1'};
const runtime = {enabled:true};
const workload = (name, env=[]) => ({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env}]}}}});
const env = [{name:'ZASP_AGENT_OWNERSHIP_WRITE_PROFILE_CHECKSUM',value:pin}];
test('Agent ownership write deployment requires explicit current API consumer and closes inherited or worker configuration', () => {
 assert.equal(normalizeAgentOwnershipWrite(undefined),undefined);
 assert.deepEqual(normalizeAgentOwnershipWrite({profileChecksum:''}),{profileChecksum:''});
 assert.deepEqual(normalizeAgentOwnershipWrite(selected,parent,runtime),selected);
 for (const value of [null,{},{profileChecksum:1},{profileChecksum:'invalid'},{...selected,enabled:true}]) assert.throws(()=>normalizeAgentOwnershipWrite(value,parent,runtime));
 assert.throws(()=>normalizeAgentOwnershipWrite(selected,undefined,runtime));
 assert.throws(()=>normalizeAgentOwnershipWrite(selected,parent,{enabled:false}));
 validateAgentOwnershipWriteResources([workload('agentsec-api')],undefined);
 validateAgentOwnershipWriteResources([workload('agentsec-api',env),workload('agentsec-worker')],selected);
 for (const resources of [[],[workload('agentsec-api')],[workload('agentsec-api',[...env,...env])],[workload('agentsec-api',env),workload('agentsec-worker',env)],[workload('agentsec-api',env),workload('agentsec-api',env)],[workload('agentsec-api',env.map(e=>({...e,valueFrom:{secretKeyRef:{name:'wrong',key:'pin'}}})))]]) assert.throws(()=>validateAgentOwnershipWriteResources(resources,selected));
 assert.throws(()=>validateAgentOwnershipWriteResources([workload('agentsec-api',env)],undefined));
 for (const kind of ['DaemonSet','StatefulSet','Pod','CronJob','Job']) {
  const pod={containers:[{env:[...env]}]};
  const resource={kind,metadata:{name:'other'},spec:kind==='Pod'?pod:kind==='CronJob'?{jobTemplate:{spec:{template:{spec:pod}}}}:{template:{spec:pod}}};
  assert.throws(()=>validateAgentOwnershipWriteResources([workload('agentsec-api',env),resource],selected));
  pod.containers[0]={envFrom:[{secretRef:{name:'unknown'}}]};
  assert.throws(()=>validateAgentOwnershipWriteResources([workload('agentsec-api',env),resource],selected));
 }
 const inherited=workload('agentsec-api');inherited.spec.template.spec.containers[0].envFrom=[];
 assert.throws(()=>validateAgentOwnershipWriteResources([inherited],undefined));
 const init=workload('agentsec-api',env);init.spec.template.spec.initContainers=[{env:[...env]}];
 assert.throws(()=>validateAgentOwnershipWriteResources([init],selected));
});
