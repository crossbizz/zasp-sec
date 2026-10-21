import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEnvironmentClass, validateEnvironmentClassResources } from './environment-class-profile.mjs';
const pin = 'a'.repeat(64);
const enabled = {enabled:true,profileChecksum:pin};
const parent = {profile:'canonical61-temporal78-authorization79-80-worker-v1'};
const runtime = {enabled:true};
const workload = (name, env=[]) => ({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env}]}}}});
const env = [{name:'ZASP_ENVIRONMENT_CLASS_ENABLED',value:'true'},{name:'ZASP_ENVIRONMENT_CLASS_PROFILE_CHECKSUM',value:pin}];
test('environment class consumers preserve disabled compatibility and explicit current profile admission', () => {
 assert.equal(normalizeEnvironmentClass(undefined),undefined);
 assert.deepEqual(normalizeEnvironmentClass({enabled:false,profileChecksum:''}),{enabled:false,profileChecksum:''});
 assert.deepEqual(normalizeEnvironmentClass(enabled,parent,runtime),enabled);
 for(const value of [{enabled:false,profileChecksum:pin},{enabled:true,profileChecksum:''},{...enabled,extra:true},{enabled:'true',profileChecksum:pin},null]) assert.throws(()=>normalizeEnvironmentClass(value,parent,runtime));
 assert.throws(()=>normalizeEnvironmentClass(enabled,undefined,runtime));
 assert.throws(()=>normalizeEnvironmentClass(enabled,parent,{enabled:false}));
 validateEnvironmentClassResources([workload('agentsec-api')],undefined);
 validateEnvironmentClassResources([workload('agentsec-api',env),workload('agentsec-worker')],enabled);
 for(const resources of [[],[workload('agentsec-api',env.slice(1))],[workload('agentsec-api',[...env,env[0]])],[workload('agentsec-api',env),workload('agentsec-worker',env)], [workload('agentsec-api',env),workload('agentsec-api',env)], [workload('agentsec-api',env.map(e=>({...e,valueFrom:{secretKeyRef:{name:'wrong',key:'pin'}}})))]]) assert.throws(()=>validateEnvironmentClassResources(resources,enabled));
 assert.throws(()=>validateEnvironmentClassResources([workload('agentsec-api',env)],undefined));
 const inherited=workload('agentsec-api',env);inherited.spec.template.spec.containers[0].envFrom=[];
 assert.throws(()=>validateEnvironmentClassResources([inherited],enabled));
 const legacyInherited=workload('agentsec-api');legacyInherited.spec.template.spec.containers[0].envFrom=[{secretRef:{name:'unknown'}}];
 assert.throws(()=>validateEnvironmentClassResources([legacyInherited],undefined));
 for(const kind of ['DaemonSet','StatefulSet','Pod','CronJob','Job']) {
  const pod={containers:[{env:[...env]}]};
  const resource={kind,metadata:{name:'other'},spec:kind==='Pod'?pod:kind==='CronJob'?{jobTemplate:{spec:{template:{spec:pod}}}}:{template:{spec:pod}}};
  assert.throws(()=>validateEnvironmentClassResources([workload('agentsec-api',env),resource],enabled));
  pod.containers[0]={envFrom:[{secretRef:{name:'unknown'}}]};
  assert.throws(()=>validateEnvironmentClassResources([workload('agentsec-api',env),resource],enabled));
 }
 const init=workload('agentsec-api',env);init.spec.template.spec.initContainers=[{env:[...env]}];
 assert.throws(()=>validateEnvironmentClassResources([init],enabled));
});
