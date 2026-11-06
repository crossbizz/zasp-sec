import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeGatewayInstallation,normalizeGatewayInstallationProducer,validateGatewayInstallationResources,validateGatewayInstallationProducerResources} from './gateway-installation-profile.mjs';
const pin='a'.repeat(64), config={enabled:true,profileChecksum:pin}, parent={profile:'canonical61-temporal78-authorization79-80-worker-v1'},runtime={enabled:true};
const serverEnv=[{name:'ZASP_GATEWAY_INSTALLATION_ACK_ENABLED',value:'true'},{name:'ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM',value:pin}];
const producerEnv=[{name:'ZASP_GATEWAY_INSTALLATION_ACK_ENABLED',value:'true'}];
const workload=(name,container,env)=>({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{name:container,env:structuredClone(env)}],initContainers:[{name:'materialize-config',env:[]}]}}}});
const server=()=>[workload('agentsec-gateway-control','gateway-control',serverEnv)];
const producer=()=>[workload('runtime-gateway','runtime-gateway',producerEnv)];
test('gateway installation server activation is closed and requires current authorization runtime',()=>{
 assert.equal(normalizeGatewayInstallation(undefined),undefined);
 assert.deepEqual(normalizeGatewayInstallation({enabled:false,profileChecksum:''}),{enabled:false,profileChecksum:''});
 assert.deepEqual(normalizeGatewayInstallation(config,parent,runtime),config);
 for(const value of [null,{}, {...config,extra:true},{enabled:'true',profileChecksum:pin},{enabled:false,profileChecksum:pin},{enabled:true,profileChecksum:''},{enabled:true,profileChecksum:'A'.repeat(64)}])assert.throws(()=>normalizeGatewayInstallation(value,parent,runtime));
 assert.throws(()=>normalizeGatewayInstallation(config,undefined,runtime));assert.throws(()=>normalizeGatewayInstallation(config,parent,{enabled:false}));
});
test('gateway installation producer activation is explicit without identity or profile configuration',()=>{
 assert.equal(normalizeGatewayInstallationProducer(undefined),undefined);
 for(const enabled of [false,true])assert.deepEqual(normalizeGatewayInstallationProducer({enabled}),{enabled});
 for(const value of [null,{}, {enabled:'true'},{enabled:true,profileChecksum:pin},{enabled:true,credentialID:'existing'}])assert.throws(()=>normalizeGatewayInstallationProducer(value));
});
test('gateway installation server flags are restricted to the actual gateway control consumer',()=>{
 validateGatewayInstallationResources(server(),config);const old=server();old[0].spec.template.spec.containers[0].env=[];validateGatewayInstallationResources(old,undefined);
 for(const mutate of [r=>r.pop(),r=>r.push(structuredClone(r[0])),r=>r[0].kind='DaemonSet',r=>r[0].metadata.name='agentsec-api',r=>r[0].spec.template.spec.containers[0].name='wrong',r=>r[0].spec.template.spec.containers[0].env.push({...serverEnv[0]}),r=>r[0].spec.template.spec.containers[0].env[1].value='b'.repeat(64),r=>r[0].spec.template.spec.containers[0].env[1].valueFrom={secretKeyRef:{name:'other',key:'pin'}},r=>r[0].spec.template.spec.initContainers[0].env=serverEnv,r=>r.push(workload('worker','worker',serverEnv)),r=>r[0].spec.template.spec.containers[0].envFrom=[]]){const r=server();mutate(r);assert.throws(()=>validateGatewayInstallationResources(r,config));}
 assert.throws(()=>validateGatewayInstallationResources(server(),undefined));old[0].spec.template.spec.containers[0].envFrom=[{secretRef:{name:'hidden'}}];assert.throws(()=>validateGatewayInstallationResources(old,undefined));
});
test('gateway installation producer flags are restricted to runtime gateway and never init or sensors',()=>{
 validateGatewayInstallationProducerResources(producer(),{enabled:true});const old=producer();old[0].spec.template.spec.containers[0].env=[];validateGatewayInstallationProducerResources(old,undefined);
 for(const mutate of [r=>r.pop(),r=>r.push(structuredClone(r[0])),r=>r[0].kind='DaemonSet',r=>r[0].metadata.name='sensor-agent',r=>r[0].spec.template.spec.containers[0].name='wrong',r=>r[0].spec.template.spec.containers[0].env.push({...producerEnv[0]}),r=>r[0].spec.template.spec.containers[0].env[0].value='false',r=>r[0].spec.template.spec.containers[0].env[0].valueFrom={secretKeyRef:{name:'other',key:'flag'}},r=>r[0].spec.template.spec.containers[0].env.push(serverEnv[1]),r=>r[0].spec.template.spec.initContainers[0].env=producerEnv,r=>r.push(workload('worker','worker',producerEnv)),r=>r[0].spec.template.spec.containers[0].envFrom=[]]){const r=producer();mutate(r);assert.throws(()=>validateGatewayInstallationProducerResources(r,{enabled:true}));}
 assert.throws(()=>validateGatewayInstallationProducerResources(producer(),undefined));old[0].spec.template.spec.containers[0].envFrom=[];assert.throws(()=>validateGatewayInstallationProducerResources(old,undefined));
});
