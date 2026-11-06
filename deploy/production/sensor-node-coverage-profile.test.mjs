import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeSensorNodeCoverage,validateSensorNodeCoverageResources,normalizeSensorNodeCoverageProducer,validateSensorNodeCoverageProducerResources} from './sensor-node-coverage-profile.mjs';
const pin='a'.repeat(64),config={enabled:true,profileChecksum:pin},parent={profile:'canonical61-temporal78-authorization79-80-worker-v1'},runtime={enabled:true};
const env=[{name:'ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED',value:'true'},{name:'ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM',value:pin}];
const workload=(name,container,entries=env)=>({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{name:container,env:entries}]}}}});
const good=()=>[workload('agentsec-api','agentsec-api'),workload('agentsec-event-ingest','event-ingest')];
test('sensor node retention requires exactly current selected API and ingest consumers',()=>{
 assert.equal(normalizeSensorNodeCoverage(undefined),undefined);assert.deepEqual(normalizeSensorNodeCoverage({enabled:false,profileChecksum:''}),{enabled:false,profileChecksum:''});assert.deepEqual(normalizeSensorNodeCoverage(config,parent,runtime),config);
 for(const value of [null,{}, {...config,extra:true},{enabled:'true',profileChecksum:pin},{enabled:false,profileChecksum:pin},{enabled:true,profileChecksum:''},{enabled:true,profileChecksum:'unknown'}])assert.throws(()=>normalizeSensorNodeCoverage(value,parent,runtime));
 assert.throws(()=>normalizeSensorNodeCoverage(config,undefined,runtime));assert.throws(()=>normalizeSensorNodeCoverage(config,parent,{enabled:false}));
 validateSensorNodeCoverageResources(good(),config);validateSensorNodeCoverageResources([workload('agentsec-api','agentsec-api',[]),workload('agentsec-event-ingest','event-ingest',[])],undefined);
 for(const change of [r=>r.pop(),r=>r.push(workload('agentsec-api','agentsec-api')),r=>r[1].spec.template.spec.containers[0].name='wrong',r=>r[0].spec.template.spec.containers[0].env.push({...env[0]}),r=>r[1].spec.template.spec.containers[0].env[1]={...env[1],valueFrom:{secretKeyRef:{name:'bad',key:'pin'}}},r=>r.push(workload('agentsec-worker','worker')),r=>r[1].spec.template.spec.initContainers=[{name:'init',env}],r=>r[0].spec.template.spec.containers[0].envFrom=[]]){const r=structuredClone(good());change(r);assert.throws(()=>validateSensorNodeCoverageResources(r,config));}
 assert.throws(()=>validateSensorNodeCoverageResources(good(),undefined));
 for(const name of ['agentsec-api','agentsec-event-ingest'])for(const enabled of [false,true]){const resources=enabled?good():[workload('agentsec-api','agentsec-api',[]),workload('agentsec-event-ingest','event-ingest',[])];resources.find(r=>r.metadata.name===name).spec.template.spec.containers[0].envFrom=[{secretRef:{name:'hidden-enablement'}}];assert.throws(()=>validateSensorNodeCoverageResources(resources,enabled?config:undefined));}
});

test('customer edge retained producer is explicit and confined to exact lineage consumer',()=>{
 const sensorID='pid_91000001-0000-4000-8000-000000000001',selected={enabled:true,sensorID};
 assert.equal(normalizeSensorNodeCoverageProducer(undefined),undefined);assert.deepEqual(normalizeSensorNodeCoverageProducer({enabled:false,sensorID:''}),{enabled:false,sensorID:''});assert.deepEqual(normalizeSensorNodeCoverageProducer(selected),selected);
 for(const value of [null,{}, {...selected,profileChecksum:pin},{enabled:'true',sensorID},{enabled:false,sensorID},{enabled:true,sensorID:''},{enabled:true,sensorID:'pid_00000000-0000-0000-0000-000000000000'},{enabled:true,sensorID:sensorID.toUpperCase()}])assert.throws(()=>normalizeSensorNodeCoverageProducer(value));
 const entries=[{name:'ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED',value:'true'},{name:'ZASP_SENSOR_ID',value:sensorID}];
 const edge=()=>[{kind:'DaemonSet',metadata:{name:'sensor-agent'},spec:{template:{spec:{containers:[{name:'sensor-agent',env:structuredClone(entries)},{name:'lineage-producer',env:[]}],initContainers:[{name:'lineage-layout',env:[]}]}}}}];
 validateSensorNodeCoverageProducerResources(edge(),selected);
 const old=edge();old[0].spec.template.spec.containers[0].env=[];validateSensorNodeCoverageProducerResources(old,undefined);validateSensorNodeCoverageProducerResources(old,{enabled:false,sensorID:''});
 for(const mutate of [r=>r.pop(),r=>r.push(structuredClone(r[0])),r=>r[0].metadata.name='other',r=>r[0].spec.template.spec.containers[0].name='other',r=>r[0].spec.template.spec.containers[1].env=entries,r=>r[0].spec.template.spec.initContainers[0].env=entries,r=>r[0].spec.template.spec.containers[0].env.push({name:'ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM',value:pin}),r=>r[0].spec.template.spec.containers[0].env[1].value=pin,r=>r[0].spec.template.spec.containers[0].env[1].valueFrom={secretKeyRef:{name:'unknown',key:'id'}},r=>r[0].spec.template.spec.containers[0].envFrom=[{secretRef:{name:'hidden'}}]]){const r=edge();mutate(r);assert.throws(()=>validateSensorNodeCoverageProducerResources(r,selected));}
 assert.throws(()=>validateSensorNodeCoverageProducerResources(edge(),undefined));
 for(const index of [0,1]){const r=structuredClone(old);r[0].spec.template.spec.containers[index].envFrom=[];assert.throws(()=>validateSensorNodeCoverageProducerResources(r,undefined));}
});
