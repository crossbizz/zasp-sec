import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRetention, validateRetentionResources, retentionConsumers, retentionConsumerManifest } from './retention-profile.mjs';
const pin='a'.repeat(64);
const profile={profile:'canonical61-temporal78-authorization79-80-worker-v1',executorDSNSecret:'executor-db'};
const runtime={enabled:true,taskQueue:'execution',discoveryTaskQueue:'discovery'};
const enabled={enabled:true,profileChecksum:pin,journalProfileChecksum:pin,taskQueue:'retention',indexStageVersion:'runtime-index-v2',sessionIndex:'zasp-runtime-sessions-v2'};
const workload=(name,env)=>({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env}]}}}});
const resources=()=>[...retentionConsumers.map(name=>workload(name,[{name:'ZASP_RETENTION_PROFILE_CHECKSUM',value:pin},...(['agentsec-runtime-index','agentsec-runtime-session-index-v2'].includes(name)?[{name:'ZASP_RETENTION_JOURNAL_PROFILE_CHECKSUM',value:pin},{name:'ZASP_RUNTIME_STAGE_VERSION',value:'runtime-index-v2'},{name:'ZASP_RUNTIME_SESSION_INDEX',value:'zasp-runtime-sessions-v2'}]:[]),...(name==='agentsec-retention-reference-expiry'?[{name:'ZASP_RETENTION_TASK_QUEUE',value:'retention'},{name:'ZASP_WORKER_MODE',value:'retention-reference-expiry'},{name:'ZASP_DATABASE_AUTHORITY',value:'zasp_temporal_executor'},{name:'ZASP_BATCH_SIZE',value:'1'},{name:'ZASP_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:'executor-db',key:'postgres-dsn'}}}]:[])])),{kind:'NetworkPolicy',metadata:{name:'retention-reference-expiry-egress'},spec:{podSelector:{matchLabels:{'app.kubernetes.io/name':'agentsec-retention-reference-expiry'}},policyTypes:['Egress'],egress:[{to:[{ipBlock:{cidr:'10.30.0.0/24'}}],ports:[{protocol:'TCP',port:5432}]},...[["temporal",7233],["openfga",8080]].map(([name,port])=>({to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'zasp-runtime'}},podSelector:{matchLabels:{'app.kubernetes.io/name':name}}}],ports:[{protocol:'TCP',port}]}))]}},{kind:'NetworkPolicy',metadata:{name:'security-agent-database'},spec:{egress:[{to:[{ipBlock:{cidr:'10.30.0.0/24'}}],ports:[{protocol:'TCP',port:5432}]}]}}];
test('retention deployment uses closed opt-in and complete fixed cutover consumers',()=>{
 assert.equal(normalizeRetention(undefined),undefined);
 assert.deepEqual(normalizeRetention({enabled:false,profileChecksum:'',journalProfileChecksum:'',taskQueue:'',indexStageVersion:'',sessionIndex:''}),{enabled:false,profileChecksum:'',journalProfileChecksum:'',taskQueue:'',indexStageVersion:'',sessionIndex:''});
 for(const value of [{...enabled,activate:true},{...enabled,profileChecksum:''},{...enabled,journalProfileChecksum:''},{...enabled,taskQueue:'execution'},{enabled:false,profileChecksum:pin,journalProfileChecksum:'',taskQueue:'',indexStageVersion:'',sessionIndex:''}])assert.throws(()=>normalizeRetention(value,profile,runtime));
 const config=normalizeRetention(enabled,profile,runtime);
 assert.match(retentionConsumerManifest(config).digest,/^[a-f0-9]{64}$/);
 assert.throws(()=>retentionConsumerManifest({...config,indexStageVersion:'runtime-index-v1'}));
 validateRetentionResources(resources(),config,profile);
 for(const mutate of [r=>{r.find(x=>x.metadata.name==='agentsec-runtime-index').spec.template.spec.containers[0].env=r.find(x=>x.metadata.name==='agentsec-runtime-index').spec.template.spec.containers[0].env.filter(e=>e.name!=='ZASP_RETENTION_JOURNAL_PROFILE_CHECKSUM');},r=>r.pop(),r=>r[0].spec.template.spec.containers[0].env[0].value='b'.repeat(64),r=>r[0].spec.template.spec.containers[0].env.push({name:'ZASP_RETENTION_TASK_QUEUE',value:'retention'}),r=>r.push(workload('unrelated',[{name:'ZASP_RETENTION_PROFILE_CHECKSUM',value:pin}]))]){
  const r=resources();mutate(r);assert.throws(()=>validateRetentionResources(r,config,profile));
 }
 assert.throws(()=>validateRetentionResources(resources(),undefined,profile));
});

test('only exact sweep capability receives executor DSN; aliases and other credentials are denied',async()=>{
 const {validateRetentionExecutorCapability}=await import('./retention-profile.mjs');
 const r=resources().find(r=>r.metadata.name==='agentsec-retention-reference-expiry'),p=r.spec.template.spec,c=p.containers[0];
 p.serviceAccountName='zasp-retention-reference-expiry';p.automountServiceAccountToken=false;
 p.volumes=[{name:'runtime-services',secret:{secretName:'runtime-tls',defaultMode:288}}];
 c.securityContext={allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,capabilities:{drop:['ALL']}};c.command=['/app/agentsec-worker'];c.volumeMounts=[{name:'runtime-services',mountPath:'/var/run/secrets/runtime-services',readOnly:true}];
 assert.equal(validateRetentionExecutorCapability(r,profile,enabled,'runtime-tls'),true);
 for(const mutate of [r=>r.spec.template.spec.containers[0].env.push({name:'ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:'compensation-db',key:'postgres-dsn'}}}),r=>r.spec.template.spec.containers[0].env.push({name:'ZASP_POSTGRES_DSN',value:'alias'}),r=>r.spec.template.spec.volumes.push({name:'signing',secret:{secretName:'authority-key'}}),r=>r.spec.template.spec.automountServiceAccountToken=true,r=>r.spec.template.spec.containers[0].securityContext.privileged=true,r=>r.spec.template.spec.hostNetwork=true,r=>r.metadata.name='other']){
  const copy=structuredClone(r);mutate(copy);assert.throws(()=>validateRetentionExecutorCapability(copy,profile,enabled,'runtime-tls'));
 }
});
