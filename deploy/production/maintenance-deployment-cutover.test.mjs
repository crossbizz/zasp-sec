import assert from 'node:assert/strict';
import test from 'node:test';
import {buildMaintenanceDeploymentCutoverPlan,renderMaintenanceDeploymentAdmissionReview} from './maintenance-deployment-cutover.mjs';
const input=()=>({schemaVersion:1,releaseReference:null,applicationNamespace:'agentsec',runtimeNamespace:'zasp-runtime',additionalCredentialHolders:[]});
const phases=['release-review','inventory-observe','application-quiesce','normal-client-drain','server-new-only-rotation','runtime-freeze','final-withdrawal-check','combined-activation','coordinator-first-composed-ack','client-release','deployed-acceptance'];

test('read-only maintenance plan holds every potential client writer until activation and same-owner first Ack',()=>{
 const p=buildMaintenanceDeploymentCutoverPlan(input());
 assert.equal(p.schema,'zasp-maintenance-deployment-cutover-plan-v1');
 assert.equal(p.verified,false);assert.equal(p.productionAvailable,false);assert.equal(p.mayActivate,false);
 assert.deepEqual(p.mutatingResources,[]);assert.equal(p.reviewInputs.bindingStatus,'unverified');
 assert.equal(p.credentialCensus.completeness,'unverified');
 assert.deepEqual(p.credentialCensus.expectedBaseline,['agentsec-api','agentsec-discovery-scheduler','agentsec-discovery-worker','agentsec-red-team-adapter','agentsec-red-team-worker','agentsec-security-agent','zasp-authorization-projector']);
 assert.deepEqual(p.phases.map(x=>x.id),phases);
 for(const [i,phase] of p.phases.entries())assert.equal(phase.after,i===0?null:phases[i-1]);
 const quiesce=p.phases.findIndex(x=>x.id==='application-quiesce'),ack=p.phases.findIndex(x=>x.id==='coordinator-first-composed-ack');
 for(const phase of p.phases.slice(quiesce,ack+1)){
  assert.equal(phase.externalClientState,'fenced');assert.equal(phase.newClientCredentialAccess,'coordinator-only');
  assert.equal(phase.soleFirstAckWriter,'same-bound-coordinator');assert.equal(phase.authorized,false);
 }
 assert.equal(p.phases[ack+1].requires.includes('activation-and-first-composed-ack'),true);
 assert.ok(p.prerequisites.length>=10);assert.ok(p.prerequisites.every(x=>x.status==='unverified'));
 assert.ok(p.prerequisites.some(x=>x.id==='cloud-ci-secret-reader-exclusion'));
 assert.ok(p.prerequisites.some(x=>x.id==='continuous-all-container-normal-exits'));
 assert.ok(Object.isFrozen(p)&&Object.isFrozen(p.phases)&&Object.isFrozen(p.phases[0]));
 assert.throws(()=>p.mayActivate=true,TypeError);
});

test('caller targets, asserted proof and extra credential holders never create authority',()=>{
 const mutations=[x=>{x.verified=true;},x=>{x.namespaceUID='caller-uid';},x=>{x.schemaVersion=2;},x=>{x.additionalCredentialHolders=['unknown-writer'];},x=>{x.additionalCredentialHolders=null;},x=>{x.runtimeNamespace=x.applicationNamespace;},x=>{x.applicationNamespace="a' || true";},x=>{x.releaseReference='https://mutable.example/latest';},x=>{x.prerequisites={allPassed:true};},x=>{delete x.runtimeNamespace;}];
 for(const change of mutations){const value=input();change(value);assert.throws(()=>buildMaintenanceDeploymentCutoverPlan(value),{message:'maintenance deployment review plan rejected'});}
 const value=input();value.releaseReference='oci://releases.example/zasp@sha256:'+'a'.repeat(64);
 const p=buildMaintenanceDeploymentCutoverPlan(value);assert.equal(p.verified,false);assert.ok(p.prerequisites.every(x=>x.status==='unverified'));
 let touched=false;const getter=input();Object.defineProperty(getter,'releaseReference',{enumerable:true,get(){touched=true;return null;}});
 assert.throws(()=>buildMaintenanceDeploymentCutoverPlan(getter));assert.equal(touched,false);
});

test('standalone admission candidates have exact resource operations and explicit review namespaces',()=>{
 const p=buildMaintenanceDeploymentCutoverPlan(input());
 const app=renderMaintenanceDeploymentAdmissionReview(p,'application-quiesce');
 const runtime=renderMaintenanceDeploymentAdmissionReview(p,'runtime-freeze');
 for(const result of [app,runtime]){
  assert.equal(result.reviewOnly,true);assert.equal(result.installed,false);assert.equal(result.enforcementVerified,false);
  assert.deepEqual(result.mutatingResources,[]);assert.equal(result.admissionReviewResources.length,2);
  const [policy,binding]=result.admissionReviewResources;
  assert.equal(policy.apiVersion,'admissionregistration.k8s.io/v1');assert.equal(policy.kind,'ValidatingAdmissionPolicy');
  assert.equal(policy.spec.failurePolicy,'Fail');assert.deepEqual(policy.spec.validations,[{expression:'false',message:'maintenance cutover review fence rejects this operation'}]);
  assert.deepEqual(binding.spec.validationActions,['Deny']);assert.equal(binding.spec.policyName,policy.metadata.name);
  assert.equal(policy.spec.matchConstraints.namespaceSelector,undefined);
  const rules=policy.spec.matchConstraints.resourceRules;
  for(const [group,operation,resource] of [['','CREATE','pods'],['','UPDATE','pods/ephemeralcontainers'],['','CONNECT','pods/exec'],['','CONNECT','pods/attach'],['batch','CREATE','jobs'],['batch','CREATE','cronjobs'],['apps','CREATE','deployments']]){
   assert.ok(rules.some(r=>r.apiGroups.includes(group)&&r.operations.includes(operation)&&r.resources.includes(resource)),`${operation} ${resource}`);
  }
  assert.ok(Object.isFrozen(policy.spec.matchConstraints.resourceRules));
  assert.ok(result.remainingUnverified.includes('cloud-ci-secret-reader-exclusion'));
  assert.ok(result.remainingUnverified.includes('actual-admission-and-rbac-enforcement'));
 }
 assert.equal(app.admissionReviewResources[0].spec.matchConditions[0].expression,"request.namespace == 'agentsec'");
 assert.equal(runtime.admissionReviewResources[0].spec.matchConditions[0].expression,"request.namespace in ['agentsec','zasp-runtime']");
 const rules=runtime.admissionReviewResources[0].spec.matchConstraints.resourceRules;
 assert.ok(rules.some(r=>r.operations.includes('UPDATE')&&r.resources.includes('deployments/scale')));
 assert.ok(rules.some(r=>r.operations.includes('UPDATE')&&r.resources.includes('cronjobs')));
 assert.ok(rules.some(r=>r.operations.includes('DELETE')&&r.resources.includes('pods')));
 assert.ok(!app.admissionReviewResources[0].spec.matchConstraints.resourceRules.some(r=>r.operations.includes('UPDATE')&&r.resources.includes('deployments/scale')),'application quiesce must permit reviewed normal scale-down before final freeze');
});

test('admission renderer refuses forged plans, unsupported phases and payload mutation',()=>{
 const p=buildMaintenanceDeploymentCutoverPlan(input());
 for(const forged of [{},JSON.parse(JSON.stringify(p)),Object.create(p)])assert.throws(()=>renderMaintenanceDeploymentAdmissionReview(forged,'runtime-freeze'),{message:'maintenance deployment review plan rejected'});
 for(const phase of ['combined-activation','client-release','runtime-freeze; apply',''])assert.throws(()=>renderMaintenanceDeploymentAdmissionReview(p,phase));
 const resources=renderMaintenanceDeploymentAdmissionReview(p,'runtime-freeze');
 assert.throws(()=>resources.admissionReviewResources[0].spec.validations[0].expression='true',TypeError);
});
