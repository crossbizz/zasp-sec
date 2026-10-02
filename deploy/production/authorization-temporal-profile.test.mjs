import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAuthorizationTemporalProfile, authorizationTemporalMigrationCommands } from './authorization-temporal-profile.mjs';

const profile = () => ({ profile: 'canonical61-temporal78-authorization79-80-worker-v1', executorPrincipal: 'temporal_executor_login', compensationPrincipal: 'temporal_compensation_login', projectorPrincipal: 'outbox_login', adapterPrincipal: 'red_team_adapter_login', executorDSNSecret: 'zasp-temporal-executor', compensationDSNSecret: 'zasp-temporal-compensation', projectorDSNSecret: 'zasp-authorization-projector', adapterDSNSecret: 'zasp-authorization-adapter', forwardKey: {purpose: 'worker-forward', secretName: 'zasp-worker-forward-key', key: 'seed'}, compensationKey: {purpose: 'captured-compensation', secretName: 'zasp-worker-compensation-key', key: 'seed'}, pricingBindingsConfigMap: 'zasp-temporal-pricing', gatewayPolicyKeysConfigMap: 'zasp-gateway-policy-verifiers', workerRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-temporal-worker', projectorRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-authorization-projector', adapterRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-red-team-adapter' });
const options = () => ({schemaVersion:61,runtimeServices:{enabled:true,timeout:'5s',temporalAddress:'temporal-frontend.zasp-runtime.svc.cluster.local:7233',namespace:'zasp-staging',taskQueue:'zasp-security-agent',discoveryTaskQueue:'zasp-discovery',openfgaURL:'https://openfga.zasp-runtime.svc.cluster.local:8080',storeID:'01ARZ3NDEKTSV4RRFFQ69G5FAV',modelID:'01ARZ3NDEKTSV4RRFFQ69G5FAW',clientSecret:'zasp-runtime-services-client'}});

test('named profile packages an inspected canonical61 installer and purpose-specific identities', () => {
  const actual=normalizeAuthorizationTemporalProfile(profile(),options(),'123456789012');
  assert.equal(actual.profile,'canonical61-temporal78-authorization79-80-worker-v1');
  assert.deepEqual(authorizationTemporalMigrationCommands(actual),['up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier']);
  assert.ok(Object.isFrozen(actual));
});

test('profile rejects wrong physical schema, missing services and ambiguous key or role bindings', () => {
  const reject=(p=profile(),o=options())=>assert.throws(()=>normalizeAuthorizationTemporalProfile(p,o,'123456789012'),/profile rejected/);
  for(const version of [49,60,78,79,80]) { const o=options();o.schemaVersion=version;reject(profile(),o); }
  for(const key of Object.keys(profile())) {const p=profile();delete p[key];reject(p);}
  for(const key of ['executorPrincipal','executorDSNSecret','pricingBindingsConfigMap','gatewayPolicyKeysConfigMap']) {for(const value of [undefined,null,42]) {const p=profile();p[key]=value;reject(p);}}
  for (const key of ['pricingBindingsConfigMap','executorDSNSecret']) { const p=profile();p.gatewayPolicyKeysConfigMap=p[key];reject(p); }
  for(const edit of [p=>p.profile='canonical61-authorization79-80-v1',p=>p.forwardKey=p.compensationKey,p=>p.compensationKey.secretName=p.forwardKey.secretName,p=>p.executorPrincipal=p.compensationPrincipal,p=>p.executorDSNSecret=p.compensationDSNSecret,p=>p.projectorRoleArn=p.workerRoleArn,p=>p.workerRoleArn='arn:aws:iam::999999999999:role/foreign',p=>p.extra='unknown',p=>p.forwardKey.key='password']) {const p=profile();edit(p);reject(p);}
  for(const edit of [o=>o.runtimeServices.enabled=false,o=>o.runtimeServices.storeID='',o=>o.runtimeServices.modelID='',o=>o.runtimeServices.discoveryTaskQueue=o.runtimeServices.taskQueue,o=>o.runtimeServices.openfgaURL='http://localhost:8080',o=>o.runtimeServices.openfgaURL+='/?token=unsafe']) {const o=options();edit(o);reject(profile(),o);}
  assert.equal(normalizeAuthorizationTemporalProfile(undefined,{},'123456789012'),undefined);
});

test('named profile addresses match the packaged private service and network contracts', () => {
  for (const [field,value] of [
    ['temporalAddress','temporal.other.svc.cluster.local:7233'],
    ['temporalAddress','temporal-frontend.zasp-runtime.svc.cluster.local:443'],
    ['openfgaURL','https://authorization.example.com:8080'],
    ['openfgaURL','https://openfga.zasp-runtime.svc.cluster.local:443'],
  ]) {
    const o=options();o.runtimeServices[field]=value;
    assert.throws(()=>normalizeAuthorizationTemporalProfile(profile(),o,'123456789012'),/profile rejected/);
  }
});
