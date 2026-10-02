import test from 'node:test';
import assert from 'node:assert/strict';
import { renderRelease, validateRenderedRelease } from './release-contract.mjs';
import { productionReleaseFixture as release } from './release-fixture.mjs';
import { load } from 'js-yaml';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, symlink, lstat, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const config = () => ({
  schemaVersion: 61,
  authorizationTemporal: {
    profile: 'canonical61-temporal78-authorization79-80-worker-v1',
    executorPrincipal: 'temporal_executor_login', compensationPrincipal: 'temporal_compensation_login',
    projectorPrincipal: 'outbox_login', adapterPrincipal: 'red_team_adapter_login',
    executorDSNSecret: 'zasp-temporal-executor', compensationDSNSecret: 'zasp-temporal-compensation',
    projectorDSNSecret: 'zasp-authorization-projector', adapterDSNSecret: 'zasp-authorization-adapter',
    forwardKey: { purpose: 'worker-forward', secretName: 'zasp-worker-forward-key', key: 'seed' },
    compensationKey: { purpose: 'captured-compensation', secretName: 'zasp-worker-compensation-key', key: 'seed' },
    pricingBindingsConfigMap: 'zasp-temporal-pricing',
    gatewayPolicyKeysConfigMap: 'zasp-gateway-policy-verifiers',
    workerRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-temporal-worker',
    projectorRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-authorization-projector',
    adapterRoleArn: 'arn:aws:iam::123456789012:role/zasp-production-red-team-adapter',
  },
  runtimeServices: { enabled: true, timeout: '5s', temporalAddress: 'temporal-frontend.zasp-runtime.svc.cluster.local:7233', namespace: 'zasp-staging', taskQueue: 'zasp-security-agent', discoveryTaskQueue: 'zasp-discovery', openfgaURL: 'https://openfga.zasp-runtime.svc.cluster.local:8080', storeID: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelID: '01ARZ3NDEKTSV4RRFFQ69G5FAW', clientSecret: 'zasp-runtime-services-client' },
});
const one = (rows, kind, name) => { const found = rows.filter(r => r.kind === kind && r.metadata.name === name); assert.equal(found.length, 1, `${kind}/${name}`); return found[0]; };
const pod = r => r.kind === 'CronJob' ? r.spec.jobTemplate.spec.template.spec : r.spec.template.spec;
const env = r => Object.fromEntries(pod(r).containers[0].env.map(e => [e.name, e.value ?? e.valueFrom]));
const runtimeSQLWorkers = ['outbox', 'coordinator', 'archive', 'index', 'correlation', 'projection', 'complete', 'session-index-v2'].map(suffix => `agentsec-runtime-${suffix}`);

test('current profile renders the real pollers, registered authorities and bounded projector without duplicate executor deployment', async () => {
  const rows = await renderRelease(release, config());
  const ingest = one(rows, 'Deployment', 'agentsec-event-ingest');
  assert.equal(env(ingest).ZASP_RUNTIME_DATABASE_PROFILE, 'canonical61-temporal78-authorization79-80-runtime-v1');
  assert.equal(env(ingest).ZASP_RUNTIME_INGEST_SCHEMA, 'runtime-event-v2');
  for (const name of runtimeSQLWorkers) {
    const runtime = one(rows, 'Deployment', name);
    assert.equal(env(runtime).ZASP_RUNTIME_DATABASE_PROFILE, 'canonical61-temporal78-authorization79-80-runtime-v1', name);
    assert.equal(env(runtime).ZASP_RUNTIME_SERVICES_ENABLED, undefined, name);
    assert.equal(pod(runtime).volumes.some(v => v.name === 'runtime-services'), false, name);
  }
  const worker = one(rows, 'Deployment', 'agentsec-security-agent');
  assert.equal(env(worker).ZASP_WORKER_MODE, 'security-agent');
  assert.equal(env(worker).ZASP_RUNTIME_SERVICES_ENABLED, 'true');
  assert.equal(env(worker).ZASP_TEMPORAL_TASK_QUEUE, 'zasp-security-agent');
  assert.equal(env(worker).ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN.secretKeyRef.name, 'zasp-temporal-executor');
  assert.equal(env(worker).ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN.secretKeyRef.name, 'zasp-temporal-compensation');
  assert.equal(env(worker).ZASP_AUTHORIZATION_WORKER_KEY_FILE, '/var/run/zasp-authority/forward.seed');
  assert.equal(env(worker).ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE, '/var/run/zasp-authority/compensation.seed');
  assert.equal(env(worker).ZASP_GATEWAY_POLICY_KEYS_FILE, '/var/run/zasp-policy-verifier/policy-keys.json');
  assert.deepEqual(pod(worker).volumes.find(v => v.name === 'policy-verifier-source').configMap, {name:config().authorizationTemporal.gatewayPolicyKeysConfigMap,defaultMode:288,items:[{key:'policy-keys.json',path:'policy-keys.json'}]});
  assert.deepEqual(pod(worker).volumes.find(v => v.name === 'policy-verifier').emptyDir, {medium:'Memory',sizeLimit:'64Ki'});
  assert.deepEqual(pod(worker).containers[0].volumeMounts.find(v => v.name === 'policy-verifier'), {name:'policy-verifier',mountPath:'/var/run/zasp-policy-verifier',readOnly:true});
  const verifierInit = pod(worker).initContainers.find(c => c.name === 'materialize-policy-verifier');
  assert.equal(verifierInit.securityContext.runAsUser, 65532);
  assert.deepEqual(verifierInit.args, ['umask 077; cp /public-keys/policy-keys.json /keys/policy-keys.json; chmod 0400 /keys/policy-keys.json']);
  assert.equal(env(worker).ZASP_RED_TEAM_ROLE_ARN, config().authorizationTemporal.workerRoleArn);
  assert.equal(pod(worker).containers[0].resources.limits.memory, '2Gi');
  assert.equal(pod(worker).containers[0].resources.limits['ephemeral-storage'], '1Gi');
  for (const name of ['agentsec-discovery-worker', 'agentsec-discovery-scheduler', 'agentsec-red-team-worker']) assert.equal(env(one(rows, 'Deployment', name)).ZASP_RUNTIME_SERVICES_ENABLED, 'true');
  for (const name of ['agentsec-runtime-outbox', 'agentsec-recovery-backup', 'agentsec-red-team-outbox']) one(rows, 'Deployment', name);
  const adapter = one(rows, 'Deployment', 'agentsec-red-team-adapter');
  assert.equal(env(adapter).ZASP_DATABASE_URL.secretKeyRef.name, 'zasp-authorization-adapter');
  assert.equal(env(adapter).ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN.secretKeyRef.name, 'zasp-temporal-compensation');
  assert.equal(env(adapter).ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN, undefined);
  for (const [resource, uid] of [[worker, 65532], [adapter, 1000]]) {
    const p = pod(resource), init = p.initContainers.find(c => c.name === 'materialize-worker-keys');
    assert.equal(init.securityContext.runAsUser, uid);
    assert.match(init.args[0], /chmod 0400 \/keys\/forward.seed \/keys\/compensation.seed/);
    assert.equal(p.containers[0].volumeMounts.find(v => v.name === 'worker-keys').readOnly, true);
    assert.deepEqual(p.volumes.find(v => v.name === 'worker-keys').emptyDir, { medium: 'Memory', sizeLimit: '64Ki' });
  }
  const projector = one(rows, 'CronJob', 'zasp-authorization-projector');
  assert.equal(projector.spec.concurrencyPolicy, 'Forbid');
  assert.deepEqual(pod(projector).containers[0].command, ['/app/zasp-authorization-reconcile']);
  assert.deepEqual(pod(projector).containers[0].args, ['--mode', 'reconcile', '--limit', '20', '--timeout', '2m']);
  assert.equal(env(projector).ZASP_POSTGRES_DSN.secretKeyRef.name, 'zasp-authorization-projector');
  assert.equal(pod(projector).containers[0].readinessProbe, undefined);
  assert.equal(one(rows, 'ServiceAccount', 'zasp-authorization-projector').metadata.annotations['eks.amazonaws.com/role-arn'], config().authorizationTemporal.projectorRoleArn);
  const migration = one(rows, 'Job', 'agentsec-schema-v61');
  assert.equal(env(migration).ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL, 'red_team_adapter_login');
  assert.equal(env(migration).ZASP_OUTBOX_WORKER_DB_PRINCIPAL, 'outbox_login');
  assert.match(pod(migration).containers[0].args[0], /up-authorization-runtime-profile.*register-temporal-executor-principals.*register-authorization-verifier.*register-worker-authorization-verifier.*register-compensation-authorization-verifier/);
  assert.deepEqual(load(one(rows, 'SecretProviderClass', 'zasp-temporal-provider-files').spec.parameters.objects).map(o=>o.objectName), ['zasp-production/gateway-policy-signing-private-key', 'zasp-production/red-team-adapter-token', 'zasp-production/red-team-adapter-tls-certificate']);
  assert.equal(load(one(rows, 'SecretProviderClass', 'zasp-authorization-projector').spec.parameters.objects)[0].objectName, 'zasp-production/postgres-outbox-worker-dsn');
});

test('current profile refuses missing, swapped and noncurrent authority inputs', async () => {
  for (const edit of [o => delete o.authorizationTemporal, o => o.schemaVersion = 80, o => o.authorizationTemporal.forwardKey = o.authorizationTemporal.compensationKey, o => o.authorizationTemporal.adapterDSNSecret = o.authorizationTemporal.executorDSNSecret, o => o.runtimeServices.discoveryTaskQueue = o.runtimeServices.taskQueue, o => o.runtimeServices.enabled = false, o => o.authorizationTemporal.workerRoleArn = release.discovery.roleArn, o => o.authorizationTemporal.projectorRoleArn = release.outbox.roleArn]) {
    const options = config(); edit(options);
    await assert.rejects(renderRelease(release, options), /rejected/);
  }
});

test('current profile refuses rendered authority drift and admits exactly its private dependency consumers', async () => {
  const options = config(), rows = await renderRelease(release, options);
  const validate = r => validateRenderedRelease(r, '123456789012', 61, 'precision-intake', undefined, undefined, undefined, undefined, undefined, 'active', options.authorizationTemporal);
  const policy = one(rows, 'NetworkPolicy', 'runtime-services-egress');
  assert.deepEqual(policy.spec.podSelector.matchExpressions[0].values.slice().sort(), ['agentsec-api', 'agentsec-discovery-scheduler', 'agentsec-discovery-worker', 'agentsec-red-team-worker', 'agentsec-security-agent', 'zasp-authorization-projector'].sort());
  assert.deepEqual(one(rows,'NetworkPolicy','authorization-adapter-fga-egress').spec.egress[0].ports,[{protocol:'TCP',port:8080}]);
  assert.doesNotThrow(() => validate(rows));
  const mutations = [
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_GATEWAY_POLICY_KEYS_FILE').value = '/var/run/zasp-temporal-provider/gateway-signing-private-key',
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).volumes.find(v => v.name === 'policy-verifier-source').configMap.name = options.authorizationTemporal.pricingBindingsConfigMap,
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).containers[0].volumeMounts.find(v => v.name === 'policy-verifier').readOnly = false,
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).initContainers.find(c => c.name === 'materialize-policy-verifier').args = ['true'],
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).initContainers.find(c => c.name === 'materialize-policy-verifier').securityContext.runAsUser = 0,
    r => pod(one(r, 'Deployment', 'agentsec-api')).containers[0].env.push({name:'ZASP_GATEWAY_POLICY_KEYS_FILE',value:'/unrequested'}),
    r => pod(one(r, 'Deployment', 'agentsec-event-ingest')).containers[0].env = pod(one(r, 'Deployment', 'agentsec-event-ingest')).containers[0].env.filter(e => e.name !== 'ZASP_RUNTIME_DATABASE_PROFILE'),
    r => envEntry(r, 'agentsec-event-ingest', 'ZASP_RUNTIME_DATABASE_PROFILE').value = 'canonical61-temporal78-authorization79-80-worker-v1',
    r => pod(one(r, 'Deployment', 'agentsec-event-ingest')).containers[0].env.push({name:'ZASP_RUNTIME_DATABASE_PROFILE',value:'canonical61-temporal78-authorization79-80-runtime-v1'}),
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN').valueFrom.secretKeyRef.name = 'zasp-temporal-compensation',
    r => envEntry(r, 'agentsec-red-team-adapter', 'ZASP_DATABASE_URL').valueFrom.secretKeyRef.name = 'zasp-temporal-executor',
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_AUTHORIZATION_WORKER_KEY_FILE').value = '/var/run/zasp-authority/compensation.seed',
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).initContainers[0].securityContext.runAsUser = 0,
    r => pod(one(r, 'Deployment', 'agentsec-red-team-adapter')).initContainers[0].args = ['true'],
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).volumes.find(v => v.name === 'forward-key-source').secret.secretName = 'zasp-worker-compensation-key',
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).containers[0].volumeMounts.find(v => v.name === 'worker-keys').readOnly = false,
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_RUNTIME_SERVICES_ENABLED').value = 'false',
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_TEMPORAL_TASK_QUEUE').value = 'zasp-discovery',
    r => envEntry(r, 'agentsec-security-agent', 'ZASP_RED_TEAM_RUNNER_IMAGE').value = 'unversioned:latest',
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).containers[0].env.push({name:'ZASP_AUTHORIZATION_WORKER_KEY_FILE', value:'/untrusted'}),
    r => pod(one(r, 'CronJob', 'zasp-authorization-projector')).containers[0].args = ['--mode', 'configure'],
    r => one(r, 'CronJob', 'zasp-authorization-projector').spec.concurrencyPolicy = 'Allow',
    r => one(r, 'NetworkPolicy', 'runtime-services-egress').spec.podSelector = {},
    r => one(r, 'ServiceAccount', 'zasp-authorization-projector').metadata.annotations['eks.amazonaws.com/role-arn'] = options.authorizationTemporal.workerRoleArn,
    r => pod(one(r, 'Deployment', 'web')).volumes = [{name:'leak',secret:{secretName:options.authorizationTemporal.forwardKey.secretName}}],
    r => pod(one(r, 'Deployment', 'agentsec-api')).containers[0].env.push({name:'ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:options.authorizationTemporal.executorDSNSecret,key:'postgres-dsn'}}}),
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).containers[0].args = ['true'],
    r => pod(one(r, 'Deployment', 'agentsec-security-agent')).initContainers.push({name:'replace-keys',command:['sh','-c','true']}),
  ];
  for (const mutate of mutations) { const changed=structuredClone(rows); mutate(changed); assert.throws(() => validate(changed), /rejected/, mutate.toString()); }
  for (const name of runtimeSQLWorkers) {
    for (const change of ['missing', 'wrong', 'duplicate', 'external-services', 'external-secret']) {
      const changed = structuredClone(rows), runtime = one(changed, 'Deployment', name), c = pod(runtime).containers[0];
      if (change === 'missing') c.env = c.env.filter(e => e.name !== 'ZASP_RUNTIME_DATABASE_PROFILE');
      if (change === 'wrong') envEntry(changed, name, 'ZASP_RUNTIME_DATABASE_PROFILE').value = 'unknown';
      if (change === 'duplicate') c.env.push({...envEntry(changed, name, 'ZASP_RUNTIME_DATABASE_PROFILE')});
      if (change === 'external-services') c.env.push({name:'ZASP_RUNTIME_SERVICES_ENABLED',value:'true'});
      if (change === 'external-secret') pod(runtime).volumes.push({name:'runtime-services',secret:{secretName:options.runtimeServices.clientSecret}});
      assert.throws(() => validate(changed), /rejected/, `${name}/${change}`);
    }
  }
});

function envEntry(rows, name, key) { return pod(one(rows, 'Deployment', name)).containers[0].env.find(e => e.name === key); }

test('historical deployment does not select the current runtime database profile', async () => {
  const rows = await renderRelease(release);
  assert.equal(env(one(rows, 'Deployment', 'agentsec-event-ingest')).ZASP_RUNTIME_DATABASE_PROFILE, undefined);
  for (const name of runtimeSQLWorkers.filter(name => !name.endsWith('session-index-v2'))) assert.equal(env(one(rows, 'Deployment', name)).ZASP_RUNTIME_DATABASE_PROFILE, undefined, name);
});

test('public verifier materializer copies projected content into an owned regular0400 file', async () => {
  const rows = await renderRelease(release, config());
  const init = pod(one(rows, 'Deployment', 'agentsec-security-agent')).initContainers.find(c => c.name === 'materialize-policy-verifier');
  const root = await mkdtemp(join(tmpdir(), 'zasp-public-verifier-'));
  try {
    await mkdir(join(root, 'source'));
    await mkdir(join(root, 'keys'));
    const value = JSON.stringify({keys:[{key_id:'owned-public-key',public_key:Buffer.alloc(32,42).toString('base64url')}]});
    await writeFile(join(root, 'source', 'actual.json'), value);
    await symlink('actual.json', join(root, 'source', 'policy-keys.json'));
    const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
    const output = join(root, 'keys', 'policy-keys.json');
    const script = init.args[0].replaceAll('/public-keys/policy-keys.json', quote(join(root, 'source', 'policy-keys.json'))).replaceAll('/keys/policy-keys.json', quote(output));
    await promisify(execFile)('/bin/sh', ['-ec', script]);
    const info = await lstat(output);
    assert.ok(info.isFile() && !info.isSymbolicLink());
    assert.equal(info.mode & 0o777, 0o400);
    assert.equal(info.uid, process.getuid());
    assert.equal(await readFile(output, 'utf8'), value);
  } finally {
    await rm(root, {recursive:true,force:true});
  }
});

test('rendered key materializers create separate regular0400 files under both runtime UIDs', {skip: !process.env.ZASP_RUNNER_ASSETS_IMAGE, timeout: 30000}, async () => {
  const rows=await renderRelease(release,config());
  for (const [name,uid] of [['agentsec-security-agent',65532],['agentsec-red-team-adapter',1000]]) {
    const init=pod(one(rows,'Deployment',name)).initContainers.find(c=>c.name==='materialize-worker-keys');
    const script=init.args[0].replaceAll('/forward/','/tmp/forward/').replaceAll('/compensation/','/tmp/compensation/').replaceAll('/keys/','/tmp/keys/');
    const program=`const fs=require('fs'),cp=require('child_process'),assert=require('assert/strict');
      for(const d of ['forward','compensation','keys'])fs.mkdirSync('/tmp/'+d);
      fs.writeFileSync('/tmp/forward/seed',Buffer.alloc(32,1));fs.writeFileSync('/tmp/compensation/seed',Buffer.alloc(32,2));
      cp.execFileSync('/bin/sh',['-ec',process.argv[1]]);
      const a=fs.lstatSync('/tmp/keys/forward.seed'),b=fs.lstatSync('/tmp/keys/compensation.seed');
      assert.ok(a.isFile()&&b.isFile());assert.equal(a.mode&511,256);assert.equal(b.mode&511,256);assert.equal(a.uid,process.getuid());assert.equal(b.uid,process.getuid());assert.notEqual(a.ino,b.ino);console.log('regular0400 distinct files uid='+process.getuid());`;
    const {stdout}=await promisify(execFile)('docker',['run','--rm','--network','none','--read-only','--user',`${uid}:${uid}`,'--tmpfs','/tmp','--entrypoint','/usr/local/bin/node',process.env.ZASP_RUNNER_ASSETS_IMAGE,'-e',program,script],{timeout:10000});
    assert.equal(stdout.trim(),`regular0400 distinct files uid=${uid}`);
  }
});
