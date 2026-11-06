import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {normalizeOptionalEgress, validateOptionalEgressResources} from './optional-egress-profile.mjs';
import {validateRenderedRelease} from './release-contract.mjs';

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const helper = source('../staging/product/templates/_optional-egress.tpl');
const workloads = source('../staging/product/templates/workloads.yaml');
const profile={profile:'canonical61-temporal78-authorization79-80-worker-v1',executorDSNSecret:'executor',compensationDSNSecret:'compensation',projectorDSNSecret:'projector',adapterDSNSecret:'adapter'};
const runtime={enabled:true,clientSecret:'runtime'};
const enabled=()=>({enabled:true,profileChecksum:'a'.repeat(64),settlementDSNSecret:'optional-settlement'});

test('release input preserves an explicit closed shared recipe and rejects orphan or aliased configuration',()=>{
  assert.equal(normalizeOptionalEgress(undefined),undefined);
  assert.deepEqual(normalizeOptionalEgress(enabled(),profile,runtime),enabled());
  assert.deepEqual(normalizeOptionalEgress({enabled:false,profileChecksum:'',settlementDSNSecret:''}),{enabled:false,profileChecksum:'',settlementDSNSecret:''});
  for(const mutate of [v=>delete v.enabled,v=>v.enabled='true',v=>v.profileChecksum='',v=>v.profileChecksum='F'.repeat(64),v=>v.settlementDSNSecret='executor',v=>v.settlementDSNSecret='runtime',v=>v.activate=true,v=>v.enabled=false]) {
    const value=enabled();mutate(value);assert.throws(()=>normalizeOptionalEgress(value,profile,runtime));
  }
  assert.throws(()=>normalizeOptionalEgress(enabled(),undefined,runtime));
  assert.throws(()=>normalizeOptionalEgress(enabled(),profile,{enabled:false}));
  const release=source('./release-contract.mjs');
  assert.match(release,/normalizeOptionalEgress\(options.optionalEgress, authorizationTemporal, runtimeServices\)/);
  assert.match(release,/\.\.\.\(optionalEgress \? \{ optionalEgress \} : \{\}\)/);
  assert.match(release,/authorizationTemporal, optionalEgress, value.securityAgentPlanner.egressCIDRs\)/);
});

test('rendered policy refuses missing planner enforcement, DSN leakage and widened provider egress',()=>{
  const config=enabled(),cidrs=['192.0.2.80/28'];
  const env=()=>[{name:'ZASP_OPTIONAL_EGRESS_ENABLED',value:'true'},{name:'ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM',value:config.profileChecksum}];
  const deployment=(name,entries)=>({kind:'Deployment',metadata:{name},spec:{template:{spec:{containers:[{env:entries}]}}}});
  const api=deployment('agentsec-api',[...env(),{name:'ZASP_OPTIONAL_EGRESS_SETTLEMENT_POSTGRES_DSN',valueFrom:{secretKeyRef:{name:config.settlementDSNSecret,key:'postgres-dsn'}}}]);
  const worker=deployment('agentsec-security-agent',env());
  const network={kind:'NetworkPolicy',metadata:{name:'api-optional-openrouter-egress'},spec:{podSelector:{matchLabels:{'app.kubernetes.io/name':'agentsec-api'}},policyTypes:['Egress'],egress:cidrs.map(cidr=>({to:[{ipBlock:{cidr}}],ports:[{protocol:'TCP',port:443}]}))}};
  const base=[api,worker,network];
  validateOptionalEgressResources(base,config,cidrs);
  for(const mutate of [r=>r[1].spec.template.spec.containers[0].env.pop(),r=>r[1].spec.template.spec.containers[0].env.push(api.spec.template.spec.containers[0].env[2]),r=>r[0].spec.template.spec.containers[0].env.push(env()[0]),r=>r[0].spec.template.spec.containers[0].env[2].valueFrom.secretKeyRef.name='executor',r=>r[2].spec.egress[0].to[0].ipBlock.cidr='0.0.0.0/0',r=>r[2].spec.egress[0].ports[0].port=80,r=>r.push(deployment('foreign-consumer',env())),r=>r[1].spec.template.spec.volumes=[{name:'leaked',secret:{secretName:config.settlementDSNSecret}}]]) {
    const resources=structuredClone(base);mutate(resources);assert.throws(()=>validateOptionalEgressResources(resources,config,cidrs));
  }
  assert.throws(()=>validateOptionalEgressResources(base,undefined,cidrs));
  validateOptionalEgressResources([deployment('agentsec-api',[]),deployment('agentsec-security-agent',[])],undefined);
});

test('standalone release validation rejects simultaneously widened expected and rendered provider ranges',()=>{
  const validate=cidrs=>validateRenderedRelease([{kind:'NetworkPolicy',metadata:{name:'api-optional-openrouter-egress'},spec:{egress:cidrs?.map(cidr=>({to:[{ipBlock:{cidr}}],ports:[{protocol:'TCP',port:443}]}))}}], '123456789012',61,'precision-intake',undefined,undefined,undefined,undefined,undefined,'active',profile,enabled(),cidrs);
  for(const cidrs of [undefined,[],['0.0.0.0/0'],['10.0.0.0/8'],['not-a-cidr'],['192.0.2.80/28','192.0.2.80/28']]) assert.throws(()=>validate(cidrs),/optional egress provider CIDRs rejected/);
  // Narrow reviewed ranges advance to the other, still-required full release
  // guards; this deliberately incomplete resource set cannot be accepted.
  assert.throws(()=>validate(['192.0.2.80/28']),error=>error.message!=='optional egress provider CIDRs rejected');
});

test('API and every shipped planner share policy selection while captured settlement remains API-only', () => {
  assert.match(source('../staging/product/values.yaml'), /optionalEgress:\n(?:.*\n)*? {2}enabled: false\n {2}profileChecksum: ""\n(?:.*\n)*? {2}settlementDSNSecret: ""/);
  assert.match(workloads, /^\{\{- include "zasp.optionalEgress.validate" \./);
  assert.equal((workloads.match(/include "zasp.optionalEgress.env"/g) ?? []).length, 2);
  assert.equal((workloads.match(/include "zasp.optionalEgress.apiEnv"/g) ?? []).length, 1);
  const planner = workloads.slice(workloads.indexOf('name: ZASP_WORKER_MODE, value: "security-agent"'));
  assert.match(planner, /include "zasp.optionalEgress.env" \./);
  assert.doesNotMatch(planner, /optionalEgress.apiEnv|ZASP_OPTIONAL_EGRESS_SETTLEMENT_POSTGRES_DSN/);
  assert.match(helper, /secretKeyRef: \{ name: .*settlementDSNSecret.*key: postgres-dsn/);
  assert.doesNotMatch(helper, /agentsec-migrate|activate_controlled|register_principal/);
});

test('AI credential IAM grants only read and KMS decrypt for the dedicated namespace', () => {
  const tf = source('../staging/main.tf');
  const policy = tf.slice(tf.indexOf('resource "aws_iam_role_policy" "api_connectors"'), tf.indexOf('resource "aws_iam_role" "worker"'));
  const path = 'arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.connector_secret_root}/ai/openrouter/*';
  assert.equal(policy.split(path).length - 1, 2);
  const start = policy.indexOf(path);
  assert.match(policy.slice(policy.lastIndexOf('{', start), start), /Resource/);
  assert.match(policy.slice(start - 100, start), /Action\s*= \["secretsmanager:GetSecretValue"\]/);
  const decrypt = policy.slice(start, policy.indexOf(path, start + path.length) + path.length);
  assert.match(decrypt, /Action\s*= \["kms:Decrypt"\]/);
  assert.match(decrypt, /Resource = aws_kms_key.connector_oauth.arn/);
  assert.match(decrypt, /kms:ViaService.*secretsmanager/);
  assert.match(decrypt, /kms:EncryptionContext:SecretARN/);
  assert.doesNotMatch(decrypt, /CreateSecret|PutSecretValue|DeleteSecret|kms:\*/);
});

test('actual Helm helper refuses incomplete, aliased or legacy enablement', t => {
  const probe = spawnSync('helm', ['version', '--short'], {encoding:'utf8'});
  if (probe.error?.code === 'ENOENT') return t.skip('Helm unavailable: helper and full product rendering remain unverified');
  assert.equal(probe.status, 0);
  const dir = mkdtempSync(join(tmpdir(), 'zasp-optional-egress-chart-'));
  try {
    mkdirSync(join(dir, 'templates'));
    writeFileSync(join(dir, 'Chart.yaml'), 'apiVersion: v2\nname: optional-egress-contract\nversion: 0.1.0\n');
    writeFileSync(join(dir, 'templates', '_optional-egress.tpl'), helper);
    writeFileSync(join(dir, 'templates', 'binding.yaml'), '{{- include "zasp.optionalEgress.validate" . }}\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: binding}\ndata:\n  flag: {{ .Values.optionalEgress.enabled | quote }}\n');
    const base = {profile:'saas',runtimeServices:{enabled:true},network:{securityAgentPlannerEgressCIDRs:['192.0.2.80/28']},authorizationTemporal:{profile:'canonical61-temporal78-authorization79-80-worker-v1',executorDSNSecret:'executor',compensationDSNSecret:'compensation'},optionalEgress:{enabled:true,profileChecksum:'a'.repeat(64),settlementDSNSecret:'optional-settlement'}};
    const render = values => {writeFileSync(join(dir,'values.json'),JSON.stringify(values));return spawnSync('helm',['template','contract',dir,'-f',join(dir,'values.json')],{encoding:'utf8'});};
    assert.equal(render(base).status, 0);
    for (const mutate of [v=>v.optionalEgress.profileChecksum='',v=>v.optionalEgress.settlementDSNSecret='',v=>v.optionalEgress.settlementDSNSecret='executor',v=>v.optionalEgress.enabled='true',v=>v.runtimeServices.enabled=false,v=>v.profile='customer_edge',v=>v.optionalEgress.enabled=false]) {
      const values=structuredClone(base); mutate(values); assert.notEqual(render(values).status,0);
    }
    const disabled=structuredClone(base); disabled.optionalEgress={enabled:false,profileChecksum:'',settlementDSNSecret:''}; assert.equal(render(disabled).status,0);
  } finally {rmSync(dir,{recursive:true,force:true});}
});
