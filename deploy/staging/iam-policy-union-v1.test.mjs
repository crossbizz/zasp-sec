import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateUnion, parseMockPlan, verifyMockPlan, retentionIndexRequests } from './iam-policy-union-v1.mjs';
const doc = (...Statement) => ({ Version: '2012-10-17', Statement });
const allow = (Action, Resource = '*', Condition) => ({ Effect: 'Allow', Action, Resource, ...(Condition ? { Condition } : {}) });
const request = { action: 's3:DeleteObject', resource: 'arn:aws:s3:::owned/organizations/example/object', context: {} };
test('an unrelated grant in the SECOND policy participates in the union', () => {
 assert.equal(evaluateUnion([doc(allow('s3:GetObject')), doc(allow('s3:DeleteObject'))], request), 'allowed');
});
test('explicit deny overrides every identity Allow, regardless of ordering', () => {
 const denial = doc({ Effect: 'Deny', Action: 's3:Delete*', Resource: '*' });
 for (const policies of [[doc(allow('s3:*')), denial], [denial, doc(allow('s3:*'))]]) assert.equal(evaluateUnion(policies, request), 'denied');
});
test('missing and wrong contexts deny; values are OR and condition keys are AND', () => {
 const policies = [doc(allow('kms:Decrypt', '*', { StringEquals: { 'kms:ViaService': 's3.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:s3:arn': ['arn:aws:s3:::owned', 'arn:aws:s3:::second'] } }))];
 const r = { action: 'kms:Decrypt', resource: 'arn:aws:kms:us-west-2:000000000000:key/test', context: {} };
 assert.equal(evaluateUnion(policies, r), 'denied');
 assert.equal(evaluateUnion(policies, { ...r, context: { 'kms:ViaService': 's3.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:s3:arn': 'arn:aws:s3:::owned' } }), 'allowed');
 assert.equal(evaluateUnion(policies, { ...r, context: { 'kms:ViaService': 'ec2.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:s3:arn': 'arn:aws:s3:::owned' } }), 'denied');
});
test('StringLike and ArnLike retain case-sensitive resource matching', () => {
 const policies = [doc(allow('kms:Decrypt', '*', { ArnLike: { 'kms:EncryptionContext:SecretARN': 'arn:aws:secretsmanager:us-west-2:000000000000:secret:owned/*' } }))];
 for (const [value, expected] of [['owned/one', 'allowed'], ['Owned/one', 'denied'], ['foreign/one', 'denied']]) assert.equal(evaluateUnion(policies, { action: 'KMS:decrypt', resource: '*', context: { 'kms:EncryptionContext:SecretARN': `arn:aws:secretsmanager:us-west-2:000000000000:secret:${value}` } }), expected);
});
for (const field of ['NotAction', 'NotResource', 'Principal']) test(`unsupported ${field} refuses even if action does not match`, () => {
 assert.throws(() => evaluateUnion([doc({ ...allow('unrelated:Read'), [field]: '*' })], request), /unsupported/);
});
for (const operator of ['StringEqualsIfExists', 'ForAllValues:StringEquals', 'Null', 'Bool']) test(`unsupported ${operator} refuses`, () => {
 assert.throws(() => evaluateUnion([doc(allow('unrelated:Read', '*', { [operator]: { 'kms:ViaService': 'x' } }))], request), /unsupported/);
});
test('malformed or unknown policy/context shapes refuse rather than become default denial', () => {
 for (const p of [{ Version: 'wrong', Statement: [] }, doc(allow([], '*')), doc(allow('*', [], {})), doc(allow('*', '*', { StringEquals: { unknown: 'value' } }))]) assert.throws(() => evaluateUnion([p], request), /policy|unsupported/);
 assert.throws(() => evaluateUnion([doc(allow('*'))], { ...request, context: { 'kms:ViaService': ['x'] } }), /context/);
});
test('complete mock intake refuses empty, truncated, errored, repeated or unbound inputs', () => {
 for (const input of ['', '{', JSON.stringify({ type: 'test_summary', test_summary: { status: 'fail' } })]) assert.throws(() => parseMockPlan(input), /mock|JSON/);
 assert.throws(() => verifyMockPlan({ resource_changes: [] }), /schema|format|roster/);
});
test('duplicate JSON keys refuse before any last-key-wins interpretation', () => {
 assert.throws(() => parseMockPlan('{"type":"test_summary","type":"test_plan"}'), /duplicate JSON key/);
});
test('unsupported variable expansion and malformed action/resources refuse', () => {
 for (const policy of [doc(allow('s3:GetObject', 'arn:aws:s3:::owned/${aws:username}/*')), doc(allow('missingcolon', '*')), doc(allow('*', 'not-an-arn'))]) assert.throws(() => evaluateUnion([policy], request), /unsupported|policy/);
});
import fs from 'node:fs';
test('existing CI IAM predecessor filters and pinned readonly initialization remain, and actual mock-plan feeds the verifier', () => {
 const workflow = fs.readFileSync(new URL('../../.github/workflows/runnable-ui.yml', import.meta.url), 'utf8');
 assert.match(workflow, /init -backend=false -input=false -lockfile=readonly/);
 assert.match(workflow, /test -filter=tests\/session_search_iam\.tftest\.hcl -filter=tests\/test_reconciler_iam\.tftest\.hcl -var-file=release\.tfvars -no-color/);
 assert.match(workflow, /node --test deploy\/staging\/iam-policy-union-v1\.test\.mjs/);
 assert.match(workflow, /test -filter=tests\/iam_policy_union\.tftest\.hcl -json -verbose -no-color > "\$task_tf_dir\/iam-policy-union\.jsonl"\s+node --max-old-space-size=512 deploy\/staging\/iam-policy-union-v1\.test\.mjs --plan "\$task_tf_dir\/iam-policy-union\.jsonl"\s+node deploy\/staging\/iam-policy-union-v1\.mjs --plan "\$task_tf_dir\/iam-policy-union\.jsonl"/);
});

// Evaluate the real new Terraform source statements, rather than a rewritten
// fixture permission list. This is source/evaluator coverage; provider-owned
// rendering and complete policy unions are verified by the --plan group below.
const retentionDomain = 'arn:aws:es:us-west-2:000000000000:domain/retention-source-test';
function retentionSourcePolicies() {
 const source = fs.readFileSync(new URL('./main.tf', import.meta.url), 'utf8');
 const start = source.indexOf('# Retention cleanup remains confined');
 const end = source.indexOf('contains(["correlation", "projection"]', start);
 assert.ok(start >= 0 && end > start);
 const matches = [...source.slice(start, end).matchAll(/Action = \[([^\]]+)\]\s*Resource = \[([^\]]+)\]/g)];
 assert.equal(matches.length, 2);
 return [doc(...matches.map(match => allow([...match[1].matchAll(/"([^"]+)"/g)].map(m => m[1]), [...match[2].matchAll(/"([^"]+)"/g)].map(m => m[1].replace('${aws_opensearch_domain.events.arn}', retentionDomain)))))];
}
test('retention actual source admits fixed search/hash documents and excludes unrelated paths and methods', () => {
 const policies = retentionSourcePolicies();
 const own = retentionIndexRequests(retentionDomain).filter(r => r.role === 'aws_iam_role.runtime["index"]');
 for (const row of own) assert.equal(evaluateUnion(policies, row.request), row.expected, row.label);
 // IAM ? constrains width, not alphabet. The concrete SDK validates hash IDs.
 assert.equal(evaluateUnion(policies, { action: 'es:ESHttpDelete', resource: `${retentionDomain}/zasp-runtime-sessions-v2/_doc/${'z'.repeat(64)}`, context: {} }), 'allowed');
});
test('retention positive and negative requests detect missing targets and broadened DELETE authority', () => {
 const policies = retentionSourcePolicies();
 const own = retentionIndexRequests(retentionDomain).filter(r => r.role === 'aws_iam_role.runtime["index"]');
 const mismatches = value => own.filter(row => evaluateUnion(value, row.request) !== row.expected);
 const removed = structuredClone(policies); removed[0].Statement[0].Resource.pop();
 assert.ok(mismatches(removed).some(r => r.label.startsWith('retention:search:')));
 const widened = structuredClone(policies); widened[0].Statement[1].Resource.push(`${retentionDomain}/*`);
 assert.ok(mismatches(widened).some(r => r.label.includes('no-other-document')));
 assert.ok(mismatches(widened).some(r => r.label.includes('no-foreign-index')));
});

// CI explicitly supplies its complete fixed mock-plan capture. Default unit tests require no providers or private fixtures.
if (process.argv.length > 2) {
 if (process.argv.length !== 4 || process.argv[2] !== '--plan') throw new Error('IAM controls require --plan complete Terraform JSONL');
 const bytes = fs.readFileSync(process.argv[3]);
 const input = bytes.toString('utf8');
 assert.ok(Buffer.from(input).equals(bytes), 'mock input must be UTF-8');
 parseMockPlan(input);
const original = input.trimEnd().split('\n').map(line => JSON.parse(line));
const p = original.find(e => e.type === 'test_plan').test_plan;
const events = () => original.map(e => e.type === 'test_plan' ? { ...e, test_plan: { ...p, resource_changes: structuredClone(p.resource_changes) } } : structuredClone(e));
const row = (e, address) => e.find(x => x.type === 'test_plan').test_plan.resource_changes.find(x => x.address === address);
const policy = (e, address, change) => { const r = row(e, address); const value = JSON.parse(r.change.after.policy); change(value); r.change.after.policy = JSON.stringify(value); };

function refuse(name, mutate, reason) {
 test(`captured mock plan: ${name}`, () => {
  const e = events(); mutate(e);
  assert.throws(() => verifyMockPlan(parseMockPlan(e.map(x => JSON.stringify(x)).join('\n') + '\n')), reason);
 });
}
test('captured mock plan: complete distinct workload unions pass independently specified requests', () => {
 assert.equal(verifyMockPlan(parseMockPlan(input)).decisionCases, 2859);
});
refuse('unlisted inline policy with unrelated-write Allow refuses', e => {
 const rows = e.find(x => x.type === 'test_plan').test_plan.resource_changes;
 const r = structuredClone(row(e, 'aws_iam_role_policy.audit_exports["writer"]'));
 r.address = 'aws_iam_role_policy.unlisted_audit_export_write';
 r.change.after.policy = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:DeleteObject', Resource: '*' }] });
 rows.push(r);
}, /resource roster/);
const secondary = 'aws_iam_role_policy.audit_export_secrets["postgres-audit-export-worker-dsn"]';
refuse('retention search removal cannot silently disable a fixed cleanup target', e => policy(e, 'aws_iam_role_policy.runtime["index"]', v => {
 const statement = v.Statement.find(s => s.Action.includes('es:ESHttpPost') && Array.isArray(s.Resource) && s.Resource.some(r => r.endsWith('/zasp-runtime-sessions-v2/_search')));
 assert.ok(statement); statement.Resource = statement.Resource.filter(r => !r.endsWith('/zasp-runtime-sessions-v2/_search'));
}), /decision matrix/);
refuse('retention DELETE widening admits forbidden schema and foreign-index documents', e => policy(e, 'aws_iam_role_policy.runtime["index"]', v => {
 const statement = v.Statement.find(s => s.Action.includes('es:ESHttpDelete'));
 assert.ok(statement); statement.Resource = [`${row(e, 'aws_opensearch_domain.events').change.after.arn}/*`];
}), /decision matrix/);
refuse('retention DELETE in another role secondary policy participates in the complete union', e => policy(e, secondary, v => v.Statement.push({ Effect: 'Allow', Action: 'es:ESHttpDelete', Resource: `${row(e, 'aws_opensearch_domain.events').change.after.arn}/zasp-runtime-sessions-v2/_doc/${'a'.repeat(64)}` })), /decision matrix/);
refuse('SECOND existing inline policy unrelated-write Allow participates in union', e => policy(e, secondary, v => v.Statement.push({ Effect: 'Allow', Action: 's3:DeleteObject', Resource: '*' })), /decision matrix/);
refuse('audit writer SSE condition removal permits missing-context write', e => policy(e, 'aws_iam_role_policy.audit_exports["writer"]', v => { delete v.Statement.find(s => s.Action.includes('s3:PutObject')).Condition; }), /decision matrix/);
refuse('SECOND secret KMS context removal permits foreign context', e => policy(e, secondary, v => { delete v.Statement.find(s => s.Action.includes('kms:Decrypt')).Condition; }), /decision matrix/);
refuse('unsupported condition in nonmatching SECOND inline row', e => policy(e, secondary, v => v.Statement.push({ Effect: 'Allow', Action: 's3:ListBucket', Resource: '*', Condition: { StringEqualsIfExists: { 'kms:ViaService': 'x' } } })), /unsupported/);
refuse('unresolved managed attachment to workload cannot be assumed denied', e => { const r = row(e, 'aws_iam_role_policy_attachment.eks_cluster'); r.change.after.role = row(e, 'aws_iam_role.audit_exports["writer"]').change.after.id; }, /managed attachment/);
refuse('extra LOCAL policy plus attachment cannot bypass closed roster', e => { const rows = e.find(x => x.type === 'test_plan').test_plan.resource_changes; rows.push({ ...structuredClone(row(e, 'aws_iam_policy.attack_lab_runner_test_boundary')), address: 'aws_iam_policy.unlisted' }); rows.push({ ...structuredClone(row(e, 'aws_iam_role_policy_attachment.eks_cluster')), address: 'aws_iam_role_policy_attachment.unlisted' }); }, /resource roster/);
refuse('embedded inline role policy refuses unlisted authority', e => { row(e, 'aws_iam_role.api').change.after.inline_policy = [{ name: 'hidden', policy: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}' }]; }, /embedded policy/);
refuse('unresolved managed_policy_arns refuses', e => { row(e, 'aws_iam_role.api').change.after.managed_policy_arns = ['arn:aws:iam::aws:policy/AdministratorAccess']; }, /embedded policy/);
refuse('unknown policy bytes refuses', e => { row(e, secondary).change.after_unknown.policy = true; }, /unbound inline/);
refuse('duplicate policy JSON key refuses', e => { row(e, secondary).change.after.policy = '{"Version":"2012-10-17","Statement":[],"Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]}'; }, /policy JSON/);
refuse('workload role alias refuses before union assignment', e => { row(e, 'aws_iam_role.api_connectors').change.after.id = row(e, 'aws_iam_role.api').change.after.id; }, /fixture identity/);
refuse('unexpected optional workload role refuses', e => { const rows = e.find(x => x.type === 'test_plan').test_plan.resource_changes; rows.push({ ...structuredClone(row(e, 'aws_iam_role.api')), address: 'aws_iam_role.compliance_worker[0]' }); }, /resource roster/);
refuse('missing role/policy resource refuses', e => { const rows = e.find(x => x.type === 'test_plan').test_plan.resource_changes; rows.splice(rows.findIndex(x => x.address === secondary), 1); }, /resource roster/);
refuse('unbound policy role refuses', e => { row(e, secondary).change.after.role = 'unbound'; }, /unbound inline/);
refuse('foreign OIDC service account refuses', e => { const r = row(e, 'aws_iam_role.api'); const v = JSON.parse(r.change.after.assume_role_policy); v.Statement[0].Condition.StringEquals['oidc.eks.us-west-2.amazonaws.com/id/staging-union:sub'] = 'system:serviceaccount:foreign:api'; r.change.after.assume_role_policy = JSON.stringify(v); }, /OIDC trust/);
refuse('runner deny-all boundary mutation refuses', e => { row(e, 'aws_iam_policy.attack_lab_runner_test_boundary').change.after.policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'; }, /deny-all boundary/);
refuse('errored mock summary refuses', e => { e.find(x => x.type === 'test_summary').test_summary.errored = 1; }, /completion/);
refuse('duplicate full plan event refuses', e => { e.push(e.find(x => x.type === 'test_plan')); }, /completion/);
refuse('unsupported provider schema refuses', e => { e.find(x => x.type === 'test_plan').test_plan.provider_schemas = {}; }, /schema/);
refuse('unsupported starting run progress refuses', e => { e.find(x => x.type === 'test_run' && x.test_run.progress === 'starting').test_run.progress = 'unsupported'; }, /lifecycle|completion/);
refuse('reversed starting/completed run lifecycle refuses', e => { const indices = e.map((x, i) => x.type === 'test_run' ? i : -1).filter(i => i !== -1); [e[indices[0]], e[indices[1]]] = [e[indices[1]], e[indices[0]]]; }, /lifecycle|completion/);
refuse('tool/version event drift refuses', e => { e.find(x => x.type === 'version').terraform = '1.15.9'; }, /Terraform version/);
refuse('unknown fixture identity cannot coexist with claimed known value', e => { row(e, 'aws_iam_role.api').change.after_unknown.arn = true; }, /unknown fixture/);
refuse('secondary policy type masking cannot remove it from union', e => { row(e, secondary).type = 'aws_s3_bucket'; }, /resource type/);
refuse('unknown boundary policy cannot become evaluated known bytes', e => { row(e, 'aws_iam_policy.attack_lab_runner_test_boundary').change.after_unknown.policy = true; }, /unknown boundary/);

}

test('independent retention IAM workflow reaches the exact locked mock-plan sequence without release authority', () => {
 const file = new URL('../../.github/workflows/retention-iam-acceptance.yml', import.meta.url);
 const validate = source => {
  assert.match(source, /^permissions:\n {2}contents: read\n\njobs:\n/m);
  assert.doesNotMatch(source, /\bneeds:|continue-on-error:|pull_request_target:|id-token:|secrets:|environment:|secrets\.|configure-aws-credentials|terraform\s+(?:apply|destroy)|production-release-gate/);
  const actions = [...source.matchAll(/uses: ([^\s]+)(?:\s|$)/g)].map(m => m[1]);
  assert.deepEqual(actions, ['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020']);
  assert.match(source, /persist-credentials: false/);
  assert.match(source, /node-version: 22\.23\.1/);
  for (const path of ['.github/workflows/retention-iam-acceptance.yml', 'deploy/staging/*.tf', 'deploy/staging/main.tf', 'deploy/staging/versions.tf', 'deploy/staging/.terraform.lock.hcl', 'deploy/staging/release.tfvars', 'deploy/staging/iam-policy-union-v1.mjs', 'deploy/staging/iam-policy-union-v1.test.mjs', 'deploy/staging/tests/*iam*.tftest.hcl']) assert.equal(source.split(`- '${path}'`).length - 1, 2, path);
  // These actual prior CI commands include the predecessor assertions and
  // complete captured-plan mutation controls. Keep their ordering and bytes.
  const original = fs.readFileSync(new URL('../../.github/workflows/runnable-ui.yml', import.meta.url), 'utf8');
  const begin = original.indexOf('          task_tf_dir=$(mktemp -d "${RUNNER_TEMP}/zasp-terraform.XXXXXX")');
  const end = original.indexOf('\n      - name:', begin);
  assert.ok(begin > 0 && end > begin);
  assert.ok(source.includes(original.slice(begin, end)));
  assert.match(source, /test "\$\(node --version\)" = v22\.23\.1/);
  assert.match(source, /git diff --exit-code -- deploy\/staging\/\.terraform\.lock\.hcl/);
 };
 const source = fs.readFileSync(file, 'utf8');
 validate(source);
 for (const mutate of [
  s => s.replace('contents: read', 'contents: write'),
  s => s.replace('contents: read', 'contents: read\n  packages: write'),
  s => s.replace('runs-on: ubuntu-24.04', 'needs: verify\n    runs-on: ubuntu-24.04'),
  s => s.replace('persist-credentials: false', 'persist-credentials: true'),
  s => s.replace('node-version: 22.23.1', 'node-version: 24'),
  s => s.replace('-backend=false', '-backend=true'),
  s => s.replace('-lockfile=readonly', '-lockfile=update'),
  s => s.replace('d25ce7b6902013ad905db3d2eab0be4cd905887fe88b81a6171b8d5503c31f3d', '0'.repeat(64)),
  s => s.replace('node --max-old-space-size=512 deploy/staging/iam-policy-union-v1.test.mjs --plan', 'node deploy/staging/iam-policy-union-v1.mjs --plan'),
  s => s + '\n# secrets.RUNTIME_TOKEN\n',
 ]) assert.throws(() => validate(mutate(source)));
});
