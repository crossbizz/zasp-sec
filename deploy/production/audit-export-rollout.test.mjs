import assert from "node:assert/strict";
import test from "node:test";
import { dump, load } from "js-yaml";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { normalizeAuditExports, validateAuditExportResources } from "./audit-export-rollout.mjs";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";

const account = "123456789012";
const normalize = value => normalizeAuditExports(value, account, 52, "precision-intake");
const resource = (rows, kind, name) => rows.find(r => r.kind === kind && r.metadata.name === name);
const container = (rows, name) => resource(rows, "Deployment", name).spec.template.spec.containers[0];
const pod = (rows, name) => resource(rows, "Deployment", name).spec.template.spec;

test("export normalization copies closed configuration and every historical policy", () => {
  const input = auditExportReleaseFixture();
  const result = normalize(input);
  assert.deepEqual(result, input);
  input.policies[0].bucket = "mutated-after-call";
  input.writerRoleArn = "mutated-after-call";
  assert.notEqual(result.writerRoleArn, input.writerRoleArn);
  assert.notEqual(result.policies[0].bucket, input.policies[0].bucket);
  assert.equal(normalize(undefined), undefined);
  for (const phase of ["precision-consumers", "precision-intake"]) assert.ok(normalizeAuditExports(auditExportReleaseFixture(), account, 52, phase));
});

test("export normalization refuses malformed authority before rendering", async t => {
  const changes = {
    null: () => null, disabled: v => ({ ...v, enabled: false }), alias: v => ({ ...v, Enabled: true }),
    missing: v => { delete v.expectedCurrentPolicyID; return v; },
    role: v => ({ ...v, readerRoleArn: v.writerRoleArn }),
    account: v => ({ ...v, publisherRoleArn: v.publisherRoleArn.replace(account, "999999999999") }),
    region: v => ({ ...v, awsRegion: "us-west-2 " }), queue: v => ({ ...v, queueURL: `${v.queueURL}-other` }),
    secret: v => ({ ...v, cursorSecretArn: v.workerDSNSecretArn }),
    principal: v => ({ ...v, workerPrincipal: "zasp_audit_export_worker" }),
    sharedPrincipal: v => ({ ...v, workerPrincipal: v.outboxPrincipal }),
    previous: v => ({ ...v, expectedCurrentPolicyID: v.currentPolicyID }),
    current: v => ({ ...v, currentPolicyID: "pid_52000003-0000-4000-8000-000000000003" }),
    unknownPolicy: v => { v.policies[0].secret = "forbidden"; return v; },
    unsafeInteger: v => { v.policies[0].maximum_export_bytes = 9007199254740992; return v; },
    numericString: v => { v.policies[0].maximum_inflight = "2"; return v; },
    timeout: v => { v.policies[0].capture_timeout_seconds = 121; return v; },
    duplicatePolicy: v => { v.policies.push(v.policies[0]); return v; },
    empty: v => ({ ...v, policies: [] }),
    symbol: v => { v[Symbol("extra")] = true; return v; },
    policyAlias: v => { v.policies[0].Schema = v.policies[0].schema; return v; },
    policyGetter: v => { Object.defineProperty(v.policies[0], "bucket", { enumerable: true, get: () => "owned-bucket" }); return v; },
    arrayProperty: v => { v.policies.secret = "forbidden"; return v; },
  };
  for (const [name, change] of Object.entries(changes)) await t.test(name, () => assert.throws(() => normalize(change(auditExportReleaseFixture())), /release rejected/));
  for (const [schema, phase] of [[51, "precision-intake"], [50, "query"], [52, "query"]]) assert.throws(() => normalizeAuditExports(auditExportReleaseFixture(), account, schema, phase), /release rejected/);
});

test("normalization retains explicit prior selection and safe boundary values", () => {
  const input = auditExportReleaseFixture();
  input.expectedCurrentPolicyID = "pid_52000003-0000-4000-8000-000000000003";
  input.policies[0].maximum_export_bytes = Number.MAX_SAFE_INTEGER;
  input.policies[0].maximum_retained_bytes = Number.MAX_SAFE_INTEGER;
  input.policies[0].maximum_inflight = 2147483647;
  input.policies[0].capture_timeout_seconds = 1;
  input.policies[0].kms_key_arn = input.policies[0].kms_key_arn.replace("us-west-2", "us-east-1");
  assert.deepEqual(normalize(input), input);
});

test("actual export manifests are pinned to independent expectations and reject authority mutations", async t => {
  const expected = auditExportReleaseFixture();
  const rendered = await renderRelease(release, { schemaVersion: 52, sessionSearchPhase: "precision-intake", auditExports: structuredClone(expected) });
  assert.doesNotThrow(() => validateAuditExportResources(rendered, expected));
  const mutations = {
    missingWorker: r => r.splice(r.findIndex(v => v.kind === "Deployment" && v.metadata.name === "zasp-audit-export-worker"), 1),
    duplicateWorker: r => r.push(structuredClone(resource(r, "Deployment", "zasp-audit-export-worker"))),
    workerNamespace: r => { resource(r, "Deployment", "zasp-audit-export-worker").metadata.namespace = "other-namespace"; },
    serviceAccountNamespace: r => { resource(r, "ServiceAccount", "zasp-audit-export-outbox").metadata.namespace = "other-namespace"; },
    providerNamespace: r => { resource(r, "SecretProviderClass", "zasp-audit-export-worker-secrets").metadata.namespace = "other-namespace"; },
    hostNetwork: r => { pod(r, "zasp-audit-export-worker").hostNetwork = true; },
    hostPID: r => { pod(r, "zasp-audit-export-worker").hostPID = true; },
    hostIPC: r => { pod(r, "zasp-audit-export-outbox").hostIPC = true; },
    podRoot: r => { pod(r, "zasp-audit-export-worker").securityContext.runAsUser = 0; },
    privileged: r => { container(r, "zasp-audit-export-worker").securityContext.privileged = true; },
    addedCapability: r => { container(r, "zasp-audit-export-worker").securityContext.capabilities.add = ["SYS_ADMIN"]; },
    internalPort: r => { container(r, "zasp-audit-export-worker").ports[0].containerPort = 8082; },
    hostPort: r => { container(r, "zasp-audit-export-worker").ports[0].hostPort = 8081; },
    workerMode: r => { container(r, "zasp-audit-export-worker").env[0].value = "runtime-index"; },
    workerShell: r => { container(r, "zasp-audit-export-worker").args = ["/bin/true"]; },
    workerEnvFrom: r => { container(r, "zasp-audit-export-worker").envFrom = [{ secretRef: { name: "ambient" } }]; },
    workerPolicy: r => { container(r, "zasp-audit-export-worker").env.find(e => e.name.endsWith("POLICIES_JSON")).value = "[]"; },
    workerToken: r => { pod(r, "zasp-audit-export-worker").volumes[1].projected.sources[0].serviceAccountToken.audience = "other"; },
    workerMount: r => { container(r, "zasp-audit-export-worker").volumeMounts[0].readOnly = false; },
    role: r => { resource(r, "ServiceAccount", "zasp-audit-export-worker").metadata.annotations["eks.amazonaws.com/role-arn"] = expected.readerRoleArn; },
    outboxPolicies: r => { container(r, "zasp-audit-export-outbox").env.push({ name: "ZASP_AUDIT_EXPORT_POLICIES_JSON", value: JSON.stringify(expected.policies) }); },
    duplicateEnv: r => { container(r, "agentsec-api").env.push({ name: "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", value: expected.writerRoleArn }); },
    apiCursorShell: r => { container(r, "agentsec-api").args[0] = container(r, "agentsec-api").args[0].replace("audit-export-cursor-signing-key", "other-key"); },
    apiCursorDuplicate: r => { container(r, "agentsec-api").args[0] = `export ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY=raw\n${container(r, "agentsec-api").args[0]}`; },
    apiToken: r => { pod(r, "agentsec-api").volumes.find(v => v.name === "connector-web-identity").projected.sources[0].serviceAccountToken.audience = "other"; },
    migrationCommand: r => { resource(r, "Job", "agentsec-schema-v52").spec.template.spec.containers[0].args = ["/bin/true"]; },
    migrationPolicy: r => { resource(r, "Job", "agentsec-schema-v52").spec.template.spec.containers[0].env.find(e => e.name === "ZASP_AUDIT_EXPORT_POLICY_ID").value = expected.policies[0].policy_id; },
    secretObject: r => { const p = resource(r, "SecretProviderClass", "zasp-audit-export-worker-secrets"); p.spec.secretObjects = [{ secretName: "leak", data: [{ objectName: "postgres-dsn", key: "raw" }] }]; },
    duplicateAlias: r => { const p = resource(r, "SecretProviderClass", "zasp-audit-export-worker-secrets"); const objects = load(p.spec.parameters.objects); objects.push(objects[0]); p.spec.parameters.objects = dump(objects); },
    webLeak: r => { container(r, "web").env.push({ name: "ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY", value: "raw" }); },
    webMount: r => { pod(r, "web").volumes = [{ name: "leak", csi: { volumeAttributes: { secretProviderClass: "zasp-audit-export-worker-secrets" } } }]; },
    hiddenSidecar: r => { pod(r, "web").initContainers = [{ name: "leak", env: [{ name: "ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN", value: expected.writerRoleArn }] }]; },
    apiWorkerCredential: r => { container(r, "agentsec-api").env.push({ name: "AWS_ROLE_ARN", value: expected.writerRoleArn }); },
    apiWorkerMount: r => { pod(r, "agentsec-api").volumes.push({ name: "leak", csi: { volumeAttributes: { secretProviderClass: "zasp-audit-export-worker-secrets" } } }); },
    aliasMount: r => { container(r, "agentsec-api").volumeMounts.push({ name: "runtime-secrets", mountPath: "/leak", readOnly: true }); },
    cursorSync: r => { const api = pod(r, "agentsec-api").volumes.find(v => v.name === "runtime-secrets").csi.volumeAttributes.secretProviderClass; resource(r, "SecretProviderClass", api).spec.secretObjects[0].data.push({ objectName: "audit-export-cursor-signing-key", key: "RAW" }); },
    secretAlias: r => { const api = pod(r, "agentsec-api").volumes.find(v => v.name === "runtime-secrets").csi.volumeAttributes.secretProviderClass; const p = resource(r, "SecretProviderClass", api); const entries = load(p.spec.parameters.objects); entries.push({ objectName: expected.cursorSecretArn, objectType: "secretsmanager", objectAlias: "secret-copy" }); p.spec.parameters.objects = dump(entries); },
  };
  for (const [name, mutate] of Object.entries(mutations)) await t.test(name, () => { const changed = structuredClone(rendered); mutate(changed); assert.throws(() => validateAuditExportResources(changed, expected), /release rejected/); });
  await t.test("absent configuration rejects enabled resources", () => assert.throws(() => validateAuditExportResources(rendered, undefined), /release rejected/));
});

test("absent configuration rejects renamed export consumers and direct Secret settings", () => {
  assert.doesNotThrow(() => validateAuditExportResources([], undefined));
  for (const resource of [
    { kind: "Deployment", metadata: { name: "unrelated" }, spec: { template: { spec: { containers: [{ env: [{ name: "ZASP_WORKER_MODE", value: "audit-export" }] }] } } } },
    { kind: "Secret", metadata: { name: "unrelated" }, stringData: { ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY: "forbidden" } },
  ]) assert.throws(() => validateAuditExportResources([resource], undefined), /release rejected/);
});
