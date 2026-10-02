import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { loadAll } from "js-yaml";

const exec = promisify(execFile);
const template = new URL("../staging/product/templates/audit-exports.yaml", import.meta.url);
const policy = { schema: "audit-export-policy-v1", policy_id: "pid_52000001-0000-4000-8000-000000000001", bucket: "owned-audit-exports", expected_bucket_owner: "123456789012", kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", maximum_export_bytes: 1073741824, maximum_retained_bytes: 10737418240, maximum_inflight: 2, capture_timeout_seconds: 120 };
function fixture() {
  return { network: { postgresCIDR: "10.30.0.0/24" }, monitoring: { enabled: true, namespace: "monitoring" }, connectors: { roleArn: "arn:aws:iam::123456789012:role/connector-reader" }, secrets: { region: "us-east-1" }, profile: "control_plane", schema: { expectedVersion: 52 }, runtime: { sessionSearchPhase: "precision-intake" }, global: { terminationGracePeriodSeconds: 30, productImages: { agentsecWorker: `registry.example/worker@sha256:${"a".repeat(64)}` } }, auditExports: {
    enabled: true, awsRegion: "us-east-1", queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-audit-exports",
    stsCIDRs: ["192.0.2.16/28"], sqsCIDRs: ["192.0.2.32/28"], s3CIDRs: ["198.51.100.0/24"],
    writerRoleArn: "arn:aws:iam::123456789012:role/export-writer", publisherRoleArn: "arn:aws:iam::123456789012:role/export-publisher",
    readerRoleArn: "arn:aws:iam::123456789012:role/export-reader", cursorSecretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:export-cursor-owned",
    workerDSNSecretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:export-worker-owned",
    outboxDSNSecretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:export-outbox-owned", policies: [policy],
    currentPolicyID: policy.policy_id, expectedCurrentPolicyID: "", workerPrincipal: "owned_export_worker", outboxPrincipal: "owned_export_outbox",
  } };
}
async function render(values, api = false) {
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-export-chart-"));
  try {
    await mkdir(path.join(directory, "templates"));
    await writeFile(path.join(directory, "Chart.yaml"), "apiVersion: v2\nname: owned-export-chart\nversion: 0.1.0\n");
    await writeFile(path.join(directory, "templates/audit-exports.yaml"), await readFile(template));
    await writeFile(path.join(directory, "templates/audit-export-network.yaml"), await readFile(new URL("../staging/product/templates/audit-export-network.yaml", import.meta.url)));
    await writeFile(path.join(directory, "templates/audit-export-operations.yaml"), await readFile(new URL("../staging/product/templates/audit-export-operations.yaml", import.meta.url)));
    await writeFile(path.join(directory, "templates/_audit-exports-api.tpl"), await readFile(new URL("../staging/product/templates/_audit-exports-api.tpl", import.meta.url)));
    await writeFile(path.join(directory, "templates/_audit-exports-migration.tpl"), await readFile(new URL("../staging/product/templates/_audit-exports-migration.tpl", import.meta.url)));
    await writeFile(path.join(directory, "templates/migration.yaml"), 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: owned-migration-snippets}\ndata:\n  env: |\n{{ include "zasp.auditExports.migrationEnv" . | indent 4 }}\n  command: |\n{{ include "zasp.auditExports.migrationCommand" . | indent 4 }}\n');
    if (api) {
      await writeFile(path.join(directory, "templates/api.yaml"), 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: owned-api-snippets}\ndata:\n  env: |\n{{ include "zasp.auditExports.apiEnv" . | indent 4 }}\n  objects: |\n{{ include "zasp.auditExports.apiSecretObject" . | indent 4 }}\n  command: |\n{{ include "zasp.auditExports.apiSecretLoad" . | indent 4 }}\n');
    }
    await writeFile(path.join(directory, "values.json"), JSON.stringify(values));
    const { stdout } = await exec("helm", ["template", "owned", directory, "-f", path.join(directory, "values.json")], { timeout: 20000, maxBuffer: 2 ** 20 });
    return loadAll(stdout).filter(Boolean);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
test("direct Helm refuses unsafe endpoint ranges and can disable metric scraping", async () => {
  for (const key of ["stsCIDRs", "sqsCIDRs", "s3CIDRs"]) {
    for (const ranges of [[], ["0.0.0.0/0"], ["127.0.0.1/32"], ["169.254.169.254/32"], ["192.0.2.1/24"], ["192.0.2.0/24", "192.0.2.0/25"], ["192.000.2.0/24"], [true]]) {
      const values = fixture(); values.auditExports[key] = ranges;
      await assert.rejects(render(values), undefined, `${key}: ${JSON.stringify(ranges)}`);
    }
  }
  const values = fixture(); values.monitoring.enabled = false;
  const resources = await render(values);
  assert.equal(resources.filter(r => r.kind === "ServiceMonitor").length, 0);
  assert.equal(resources.filter(r => r.kind === "NetworkPolicy" && r.metadata.name.endsWith("-monitoring")).length, 0);
  assert.equal(resources.filter(r => r.kind === "Service").length, 2);
  assert.equal(resources.filter(r => r.kind === "PodDisruptionBudget").length, 2);
  assert.equal(resources.filter(r => r.kind === "HorizontalPodAutoscaler").length, 2);
  assert.equal(resources.filter(r => r.kind === "PrometheusRule").length, 0);
});
test("export workers render isolated production modes with owned credentials", async () => {
  const resources = await render(fixture());
  const deployments = resources.filter(value => value.kind === "Deployment");
  assert.equal(deployments.length, 2);
  for (const [suffix, mode, roleKey, secretKey] of [["worker", "audit-export", "writerRoleArn", "workerDSNSecretArn"], ["outbox", "audit-export-outbox", "publisherRoleArn", "outboxDSNSecretArn"]]) {
    const name = `zasp-audit-export-${suffix}`;
    const deployment = deployments.find(value => value.metadata.name === name);
    const pod = deployment.spec.template.spec;
    const container = pod.containers[0];
    const env = Object.fromEntries(container.env.map(value => [value.name, value.value]));
    assert.equal(pod.serviceAccountName, name);
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(container.envFrom, undefined);
    assert.equal(env.ZASP_WORKER_MODE, mode);
    assert.equal(env.ZASP_DATABASE_AUTHORITY, suffix === "worker" ? "zasp_audit_export_worker" : "zasp_audit_export_outbox");
    assert.equal(env.ZASP_LEASE_DURATION, "300s");
    assert.equal(env.ZASP_PROVIDER_TIMEOUT, "5s");
    assert.equal(env.ZASP_SHUTDOWN_TIMEOUT, "20s");
    assert.equal(env.ZASP_POLL_INTERVAL, "1s");
    assert.equal(env.ZASP_BATCH_SIZE, "1");
    assert.deepEqual(container.command, ["/bin/sh", "-ec"]);
    assert.deepEqual(container.args, ['export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-export/postgres-dsn)"; exec /app/agentsec-worker']);
    assert.deepEqual(container.env.find(value => value.name === "ZASP_WORKER_ID").valueFrom, { fieldRef: { fieldPath: "metadata.name" } });
    assert.equal(env.ZASP_AUDIT_EXPORT_QUEUE_URL, fixture().auditExports.queueURL);
    assert.equal(env.ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE, "/var/run/secrets/eks.amazonaws.com/serviceaccount/token");
    assert.equal(env.ZASP_AUDIT_EXPORT_READER_ROLE_ARN, undefined);
    assert.equal(env.ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY, undefined);
    assert.equal(env[suffix === "worker" ? "ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN" : "ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN"], fixture().auditExports[roleKey]);
    assert.equal(env[suffix === "worker" ? "ZASP_AUDIT_EXPORT_PUBLISHER_ROLE_ARN" : "ZASP_AUDIT_EXPORT_WRITER_ROLE_ARN"], undefined);
    if (suffix === "worker") assert.deepEqual(JSON.parse(env.ZASP_AUDIT_EXPORT_POLICIES_JSON), [policy]);
    else assert.equal(env.ZASP_AUDIT_EXPORT_POLICIES_JSON, undefined);
    assert.equal(resources.find(value => value.kind === "ServiceAccount" && value.metadata.name === name).metadata.annotations["eks.amazonaws.com/role-arn"], fixture().auditExports[roleKey]);
    const provider = resources.find(value => value.kind === "SecretProviderClass" && value.metadata.name === `${name}-secrets`);
    assert.deepEqual(loadAll(provider.spec.parameters.objects), [[{ objectName: fixture().auditExports[secretKey], objectType: "secretsmanager", objectAlias: "postgres-dsn" }]]);
    assert.deepEqual(container.volumeMounts, [{ name: "database", mountPath: "/var/run/secrets/zasp-export", readOnly: true }, { name: "identity", mountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", readOnly: true }]);
    assert.equal(pod.volumes.find(value => value.name === "database").csi.volumeAttributes.secretProviderClass, `${name}-secrets`);
    assert.deepEqual(pod.volumes.find(value => value.name === "identity").projected.sources, [{ serviceAccountToken: { audience: "sts.amazonaws.com", expirationSeconds: 3600, path: "token" } }]);
    assert.equal(container.securityContext.readOnlyRootFilesystem, true);
    assert.equal(container.readinessProbe.httpGet.path, "/readyz");
  }
});
test("migration selects explicit policy and preserves canonical limits and predecessor", async () => {
  const values = fixture(); values.auditExports.expectedCurrentPolicyID = "pid_52000002-0000-4000-8000-000000000002";
  const data = (await render(values)).find(value => value.metadata.name === "owned-migration-snippets").data;
  const env = Object.fromEntries(loadAll(data.env)[0].map(value => [value.name, value.value]));
  assert.deepEqual(env, {
    ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL: "owned_export_worker", ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL: "owned_export_outbox",
    ZASP_AUDIT_EXPORT_POLICY_ID: policy.policy_id, ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID: values.auditExports.expectedCurrentPolicyID,
    ZASP_AUDIT_EXPORT_BUCKET: policy.bucket, ZASP_AUDIT_EXPORT_EXPECTED_BUCKET_OWNER: policy.expected_bucket_owner, ZASP_AUDIT_EXPORT_KMS_KEY_ARN: policy.kms_key_arn,
    ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES: "1073741824", ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES: "10737418240", ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT: "2", ZASP_AUDIT_EXPORT_CAPTURE_TIMEOUT_SECONDS: "120",
  });
  assert.match(data.command, /up-to-52 && \/app\/agentsec-migrate register-audit-export-api && \/app\/agentsec-migrate register-audit-export-workers && exec \/app\/agentsec-migrate configure-audit-exports/);
  for (const mutate of [v => { v.auditExports.currentPolicyID = ""; }, v => { v.auditExports.currentPolicyID = v.auditExports.expectedCurrentPolicyID; }, v => { v.auditExports.workerPrincipal = v.auditExports.outboxPrincipal; }, v => { v.auditExports.policies.push({ ...policy }); }, v => { v.auditExports.policies[0] = { ...policy, maximum_inflight: 1.5 }; }, v => { v.auditExports.policies[0] = { ...policy, maximum_export_bytes: 9007199254740992 }; }]) {
    const invalid = structuredClone(values); mutate(invalid); await assert.rejects(render(invalid));
  }
});
test("migration integer limits are exact and malformed retained history is rejected", async () => {
  const values = fixture();
  values.auditExports.policies = [{ ...policy, maximum_export_bytes: 9007199254740991, maximum_retained_bytes: 9007199254740991, maximum_inflight: 2147483647 }];
  const data = (await render(values)).find(value => value.metadata.name === "owned-migration-snippets").data;
  const env = Object.fromEntries(loadAll(data.env)[0].map(value => [value.name, value.value]));
  assert.equal(env.ZASP_AUDIT_EXPORT_MAXIMUM_EXPORT_BYTES, "9007199254740991");
  assert.equal(env.ZASP_AUDIT_EXPORT_MAXIMUM_RETAINED_BYTES, "9007199254740991");
  assert.equal(env.ZASP_AUDIT_EXPORT_MAXIMUM_INFLIGHT, "2147483647");
  for (const mutate of [v => { v.auditExports.expectedCurrentPolicyID = false; }, v => { v.auditExports.policies[0].maximum_inflight = 2147483648; }, v => { v.auditExports.policies[0].capture_timeout_seconds = 121; }, v => { v.auditExports.policies[0].maximum_export_bytes = true; }, v => { v.auditExports.policies[0].maximum_export_bytes = "2"; }, v => { v.auditExports.policies.push({ ...policy, policy_id: "pid_52000002-0000-4000-8000-000000000002", maximum_inflight: 1.5 }); }]) {
    const invalid = structuredClone(values); mutate(invalid); await assert.rejects(render(invalid));
  }
});
test("migration shell stops at credential read and each failed command", async () => {
  const command = (await render(fixture())).find(value => value.metadata.name === "owned-migration-snippets").data.command.trim();
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-export-command-"));
  try {
    const binary = path.join(directory, "migrate");
    const dsn = path.join(directory, "dsn");
    const log = path.join(directory, "calls");
    await writeFile(dsn, "owned-not-a-live-dsn");
    await writeFile(binary, '#!/bin/sh\nprintf "%s\\n" "$1" >> "$OWNED_LOG"\n[ "$1" != "$OWNED_FAIL" ]\n', { mode: 0o700 });
    for (const [failure, expected] of [["", ["up-to-52", "register-audit-export-api", "register-audit-export-workers", "configure-audit-exports"]], ["up-to-52", ["up-to-52"]], ["register-audit-export-api", ["up-to-52", "register-audit-export-api"]], ["register-audit-export-workers", ["up-to-52", "register-audit-export-api", "register-audit-export-workers"]], ["configure-audit-exports", ["up-to-52", "register-audit-export-api", "register-audit-export-workers", "configure-audit-exports"]], ["missing-dsn", []]]) {
      await writeFile(log, "");
      const owned = command.replaceAll("/app/agentsec-migrate", binary).replace("/var/run/secrets/zasp-migration/postgres-dsn", failure === "missing-dsn" ? `${dsn}-missing` : dsn);
      const call = exec("/bin/sh", ["-ec", owned], { env: { ...process.env, OWNED_LOG: log, OWNED_FAIL: failure }, timeout: 5000 });
      if (failure) await assert.rejects(call); else await call;
      assert.deepEqual((await readFile(log, "utf8")).trim().split("\n").filter(Boolean), expected);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test("actual chart defaults disable exports and both precision phases retain bounded history", async () => {
  const defaults = loadAll(await readFile(new URL("../staging/product/values.yaml", import.meta.url), "utf8"))[0];
  assert.equal((await render(defaults)).filter(value => value.kind !== "ConfigMap").length, 0);
  const values = fixture(); values.runtime.sessionSearchPhase = "precision-consumers";
  values.auditExports.policies = Array.from({ length: 64 }, (_, index) => ({ ...policy, policy_id: `pid_52000001-0000-4000-8000-${String(index + 1).padStart(12, "0")}` }));
  assert.equal((await render(values)).filter(value => value.kind === "Deployment").length, 2);
  values.auditExports.policies.push({ ...policy });
  await assert.rejects(render(values));
});
test("API export configuration uses only reader policy and mounted cursor secret", async () => {
  const values = fixture();
  values.connectors = { roleArn: "arn:aws:iam::123456789012:role/connector-reader" };
  values.secrets = { region: "us-east-1" };
  values.auditExports.readerRoleArn = "arn:aws:iam::123456789012:role/export-reader";
  values.auditExports.cursorSecretArn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:export-cursor-owned";
  const data = (await render(values, true)).find(value => value.metadata.name === "owned-api-snippets").data;
  const environment = loadAll(data.env)[0];
  assert.deepEqual(environment.map(entry => entry.name === "ZASP_AUDIT_EXPORT_POLICIES_JSON" ? { ...entry, value: JSON.parse(entry.value) } : entry), [
    { name: "ZASP_AUDIT_EXPORT_POLICIES_JSON", value: [policy] },
    { name: "ZASP_AUDIT_EXPORT_READER_ROLE_ARN", value: values.auditExports.readerRoleArn },
    { name: "ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE", value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" },
  ]);
  assert.deepEqual(loadAll(data.objects), [[{ objectName: values.auditExports.cursorSecretArn, objectType: "secretsmanager", objectAlias: "audit-export-cursor-signing-key" }]]);
  assert.match(data.command, /ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY/);
  assert.match(data.command, /\/var\/run\/secrets\/zasp\/audit-export-cursor-signing-key/);
  const disabled = structuredClone(values); disabled.auditExports.enabled = false;
  const empty = (await render(disabled, true)).find(value => value.metadata.name === "owned-api-snippets").data;
  assert.deepEqual(empty, { env: "", objects: "", command: "" });
  for (const mutate of [v => { v.auditExports.readerRoleArn = v.auditExports.writerRoleArn; }, v => { v.auditExports.readerRoleArn = v.connectors.roleArn; }, v => { v.auditExports.cursorSecretArn = ""; }, v => { v.secrets.region = "us-west-2"; }]) {
    const invalid = structuredClone(values); mutate(invalid);
    await assert.rejects(render(invalid, true));
  }
});
test("export workload activation refuses missing or incompatible authority", async () => {
  const disabled = fixture(); disabled.auditExports.enabled = false;
  assert.equal((await render(disabled)).filter(value => value.kind !== "ConfigMap").length, 0);
  for (const mutate of [v => { v.schema.expectedVersion = 51; }, v => { v.profile = "customer_edge"; }, v => { v.auditExports.writerRoleArn = ""; }, v => { v.auditExports.publisherRoleArn = v.auditExports.writerRoleArn; }, v => { v.auditExports.policies = []; }, v => { v.auditExports.workerDSNSecretArn = v.auditExports.outboxDSNSecretArn; }]) {
    const values = fixture(); mutate(values);
    await assert.rejects(render(values));
  }
});
test("export activation rejects malformed flags and deployment boundaries", async () => {
  for (const mutate of [v => { v.auditExports.enabled = "false"; }, v => { v.profile = "unknown"; }, v => { v.global.terminationGracePeriodSeconds = 20; }, v => { v.global.productImages.agentsecWorker = "worker:latest"; }, v => { v.runtime.sessionSearchPhase = "compatibility"; }, v => { v.auditExports.workerDSNSecretArn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:"; }, v => { v.auditExports.queueURL += "?override=1"; }]) {
    const values = fixture(); mutate(values);
    await assert.rejects(render(values));
  }
});
