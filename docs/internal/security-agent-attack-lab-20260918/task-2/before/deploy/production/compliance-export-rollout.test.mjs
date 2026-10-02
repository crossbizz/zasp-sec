import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";
import { normalizeComplianceExports } from "./compliance-export-rollout.mjs";

const options = (complianceExports = complianceExportReleaseFixture()) => ({ schemaVersion: 56, sessionSearchPhase: "precision-intake", complianceExports });
const resource = (rows, kind, name) => rows.find(r => r.kind === kind && r.metadata.name === name);
const pod = (rows, name = "zasp-compliance-export-worker") => resource(rows, "Deployment", name).spec.template.spec;
const env = (rows, name, field) => pod(rows, name).containers[0].env.find(e => e.name === field);

test("compliance API startup rejects shell authority and command changes with and without audit", async t => {
  for (const auditEnabled of [false, true]) {
    const compliance = complianceExportReleaseFixture();
    const audit = auditEnabled ? auditExportReleaseFixture() : undefined;
    const valid = await renderRelease(productionReleaseFixture, { ...options(compliance), auditExports: audit });
    const validate = rows => validateRenderedRelease(rows, "123456789012", 56, "precision-intake", audit, undefined, compliance);
    assert.doesNotThrow(() => validate(valid));
    for (const [name, mutate] of Object.entries({
      "worker authority export": c => { c.args[0] = `export ZASP_COMPLIANCE_EXPORT_ROLE_ARN="${compliance.writerRoleArn}"\n${c.args[0]}`; },
      "replacement command": c => { c.command = ["/bin/sh", "-c"]; },
      "extra argument": c => { c.args.push("unexpected"); },
      "replacement executable": c => { c.args[0] = c.args[0].replace("exec /app/agentsec-api", "exec /app/agentsec-worker"); },
      "missing secret load": c => { c.args[0] = c.args[0].split("\n").filter(line => !line.includes("ZASP_POSTGRES_DSN=")).join("\n"); },
    })) await t.test(`${auditEnabled ? "audit" : "compliance-only"}: ${name}`, () => {
      const rows = structuredClone(valid);
      mutate(pod(rows, "agentsec-api").containers[0]);
      assert.throws(() => validate(rows), /release rejected/);
    });
  }
});

test("migration uses the published registration environment names", async () => {
  const rows = await renderRelease(productionReleaseFixture, options());
  const entries = resource(rows, "Job", "agentsec-schema-v56").spec.template.spec.containers[0].env.filter(e => e.name.startsWith("ZASP_COMPLIANCE_"));
  assert.deepEqual(entries, [
    { name: "ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL", value: "compliance_export_runtime" },
    { name: "ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL", value: "compliance_cleanup_runtime" },
  ]);
});

test("closed compliance input refuses authority confusion and snapshots before await", async () => {
  const normalize = v => normalizeComplianceExports(v, "123456789012", 56, "precision-intake");
  assert.equal(normalize(undefined), undefined);
  let getterCalls = 0;
  for (const mutate of [
    c => ({ ...c, extra: true }), c => ({ ...c, enabled: false }), c => ({ ...c, bucket: c.bucket + "\n" }),
    c => ({ ...c, bucketOwner: "987654321098" }), c => ({ ...c, awsRegion: "us-east-1" }),
    c => ({ ...c, cleanupRoleArn: c.writerRoleArn }), c => ({ ...c, cleanupDSNSecretArn: c.workerDSNSecretArn }),
    c => ({ ...c, cleanupPrincipal: c.workerPrincipal }), c => ({ ...c, workerPrincipal: "zasp_runtime" }),
    c => Object.defineProperty(c, "bucket", { get() { getterCalls++; return "bad"; } }),
    c => Object.assign(c, { [Symbol("hidden")]: true }),
    ...[["127.0.0.0/24"], ["169.254.0.0/16"], ["10.30.0.1/24"], ["10.30.0.0/24", "10.30.0.0/25"], ["10.30.0.0/24\n"]].map(databaseCIDRs => c => ({ ...c, databaseCIDRs })),
  ]) assert.throws(() => normalize(mutate(complianceExportReleaseFixture())), /release rejected/);
  assert.equal(getterCalls, 0);
  const c = complianceExportReleaseFixture();
  const pending = renderRelease(productionReleaseFixture, options(c));
  c.bucket = "changed-after-call"; c.databaseCIDRs[0] = "0.0.0.0/0";
  const rows = await pending;
  assert.equal(env(rows, "agentsec-api", "ZASP_COMPLIANCE_EXPORT_BUCKET").value, "zasp-compliance-fixture");
  for (const field of ["readerRoleArn", "writerRoleArn", "cleanupRoleArn"]) await assert.rejects(renderRelease(productionReleaseFixture, options({ ...complianceExportReleaseFixture(), [field]: productionReleaseFixture.discovery.roleArn })), /release rejected/);
  for (const [field, value] of [["bucket", productionReleaseFixture.discovery.evidenceBucket], ["workerDSNSecretArn", auditExportReleaseFixture().workerDSNSecretArn], ["workerPrincipal", auditExportReleaseFixture().workerPrincipal]]) await assert.rejects(renderRelease(productionReleaseFixture, { ...options({ ...complianceExportReleaseFixture(), [field]: value }), auditExports: auditExportReleaseFixture() }), /release rejected/);
});

test("rendered compliance rejects authority, sidecar, readiness and additive network mutations", async t => {
  const c = complianceExportReleaseFixture(), audit = auditExportReleaseFixture(), reconciler = testReconcilerReleaseFixture();
  const valid = await renderRelease(productionReleaseFixture, { ...options(c), auditExports: audit, testReconciler: reconciler });
  const mutations = {
    "unreviewed pinned image": rows => { pod(rows).containers[0].image = `registry.example/foreign@sha256:${"f".repeat(64)}`; },
    "writer swapped": rows => { env(rows, "zasp-compliance-export-worker", "ZASP_COMPLIANCE_EXPORT_ROLE_ARN").value = c.cleanupRoleArn; },
    "DSN swapped": rows => { resource(rows, "SecretProviderClass", "zasp-compliance-export-worker-secrets").spec.parameters.objects = resource(rows, "SecretProviderClass", "zasp-compliance-cleanup-worker-secrets").spec.parameters.objects; },
    "schema requirement removed": rows => { pod(rows, "agentsec-api").containers[0].env = pod(rows, "agentsec-api").containers[0].env.filter(e => e.name !== "ZASP_EXPECTED_SCHEMA_VERSION"); },
    "worker authority on API": rows => { pod(rows, "agentsec-api").containers[0].env.push({ name: "ZASP_COMPLIANCE_EXPORT_ROLE_ARN", value: c.writerRoleArn }); },
    "sidecar": rows => { pod(rows).containers.push({ name: "extra", image: "sidecar" }); },
    "envFrom": rows => { pod(rows).containers[0].envFrom = [{ secretRef: { name: "shared" } }]; },
    "host network": rows => { pod(rows).hostNetwork = true; },
    "cross-workload mount": rows => { pod(rows, "agentsec-api").volumes.push(structuredClone(pod(rows).volumes[0])); },
    "migration ordering": rows => { const c = resource(rows, "Job", "agentsec-schema-v56").spec.template.spec.containers[0]; c.args[0] = c.args[0].replace("configure-audit-exports && exec /app/agentsec-migrate register-compliance-workers", "register-compliance-workers && exec /app/agentsec-migrate configure-audit-exports"); },
    "readiness weakened": rows => { pod(rows).containers[0].readinessProbe.httpGet.path = "/healthz"; },
    "memory request removed": rows => { delete pod(rows).containers[0].resources.requests.memory; },
    "unbounded HPA": rows => { resource(rows, "HorizontalPodAutoscaler", "zasp-compliance-export-worker").spec.maxReplicas = 100; },
    "monitor absent": rows => rows.splice(rows.findIndex(r => r.kind === "ServiceMonitor" && r.metadata.name === "zasp-compliance-export-worker"), 1),
    "broad expected selector": rows => { resource(rows, "NetworkPolicy", "zasp-compliance-export-worker-dependencies").spec.podSelector = {}; },
    "broad egress": rows => { resource(rows, "NetworkPolicy", "zasp-compliance-export-worker-dependencies").spec.egress.push({}); },
    "unnamed broad policy": rows => rows.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "extra" }, spec: { podSelector: {}, policyTypes: ["Egress"], egress: [{}] } }),
    "malformed unselected selector": rows => rows.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "extra" }, spec: { podSelector: { matchLabels: { app: "other" }, matchExpressions: [{ key: "app", operator: "Bogus" }] } } }),
    "group RBAC": rows => rows.push({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: { name: "extra" }, subjects: [{ kind: "Group", name: "system:serviceaccounts:agentsec" }], roleRef: { kind: "ClusterRole", name: "admin", apiGroup: "rbac.authorization.k8s.io" } }),
    "cross namespace RBAC": rows => rows.push({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: { name: "extra", namespace: "other" }, subjects: [{ kind: "ServiceAccount", name: "zasp-compliance-export-worker", namespace: "agentsec" }], roleRef: { kind: "Role", name: "reader", apiGroup: "rbac.authorization.k8s.io" } }),
  };
  for (const [name, mutate] of Object.entries(mutations)) await t.test(name, () => {
    const rows = structuredClone(valid); mutate(rows);
    assert.throws(() => validateRenderedRelease(rows, "123456789012", 56, "precision-intake", audit, reconciler, c), /release rejected/);
  });
  const legacy = await renderRelease(productionReleaseFixture);
  for (const r of valid.filter(r => JSON.stringify(r).includes("zasp-compliance"))) assert.throws(() => validateRenderedRelease([...legacy, r], "123456789012"), /release rejected/);
});

test("compliance56 coexists with both optional predecessors in both phases", async () => {
  for (const phase of ["precision-consumers", "precision-intake"]) {
    for (const enabled of [false, true]) for (const auditEnabled of [false, true]) for (const reconcileEnabled of [false, true]) {
      const compliance = enabled ? complianceExportReleaseFixture() : undefined;
      const audit = auditEnabled ? auditExportReleaseFixture() : undefined;
      const reconciler = reconcileEnabled ? testReconcilerReleaseFixture() : undefined;
      const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 56, sessionSearchPhase: phase, auditExports: audit, testReconciler: reconciler, complianceExports: compliance });
      assert.doesNotThrow(() => validateRenderedRelease(rows, "123456789012", 56, phase, audit, reconciler, compliance));
      assert.equal(rows.filter(r => r.kind === "Deployment" && r.metadata.name.startsWith("zasp-compliance")).length, enabled ? 2 : 0);
      if (enabled) {
        const migration = rows.find(r => r.kind === "Job" && r.metadata.name === "agentsec-schema-v56");
        const auditChain = auditEnabled ? " && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && /app/agentsec-migrate configure-audit-exports" : "";
        assert.equal(migration.spec.template.spec.containers[0].args[0], 'ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-56' + auditChain + " && exec /app/agentsec-migrate register-compliance-workers");
      }
    }
  }
});

test("schema55 predecessors still render and57 stays closed", async () => {
  await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: "precision-intake", auditExports: auditExportReleaseFixture(), testReconciler: testReconcilerReleaseFixture() });
  await assert.rejects(renderRelease(productionReleaseFixture, { schemaVersion: 57, sessionSearchPhase: "precision-intake" }), /release rejected/);
});
