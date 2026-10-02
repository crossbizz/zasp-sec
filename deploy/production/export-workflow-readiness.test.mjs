import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";
import { attackLabReconcilerReleaseFixture } from "./attack-lab-reconciler-release-fixture.mjs";
import { validateExportWorkflowReadiness } from "./export-workflow-readiness.mjs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadAll } from "js-yaml";

const option = () => ({ schemaVersion: 58, sessionSearchPhase: "precision-intake", complianceExports: complianceExportReleaseFixture(), evidenceExportWorkflow: true });
const one = (rows, kind, name) => rows.find(r => r.kind === kind && r.metadata.name === name);
const api = rows => one(rows, "Deployment", "agentsec-api").spec.template.spec.containers[0];
const prefix = "ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW";

test("export workflow opt-in renders only fixed private worker health access", async t => {
  for (const attackEnabled of [false, true]) {
    const options = { ...option(), ...(attackEnabled ? { attackLabReconciler: attackLabReconcilerReleaseFixture() } : {}) };
    const rows = await renderRelease(productionReleaseFixture, options);
    const validate = rs => validateRenderedRelease(rs, "123456789012", 58, "precision-intake", undefined, undefined, options.complianceExports, options.attackLabReconciler, true);
    assert.doesNotThrow(() => validate(rows));
    assert.deepEqual(api(rows).env.filter(e => e.name.startsWith(prefix)), [{ name: prefix, value: "enabled" }]);
    const ingress = one(rows, "NetworkPolicy", "export-workflow-readiness-ingress");
    assert.deepEqual(ingress.spec.podSelector, { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: ["agentsec-security-agent", "agentsec-security-agent-action", "zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"] }] });
    assert.deepEqual(ingress.spec.ingress, [{ from: [{ podSelector: { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } } }], ports: [{ protocol: "TCP", port: 8081 }] }]);
    for (const [name, mutate] of Object.entries({
      "missing switch": rs => { api(rs).env = api(rs).env.filter(e => e.name !== prefix); },
      "wrong switch": rs => { api(rs).env.find(e => e.name === prefix).value = "true"; },
      "URL override": rs => { api(rs).env.push({ name: `${prefix}_URL`, value: "https://arbitrary.invalid" }); },
      "other workload switch": rs => { one(rs, "Deployment", "agentsec-security-agent").spec.template.spec.containers[0].env.push({ name: prefix, value: "enabled" }); },
      "missing ingress": rs => { rs.splice(rs.findIndex(r => r.metadata.name === "export-workflow-readiness-ingress"), 1); },
      "foreign namespace": rs => { one(rs, "NetworkPolicy", "export-workflow-readiness-ingress").metadata.namespace = "other"; },
      "all workers": rs => { one(rs, "NetworkPolicy", "export-workflow-readiness-ingress").spec.podSelector = {}; },
      "all callers": rs => { one(rs, "NetworkPolicy", "export-workflow-readiness-ingress").spec.ingress[0].from = [{}]; },
      "all destinations": rs => { one(rs, "NetworkPolicy", "export-workflow-readiness-egress").spec.egress[0].to = [{}]; },
      "wrong port": rs => { one(rs, "NetworkPolicy", "export-workflow-readiness-egress").spec.egress[0].ports[0].port = 443; },
      "service destination": rs => { one(rs, "Service", "agentsec-security-agent-action").spec.selector = { app: "untrusted" }; },
      "external service": rs => { one(rs, "Service", "agentsec-security-agent").spec.externalIPs = ["203.0.113.1"]; },
      "additive broad ingress": rs => { rs.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "untrusted-export-access" }, spec: { podSelector: { matchLabels: { "app.kubernetes.io/name": "zasp-compliance-export-worker" } }, policyTypes: ["Ingress"], ingress: [{}] } }); },
      "additive agent ingress": rs => { rs.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "untrusted-agent-access" }, spec: { podSelector: { matchLabels: { "app.kubernetes.io/name": "agentsec-security-agent" } }, policyTypes: ["Ingress"], ingress: [{}] } }); },
      "additive generated-label ingress": rs => { rs.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "untrusted-generated-label-access", namespace: "agentsec" }, spec: { podSelector: { matchExpressions: [{ key: "pod-template-hash", operator: "Exists" }] }, policyTypes: ["Ingress"], ingress: [{}] } }); },
    })) await t.test(`${attackEnabled}/${name}`, () => { const changed = structuredClone(rows); mutate(changed); assert.throws(() => validate(changed), /release rejected/); });
    assert.throws(() => validateRenderedRelease(rows, "123456789012", 58, "precision-intake", undefined, undefined, options.complianceExports, options.attackLabReconciler), /release rejected/);
  }
});

test("untrusted ingress needs fixed worker identity disjointness and a well-formed selector", async t => {
  const rows = await renderRelease(productionReleaseFixture, option());
  const withSelector = podSelector => [...rows, { apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "untrusted-selector", namespace: "agentsec" }, spec: { podSelector, policyTypes: ["Ingress"], ingress: [{}] } }];
  for (const [name, selector] of Object.entries({
    "unknown matchLabels": { matchLabels: { "pod-template-hash": "future-revision" } },
    "unknown In": { matchExpressions: [{ key: "pod-template-hash", operator: "In", values: ["future-revision"] }] },
    "unknown NotIn": { matchExpressions: [{ key: "pod-template-hash", operator: "NotIn", values: ["old-revision"] }] },
    "unknown Exists": { matchExpressions: [{ key: "pod-template-hash", operator: "Exists" }] },
    "unknown DoesNotExist": { matchExpressions: [{ key: "future-label", operator: "DoesNotExist" }] },
    "null selector": null,
    "unknown selector field": { unexpected: true },
    "null matchLabels": { matchLabels: null },
    "non-string label": { matchLabels: { unrelated: 1 } },
    "invalid label key": { matchLabels: { "bad/key/extra": "value" } },
    "null matchExpressions": { matchExpressions: null },
    "empty In": { matchExpressions: [{ key: "pod-template-hash", operator: "In", values: [] }] },
    "non-string values": { matchExpressions: [{ key: "pod-template-hash", operator: "NotIn", values: [1] }] },
    "Exists with values": { matchExpressions: [{ key: "pod-template-hash", operator: "Exists", values: ["hash"] }] },
    "unknown expression field": { matchExpressions: [{ key: "pod-template-hash", operator: "Exists", unexpected: true }] },
    "malformed after disjoint label": { matchLabels: { "app.kubernetes.io/name": "agentsec-api" }, matchExpressions: [{ key: "pod-template-hash", operator: "Unknown" }] },
    "trailing newline after disjoint label": { matchLabels: { "app.kubernetes.io/name": "agentsec-api", "pod-template-hash": "hash\n" } },
    "trailing newline in label prefix": { matchLabels: { "app.kubernetes.io/name": "agentsec-api", "controller.invalid\n/hash": "value" } },
    "malformed after disjoint expression": { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: ["agentsec-api"] }, { key: "pod-template-hash", operator: "Unknown" }] },
  })) await t.test(name, () => assert.throws(() => validateExportWorkflowReadiness(withSelector(selector), true), /release rejected/));
  for (const selector of [
    { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } },
    { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "In", values: ["agentsec-api"] }] },
    { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "NotIn", values: ["agentsec-security-agent", "agentsec-security-agent-action", "zasp-compliance-export-worker", "zasp-compliance-cleanup-worker"] }] },
    { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "DoesNotExist" }] },
    { matchLabels: { "app.kubernetes.io/name": "agentsec-api" }, matchExpressions: [{ key: "pod-template-hash", operator: "Exists" }] },
  ]) assert.doesNotThrow(() => validateExportWorkflowReadiness(withSelector(selector), true));
});

test("export workflow requires exact58 configured retrieval and explicit true", async () => {
  for (const value of [false, null, "true", "enabled", 1, {}, { enabled: true }]) await assert.rejects(renderRelease(productionReleaseFixture, { ...option(), evidenceExportWorkflow: value }), /release rejected/);
  for (const schemaVersion of [56, 57, 59]) await assert.rejects(renderRelease(productionReleaseFixture, { ...option(), schemaVersion }), /release rejected/);
  await assert.rejects(renderRelease(productionReleaseFixture, { ...option(), complianceExports: undefined }), /release rejected/);
  const rows = await renderRelease(productionReleaseFixture, { ...option(), evidenceExportWorkflow: undefined });
  assert.equal(api(rows).env.some(e => e.name.startsWith(prefix)), false);
  assert.equal(rows.some(r => r.metadata.name.startsWith("export-workflow-readiness-")), false);
});

test("direct Helm keeps the workflow switch closed without JS normalization", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-export-workflow-helm-"));
  try {
    await mkdir(path.join(directory, "templates"));
    await writeFile(path.join(directory, "Chart.yaml"), "apiVersion: v2\nname: export-workflow-owned\nversion: 0.1.0\n");
    await writeFile(path.join(directory, "templates", "export-workflow-network.yaml"), await readFile(new URL("../staging/product/templates/export-workflow-network.yaml", import.meta.url)));
    const fixture = () => ({ profile: "control_plane", schema: { expectedVersion: 58 }, complianceExports: { enabled: true }, evidenceExportWorkflow: { enabled: true } });
    const render = async values => {
      await writeFile(path.join(directory, "values.json"), JSON.stringify(values));
      const { stdout } = await promisify(execFile)("helm", ["template", "owned", directory, "-n", "agentsec", "-f", path.join(directory, "values.json")], { timeout: 20000 });
      return loadAll(stdout).filter(Boolean);
    };
    assert.equal((await render(fixture())).filter(r => r.kind === "NetworkPolicy").length, 2);
    const disabled = fixture(); disabled.evidenceExportWorkflow.enabled = false;
    assert.deepEqual(await render(disabled), []);
    for (const change of [
      v => { v.evidenceExportWorkflow = true; },
      v => { v.evidenceExportWorkflow.enabled = "true"; },
      v => { v.evidenceExportWorkflow.destination = "untrusted"; },
      v => { v.evidenceExportWorkflow = { enabled: false, destination: "untrusted" }; },
      v => { v.schema.expectedVersion = 57; },
      v => { v.schema.expectedVersion = 59; },
      v => { v.profile = "customer_edge"; },
      v => { v.complianceExports.enabled = false; },
    ]) {
      const values = fixture(); change(values);
      await assert.rejects(render(values));
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
