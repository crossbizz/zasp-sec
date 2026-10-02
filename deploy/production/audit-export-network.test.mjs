import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

const one = (rows, kind, name) => {
  const found = rows.filter(r => r.kind === kind && r.metadata.name === name);
  assert.equal(found.length, 1, `${kind}/${name}`);
  return found[0];
};
const config = () => ({ ...auditExportReleaseFixture(), stsCIDRs: ["192.0.2.16/28"], sqsCIDRs: ["192.0.2.32/28"], s3CIDRs: ["198.51.100.0/24"] });
const render = auditExports => renderRelease(release, { schemaVersion: 52, sessionSearchPhase: "precision-intake", auditExports });

test("exports have mode-specific dependency access and privately scraped healthy workers", async () => {
  const expected = config();
  const resources = await render(expected);
  for (const suffix of ["worker", "outbox"]) {
    const name = `zasp-audit-export-${suffix}`;
    const dependencies = one(resources, "NetworkPolicy", `${name}-dependencies`).spec;
    assert.deepEqual(dependencies.podSelector, { matchLabels: { "app.kubernetes.io/name": name } });
    assert.deepEqual(dependencies.policyTypes, ["Egress"]);
    assert.deepEqual(dependencies.egress, [
      { to: [{ ipBlock: { cidr: "10.30.0.0/24" } }], ports: [{ protocol: "TCP", port: 5432 }] },
      { to: (suffix === "worker" ? ["192.0.2.16/28", "192.0.2.32/28", "198.51.100.0/24"] : ["192.0.2.16/28", "192.0.2.32/28"]).map(cidr => ({ ipBlock: { cidr } })), ports: [{ protocol: "TCP", port: 443 }] },
    ]);
    assert.deepEqual(one(resources, "Service", name).spec, { type: "ClusterIP", selector: { "app.kubernetes.io/name": name }, ports: [{ name: "internal", port: 8081, targetPort: "internal", protocol: "TCP" }] });
    assert.deepEqual(one(resources, "PodDisruptionBudget", name).spec, { minAvailable: 1, selector: { matchLabels: { "app.kubernetes.io/name": name } } });
    const monitor = one(resources, "ServiceMonitor", name).spec;
    assert.deepEqual(monitor.selector.matchLabels, { "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "zasp" });
    assert.deepEqual(monitor.endpoints, [{ port: "internal", path: "/metrics", interval: "30s", scrapeTimeout: "5s" }]);
    assert.deepEqual(one(resources, "NetworkPolicy", `${name}-monitoring`).spec.ingress, [{ from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "monitoring" } } }], ports: [{ protocol: "TCP", port: 8081 }] }]);
  }
  assert.deepEqual(one(resources, "NetworkPolicy", "zasp-audit-export-api-dependencies").spec, {
    podSelector: { matchLabels: { "app.kubernetes.io/name": "agentsec-api" } }, policyTypes: ["Egress"],
    egress: [{ to: [{ ipBlock: { cidr: "192.0.2.16/28" } }, { ipBlock: { cidr: "198.51.100.0/24" } }], ports: [{ protocol: "TCP", port: 443 }] }],
  });
  assert.deepEqual(one(resources, "NetworkPolicy", "default-deny").spec, { podSelector: {}, policyTypes: ["Ingress", "Egress"] });
  assert.ok(one(resources, "NetworkPolicy", "dns-egress"));
  for (const mutate of [
    r => { one(r, "NetworkPolicy", "zasp-audit-export-outbox-dependencies").spec.egress[1].to.push({ ipBlock: { cidr: "198.51.100.0/24" } }); },
    r => { one(r, "NetworkPolicy", "zasp-audit-export-worker-dependencies").spec.podSelector = {}; },
    r => { one(r, "NetworkPolicy", "zasp-audit-export-worker-monitoring").spec.ingress[0].from = [{}]; },
    r => { one(r, "Service", "zasp-audit-export-worker").spec.type = "LoadBalancer"; },
    r => { one(r, "ServiceMonitor", "zasp-audit-export-worker").spec.endpoints[0].port = "public"; },
    r => { one(r, "PodDisruptionBudget", "zasp-audit-export-worker").spec.minAvailable = 0; },
    r => { r.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "unexpected-allow-all" }, spec: { podSelector: {}, policyTypes: ["Egress"], egress: [{}] } }); },
    r => { one(r, "NetworkPolicy", "dns-egress").spec.egress.push({}); },
    r => { one(r, "NetworkPolicy", "dns-egress").spec.podSelector.matchExpressions[0].values = ["zasp-audit-export-worker"]; },
    r => { delete one(r, "NetworkPolicy", "dns-egress").spec.podSelector.matchExpressions; },
    r => { delete one(r, "Deployment", "zasp-audit-export-worker").spec.template.metadata.labels["app.kubernetes.io/part-of"]; },
    r => { r.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "unexpected-expression" }, spec: { podSelector: { matchExpressions: [{ key: "app.kubernetes.io/name", operator: "NotIn", values: ["web"] }] }, policyTypes: ["Egress"], egress: [{}] } }); },
  ]) {
    const changed = structuredClone(resources); mutate(changed);
    assert.throws(() => validateRenderedRelease(changed, "123456789012", 52, "precision-intake", expected), /release rejected/);
  }
});

test("endpoint normalization rejects executable array entries without invoking them", async () => {
  const expected = config();
  let reads = 0;
  Object.defineProperty(expected.stsCIDRs, "0", { get() { reads++; return "192.0.2.16/28"; }, enumerable: true });
  await assert.rejects(render(expected), /release rejected/);
  assert.equal(reads, 0);
});

test("exports refuse missing, broad or noncanonical endpoint snapshots", async () => {
  for (const key of ["stsCIDRs", "sqsCIDRs", "s3CIDRs"]) {
    for (const values of [undefined, [], ["0.0.0.0/0"], ["127.0.0.1/32"], ["169.254.169.254/32"], ["192.0.2.1/24"], ["192.0.2.0/24", "192.0.2.0/25"]]) {
      await assert.rejects(render({ ...config(), [key]: values }), /release rejected/);
    }
  }
});
