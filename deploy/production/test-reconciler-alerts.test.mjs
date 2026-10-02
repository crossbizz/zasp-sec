import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { dump } from "js-yaml";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";

test("rendered reconciler alerts fire for failed or absent targets and clear on recovery", async () => {
  const resources = await renderRelease(productionReleaseFixture, { schemaVersion: 55, sessionSearchPhase: "precision-intake", testReconciler: testReconcilerReleaseFixture() });
  const rule = resources.find(r => r.kind === "PrometheusRule" && r.metadata.name === "zasp-test-reconciler-availability");
  assert.ok(rule, "reconciler rules missing");
  assert.ok(process.env.ZASP_PROMTOOL_BIN, "ZASP_PROMTOOL_BIN must select the pinned Prometheus test tool");
  const labels = { namespace: "agentsec", service: "zasp-test-reconciler", instance: "target-1" };
  const series = (metric, values, extra = {}) => ({ series: metric + "{" + Object.entries({ ...labels, ...extra }).map(([k, v]) => k + '="' + v + '"').join(",") + "}", values });
  const expected = (absent = false) => ({ exp_labels: { ...(absent ? { namespace: "agentsec", service: "zasp-test-reconciler" } : labels), severity: "ticket" }, exp_annotations: { summary: "Test reconciler readiness is unavailable" } });
  const healthyOther = [series("up", "1x14", { service: "other-worker" }), series("agentsec_ready", "1x14", { service: "other-worker" })];
  const cases = [
    ["healthy", [series("up", "1x14"), series("agentsec_ready", "1x14")], [], false],
    ["ready false", [series("up", "1x14"), series("agentsec_ready", "0x11 1x3")], [expected()], true],
    ["scrape down", [series("up", "0x11 1x3"), series("agentsec_ready", "1x14")], [expected()], true],
    ["metric missing on one replica", [series("up", "1x14"), series("agentsec_ready", "_x11 1x3"), series("up", "1x14", { instance: "target-2" }), series("agentsec_ready", "1x14", { instance: "target-2" })], [expected()], true],
    ["all targets absent", [series("up", "_x11 1x3"), series("agentsec_ready", "_x11 1x3")], [expected(true)], true],
  ];
  const tests = cases.map(([name, input, exp_alerts, recovers]) => ({ name, interval: "1m", input_series: [...healthyOther, ...input], alert_rule_test: [
    { eval_time: "9m", alertname: "ZaspTestReconcilerNotReady", exp_alerts: [] },
    { eval_time: "10m", alertname: "ZaspTestReconcilerNotReady", exp_alerts },
    ...(recovers ? [{ eval_time: "12m", alertname: "ZaspTestReconcilerNotReady", exp_alerts: [] }] : []),
  ] }));
  for (const absent of [false, true]) tests.push({ name: absent ? "deployment absent then recovery" : "zero replicas then recovery", interval: "1m", input_series: [
    { series: 'kube_deployment_status_replicas_available{namespace="agentsec",deployment="zasp-test-reconciler"}', values: absent ? "_x6 2x8" : "0x6 2x8" },
  ], alert_rule_test: [
    { eval_time: "4m", alertname: "ZaspTestReconcilerUnavailable", exp_alerts: [] },
    { eval_time: "5m", alertname: "ZaspTestReconcilerUnavailable", exp_alerts: [{ exp_labels: { namespace: "agentsec", deployment: "zasp-test-reconciler", severity: "page" }, exp_annotations: { summary: "Test reconciler workload is unavailable or absent" } }] },
    { eval_time: "8m", alertname: "ZaspTestReconcilerUnavailable", exp_alerts: [] },
  ] });
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-reconciler-alerts-"));
  try {
    await writeFile(path.join(directory, "rules.yml"), dump(rule.spec));
    await writeFile(path.join(directory, "test.yml"), dump({ rule_files: ["rules.yml"], evaluation_interval: "1m", tests }));
    const { stdout } = await promisify(execFile)(process.env.ZASP_PROMTOOL_BIN, ["test", "rules", "test.yml"], { cwd: directory, timeout: 30000, maxBuffer: 1024 * 1024 });
    assert.match(stdout, /SUCCESS/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
