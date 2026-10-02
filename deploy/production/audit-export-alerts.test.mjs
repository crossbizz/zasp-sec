import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { dump } from "js-yaml";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

test("actual export Prometheus rules detect missing targets and recover independently", async () => {
  const resources = await renderRelease(release, { schemaVersion: 52, sessionSearchPhase: "precision-intake", auditExports: auditExportReleaseFixture() });
  const rule = resources.find(r => r.kind === "PrometheusRule" && r.metadata.name === "zasp-audit-export-availability");
  assert.ok(rule, "export availability rules missing");
  assert.ok(process.env.ZASP_PROMTOOL_BIN, "ZASP_PROMTOOL_BIN must select the pinned Prometheus test tool");
  const tests = [];
  for (const [suffix, prefix, other] of [["worker", "ZaspAuditExportWorker", "outbox"], ["outbox", "ZaspAuditExportOutbox", "worker"]]) {
    const service = `zasp-audit-export-${suffix}`;
    const labels = { namespace: "agentsec", service, instance: "target-1" };
    const series = (metric, values, extra = {}) => ({ series: `${metric}{${Object.entries({ ...labels, ...extra }).map(([k, v]) => `${k}="${v}"`).join(",")}}`, values });
    const healthyOther = [series("up", "1x14", { service: `zasp-audit-export-${other}` }), series("agentsec_ready", "1x14", { service: `zasp-audit-export-${other}` })];
    const readyExpected = (absent = false) => ({ exp_labels: { ...(absent ? { namespace: "agentsec", service } : labels), severity: "ticket" }, exp_annotations: { summary: "Audit export worker readiness is unavailable" } });
    for (const [name, input, expected] of [
      ["healthy", [series("up", "1x14"), series("agentsec_ready", "1x14")], []],
      ["missing one replica metric", [series("up", "1x14"), series("up", "1x14", { instance: "target-2" }), series("agentsec_ready", "1x14", { instance: "target-2" })], [readyExpected()]],
      ["target down", [series("up", "0x11 1x3"), series("agentsec_ready", "1x14")], [readyExpected()]],
      ["ready false on healthy scrape", [series("up", "1x14"), series("agentsec_ready", "0x11 1x3"), series("up", "1x14", { instance: "target-2" }), series("agentsec_ready", "1x14", { instance: "target-2" })], [readyExpected()]],
      ["entire mode absent", [], [readyExpected(true)]],
    ]) tests.push({ name: `${suffix} ${name}`, interval: "1m", input_series: [...healthyOther, ...input], alert_rule_test: [
      { eval_time: "9m", alertname: `${prefix}NotReady`, exp_alerts: [] },
      { eval_time: "10m", alertname: `${prefix}NotReady`, exp_alerts: expected },
      ...(["target down", "ready false on healthy scrape"].includes(name) ? [{ eval_time: "12m", alertname: `${prefix}NotReady`, exp_alerts: [] }] : []),
    ] });
    const deployLabels = { namespace: "agentsec", deployment: service };
    for (const absent of [false, true]) tests.push({ name: `${suffix} replicas ${absent ? "absent" : "zero then recovered"}`, interval: "1m", input_series: absent ? [] : [{ series: `kube_deployment_status_replicas_available{namespace="agentsec",deployment="${service}"}`, values: "0x6 2x8" }], alert_rule_test: [
      { eval_time: "4m", alertname: `${prefix}Unavailable`, exp_alerts: [] },
      { eval_time: "5m", alertname: `${prefix}Unavailable`, exp_alerts: [{ exp_labels: { ...deployLabels, severity: "page" }, exp_annotations: { summary: "Audit export workload is unavailable or absent" } }] },
      ...(absent ? [] : [{ eval_time: "8m", alertname: `${prefix}Unavailable`, exp_alerts: [] }]),
    ] });
  }
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-export-alerts-"));
  try {
    await writeFile(path.join(directory, "rules.yml"), dump(rule.spec));
    await writeFile(path.join(directory, "test.yml"), dump({ rule_files: ["rules.yml"], evaluation_interval: "1m", tests }));
    const { stdout } = await promisify(execFile)(process.env.ZASP_PROMTOOL_BIN, ["test", "rules", "test.yml"], { cwd: directory, timeout: 30000, maxBuffer: 1024 * 1024 });
    assert.match(stdout, /SUCCESS/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
