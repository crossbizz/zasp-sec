import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { dump } from "js-yaml";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";

const exec = promisify(execFile);
const names = ["ZaspReconciliationMaintenanceUnavailable", "ZaspReconciliationMaintenanceDebt", "ZaspReconciliationAutovacuumDisabled"];

test("rendered reconciliation maintenance alerts fire and recover in Prometheus", { skip: !process.env.ZASP_PROMTOOL_BIN }, async () => {
  const resources = await renderRelease(productionReleaseFixture);
  const rules = resources.filter(r => r.kind === "PrometheusRule").flatMap(r => r.spec.groups.flatMap(g => g.rules)).filter(r => names.includes(r.alert));
  assert.equal(rules.length, 3, "production maintenance alerts missing");
  const labels = { namespace: "agentsec", instance: "api-1", service: "agentsec-api" };
  const series = (name, extra = {}) => `${name}{${Object.entries({ ...labels, ...extra }).map(([k,v]) => `${k}="${v}"`).join(",")}}`;
  const sample = (name, values, extra) => ({ series: series(name, extra), values });
  const expected = (name, extra = {}, absent = false) => ({
    exp_labels: { ...(absent ? { namespace: "agentsec", service: "agentsec-api" } : labels), ...extra, severity: "ticket" },
    exp_annotations: { summary: {
      ZaspReconciliationMaintenanceUnavailable: "Reconciliation maintenance statistics are unavailable or stale",
      ZaspReconciliationMaintenanceDebt: "Reconciliation dead-tuple estimate remains elevated",
      ZaspReconciliationAutovacuumDisabled: "Ordinary reconciliation autovacuum is disabled",
    }[name] },
  });
  const valid = sample("zasp_reconciliation_maintenance_sample_valid", "1x8");
  const up = sample("up", "1x8");
  const unavailable = names[0], debt = names[1], disabled = names[2];
  const checks = (name, active, extra = {}, absent = false) => [
    { eval_time: "30s", alertname: name, exp_alerts: [] },
    { eval_time: "3m", alertname: name, exp_alerts: active ? [expected(name, extra, absent)] : [] },
  ];
  const tests = [
    { name: "healthy", input_series: [up, valid, sample("zasp_reconciliation_maintenance_dead_tuples", "0x8", { table: "zasp_connector_effect_lane_scopes" })], alert_rule_test: names.flatMap(n => checks(n, false)) },
    { name: "debt despite recent vacuum", input_series: [up, valid, sample("zasp_reconciliation_maintenance_dead_tuples", "10000x6 0x2", { table: "zasp_connector_effect_lane_scopes" }), sample("zasp_reconciliation_maintenance_last_autovacuum_seconds", "100+30x8", { table: "zasp_connector_effect_lane_scopes" })], alert_rule_test: [...checks(debt, true, { table: "zasp_connector_effect_lane_scopes" }), {eval_time:"4m",alertname:debt,exp_alerts:[]}] },
    { name: "invalid sampler", input_series: [up, sample("zasp_reconciliation_maintenance_sample_valid", "0x6 1x2")], alert_rule_test: [...checks(unavailable, true), {eval_time:"4m",alertname:unavailable,exp_alerts:[]}] },
    { name: "metric absent on live target", input_series: [up], alert_rule_test: checks(unavailable, true) },
    { name: "target down", input_series: [sample("up", "0x8")], alert_rule_test: checks(unavailable, true) },
    { name: "all targets absent", input_series: [], alert_rule_test: checks(unavailable, true, {}, true) },
    { name: "autovacuum disabled", input_series: [up, valid, sample("zasp_reconciliation_maintenance_autovacuum_enabled", "0x8", { table: "zasp_connector_effect_lane_scopes" })], alert_rule_test: checks(disabled, true, { table: "zasp_connector_effect_lane_scopes" }) },
  ];
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-maintenance-alerts-"));
  try {
    await writeFile(path.join(directory,"rules.yml"),dump({groups:[{name:"maintenance",rules}]}));
    await writeFile(path.join(directory,"test.yml"),dump({rule_files:["rules.yml"],evaluation_interval:"30s",tests:tests.map(t=>({interval:"30s",...t}))}));
    const result = await exec(process.env.ZASP_PROMTOOL_BIN,["test","rules","test.yml"],{cwd:directory,timeout:30000,maxBuffer:1024*1024});
    assert.match(result.stdout,/SUCCESS/);
  } finally { await rm(directory,{recursive:true,force:true}); }
});
