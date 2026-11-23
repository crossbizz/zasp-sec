import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { AnalystFeedback, CalibrationMetrics, RuleSuppressionMode } from "../../../apps/web/api/generated";

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("Invalid calibration response");
  return value as Record<string, unknown>;
}
const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const score = (v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;
const rate = (v: unknown) => v === null || score(v);
const label = (v: unknown) => v === "confirm_tp" || v === "mark_fp";
function rows(v: unknown, max: number, valid: (r: Record<string, unknown>) => boolean) {
  return Array.isArray(v) && v.length <= max && v.every(row => valid(object(row)));
}
export function decodeCalibration(value: unknown): CalibrationMetrics {
  const m = object(value), d = object(m.discovery);
  if (m.days !== 30 || typeof m.environment_id !== "string" || !count(m.labelled) || !count(m.evaluated)
    || !rate(m.brier) || !rate(m.ece) || ![d.tp, d.fp, d.fn].every(count) || ![d.precision, d.recall].every(rate)
    || !rows(m.bins, 10, b => score(b.lower) && score(b.upper) && count(b.count) && rate(b.mean_probability) && rate(b.observed_rate))
    || !rows(m.thresholds, 101, t => score(t.threshold) && [t.tp, t.fp, t.tn, t.fn].every(count))
    || !rows(m.recent, 100, r => typeof r.decision_id === "string" && typeof r.rule_id === "string" && typeof r.occurred_at === "string" && (r.label === null || label(r.label))))
    throw Error("Invalid calibration response");
  return value as CalibrationMetrics;
}
function decodeRule(value: unknown, id: string): RuleSuppressionMode {
  const r = object(value);
  if (r.rule_id !== id || !["hard", "heuristic"].includes(String(r.rule_class)) || !["off", "shadow", "active"].includes(String(r.mode))
    || typeof r.eligible !== "boolean" || ![r.version, r.shadow_labels, r.false_alerts_avoided, r.serious_total, r.serious_missed].every(count))
    throw Error("Invalid rule suppression response");
  return value as RuleSuppressionMode;
}
const headers = (key: string) => ({ "Idempotency-Key": key, "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" as const });
export function createCalibrationAPI(client: APIClient) {
  return {
    async metrics(signal?: AbortSignal) {
      return requireAPIData(await client.GET("/api/v1/calibration/metrics", { signal }), decodeCalibration);
    },
    async rule(id: string, signal?: AbortSignal) {
      return requireAPIData(await client.GET("/api/v1/rules/{ruleId}/suppression-mode", { params: { path: { ruleId: id } }, signal }), value => decodeRule(value, id));
    },
    async setMode(rule: RuleSuppressionMode, mode: RuleSuppressionMode["mode"], key: string) {
      const result = await client.PUT("/api/v1/rules/{ruleId}/suppression-mode", { params: { path: { ruleId: rule.rule_id }, header: { ...headers(key), "If-Match": `"${rule.version}"` } }, body: { mode } });
      return requireAPIData(result, value => decodeRule(value, rule.rule_id));
    },
    async feedback(body: AnalystFeedback, key: string) {
      return requireAPIData(await client.POST("/api/v1/feedback", { params: { header: headers(key) }, body }), value => {
        const row = object(value);
        if (row.decision_id !== body.decision_id || row.rule_id !== body.rule_id || row.label !== body.label) throw Error("Feedback receipt did not match the decision");
        return body;
      });
    },
  };
}
