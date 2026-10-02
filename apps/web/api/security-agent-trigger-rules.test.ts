import { describe, expect, it } from "vitest";
import { decodeSecurityAgentDefinition } from "./decoders";

const definition = { id: "pid_40000001-0000-4000-8000-000000000001", name: "Configured responder", trigger_kind: "finding", trigger_source: "credential", environment_ids: ["pid_10000003-0000-4000-8000-000000000003"], autonomy: "supervised", max_steps: 1, max_duration_seconds: 900, temporary_policy_seconds: 3600, ai_token_budget: 4000, concurrency_limit: 2, allowed_actions: ["update_finding_response"], verification_kind: "finding_state", definition_version: 1, enabled: false };
const finding = { version: 1, mode: "automatic", cooldown_seconds: 600, finding: { family: "credential", minimum_severity: "high" } };

describe("trigger rules public readback", () => {
  it.each<[string, string, unknown]>([
    ["finding", "credential", finding],
    ["finding", "credential", { version: 1, mode: "manual" }],
    ...["potential", "observed", "verified"].map((state): [string, string, unknown] => ["attack_path", state, { version: 1, mode: "automatic", cooldown_seconds: 600, attack_path: { state } }]),
    ["runtime_decision", "block", { version: 1, mode: "automatic", cooldown_seconds: 1, runtime: { decision: "block", action: "http_request", count: 3, window_seconds: 300, risk: "high" } }],
    ["runtime_decision", "block", { version: 1, mode: "automatic", cooldown_seconds: 86400, runtime: { decision: "monitor", action: "tool_call", count: 100, window_seconds: 86400 } }],
  ])("retains configured %s rule", (kind, source, rules) => {
    const value = { ...definition, trigger_kind: kind, trigger_source: source, trigger_rules: rules };
    expect(decodeSecurityAgentDefinition(value)).toEqual(value);
  });
  it("does not invent rules for historical definitions", () => {
    expect(decodeSecurityAgentDefinition(definition)).toEqual(definition);
  });
  it.each([null, {}, { version: 2, mode: "manual" }, { version: 1, mode: "manual", extra: true }, { ...finding, cooldown_seconds: 0 }, { ...finding, cooldown_seconds: 86401 }, { ...finding, cooldown_seconds: 1.5 }, { ...finding, finding: { family: "other", minimum_severity: "high" } }, { ...finding, finding: { family: "credential", minimum_severity: "severe" } }, { ...finding, runtime: { decision: "block", action: "http_request", count: 1, window_seconds: 1 } }])("refuses invalid rule %j", rules => {
    expect(() => decodeSecurityAgentDefinition({ ...definition, trigger_rules: rules })).toThrow();
  });
});
