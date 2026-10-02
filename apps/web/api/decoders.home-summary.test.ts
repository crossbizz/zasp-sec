import { describe, expect, it } from "vitest";
import { decodeHomeSummary } from "./decoders";

const counts = { agent_count: 4, high_risk_paths: 0, verified_changes: 2, blocked_changes: 1, pending_approvals: 0, oldest_approval_age_seconds: 0, needs_human_runs: 0, failed_runs: 0, inconclusive_runs: 0, recent_contained: 0, recent_remediated: 0 };

describe("home summary status authority", () => {
  it.each([[null, null], [true, false], [false, true]])("accepts the complete status pair %s/%s without changing authorized counts", (healthy, attention_required) => {
    const input = { ...counts, healthy, attention_required };
    expect(decodeHomeSummary(input)).toEqual(input);
  });
  it.each([[null, false], [null, true], [false, null], [true, null], [true, true], [false, false], ["true", false], [true, 0], [undefined, null], [null, undefined]])("rejects mixed, contradictory or malformed status %s/%s", (healthy, attention_required) => {
    expect(() => decodeHomeSummary({ ...counts, healthy, attention_required })).toThrow();
  });
  it.each(["healthy", "attention_required"])("requires the %s field even when environment health is unavailable", (key) => {
    const input: Record<string, unknown> = { ...counts, healthy: null, attention_required: null };
    delete input[key];
    expect(() => decodeHomeSummary(input)).toThrow();
  });
  it.each(Object.keys(counts))("keeps %s a required nonnegative safe integer in restricted results", (key) => {
    for (const invalid of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, "0", undefined]) {
      expect(() => decodeHomeSummary({ ...counts, healthy: null, attention_required: null, [key]: invalid })).toThrow();
    }
    expect(decodeHomeSummary({ ...counts, healthy: null, attention_required: null, [key]: Number.MAX_SAFE_INTEGER })[key as keyof typeof counts]).toBe(Number.MAX_SAFE_INTEGER);
  });
  it("rejects extra fields rather than displaying inferred health", () => {
    expect(() => decodeHomeSummary({ ...counts, healthy: null, attention_required: null, environment_healthy: true })).toThrow();
  });
});
