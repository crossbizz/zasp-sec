import { describe, expect, it } from "vitest";
import type { TestRun } from "../../../apps/web/api/generated";
import { canReviewRedTeamRunInAttackLab, groupRedTeamRuns } from "./outcomes";

const complete: TestRun = { id: "pid_97000001-0000-4000-8000-000000000001", definition_id: "pid_97000002-0000-4000-8000-000000000002", definition_version: 1, version: 3, status: "complete", attempt: 1, cancel_requested: false, queued_at: "2026-09-09T01:00:00Z", started_at: "2026-09-09T01:00:01Z", completed_at: "2026-09-09T01:00:02Z", verdict: "fail", evidence_reference: "s3://zasp-evidence/result" };
describe("Red Team security outcomes", () => {
  it("groups each run once without changing source order within an outcome", () => {
    const runs: TestRun[] = [
      { ...complete, id: "pending", status: "leased", verdict: undefined },
      { ...complete, id: "protected", verdict: "pass" },
      { ...complete, id: "unsafe-1" }, { ...complete, id: "unsafe-2" },
      { ...complete, id: "engine", verdict: "engine_error" },
      { ...complete, id: "exhausted", status: "failed", verdict: undefined },
      { ...complete, id: "cancelled", status: "cancelled", verdict: undefined },
    ];
    const snapshot = structuredClone(runs);
    expect(groupRedTeamRuns(runs).map(group => [group.id, group.runs.map(run => run.id)])).toEqual([
      ["unsafe", ["unsafe-1", "unsafe-2"]], ["protected", ["protected"]], ["errors", ["engine", "exhausted"]], ["pending", ["pending"]], ["cancelled", ["cancelled"]],
    ]);
    expect(runs).toEqual(snapshot); expect(groupRedTeamRuns([])).toEqual([]);
  });
  it("does not turn a nonterminal or cancelled run into a security verdict", () => {
    for (const status of ["queued", "leased", "retryable", "cancelled"] as const) {
      const run = { ...complete, status };
      expect(groupRedTeamRuns([run])[0].id).toBe(status === "cancelled" ? "cancelled" : "pending");
      expect(canReviewRedTeamRunInAttackLab(run)).toBe(false);
    }
  });
  it("allows safety review only for a completed unsafe result with evidence", () => {
    expect(canReviewRedTeamRunInAttackLab(complete)).toBe(true);
    for (const patch of [{ verdict: "pass" as const }, { verdict: "engine_error" as const }, { evidence_reference: undefined }, { completed_at: undefined }, { attempt: 0 }, { cancel_requested: true }]) {
      expect(canReviewRedTeamRunInAttackLab({ ...complete, ...patch })).toBe(false);
    }
  });
});
