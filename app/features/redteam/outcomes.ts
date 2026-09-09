import type { TestRun } from "../../../apps/web/api/generated";

const outcomes = [
  { id: "unsafe", label: "Unsafe behavior observed", description: "Completed checks found unsafe behavior. Attack Lab requires a separate safety review." },
  { id: "protected", label: "Curated checks passed", description: "The selected checks passed. This does not establish coverage beyond those categories." },
  { id: "errors", label: "Evaluation errors", description: "Execution did not establish a security verdict. Inspect the error before retrying." },
  { id: "pending", label: "In progress", description: "Queued, running or retrying. No completed security verdict is available." },
  { id: "cancelled", label: "Cancelled", description: "Execution was cancelled. No security verdict is established." },
] as const;

type OutcomeID = typeof outcomes[number]["id"];
function outcomeID(run: TestRun): OutcomeID {
  if (run.status === "cancelled") return "cancelled";
  if (run.status === "failed") return "errors";
  if (run.status !== "complete") return "pending";
  return run.verdict === "fail" ? "unsafe" : run.verdict === "pass" ? "protected" : "errors";
}

export function groupRedTeamRuns(runs: readonly TestRun[]) {
  return outcomes.map(outcome => ({ ...outcome, runs: runs.filter(run => outcomeID(run) === outcome.id) })).filter(group => group.runs.length > 0);
}

export function canReviewRedTeamRunInAttackLab(run: TestRun): boolean {
  return run.status === "complete" && run.verdict === "fail" && run.attempt > 0 && !run.cancel_requested && Boolean(run.completed_at) && Boolean(run.evidence_reference);
}
