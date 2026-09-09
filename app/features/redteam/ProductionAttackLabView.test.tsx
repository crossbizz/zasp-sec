import { useEffect, type ReactNode } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AttackLabPreflight, AttackLabRun, AttackLabRunDetail, TestRun } from "../../../apps/web/api/generated";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { ProductionAttackLabView } from "./ProductionAttackLabView";
import type { ProductionRedTeamAPI } from "./api";

const sourceRunID = "pid_93000001-0000-4000-8000-000000000001";
const runID = "pid_93000002-0000-4000-8000-000000000002";
const definitionID = "pid_93000003-0000-4000-8000-000000000003";
const targetID = "pid_93000004-0000-4000-8000-000000000004";
const limits = { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 } as const;
const sourceRun: TestRun = { id: sourceRunID, version: 3, definition_id: definitionID, definition_version: 2, status: "complete", attempt: 1, cancel_requested: false, queued_at: "2026-08-28T09:00:00Z", started_at: "2026-08-28T09:00:01Z", completed_at: "2026-08-28T09:00:05Z", verdict: "fail", evidence_reference: "s3://zasp-red-team/source" };
const preflight: AttackLabPreflight = { source_run_id: sourceRunID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", allowed_destinations: ["adapter.customer.example"], success_criterion: "Reject direct prompt injection", expected_side_effects: ["bounded evaluation"], decision_digest: "a".repeat(64), decision_expires_at: "2099-08-28T10:05:00Z", limits };
const queued: AttackLabRun = { id: runID, version: 1, source_run_id: sourceRunID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", status: "queued", attempt: 0, cancel_requested: false, cleanup_state: "pending", limits, queued_at: "2026-08-28T10:00:00Z" };
const complete: AttackLabRunDetail = { ...queued, version: 4, status: "complete", attempt: 1, cleanup_state: "complete", started_at: "2026-08-28T10:00:01Z", attempt_started_at: "2026-08-28T10:00:01Z", completed_at: "2026-08-28T10:00:05Z", verdict: "verified", evidence_reference: "s3://zasp-attack-lab/evidence", evidence_version_id: "version-attack-lab-1", evidence_checksum: "c".repeat(64), evidence_size: 512, attempts: [{ attempt: 1, evidence_state: "complete", verdict: "verified", criterion_observed: true, canary_touched: true, cleanup_completed: true, evidence: ["semantic:criterion", "gateway:allowed", "egress:exact", "kubernetes:complete", "cloud:canary"], evidence_reference: "s3://zasp-attack-lab/evidence", evidence_version_id: "version-attack-lab-1", evidence_checksum: "c".repeat(64), evidence_size: 512, completed_at: "2026-08-28T10:00:05Z" }] };

function api(overrides: Partial<ProductionRedTeamAPI> = {}): ProductionRedTeamAPI {
  return {
    getTargetRecommendations: async () => ({targetID,freshUntil:"2099-01-01T00:00:00Z",items:[]}),
    listDefinitions: async () => [], getDefinition: async () => { throw new Error("unused"); }, createDefinition: async () => { throw new Error("unused"); }, updateDefinition: async () => { throw new Error("unused"); }, runDefinition: async () => { throw new Error("unused"); }, listRuns: async () => [sourceRun], getRun: async () => { throw new Error("unused"); }, cancelRun: async () => { throw new Error("unused"); },
    preflightAttackLab: async () => preflight, listAttackLabRuns: async () => [queued], getAttackLabRun: async () => complete, createAttackLabRun: async () => queued, cancelAttackLabRun: async () => ({ ...queued, version: 2, status: "cancelled", cancel_requested: true, cleanup_state: "complete", completed_at: "2026-08-28T10:01:00Z", error_code: "cancelled" }), rerunAttackLabRun: async () => queued,
    listTargets: async () => [], ...overrides,
  };
}

function view(value: ProductionRedTeamAPI, canWrite = true) {
  return render(<APIProvider><QueryScope><ProductionAttackLabView api={value} canWrite={canWrite} /></QueryScope></APIProvider>);
}

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI(); useEffect(() => setQueryScope("attack-lab-test-scope"), [setQueryScope]); return children;
}

describe("production Attack Lab view", () => {
  it("requires exact preflight and explicit approval before queueing", async () => {
    const preflightAttackLab = vi.fn(api().preflightAttackLab); const createAttackLabRun = vi.fn(api().createAttackLabRun); view(api({ preflightAttackLab, createAttackLabRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Review safety decision" }); expect(screen.getByRole("button", { name: "Run Attack Lab" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Review safety decision" })); expect(preflightAttackLab).toHaveBeenCalledWith(sourceRunID, expect.any(AbortSignal));
    expect(await screen.findByText("adapter.customer.example")).toBeVisible(); expect(screen.getByText("Reject direct prompt injection")).toBeVisible();
    await user.click(screen.getByRole("checkbox", { name: "Approve exact safety decision" })); await user.click(screen.getByRole("button", { name: "Run Attack Lab" }));
    expect(createAttackLabRun).toHaveBeenCalledWith(preflight, expect.stringMatching(/^pid_/), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
  });

  it("reuses one mutation identity and blocks rapid duplicate sandbox creation", async () => {
    let resolveCreate: ((value: AttackLabRun) => void) | undefined;
    const createAttackLabRun = vi.fn(() => new Promise<AttackLabRun>((resolve) => { resolveCreate = resolve; }));
    view(api({ createAttackLabRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Review safety decision" });
    await user.click(screen.getByRole("button", { name: "Review safety decision" }));
    await user.click(await screen.findByRole("checkbox", { name: "Approve exact safety decision" }));
    const button = screen.getByRole("button", { name: "Run Attack Lab" });
    fireEvent.click(button); fireEvent.click(button);
    expect(createAttackLabRun).toHaveBeenCalledTimes(1);
    expect(button).toBeDisabled();
    resolveCreate?.(queued);
  });

  it("replays the exact mutation identity after an ambiguous create response", async () => {
    const createAttackLabRun = vi.fn()
      .mockRejectedValueOnce(new Error("lost response"))
      .mockImplementationOnce(async (_preflight: AttackLabPreflight, createdRunID: string) => ({ ...queued, id: createdRunID }));
    view(api({ createAttackLabRun, listAttackLabRuns: async () => [] })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Review safety decision" });
    await user.click(screen.getByRole("button", { name: "Review safety decision" }));
    await user.click(await screen.findByRole("checkbox", { name: "Approve exact safety decision" }));
    await user.click(screen.getByRole("button", { name: "Run Attack Lab" }));
    const retry = await screen.findByRole("button", { name: "Retry unresolved Attack Lab request" });
    await user.click(retry);
    expect(createAttackLabRun).toHaveBeenCalledTimes(2);
    expect(createAttackLabRun.mock.calls[1]).toEqual(createAttackLabRun.mock.calls[0]);
  });

  it("loads durable evidence and version-fences rerun", async () => {
    const getAttackLabRun = vi.fn(api().getAttackLabRun); const rerunAttackLabRun = vi.fn(api().rerunAttackLabRun); view(api({ getAttackLabRun, rerunAttackLabRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: `Open Attack Lab run ${runID}` }); await user.click(screen.getByRole("button", { name: `Open Attack Lab run ${runID}` }));
    expect(await screen.findByText("semantic:criterion")).toBeVisible(); expect(getAttackLabRun).toHaveBeenCalledWith(runID, expect.any(AbortSignal));
    expect(screen.getByText(/version-attack-lab-1/)).toBeVisible(); expect(screen.getByText(/sha256:cccc/)).toBeVisible(); expect(screen.getByText(/512 bytes/)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Re-run safely" })); expect(rerunAttackLabRun).toHaveBeenCalledWith(runID, 4, expect.stringMatching(/^pid_/), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
  });

  it("version-fences active cancellation", async () => {
    const running: AttackLabRunDetail = { ...queued, version: 3, status: "running", attempt: 1, started_at: "2026-08-28T10:00:01Z", attempt_started_at: "2026-08-28T10:00:01Z", attempts: [] };
    const cancelAttackLabRun = vi.fn(api().cancelAttackLabRun); view(api({ getAttackLabRun: async () => running, cancelAttackLabRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: `Open Attack Lab run ${runID}` }); await user.click(screen.getByRole("button", { name: `Open Attack Lab run ${runID}` })); await user.click(await screen.findByRole("button", { name: "Cancel run" }));
    expect(cancelAttackLabRun).toHaveBeenCalledWith(runID, 3, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
  });

  it("keeps the tenant surface read-only without write capability", async () => {
    view(api(), false); expect(await screen.findByLabelText("Failed Red Team run")).toBeDisabled(); expect(screen.queryByRole("button", { name: "Review safety decision" })).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: "Cancel run" })).not.toBeInTheDocument();
  });
});
