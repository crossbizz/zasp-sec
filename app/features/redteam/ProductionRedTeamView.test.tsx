import { useEffect, type ReactNode } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "../../api/APIProvider";
import { ProductionRedTeamView } from "./ProductionRedTeamView";
import type { ProductionRedTeamAPI } from "./api";

const definitionID = "pid_92000001-0000-4000-8000-000000000001";
const targetID = "pid_92000002-0000-4000-8000-000000000002";
const runID = "pid_92000003-0000-4000-8000-000000000003";
const definition = { id: definitionID, version: 2, name: "Staging agent safety", target_id: targetID, target_kind: "agent_endpoint" as const, categories: ["prompt_injection" as const], safety: { environment: "staging" as const, credential_class: "read_only" as const, expected_side_effects: ["bounded evaluation"] }, enabled: true, created_at: "2026-08-24T10:00:00Z", updated_at: "2026-08-24T10:01:00Z" };
const run = { id: runID, version: 1, definition_id: definitionID, definition_version: 2, status: "queued" as const, attempt: 0, cancel_requested: false, queued_at: "2026-08-24T10:02:00Z" };

function api(overrides: Partial<ProductionRedTeamAPI> = {}): ProductionRedTeamAPI {
  return {
    listDefinitions: async () => [definition], getDefinition: async () => definition, createDefinition: async (input) => ({ ...definition, ...input, version: 1, enabled: true }), updateDefinition: async (_id, _version, input) => ({ ...definition, ...input, version: 3 }), runDefinition: async () => run, listRuns: async () => [run], getRun: async () => ({ ...run, attempts: [] }), cancelRun: async () => ({ ...run, version: 2, status: "cancelled", cancel_requested: true, completed_at: "2026-08-24T10:03:00Z", error_code: "cancelled" }), preflightAttackLab: async () => { throw new Error("unused"); }, listAttackLabRuns: async () => [], getAttackLabRun: async () => { throw new Error("unused"); }, createAttackLabRun: async () => { throw new Error("unused"); }, cancelAttackLabRun: async () => { throw new Error("unused"); }, rerunAttackLabRun: async () => { throw new Error("unused"); }, listTargets: async () => [{ id: targetID, name: "customer-agent", kind: "agent", owner: "platform", team: "agents", tags: [], evidence_id: "pid_92000004-0000-4000-8000-000000000004", confidence_basis_points: 9500, first_seen: "2026-08-24T09:00:00Z", last_seen: "2026-08-24T10:00:00Z", observed_at: "2026-08-24T10:00:00Z", fresh_until: "2026-08-24T11:00:00Z", freshness_state: "fresh", version: 1 }], ...overrides,
  };
}

function view(value: ProductionRedTeamAPI, canWrite = true) {
  return render(<APIProvider><QueryScope><ProductionRedTeamView api={value} canWrite={canWrite} onNavigate={() => undefined} /></QueryScope></APIProvider>);
}

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("red-team-test-scope"), [setQueryScope]);
  return children;
}

describe("production red team view", () => {
  it("renders tenant-backed definitions and queued runs", async () => {
    view(api(), false);
    expect(await screen.findByRole("button", { name: "Staging agent safety" })).toBeVisible();
    expect(screen.getByText("customer-agent")).toBeVisible();
    expect(screen.getByText("queued")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Create test" })).not.toBeInTheDocument();
  });

  it("creates a bounded definition for an authoritative target", async () => {
    const createDefinition = vi.fn(api().createDefinition); view(api({ createDefinition })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Staging agent safety" }); await user.click(screen.getByRole("button", { name: "Create test" }));
    await user.clear(screen.getByLabelText("Test name")); await user.type(screen.getByLabelText("Test name"), "Customer agent safety");
    await user.click(screen.getByRole("button", { name: "Save test" }));
    expect(createDefinition).toHaveBeenCalledWith(expect.objectContaining({ name: "Customer agent safety", target_id: targetID, target_kind: "agent_endpoint", categories: ["prompt_injection"], safety: { environment: "staging", credential_class: "read_only", expected_side_effects: ["bounded evaluation"] } }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
  });

  it("runs, inspects, and cancels with exact versions", async () => {
    const runDefinition = vi.fn(api().runDefinition); const getRun = vi.fn(api().getRun); const cancelRun = vi.fn(api().cancelRun); view(api({ runDefinition, getRun, cancelRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Staging agent safety" }); await user.click(screen.getByRole("button", { name: "Run Staging agent safety" }));
    expect(runDefinition).toHaveBeenCalledWith(definitionID, 2, expect.stringMatching(/^pid_/), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
    await user.click(screen.getByRole("button", { name: `Open run ${runID}` })); expect(await screen.findByRole("dialog", { name: "Red team run" })).toBeVisible(); expect(getRun).toHaveBeenCalledWith(runID, expect.any(AbortSignal));
    await user.click(screen.getByRole("button", { name: "Cancel run" })); expect(cancelRun).toHaveBeenCalledWith(runID, 1, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }));
  });
});
