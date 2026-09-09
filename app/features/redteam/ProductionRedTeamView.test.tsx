import { StrictMode, useEffect, type ReactNode } from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { APIProvider, useAPI } from "../../api/APIProvider";
import { APIProductError } from "../../../apps/web/api/client";
import { ProductionRedTeamView } from "./ProductionRedTeamView";
import type { ProductionRedTeamAPI, RedTeamRecommendations } from "./api";

const definitionID = "pid_92000001-0000-4000-8000-000000000001";
const targetID = "pid_92000002-0000-4000-8000-000000000002";
const runID = "pid_92000003-0000-4000-8000-000000000003";
const scopeKey = "pid_92100001-0000-4000-8000-000000000001/pid_92100002-0000-4000-8000-000000000002/pid_92100003-0000-4000-8000-000000000003/pid_92100004-0000-4000-8000-000000000004";
beforeEach(() => window.sessionStorage.clear());
const definition = { id: definitionID, version: 2, name: "Staging agent safety", target_id: targetID, target_kind: "agent_endpoint" as const, categories: ["prompt_injection" as const], safety: { environment: "staging" as const, credential_class: "read_only" as const, expected_side_effects: ["bounded evaluation"] }, enabled: true, created_at: "2026-08-24T10:00:00Z", updated_at: "2026-08-24T10:01:00Z" };
const run = { id: runID, version: 1, definition_id: definitionID, definition_version: 2, status: "queued" as const, attempt: 0, cancel_requested: false, queued_at: "2026-08-24T10:02:00Z" };
function recommendationSet(items:RedTeamRecommendations["items"],id=targetID):RedTeamRecommendations {return {targetID:id,freshUntil:"2099-01-01T00:00:00Z",items};}

function api(overrides: Partial<ProductionRedTeamAPI> = {}): ProductionRedTeamAPI {
  return {
    getTargetRecommendations: async () => recommendationSet([]),
    listDefinitions: async () => [definition], getDefinition: async () => definition, createDefinition: async (input) => ({ ...definition, ...input, version: 1, enabled: true }), updateDefinition: async (_id, _version, input) => ({ ...definition, ...input, version: 3 }), runDefinition: async () => run, listRuns: async () => [run], getRun: async () => ({ ...run, attempts: [] }), cancelRun: async () => ({ ...run, version: 2, status: "cancelled", cancel_requested: true, completed_at: "2026-08-24T10:03:00Z", error_code: "cancelled" }), preflightAttackLab: async () => { throw new Error("unused"); }, listAttackLabRuns: async () => [], getAttackLabRun: async () => { throw new Error("unused"); }, createAttackLabRun: async () => { throw new Error("unused"); }, cancelAttackLabRun: async () => { throw new Error("unused"); }, rerunAttackLabRun: async () => { throw new Error("unused"); }, listTargets: async () => [{ id: targetID, name: "customer-agent", kind: "agent", owner: "platform", team: "agents", tags: [], evidence_id: "pid_92000004-0000-4000-8000-000000000004", confidence_basis_points: 9500, first_seen: "2026-08-24T09:00:00Z", last_seen: "2026-08-24T10:00:00Z", observed_at: "2026-08-24T10:00:00Z", fresh_until: "2026-08-24T11:00:00Z", freshness_state: "fresh", version: 1 }], ...overrides,
  };
}

function view(value: ProductionRedTeamAPI, canWrite = true, scope = scopeKey) {
  return render(<APIProvider><QueryScope><ProductionRedTeamView scopeKey={scope} api={value} canWrite={canWrite} onNavigate={() => undefined} /></QueryScope></APIProvider>);
}

function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("red-team-test-scope"), [setQueryScope]);
  return children;
}

describe("production red team view", () => {
  it("shows durable input metadata and identifies legacy evidence", async () => {
    const input = { reference: "s3://zasp-evidence/exact-input", version_id: "input-version-7", sha256: "b".repeat(64), size_bytes: 512 };
    const legacyAttempt = { attempt: 1, verdict: "pass" as const, objective: "Evaluate bounded input", behavior: "Target refused", evidence: ["Protected"], evidence_reference: "s3://zasp-evidence/result", completed_at: "2026-09-09T02:00:00Z" };
    const detail = { ...run, status: "complete" as const, verdict: "pass" as const, attempts: [{ ...legacyAttempt, input_artifact: input }] };
    const getRun = vi.fn().mockResolvedValueOnce(detail).mockResolvedValueOnce({ ...detail, attempts: [legacyAttempt] });
    view(api({ getRun })); const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: `Open run ${runID}` }));
    expect(await screen.findByText(input.reference)).toBeVisible();
    expect(screen.getByText(input.version_id)).toBeVisible(); expect(screen.getByText(input.sha256)).toBeVisible();
    expect(screen.getByText("512 bytes")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByRole("button", { name: `Open run ${runID}` }));
    expect(await screen.findByText("Input artifact unavailable for this legacy attempt.")).toBeVisible();
  });
  it("automatically removes current recommendations when evidence expires",async()=>{
    vi.useFakeTimers();
    try {
      const value={...recommendationSet([{category:"data_leakage",explanation:"Briefly current data.",evidenceIDs:[targetID]}]),freshUntil:new Date(Date.now()+1000).toISOString()};
      const getTargetRecommendations=vi.fn().mockResolvedValueOnce(value).mockRejectedValueOnce(new Error("expired"));
      view(api({getTargetRecommendations}));await act(async()=>{});
      await act(async()=>{fireEvent.click(screen.getByRole("button",{name:"Create test"}));});
      expect(screen.getByRole("button",{name:"Use recommended categories"})).toBeInTheDocument();
      await act(async()=>{vi.advanceTimersByTime(1001);});
      expect(getTargetRecommendations).toHaveBeenCalledTimes(2);
      expect(screen.queryByRole("button",{name:"Use recommended categories"})).not.toBeInTheDocument();
      expect(screen.getByText("Capability recommendations are unavailable. No recommended pack is confirmed.")).toBeInTheDocument();
    } finally {vi.useRealTimers();}
  });
  it("refuses an expired recommendation when the browser clock advances before Apply",async()=>{
    const original=Date.now();const clock=vi.spyOn(Date,"now").mockReturnValue(original);
    try {
      const values=recommendationSet([{category:"data_leakage",explanation:"Expiring data boundary.",evidenceIDs:[targetID]}]);
      const getTargetRecommendations=vi.fn().mockResolvedValueOnce(values).mockRejectedValueOnce(new Error("stale"));
      view(api({getTargetRecommendations}));const user=userEvent.setup();
      await user.click(await screen.findByRole("button",{name:"Create test"}));
      const apply=await screen.findByRole("button",{name:"Use recommended categories"});
      clock.mockReturnValue(Date.parse("2100-01-01T00:00:00Z"));
      await user.click(apply);
      expect(screen.getByLabelText("Data leakage")).not.toBeChecked();
      await waitFor(()=>expect(getTargetRecommendations).toHaveBeenCalledTimes(2));
    } finally {clock.mockRestore();}
  });
  it("aborts old-target recommendations and ignores a late result after target selection changes",async()=>{
    let finish!:(value:readonly {category:"data_leakage";explanation:string;evidenceIDs:readonly string[]}[])=>void;
    const getTargetRecommendations=vi.fn().mockImplementationOnce(()=>new Promise(resolve=>{finish=values=>resolve(recommendationSet(values));})).mockResolvedValueOnce(recommendationSet([{category:"tool_abuse",explanation:"Current tool boundary.",evidenceIDs:[targetID]}],"pid_92000005-0000-4000-8000-000000000005"));
    const targets=await api().listTargets();const other="pid_92000005-0000-4000-8000-000000000005";
    view(api({getTargetRecommendations,listTargets:async()=>[...targets,{...targets[0],id:other,name:"Other tool",kind:"tool"}]}));const user=userEvent.setup();
    await user.click(await screen.findByRole("button",{name:"Create test"}));await waitFor(()=>expect(getTargetRecommendations).toHaveBeenCalledTimes(1));
    await user.selectOptions(screen.getByLabelText("Fresh discovered target"),other);
    expect(await screen.findByText("Current tool boundary.")).toBeInTheDocument();expect(getTargetRecommendations.mock.calls[0][2].aborted).toBe(true);
    await act(async()=>{finish([{category:"data_leakage",explanation:"Stale prior target.",evidenceIDs:[targetID]}]);});
    expect(screen.queryByText("Stale prior target.")).not.toBeInTheDocument();
  });
  it("shows capability-backed recommendations and applies only the explicit recommended pack",async()=>{
    const getTargetRecommendations=vi.fn().mockResolvedValue(recommendationSet([{category:"data_leakage",explanation:"Discovered data read boundary.",evidenceIDs:[targetID]}]));
    const createDefinition=vi.fn(api().createDefinition);
    view(api({getTargetRecommendations,createDefinition}));const user=userEvent.setup();
    await user.click(await screen.findByRole("button",{name:"Create test"}));
    await user.click(await screen.findByRole("button",{name:"Use recommended categories"}));
    expect(screen.getByText("Discovered data read boundary.")).toBeInTheDocument();
    expect(getTargetRecommendations).toHaveBeenCalledWith(targetID,"agent",expect.any(AbortSignal));
    expect(screen.getByLabelText("Data leakage")).toBeChecked();expect(screen.getByLabelText("Prompt injection")).not.toBeChecked();
    expect(screen.getByLabelText("Safe environment")).toHaveValue("staging");
    await user.click(screen.getByRole("button",{name:"Save test"}));
    expect(createDefinition.mock.calls[0][0].categories).toEqual(["data_leakage"]);
  });
  it("reports unavailable recommendations without claiming a recommended or safe pack",async()=>{
    view(api({getTargetRecommendations:async()=>{throw new Error("unavailable");}}));
    await userEvent.setup().click(await screen.findByRole("button",{name:"Create test"}));
    expect(await screen.findByText("Capability recommendations are unavailable. No recommended pack is confirmed.")).toBeInTheDocument();
    expect(screen.queryByRole("button",{name:"Use recommended categories"})).not.toBeInTheDocument();
  });
  it("refreshes a rejected version before allowing another write and closes stale detail", async () => {
    let finish!: (value: typeof definition[]) => void;
    const listDefinitions = vi.fn().mockResolvedValueOnce([definition]).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const updateDefinition = vi.fn().mockRejectedValueOnce(new APIProductError(409, {code:"version_conflict",message:"version conflict",retryable:false,correlation_id:definitionID}));
    view(api({listDefinitions,updateDefinition})); const user = userEvent.setup();
    await user.click(await screen.findByRole("button",{name:definition.name}));
    await user.click(await screen.findByRole("button",{name:"Disable test"}));
    await waitFor(() => expect(listDefinitions).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("button",{name:"Disable test"})).not.toBeInTheDocument();
    expect(screen.getByRole("button",{name:"Run Staging agent safety"})).toBeDisabled();
    await act(async () => { finish([{...definition,version:3}]); });
    expect(screen.getByRole("button",{name:"Run Staging agent safety"})).toBeEnabled();
  });
	it("recovers a lost run response across a full component remount without a replacement ID", async () => {
		const runDefinition = vi.fn(api().runDefinition).mockRejectedValueOnce(new TypeError("response lost"));
		const first = view(api({ runDefinition }));const user=userEvent.setup();
		await user.click(await screen.findByRole("button", { name:"Run Staging agent safety" }));
		await screen.findByRole("button", { name:"Retry retained operation" });const original=runDefinition.mock.calls[0];first.unmount();
		view(api({runDefinition}));
		await user.click(await screen.findByRole("button",{name:"Retry retained operation"}));
		expect(runDefinition.mock.calls[1].slice(0,4)).toEqual(original.slice(0,4));
		await waitFor(()=>expect(window.sessionStorage.length).toBe(0));
	});
	it("does not reveal a retained operation after the authenticated principal changes",async()=>{
		const runDefinition=vi.fn(api().runDefinition).mockRejectedValueOnce(new TypeError("lost"));const first=view(api({runDefinition}));const user=userEvent.setup();
		await user.click(await screen.findByRole("button",{name:"Run Staging agent safety"}));await screen.findByRole("button",{name:"Retry retained operation"});first.unmount();
		view(api(),true,scopeKey.replace("pid_92100001","pid_92400001"));
		expect(await screen.findByRole("button",{name:"Run Staging agent safety"})).toBeEnabled();
		expect(screen.queryByRole("button",{name:"Retry retained operation"})).not.toBeInTheDocument();
	});
	it("freezes an ambiguous creation and retries it without accepting changed inputs",async()=>{
		const createDefinition=vi.fn(api().createDefinition).mockRejectedValueOnce(new TypeError("lost"));view(api({createDefinition}));const user=userEvent.setup();
		await user.click(await screen.findByRole("button",{name:"Create test"}));await user.click(screen.getByRole("button",{name:"Save test"}));
		const retry=await screen.findByRole("button",{name:"Retry retained operation"});
		expect(screen.getByLabelText("Test name")).toBeDisabled();expect(screen.getByLabelText("Fresh discovered target")).toBeDisabled();
		await user.click(retry);expect(createDefinition.mock.calls[1].slice(0,2)).toEqual(createDefinition.mock.calls[0].slice(0,2));
	});
	it("cannot submit an already open creation after write permission is removed",async()=>{
		const createDefinition=vi.fn(api().createDefinition);const value=api({createDefinition});
		const first=view(value);const user=userEvent.setup();await user.click(await screen.findByRole("button",{name:"Create test"}));
		first.rerender(<APIProvider><QueryScope><ProductionRedTeamView scopeKey={scopeKey} api={value} canWrite={false} onNavigate={()=>undefined}/></QueryScope></APIProvider>);
		expect(screen.getByRole("button",{name:"Save test"})).toBeDisabled();await user.click(screen.getByRole("button",{name:"Save test"}));expect(createDefinition).not.toHaveBeenCalled();
	});
	it("keeps recovery usable under StrictMode effect replay",async()=>{
		const runDefinition=vi.fn(api().runDefinition);render(<StrictMode><APIProvider><QueryScope><ProductionRedTeamView scopeKey={scopeKey} api={api({runDefinition})} canWrite onNavigate={()=>undefined}/></QueryScope></APIProvider></StrictMode>);
		await userEvent.setup().click(await screen.findByRole("button",{name:"Run Staging agent safety"}));expect(runDefinition).toHaveBeenCalledTimes(1);
	});
	it("synchronously fences duplicate and competing run submissions", async () => {
		let finish!: (value: typeof run) => void;
		const runDefinition = vi.fn(() => new Promise<typeof run>((resolve) => { finish = resolve; }));
		view(api({ runDefinition }));
		const button = await screen.findByRole("button", { name: "Run Staging agent safety" });
		act(() => { fireEvent.click(button); fireEvent.click(button); });
		expect(runDefinition).toHaveBeenCalledTimes(1);
		expect(button).toBeDisabled();
		expect(screen.getByRole("button", { name: "Create test" })).toBeDisabled();
		await act(async () => { finish(run); });
	});

	it("retries an ambiguous run with its exact frozen run ID, version, and idempotency key", async () => {
		const runDefinition = vi.fn(api().runDefinition).mockRejectedValueOnce(new TypeError("response lost"));
		view(api({ runDefinition })); const user = userEvent.setup();
		await user.click(await screen.findByRole("button", { name: "Run Staging agent safety" }));
		const first = runDefinition.mock.calls[0];
		expect(await screen.findByRole("button", { name: "Retry retained operation" })).toBeEnabled();
		expect(screen.getByRole("button", { name: "Run Staging agent safety" })).toBeDisabled();
		await user.click(screen.getByRole("button", { name: "Retry retained operation" }));
		await waitFor(() => expect(runDefinition).toHaveBeenCalledTimes(2));
		expect(runDefinition.mock.calls[1].slice(0,4)).toEqual(first.slice(0,4));
	});

	it("disables new mutations when the authoritative list becomes stale", async () => {
		const listDefinitions = vi.fn(api().listDefinitions).mockResolvedValueOnce([definition]).mockRejectedValue(new TypeError("offline"));
		view(api({ listDefinitions })); const user = userEvent.setup();
		await user.click(await screen.findByRole("button", { name: "Run Staging agent safety" }));
		expect(await screen.findByText("Showing stale Red Team data. Reload before making changes.")).toBeVisible();
		expect(screen.getByRole("button", { name: "Run Staging agent safety" })).toBeDisabled();
		expect(screen.getByRole("button", { name: "Create test" })).toBeDisabled();
	});

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
    expect(createDefinition).toHaveBeenCalledWith(expect.objectContaining({ name: "Customer agent safety", target_id: targetID, target_kind: "agent_endpoint", categories: ["prompt_injection"], safety: { environment: "staging", credential_class: "read_only", expected_side_effects: ["bounded evaluation"] } }), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }), expect.any(AbortSignal));
  });

  it("runs, inspects, and cancels with exact versions", async () => {
    const runDefinition = vi.fn(api().runDefinition); const getRun = vi.fn(api().getRun); const cancelRun = vi.fn(api().cancelRun); view(api({ runDefinition, getRun, cancelRun })); const user = userEvent.setup();
    await screen.findByRole("button", { name: "Staging agent safety" }); await user.click(screen.getByRole("button", { name: "Run Staging agent safety" }));
    expect(runDefinition).toHaveBeenCalledWith(definitionID, 2, expect.stringMatching(/^pid_/), expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }), expect.any(AbortSignal));
    await user.click(screen.getByRole("button", { name: `Open run ${runID}` })); expect(await screen.findByRole("dialog", { name: "Red team run" })).toBeVisible(); expect(getRun).toHaveBeenCalledWith(runID, expect.any(AbortSignal));
    await user.click(screen.getByRole("button", { name: "Cancel run" })); expect(cancelRun).toHaveBeenCalledWith(runID, 1, expect.objectContaining({ idempotencyKey: expect.stringMatching(/^redteam_/) }), expect.any(AbortSignal));
  });
});
