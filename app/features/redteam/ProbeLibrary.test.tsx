import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { decodeTestAttempt, decodeTestProbeCatalog, decodeTestSchedule } from "../../../apps/web/api/decoders";
import type { TestDefinition, TestProbeCatalog, TestSchedule } from "../../../apps/web/api/generated";
import type { ProductionRedTeamAPI } from "./api";
import { ProbeLibraryCard, ProbeResults, ScheduleControl, probeCountLabel } from "./ProbeLibrary";

const definitionID = "pid_92000001-0000-4000-8000-000000000001";
const names = ["prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information", "indirect_injection", "poisoned_resource", "cross_agent_delegation"] as const;
const catalog: TestProbeCatalog = {
  version: "zasp-probe-library-v1", digest: "a".repeat(64), probe_count: 1080, default_sample_size: 25,
  categories: names.map((category) => ({ category, title: category.replaceAll("_", " "), probe_count: 120, techniques: ["direct_override", "role_play"], frameworks: [{ framework: "owasp_llm_top10_2025" as const, control: "LLM01", title: "Prompt Injection" }] })),
};
const unsaved: TestSchedule = { definition_id: definitionID, version: 0, enabled: false, cadence_seconds: null, on_target_change: false, next_run_at: null, last_run_id: null, last_trigger: null, last_outcome: null, last_fired_at: null, updated_at: null };
const saved: TestSchedule = { ...unsaved, version: 1, enabled: true, cadence_seconds: 86400, on_target_change: true, next_run_at: "2026-11-15T10:00:00Z", updated_at: "2026-11-14T10:00:00Z" };
const definition: TestDefinition = { id: definitionID, version: 2, name: "Staging agent safety", target_id: "pid_92000002-0000-4000-8000-000000000002", target_kind: "agent_endpoint", categories: ["indirect_injection"], safety: { environment: "staging", credential_class: "read_only", expected_side_effects: ["bounded evaluation"] }, enabled: true, created_at: "2026-08-24T10:00:00Z", updated_at: "2026-08-24T10:01:00Z" };
const probe = (suffix: string, outcome: "protected" | "unsafe") => ({ probe_id: `zasp.indirect_injection.${suffix}.suppress_answer.tool_result.v1`, category: "indirect_injection" as const, outcome });
const attempt = { attempt: 1, verdict: "fail", objective: "Evaluate curated categories: indirect_injection", behavior: "1 of 2 curated probes passed; 1 exposed unsafe behavior.", evidence: ["indirect_injection: unsafe behavior observed"], evidence_reference: "s3://zasp-evidence/organizations/o/workspaces/w/environments/e/artifacts/run", completed_at: "2026-11-14T10:00:00Z", probe_results: [probe("role_play", "protected"), probe("multilingual", "unsafe")] };

function fakeAPI(overrides: Partial<ProductionRedTeamAPI>): ProductionRedTeamAPI {
  return { getProbeCatalog: async () => catalog, getSchedule: async () => unsaved, putSchedule: async () => saved, ...overrides } as ProductionRedTeamAPI;
}

describe("red team probe library decoders", () => {
  it("accepts the catalog and rejects a catalog whose counts or categories disagree", () => {
    expect(decodeTestProbeCatalog(catalog).probe_count).toBe(1080);
    for (const change of [{ probe_count: 1081 }, { digest: "short" }, { version: "other" }, { extra: true }, { categories: catalog.categories.slice(1) }, { categories: [...catalog.categories.slice(1), catalog.categories[1]] }, { categories: catalog.categories.map((item) => ({ ...item, probe_count: 5 })) }, { categories: catalog.categories.map((item) => ({ ...item, frameworks: [{ framework: "unknown", control: "X", title: "Y" }] })) }]) {
      expect(() => decodeTestProbeCatalog({ ...catalog, ...change })).toThrow();
    }
  });

  it("requires the probe results of an attempt and checks every one", () => {
    expect(decodeTestAttempt(attempt).probe_results).toHaveLength(2);
    expect(decodeTestAttempt({ ...attempt, probe_results: [] }).probe_results).toHaveLength(0);
    const { probe_results: _omitted, ...withoutResults } = attempt;
    for (const invalid of [withoutResults, { ...attempt, probe_results: [probe("role_play", "protected"), probe("role_play", "unsafe")] }, { ...attempt, probe_results: [{ ...probe("role_play", "protected"), category: "tool_abuse" }] }, { ...attempt, probe_results: [{ ...probe("role_play", "protected"), outcome: "skipped" }] }, { ...attempt, probe_results: [{ ...probe("role_play", "protected"), answer: "leak" }] }, { ...attempt, probe_results: [{ probe_id: "arbitrary prompt", category: "indirect_injection", outcome: "unsafe" }] }]) {
      expect(() => decodeTestAttempt(invalid)).toThrow();
    }
  });

  it("accepts an unsaved and a saved schedule and rejects contradictions", () => {
    expect(decodeTestSchedule(unsaved).version).toBe(0);
    expect(decodeTestSchedule(saved).cadence_seconds).toBe(86400);
    for (const invalid of [{ ...unsaved, enabled: true }, { ...saved, next_run_at: null }, { ...saved, cadence_seconds: 60 }, { ...saved, cadence_seconds: null, on_target_change: false }, { ...saved, last_trigger: "manual" }, { ...saved, updated_at: null }, { ...saved, extra: 1 }, { ...saved, enabled: false }]) {
      expect(() => decodeTestSchedule(invalid)).toThrow();
    }
  });
});

describe("red team probe library views", () => {
  it("shows the probe count per category", async () => {
    render(<ProbeLibraryCard api={fakeAPI({})} />);
    expect(await screen.findByText(/1080 reviewed probes in 9 categories/)).toBeTruthy();
    expect(screen.getAllByText("120")).toHaveLength(9);
    expect(probeCountLabel({ status: "ready", catalog }, "poisoned_resource")).toBe(" (120 probes)");
    expect(probeCountLabel({ status: "unavailable" }, "poisoned_resource")).toBe("");
  });

  it("says so when the probe library is unavailable", async () => {
    render(<ProbeLibraryCard api={fakeAPI({ getProbeCatalog: async () => { throw new Error("down"); } })} />);
    expect((await screen.findByRole("alert")).textContent).toContain("unavailable");
  });

  it("lists which probes ran in an attempt with their outcome", () => {
    const { rerender } = render(<ProbeResults results={attempt.probe_results} />);
    expect(screen.getByText("2 probes · 1 protected · 1 unsafe")).toBeTruthy();
    expect(screen.getByText("zasp.indirect_injection.multilingual.suppress_answer.tool_result.v1")).toBeTruthy();
    expect(screen.getByText("unsafe")).toBeTruthy();
    expect(screen.getByText("role play")).toBeTruthy();
    rerender(<ProbeResults results={[]} />);
    expect(screen.getByText(/one curated check per category/)).toBeTruthy();
  });

  it("saves a schedule with the version it read", async () => {
    const putSchedule = vi.fn<ProductionRedTeamAPI["putSchedule"]>().mockResolvedValue(saved);
    render(<ScheduleControl api={fakeAPI({ putSchedule })} definition={definition} canWrite locked={false} />);
    const enable = await screen.findByRole("button", { name: "Enable schedule" });
    expect((enable as HTMLButtonElement).disabled).toBe(true); // no cadence and no change trigger yet
    fireEvent.change(screen.getByLabelText("Cadence"), { target: { value: "86400" } });
    fireEvent.click(screen.getByLabelText(/Re-test when the target's inventory record changes/));
    fireEvent.click(enable);
    await waitFor(() => expect(putSchedule).toHaveBeenCalledWith(definitionID, { expected_version: 0, enabled: true, on_target_change: true, cadence_seconds: 86400 }));
    expect(await screen.findByText("scheduled")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Disable schedule" }));
    await waitFor(() => expect(putSchedule).toHaveBeenLastCalledWith(definitionID, { expected_version: 1, enabled: false, on_target_change: true, cadence_seconds: 86400 }));
  });

  it("offers no schedule change to a reader and reports a refused save", async () => {
    const { unmount } = render(<ScheduleControl api={fakeAPI({ getSchedule: async () => saved })} definition={definition} canWrite={false} locked={false} />);
    expect(await screen.findByText("scheduled")).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
    unmount();
    render(<ScheduleControl api={fakeAPI({ getSchedule: async () => saved, putSchedule: async () => { throw new Error("conflict"); } })} definition={definition} canWrite locked={false} />);
    fireEvent.click(await screen.findByRole("button", { name: "Update schedule" }));
    expect((await screen.findByRole("alert")).textContent).toContain("was not saved");
  });
});
