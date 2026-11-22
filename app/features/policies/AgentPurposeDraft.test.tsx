import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import type { AgentSuggestionPage, InventorySummary, Policy } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { AgentPurposeDraft } from "./AgentPurposeDraft";
import { ScopedReplay } from "./ScopedReplay";

const id = (n: number) => `pid_7000000${n}-0000-4000-8000-00000000000${n}`;
const agent = id(1), read = id(2), send = id(3), evidence = id(4);
function record(key: string, name: string, kind: InventorySummary["kind"]): InventorySummary {
  return { id: key, name, kind, owner: "", team: "", tags: [], evidence_id: evidence, confidence_basis_points: 9500, first_seen: "2026-08-19T00:00:00Z", last_seen: "2026-08-19T01:00:00Z", observed_at: "2026-08-19T01:00:00Z", fresh_until: "2026-08-19T01:15:00Z", freshness_state: "fresh", provider: "kubernetes", source_kind: "kubernetes_agent", discovery: { method: kind === "agent" ? "declared" : "provider_api", platform: "kubernetes_agent", signals: [] }, management_state: kind === "agent" ? "managed" : "not_applicable", last_activity_at: null, activity_state: kind === "agent" ? "unknown" : "not_applicable", version: 1 };
}
const policy: Policy = { id: "policy-agent", name: "Restrict send", scope: "environment", trigger: "tool", conditions: [{ field: "agent_id", operator: "equals", value: agent }, { field: "resource", operator: "equals", value: send }], action: "block", rollout: "draft", failure_mode: "open" };

describe("purpose-based policy review", () => {
  it("reviews only persisted deviations, requests an inactive draft and reloads a recorded dismissal", async () => {
    const user = userEvent.setup();
    const save = vi.fn();
    const times = { from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00Z" };
    const proposed = { ...times, tool_id: send, evidence_ids: [evidence], draft_audit_id:null, policy_id: "policy-purpose-"+"a".repeat(64), state: "suggested" as const };
    let page: AgentSuggestionPage = {agent_id: agent, purpose_revision: 1, last_scan: null, more: false, items: []};
    const ok = (data: unknown) => ({data, response: new Response(null,{status:200})});
    const get = vi.fn(async (path: string) => {
      if (path.endsWith("/purpose")) return ok({agent_id:agent,revision:0,allowed_tool_ids:[],updated_at:null});
      if (path.endsWith("/suggestions")) return ok(page);
      return ok({items: path.endsWith("/agents") ? [record(agent,"Support","agent")] : [record(read,"Read tickets","tool"),record(send,"Send tickets","tool")],page_info:{next_cursor:null,has_more:false}});
    });
    const post = vi.fn(async () => {page={...page,items:[proposed],last_scan:{...times,examined:8,eligible:2,truncated:true}}; return ok(page);});
    const put = vi.fn(async (path:string, options: {body:{decision?:string}}) => {
      if (path.endsWith("/purpose")) return ok({agent_id:agent,revision:1,allowed_tool_ids:[read],updated_at:times.from});
      page={...page,items:[{...proposed,state:options.body.decision === "dismiss" ? "dismissed" : "draft_requested"}]}; return ok(page);
    });
    const client = {GET:get,POST:post,PUT:put} as unknown as APIClient;
    render(<APIProvider client={client}><AgentPurposeDraft onCreate={save} disabled={false} /></APIProvider>);
    fireEvent.click(screen.getByRole("button",{name:"Review agent purpose"}));
    await user.selectOptions(screen.getByLabelText("Agent"),await screen.findByRole("option",{name:"Support"}));
    fireEvent.click(await screen.findByRole("checkbox",{name:"Read tickets"}));
    fireEvent.click(screen.getByRole("button",{name:"Save agent purpose"}));
    expect(await screen.findByText("No runtime observation window has been reviewed.")).toBeVisible();
    expect(screen.queryByRole("button",{name:"Review Send tickets"})).toBeNull();
    fireEvent.click(screen.getByRole("button",{name:"Check runtime observations"}));
    fireEvent.click(await screen.findByRole("button",{name:"Review Send tickets"}));
    expect(screen.getByText(evidence)).toBeVisible();
    expect(screen.getByText(/2 of 8 indexed events/)).toHaveTextContent("Additional indexed events");
    expect(save).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button",{name:"Save as inactive draft"}));
    await waitFor(() => expect(save).toHaveBeenCalledWith({...policy,id:proposed.policy_id,name:"Restrict Send tickets (purpose r1)"}));
    expect(put).toHaveBeenCalledWith("/api/v1/agents/{id}/suggestions/{toolId}/decision",expect.objectContaining({body:{decision:"request_draft",purpose_revision:1}}));
    page={...page,items:[proposed]}; fireEvent.click(screen.getByRole("button",{name:"Reload saved reviews"}));
    fireEvent.click(await screen.findByRole("button",{name:"Review Send tickets"}));
    fireEvent.click(screen.getByRole("button",{name:"Dismiss suggestion"}));
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/v1/agents/{id}/suggestions/{toolId}/decision",expect.objectContaining({body:{decision:"dismiss",purpose_revision:1}})));
    fireEvent.click(screen.getByRole("button",{name:"Reload saved reviews"}));
    await waitFor(()=>expect(screen.queryByRole("button",{name:"Review Send tickets"})).toBeNull());
    expect(get.mock.calls.every(([path])=>!path.endsWith("/capabilities"))).toBe(true);
  });

  it("shows retained evidence to a read-only analyst without offering a policy change", async () => {
    const user = userEvent.setup();
    const from = "2026-01-01T00:00:00Z", to = "2026-01-02T00:00:00Z";
    const client = {GET:vi.fn(async (path:string)=>{
      let data:unknown;
      if (path.endsWith("/purpose")) data={agent_id:agent,revision:1,updated_at:from,allowed_tool_ids:[read]};
      else if(path.endsWith("/suggestions")) data={agent_id:agent,purpose_revision:1,more:false,last_scan:{from,to,examined:1,eligible:1,truncated:false},items:[{from,to,tool_id:send,evidence_ids:[evidence],policy_id:"policy-purpose-"+"c".repeat(64),state:"dismissed",draft_audit_id:null}]};
      else data={items:path.endsWith("/agents")?[record(agent,"Support","agent")]:[record(send,"Send tickets","tool")],page_info:{next_cursor:null,has_more:false}};
      return {data,response:new Response(null,{status:200})};
    })} as unknown as APIClient;
    render(<APIProvider client={client}><AgentPurposeDraft initialAgent={agent} canManage={false} disabled={false} onCreate={vi.fn()} /></APIProvider>);
    await user.click(await screen.findByRole("button",{name:"View evidence for Send tickets"}));
    expect(screen.getByText(evidence)).toBeVisible();
    expect(screen.queryByRole("button",{name:"Check runtime observations"})).toBeNull();
    expect(screen.queryByRole("button",{name:"Save as inactive draft"})).toBeNull();
    expect(screen.queryByRole("button",{name:"Save agent purpose"})).toBeNull();
  });

  it("pins revision, agent and UTC window and discloses truncated replay and missing telemetry", async () => {
    const run = vi.fn(async input => ({ matches: 7, would_block: 7, example_session_ids: [id(5)], replay: { policy_revision: input.policy_revision, agent_id: input.agent_id, from: input.from, to: input.to, evaluated: 5000, examined_count: 5000, eligible_count: 5000, would_block_rate: { tool: 7 / 5000 }, next_window_to: "2026-01-01T20:30:00.000Z", next_before_event_id: id(43), truncated: true, coverage: "indexed_events_only" as const } }));
    const user = userEvent.setup();
    render(<ScopedReplay policy={policy} version={'"3"'} disabled={false} runReplay={run} />);
    fireEvent.change(screen.getByLabelText("Replay from (UTC)"), { target: { value: "2026-01-01T12:00" } });
    fireEvent.change(screen.getByLabelText("Replay to (UTC, exclusive)"), { target: { value: "2026-01-02T12:00" } });
    await user.click(screen.getByRole("button", { name: "Replay revision 3" }));
    await waitFor(() => expect(run).toHaveBeenCalledWith({ schema_version: 2, agent_id: agent, policy_revision: 3, from: "2026-01-01T12:00:00.000Z", to: "2026-01-02T12:00:00.000Z" }));
    expect(await screen.findByText(/Additional indexed actions/)).toBeVisible();
    expect(screen.getByText(/Unreported activity/)).toBeVisible();
    expect(screen.getByText("Would block 0.1% of eligible tool actions.")).toBeVisible();
    await user.click(screen.getByRole("button", {name: "Replay remaining actions"}));
    await waitFor(() => expect(run).toHaveBeenCalledWith({ schema_version: 2, agent_id: agent, policy_revision: 3, from: "2026-01-01T12:00:00.000Z", to: "2026-01-01T20:30:00.000Z", before_event_id: id(43) }));
    fireEvent.change(screen.getByLabelText("Replay from (UTC)"), { target: { value: "2025-01-01T12:00" } });
    await user.click(screen.getByRole("button", { name: "Replay revision 3" }));
    expect(screen.getByRole("alert")).toHaveTextContent("up to 30 days");
    expect(run).toHaveBeenCalledTimes(2);
  });
});
