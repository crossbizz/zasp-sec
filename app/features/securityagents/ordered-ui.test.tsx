import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { SecurityAgentDefinition, SecurityAgentManualRunInput } from "../../../apps/web/api/generated";
import { decodeSecurityAgentRunDetail } from "../../../apps/web/api/decoders";
import { createSecurityAgentsAPI, SecurityAgentsView } from "./SecurityAgentsView";

const id = (n: number) => `pid_78000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const digest = `sha256:${"a".repeat(64)}`;
const expires = "2026-09-22T12:15:00Z";
const definition: SecurityAgentDefinition = { id: id(2), name: "Ordered containment", trigger_kind: "finding", trigger_source: "credential", environment_ids: [id(20)], autonomy: "supervised", max_steps: 2, max_duration_seconds: 900, temporary_policy_seconds: 300, ai_token_budget: 4000, concurrency_limit: 1, allowed_actions: ["create_temporary_policy", "run_test"], verification_kind: "test_run", definition_version: 1, enabled: true };
function detail(stage = "waiting") {
  const applied = stage === "successor" || stage === "unknown";
  const terminal = stage === "unknown" || stage === "partial" || stage === "cancelled";
  const steps = [0, 1].map((index) => ({
    step_id: id(index + 4), index, action: index === 0 ? "create_temporary_policy" : "run_test",
    state: index === 0 ? applied ? "succeeded" : terminal ? "cancelled" : "waiting_approval" : stage === "unknown" ? "succeeded" : applied ? "waiting_approval" : terminal ? "cancelled" : "blocked",
    version: applied ? 4 : terminal ? 2 : 1, authorization: "approval_required",
    dependency: { predecessor_step_id: index === 0 ? null : id(4), required_receipt_kind: index === 0 ? null : "temporary_policy_applied.v1", satisfied: index === 0 || applied, blocked: index === 1 && !applied && !terminal, ready: !terminal && (index === 0 ? !applied : applied) },
    approval: index === 1 && !applied ? { state: "absent", version: 0, approval_id: null } : { state: terminal || index === 0 && applied ? "approved" : "pending", version: terminal || index === 0 && applied ? 2 : 1, approval_id: id(index + 6) },
    receipt: index === 0 && applied || index === 1 && stage === "unknown" ? { kind: index === 0 ? "temporary_policy_applied.v1" : "existing_test_settled.v1", version: 1, digest, reference: id(index + 8) } : null,
    settlement: index === 0 ? "not_applicable" : stage === "unknown" ? "unknown" : "pending",
    cleanup: { state: index === 1 ? "not_applicable" : stage === "partial" ? "leased" : applied ? "pending" : "not_started", version: index === 0 && stage === "partial" ? 1 : 0, attempt: index === 0 && stage === "partial" ? 1 : 0, partial: index === 0 && stage === "partial", cleaned: false },
  }));
  return decodeSecurityAgentRunDetail({
    run: { id: id(1), agent_id: id(2), state: terminal ? stage === "cancelled" ? "cancelled" : "needs_human" : "waiting_approval", evidence_ids: [id(3)], definition_version: 1, version: 10 },
    evidence_ids: [id(3)], authorization: stage === "cancelled" ? "cancelled" : "approval_required", verification: terminal ? "inconclusive" : "pending",
    plan: { plan_hash: digest, catalog_version: "security-agent-actions-v1", expires_at: expires, steps: steps.map((s) => ({ id: s.step_id, index: s.index, action: s.action, state: s.state === "blocked" ? "queued" : s.state, version: s.version, authorization: s.authorization })) },
    execution: steps.map((s) => ({ step_id: s.step_id, action: s.action, state: s.state === "blocked" ? "queued" : s.state, version: s.version, ...(s.receipt ? { result_digest: digest } : {}) })),
    approvals: steps.filter((s) => s.approval.approval_id !== null).map((s) => ({ id: s.approval.approval_id, run_id: id(1), step_id: s.step_id, state: s.approval.state, version: s.approval.version, expires_at: expires, expected_effect: s.index === 0 ? "Apply temporary containment policy" : "Run existing test", reversible: s.index === 0, ttl_seconds: s.index === 0 ? 300 : 0, evidence_summary: [id(3)] })), ordered: { contract_version: 62, steps },
  });
}
function response(value: unknown, version = 1) {
  return new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ETag: `"${version}"`, "X-Audit-ID": id(30), "X-Mutation-Receipt-ID": id(31) } });
}
function apiWith(handler: (request: Request) => Response | Promise<Response>) { return createSecurityAgentsAPI(createAPIClient({ fetch: async (request) => handler(request) })); }
const snapshot = (stage = "waiting") => ({ agents: [definition], templates: [], runs: [detail(stage).run], approvals: detail(stage).approvals });

describe("ordered product wrapper", () => {
  it("preserves legacy authentication errors without an ordered lookup", async () => {
    let calls = 0;
    const api = apiWith(() => { calls++; return new Response(JSON.stringify({ code: "authentication_required", message: "Authentication required", correlation_id: id(30), retryable: false }), { status: 401, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); });
    await expect(api.getSecurityAgentApproval(id(6))).rejects.toMatchObject({ status: 401 });
    expect(calls).toBe(1);
  });
  it("does not replay an ambiguous mutation after the captured scope becomes stale", async () => {
    let current = true; let calls = 0;
    const client = createAPIClient({ fetch: async () => { calls++; current = false; throw new TypeError("Network response lost"); } });
    const api = createSecurityAgentsAPI(client, undefined, () => current);
    await expect(api.cancelSecurityAgentRun(id(1), 10)).rejects.toThrow();
    expect(calls).toBe(1);
  });
  it("keeps standalone legacy cancelled approvals on the legacy decoder", async () => {
    const approval = { ...detail().approvals[0], expected_effect: "Move finding to under review", ttl_seconds: 0, state: "cancelled", version: 2 };
    const api = apiWith(() => response(approval, 2));
    expect((await api.decideSecurityAgentApproval(id(6), 1, "cancelled")).value.state).toBe("cancelled");
  });
  it("opens a legacy approval without depending on a run-detail read", async () => {
    const user = userEvent.setup(); const approval = { ...detail().approvals[0], expected_effect: "Move finding to under review" as const, ttl_seconds: 0 };
    const api = apiWith(() => response(approval));
    render(<SecurityAgentsView api={api} initialSnapshot={{ agents: [], templates: [], approvals: [approval] }} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open approval ${id(6)}` }));
    expect(await screen.findByRole("dialog", { name: `Approval ${id(6)}` })).toBeInTheDocument();
  });
  it("rejects incomplete ordered trigger metadata before transport", async () => {
    const fetch = vi.fn(() => response({ ...detail().run, state: "queued", version: 1 }));
    const api = apiWith(fetch);
    await expect(api.runSecurityAgent(id(2), 1, { environment_id: id(20), trigger_kind: "finding", trigger_id: id(3), trigger_version: 7 } as SecurityAgentManualRunInput)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each(["cancelled", "needs_human"] as const)("decodes %s cancellation authority", async (state) => {
    const api = apiWith(() => response({ ...detail().run, state, version: 11, ordered: { cleanup_required: state === "cancelled" } }, 11));
    expect((await api.cancelSecurityAgentRun(id(1), 10)).value).toMatchObject({ state, ordered: { cleanup_required: state === "cancelled" } });
  });
  it("uses ordered approval decoding only after exact run linkage and forbids ordered cancelled decisions", async () => {
    const value = detail("successor"); const approval = value.approvals[1];
    let posts = 0;
    const api = apiWith((request) => { if (request.method === "POST") { posts++; return response({ ...approval, state: "approved", version: 2 }, 2); } return response(request.url.includes("security-agent-runs") ? value : approval); });
    await api.getSecurityAgentRun(id(1));
    expect(await api.getSecurityAgentApproval(id(7))).toEqual(approval);
    await expect(api.decideSecurityAgentApproval(id(7), 1, "cancelled")).rejects.toThrow();
    expect(posts).toBe(0);
    expect((await api.decideSecurityAgentApproval(id(7), 1, "approved")).value.state).toBe("approved");
  });
  it("loads a mixed approval page without treating an effect label as ordered authority", async () => {
    const value = detail("successor");
    const api = apiWith((request) => response(request.url.includes("security-agent-runs/") ? value : { items: value.approvals }));
    expect((await api.listSecurityAgentApprovals()).items).toEqual(value.approvals);
    const bad = apiWith((request) => response(request.url.includes("security-agent-runs/") ? { ...value, ordered: { contract_version: 62, steps: [] } } : { items: value.approvals.map((approval) => ({ ...approval, private_plan: "forbidden" })) }));
    await expect(bad.listSecurityAgentApprovals()).rejects.toThrow();
  });
});

describe("ordered run drawer", () => {
  it.each([
    ["approved", "direct", "pending"],
    ["rejected", "direct", "pending"],
    ["approved", "retained", "pending"],
    ["approved", "direct", "error"],
  ] as const)("keeps %s v2 after %s decision when an older refresh returns %s", async (decision, mode, lateResult) => {
    const user = userEvent.setup(); const value = detail(); const approval = value.approvals[0];
    let deferRead = false; let resolveRead!: (response: Response) => void; let posts = 0;
    const api = apiWith((request) => {
      if (request.method === "POST") {
        posts++;
        if (mode === "retained" && posts < 3) throw new TypeError("Decision response lost");
        return response({ ...approval, state: decision, version: 2 }, 2);
      }
      if (request.url.includes("security-agent-runs/")) return response(value);
      return deferRead ? new Promise<Response>((resolve) => { resolveRead = resolve; }) : response(approval);
    });
    await api.getSecurityAgentRun(id(1));
    render(<SecurityAgentsView api={api} initialSnapshot={snapshot()} autoLoad={false} fresh />);
    await user.click(screen.getByRole("button", { name: `Open approval ${id(6)}` }));
    await screen.findByRole("dialog");
    deferRead = true; await act(async () => { window.dispatchEvent(new Event("online")); });
    await waitFor(() => expect(resolveRead).toBeTypeOf("function"));
    await user.click(screen.getByRole("button", { name: decision === "approved" ? "Approve" : "Reject" }));
    if (mode === "retained") await user.click(await screen.findByRole("button", { name: "Retry retained approval decision" }));
    expect(await screen.findByText(decision, { selector: ".badge" })).toBeInTheDocument();
    expect(within(screen.getByRole("dialog")).getByText(/Version 2/)).toBeInTheDocument();
    await act(async () => { resolveRead(response(lateResult === "pending" ? approval : { private_plan: "invalid old response" })); });
    const drawer = screen.getByRole("dialog");
    expect(within(drawer).getByText(decision, { selector: ".badge" })).toBeInTheDocument();
    expect(within(drawer).getByText(/Version 2/)).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: "Close" }));
    expect(screen.getByRole("button", { name: `Open approval ${id(6)}` })).toHaveTextContent(decision);
  });
  it("keeps the decision error visible when a pre-decision refresh fails late", async () => {
    const user = userEvent.setup(); const approval = detail().approvals[0];
    let deferRead = false; let resolveRead!: (response: Response) => void;
    const api = apiWith((request) => {
      if (request.method === "POST") return new Response(JSON.stringify({ code: "authorization_rejected", message: "Authorization rejected", correlation_id: id(30), retryable: false }), { status: 403, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      return deferRead ? new Promise<Response>((resolve) => { resolveRead = resolve; }) : response(approval);
    });
    render(<SecurityAgentsView api={api} initialSnapshot={snapshot()} autoLoad={false} fresh />);
    await user.click(screen.getByRole("button", { name: `Open approval ${id(6)}` }));
    await screen.findByRole("dialog");
    deferRead = true; await act(async () => { window.dispatchEvent(new Event("online")); });
    await waitFor(() => expect(resolveRead).toBeTypeOf("function"));
    await user.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be decided");
    await act(async () => { resolveRead(response({ private_plan: "invalid old response" })); });
    const drawer = screen.getByRole("dialog");
    expect(within(drawer).getByRole("alert")).toHaveTextContent("could not be decided");
    expect(within(drawer).getByText("pending", { selector: ".badge" })).toBeInTheDocument();
    expect(within(drawer).getByText(/Version 1/)).toBeInTheDocument();
  });
  it("does not resurrect a closed approval from an in-flight reconnect read", async () => {
    const user = userEvent.setup(); const value = detail("successor"); let late = false; let resolve!: (value: Response) => void;
    const api = apiWith((request) => request.url.includes("security-agent-runs/") ? response(value) : late ? new Promise<Response>((done) => { resolve = done; }) : response(value.approvals[1]));
    render(<SecurityAgentsView api={api} initialSnapshot={snapshot("successor")} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open approval ${id(7)}` }));
    const drawer = await screen.findByRole("dialog");
    late = true; await act(async () => { window.dispatchEvent(new Event("online")); });
    await waitFor(() => expect(resolve).toBeTypeOf("function"));
    await user.click(within(drawer).getByRole("button", { name: "Close" }));
    await act(async () => { resolve(response(value.approvals[1])); });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it.each(["private", "duplicate", "malformed"])("refuses %s ordered JSON without presenting success", async (kind) => {
    const user = userEvent.setup();
    const wire = kind === "private" ? JSON.stringify({ ...detail(), private_plan: "private" }) : kind === "duplicate" ? JSON.stringify(detail()).replace('"contract_version":62', '"contract_version":62,"contract_version":62') : '{"ordered":';
    const api = apiWith(() => new Response(wire, { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }));
    render(<SecurityAgentsView api={api} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open run ${id(1)}` }));
    await screen.findByRole("alert"); expect(screen.queryByRole("region", { name: "Ordered execution" })).not.toBeInTheDocument();
  });
  it("refreshes an open ordered approval on reconnect", async () => {
    const user = userEvent.setup(); const value = detail("successor"); let approved = false;
    const api = apiWith((request) => response(request.url.includes("security-agent-runs/") ? value : { ...value.approvals[1], ...(approved ? { state: "approved", version: 2 } : {}) }));
    render(<SecurityAgentsView api={api} initialSnapshot={snapshot("successor")} autoLoad={false} fresh />);
    await user.click(screen.getByRole("button", { name: `Open approval ${id(7)}` }));
    await screen.findByRole("dialog", { name: `Approval ${id(7)}` });
    approved = true; await act(async () => { window.dispatchEvent(new Event("online")); });
    expect(await screen.findByText("approved", { selector: ".badge" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
  });
  it.each(["waiting", "successor", "unknown", "partial"])("renders complete conservative %s authority and inert receipts", async (stage) => {
    const user = userEvent.setup(); const value = detail(stage);
    render(<SecurityAgentsView api={apiWith(() => response(value))} environmentID={id(20)} initialSnapshot={snapshot(stage)} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open run ${id(1)}` }));
    const ordered = await screen.findByRole("region", { name: "Ordered execution" });
    for (const step of value.ordered!.steps) {
      const section = within(ordered).getByRole("region", { name: `Ordered step ${step.index + 1}` });
      for (const label of ["Action", "State", "Version", "Predecessor", "Required receipt kind", "Dependency satisfied", "Dependency blocked", "Dependency ready", "Authorization", "Approval state", "Approval version", "Approval ID", "Settlement", "Cleanup state", "Cleanup version", "Cleanup attempt", "Cleanup partial", "Cleanup cleaned"]) expect(within(section).getByText(label, { exact: true })).toBeInTheDocument();
      expect(within(section).getByText("Action", { exact: true }).nextElementSibling).toHaveTextContent(step.index === 0 ? "create_temporary_policy" : "run_test");
      expect(within(section).getByText("Predecessor", { exact: true }).nextElementSibling).toHaveTextContent(step.index === 0 ? "None" : id(4));
      expect(within(section).getByText("Cleanup cleaned", { exact: true }).nextElementSibling).toHaveTextContent("false");
      if (stage === "partial" && step.index === 0) {
        expect(within(section).getByText("Cleanup state", { exact: true }).nextElementSibling).toHaveTextContent("leased");
        expect(within(section).getByText("Cleanup partial", { exact: true }).nextElementSibling).toHaveTextContent("true");
      }
      if (step.index === 1) expect(within(section).getByText("Settlement", { exact: true }).nextElementSibling).toHaveTextContent(stage === "unknown" ? "unknown" : "pending");
      if (step.receipt) { expect(within(section).getByText(step.receipt.reference)).toBeInTheDocument(); expect(within(section).getByText(step.receipt.digest)).toBeInTheDocument(); }
      else expect(within(section).getByText("No receipt reported")).toBeInTheDocument();
    }
    expect(within(ordered).queryByRole("link")).not.toBeInTheDocument();
  });
  it("replaces ordered versions on reconnect and clears stale detail when refresh fails", async () => {
    const user = userEvent.setup(); let value: unknown = detail();
    render(<SecurityAgentsView api={apiWith(() => response(value))} environmentID={id(20)} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open run ${id(1)}` }));
    await screen.findByRole("region", { name: "Ordered execution" });
    value = detail("successor"); await act(async () => { window.dispatchEvent(new Event("online")); });
    expect(await screen.findByText(id(8))).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Ordered step 1" })).getByText("Version", { exact: true }).nextElementSibling).toHaveTextContent("4");
    value = { ...detail(), private_plan: "forbidden" }; await act(async () => { window.dispatchEvent(new Event("online")); });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Ordered execution" })).not.toBeInTheDocument());
  });
  it("clears detail on a boundary change and aborts a late read", async () => {
    const user = userEvent.setup(); let resolve!: (value: Response) => void; let signal: AbortSignal | undefined;
    const api = apiWith((request) => { signal = request.signal; return new Promise<Response>((done) => { resolve = done; }); });
    const { rerender } = render(<SecurityAgentsView api={api} environmentID={id(20)} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open run ${id(1)}` }));
    rerender(<SecurityAgentsView api={api} environmentID={id(21)} initialSnapshot={{ agents: [], templates: [] }} autoLoad={false} />);
    await act(async () => { resolve(response(detail())); });
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: `Open run ${id(1)}` })).not.toBeInTheDocument();
  });
  it.each(["cancelled", "needs_human"] as const)("renders %s cleanup authority and reloads detail without inventing step cancellation", async (state) => {
    const user = userEvent.setup(); let cancelled = false;
    const api = apiWith((request) => { if (request.method === "POST") { cancelled = true; return response({ ...detail().run, state, version: 11, ordered: { cleanup_required: state === "cancelled" } }, 11); } return response(cancelled ? detail("partial") : detail()); });
    render(<SecurityAgentsView api={api} environmentID={id(20)} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: `Open run ${id(1)}` }));
    await user.click(await screen.findByRole("button", { name: "Cancel run" }));
    expect(await screen.findByText(state === "cancelled" ? "Cleanup required: yes" : "Cleanup required: no")).toBeInTheDocument();
    expect(await screen.findByText("needs_human", { selector: ".badge" })).toBeInTheDocument();
    expect(screen.queryByText("Cleanup complete")).not.toBeInTheDocument();
  });
});

describe("ordered trigger selection", () => {
  it("retries retained ordered trigger bytes without looking up a newer evidence version", async () => {
    const user = userEvent.setup(); const bodies: unknown[] = []; const keys: (string | null)[] = []; let evidenceReads = 0;
    const api = apiWith(async (request) => {
      if (request.method === "POST") { bodies.push(await request.json()); keys.push(request.headers.get("Idempotency-Key")); if (bodies.length < 3) throw new TypeError("Network response lost"); return response({ ...detail().run, state: "queued", version: 1 }); }
      if (request.url.includes("/activation")) return response({ id: id(2), activation: "supervised", enabled: true, version: 1 });
      if (request.url.includes("/findings/")) { evidenceReads++; return response({ id: id(3), title: "Evidence", severity: "high", status: "open", source: "posture", evidence_ids: [id(40)], risk_factors: [], created_at: expires, updated_at: expires, version: evidenceReads === 1 ? 7 : 8 }); }
      return response(definition);
    });
    render(<SecurityAgentsView api={api} environmentID={id(20)} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: "Open Ordered containment" }));
    await user.type(await screen.findByLabelText("Evidence ID"), id(3));
    await user.click(screen.getByRole("button", { name: "Start supervised run" }));
    const retry = await screen.findByRole("button", { name: "Retry retained manual run" });
    expect(retry).toBeEnabled(); await user.click(retry);
    await waitFor(() => expect(bodies).toHaveLength(3));
    expect(evidenceReads).toBe(1); expect(new Set(keys).size).toBe(1);
    expect(bodies).toEqual(Array.from({ length: 3 }, () => ({ environment_id: id(20), trigger_kind: "finding", trigger_id: id(3), trigger_version: 7, trigger_source: "credential" })));
  });
  it.each([7, undefined])("uses selected evidence version %s with the persisted source, or refuses", async (version) => {
    const user = userEvent.setup(); const bodies: unknown[] = [];
    const api = apiWith(async (request) => {
      if (request.method === "POST") { bodies.push(await request.json()); return response({ ...detail().run, state: "queued", version: 1 }); }
      if (request.url.includes("/activation")) return response({ id: id(2), activation: "supervised", enabled: true, version: 1 });
      if (request.url.includes("/findings/")) return response({ id: id(3), title: "Evidence", severity: "high", status: "open", source: "posture", evidence_ids: [id(40)], risk_factors: [], created_at: expires, updated_at: expires, ...(version ? { version } : {}) });
      return response(definition);
    });
    if (version) expect(await api.getTriggerEvidence!("finding", id(3))).toEqual({ id: id(3), version: 7 });
    render(<SecurityAgentsView api={api} environmentID={id(20)} initialSnapshot={snapshot()} autoLoad={false} />);
    await user.click(screen.getByRole("button", { name: "Open Ordered containment" }));
    await user.type(await screen.findByLabelText("Evidence ID"), id(3));
    await user.click(screen.getByRole("button", { name: "Start supervised run" }));
    if (version) await waitFor(() => expect(bodies).toEqual([{ environment_id: id(20), trigger_kind: "finding", trigger_id: id(3), trigger_version: 7, trigger_source: "credential" }]));
    else { await screen.findByRole("alert"); expect(bodies).toEqual([]); }
  });
});
