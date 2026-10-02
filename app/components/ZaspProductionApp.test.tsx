import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ZaspProductionApp } from "./ZaspProductionApp";

// Keep the real provider/client/session flow; expose only its existing cache
// invalidation operation so the production route must consume its generation.
vi.mock("../api/APIProvider", async importOriginal => {
  const actual = await importOriginal<typeof import("../api/APIProvider")>();
  function InvalidationControl() {
    const api = actual.useAPI();
    return <button onClick={() => api.clearQueryCache()}>Invalidate test query cache</button>;
  }
  return { ...actual, APIProvider: (props: React.ComponentProps<typeof actual.APIProvider>) => <actual.APIProvider {...props}><InvalidationControl />{props.children}</actual.APIProvider> };
});

const organization = "pid_10000001-0000-4000-8000-000000000001";
const workspace = "pid_10000002-0000-4000-8000-000000000002";
const environment = "pid_10000003-0000-4000-8000-000000000003";
const principal = "pid_10000004-0000-4000-8000-000000000004";
const otherPrincipal = "pid_10000005-0000-4000-8000-000000000005";
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }); }
function bootstrap(actor: string) {
  return { principal: { id: actor, organization_id: organization, organization_reference: "organization-live", member_reference: "member-live", role: "security_admin", active: true }, organization_id: organization, workspace_id: workspace, environment_id: environment, permissions: ["view", "view_audit"], capabilities: ["audit.read"], csrf_token: "cccccccccccccccccccccccccccccccc", fresh_auth_expires_at: "2000-01-01T00:00:00Z", correlation_id: principal };
}
function page(action: string) {
  return json({ items: [{ id: principal, workspace_id: workspace, environment_id: environment, actor_id: principal, action, target_id: principal, outcome: "succeeded", metadata: {}, occurred_at: "2026-09-12T00:00:00Z" }], page_info: { has_more: true, next_cursor: "next-cursor" } });
}

describe("production scoped activity navigation", () => {
  it("routes a generic audit compliance selector to typed compliance detail, including reload", async () => {
    window.history.replaceState({}, "", `/compliance/evidence?source_kind=administration&source_id=audit:42&source_version=1&organization_id=${organization}&workspace_id=${workspace}&environment_id=${environment}`);
    const reads: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), permissions: ["view", "view_audit", "view_compliance"], capabilities: ["compliance.read", "audit.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (decodeURIComponent(path) === "/api/v1/compliance/evidence/administration/audit:42") return json({ record: { id: "audit:42", asset_id: "audit:42", source: "audit", at: "2026-09-17T00:00:00Z", target: { source_kind: "administration", source_id: "audit:42", source_version: 1 }, metadata: { action: "membership.updated", status: "succeeded" } }, freshness: "fresh", organization_id: organization, workspace_id: workspace, environment_id: environment });
      throw new Error("Unexpected compliance route request");
    });
    const view = render(<ZaspProductionApp />);
    expect(await screen.findByRole("heading", { name: "Evidence source" })).toBeVisible();
    expect(screen.getByText(/membership.updated/)).toBeVisible();
    expect(reads.some(path => path.includes("security-agent") || path === "/api/v1/session/scope")).toBe(false);
    view.unmount(); render(<ZaspProductionApp />);
    expect(await screen.findByRole("heading", { name: "Evidence source" })).toBeVisible();
  });
  const inventoryRoutes = [
    ["/discovery/assets", "agents", "agent", "Support agent"],
    ["/inventory/tools", "tools", "tool", "Support tool"],
    ["/identities", "identities", "identity", "Support identity"],
    ["/inventory/runtimes", "runtimes", "runtime", "Support runtime"],
  ] as const;
  describe.each(["click", "initial location"])("inventory record selection through %s", mode => {
    it.each(inventoryRoutes)("keeps %s selection under its real product reader", async (route, endpoint, kind, name) => {
      const id = "pid_21000001-0000-4000-8000-000000000001";
      const location = `${route}?inventory=${id}`;
      window.history.replaceState({}, "", mode === "click" ? route : location);
      const summary = { id, name, kind, owner: "support", team: "platform", tags: [], evidence_id: principal, confidence_basis_points: 9500, first_seen: "2026-09-17T00:00:00Z", last_seen: "2026-09-17T00:01:00Z", observed_at: "2026-09-17T00:01:00Z", fresh_until: "2026-09-17T00:15:00Z", freshness_state: "fresh", version: 1 };
      const requests: Request[] = [];
      vi.stubGlobal("fetch", async (request: Request) => {
        const path = new URL(request.url).pathname; requests.push(request);
        if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["inventory.read"] });
        if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
        if (path === `/api/v1/${endpoint}`) return json({ items: [summary], page_info: { next_cursor: null, has_more: false } });
        if (path === `/api/v1/${endpoint}/${id}`) return json({ summary,
          sources: [{ integration_id: otherPrincipal, provider: "kubernetes", source: "kubernetes", source_identifier: `sha256:${"b".repeat(64)}`, snapshot_id: otherPrincipal, generation: 1, evidence_id: principal, confidence_basis_points: 9500, observed_at: summary.observed_at, fresh_until: summary.fresh_until, projection_version: 1, winning: true }],
          evidence: [{ id: principal, checksum: `sha256:${"a".repeat(64)}`, media_type: "application/json", schema_version: "raw_v1", parser_version: "parser_v1", tool_version: "tool_v1", collected_at: summary.observed_at, size_bytes: 128 }],
        });
        if (kind === "agent" && ["capabilities", "relationships", "sessions"].some(suffix => path === `/api/v1/agents/${id}/${suffix}`)) return json({ items: [], page_info: { next_cursor: null, has_more: false } });
        throw new Error(`Unexpected inventory route request ${path}`);
      });
      const view = render(<ZaspProductionApp />);
      if (mode === "click") {
        await userEvent.click(await screen.findByRole("button", { name: `Open ${name}` }));
        expect(await screen.findByRole("heading", { name: "Canonical record" })).toBeVisible();
        expect(window.location.pathname + window.location.search).toBe(location);
        // History traversal must pass the product-generated selector through the
        // actual shell parser too, without substituting a fixture route.
        await act(async () => window.dispatchEvent(new PopStateEvent("popstate")));
      }
      expect(await screen.findByRole("heading", { name: "Canonical record" })).toBeVisible();
      expect(screen.getByRole("dialog", { name })).toHaveTextContent(id);
      expect(screen.queryByText(/This activity link is invalid/)).not.toBeInTheDocument();
      expect(requests.some(request => new URL(request.url).pathname === `/api/v1/${endpoint}/${id}`)).toBe(true);
      expect(requests.every(request => request.method === "GET")).toBe(true);
      view.unmount();
      render(<ZaspProductionApp />);
      expect(await screen.findByRole("heading", { name: "Canonical record" })).toBeVisible();
      expect(screen.getByRole("dialog", { name })).toHaveTextContent(id);
    });
  });

  it.each([
    `inventory=${principal}&entity_id=${otherPrincipal}`,
    `inventory=${principal}&organization_id=${organization}&workspace_id=${workspace}&environment_id=${environment}`,
    `inventory=${principal}&entity%5fid=${otherPrincipal}`,
    `inventory=${principal}&inventory=${otherPrincipal}`,
  ])("rejects mixed or duplicate inventory selectors before product reads: %s", async query => {
    window.history.replaceState({}, "", `/discovery/assets?${query}`);
    const reads: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["inventory.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      throw new Error(`Unexpected inventory reader ${path}`);
    });
    render(<ZaspProductionApp />);
    expect(await screen.findByRole("alert")).toHaveTextContent("This activity link is invalid");
    expect(reads.some(path => path.startsWith("/api/v1/agents") || path === "/api/v1/session/scope")).toBe(false);
  });

  it.each([["selected", true], ["selected", false], ["normal", true], ["normal", false]] as const)("passes Red Team read permission through the %s Security Agent route (%s)", async (mode, permitted) => {
    const query = `organization_id=${organization}&workspace_id=${workspace}&environment_id=${environment}`;
    window.history.replaceState({}, "", `/protect/security-agents${mode === "selected" ? `?entity_id=${principal}&${query}` : ""}`);
    const agentRun = { id: principal, agent_id: principal, state: "running", evidence_ids: [principal], definition_version: 1, version: 1 };
    const detail = { run: agentRun, evidence_ids: [principal], plan: { plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: "2030-01-01T00:00:00Z", steps: [{ id: principal, index: 0, action: "run_test", authorization: "autonomous", state: "executing", version: 1 }] }, authorization: "authorized", approvals: [], execution: [{ step_id: principal, action: "run_test", state: "executing", version: 1, outcome_id: principal, result_digest: `sha256:${"a".repeat(64)}` }], verification: "not_started", action_details: [{ step_id: principal, action: "run_test", arguments: { target_id: principal, expected_version: 1 }, result: { state: "pending", outcome_id: principal, result_digest: `sha256:${"a".repeat(64)}` }, ttl_seconds: null, control_expires_at: null, rollback: { support: "not_supported", state: "unavailable", verification: { source: "none", state: "unavailable" } }, verification: { source: "effect_record", state: "pending" }, existing_test: { definition_id: principal, definition_version: 1, test_run_id: otherPrincipal, state: "pending", cancellation_outcome: null, verification: null } }] };
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["security-agents.read", ...(permitted ? ["red-team.read"] : [])] });
      if (path === `/api/v1/security-agent-runs/${principal}`) return new Response(JSON.stringify(detail), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (path === "/api/v1/security-agent-runs") return new Response(JSON.stringify({ items: [agentRun] }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (path === "/api/v1/security-agents") return json({ items: [], page_info: { next_cursor: null, has_more: false } });
      if (path === "/api/v1/security-agent-approvals") return new Response(JSON.stringify({ items: [] }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (["/api/v1/security-agent-templates", "/api/v1/security-actions", "/api/v1/workflow-mutation-receipts"].includes(path)) return json({ items: [] });
      throw new Error(`Unexpected permission fixture request ${path}`);
    });
    render(<ZaspProductionApp />);
    if (mode === "normal") await userEvent.click(await screen.findByRole("button", { name: `Open run ${principal}` }));
    await screen.findByRole("region", { name: "Recorded test evidence" });
    if (permitted) expect(screen.getByRole("link", { name: "Open linked test run" })).toHaveAttribute("href", `/red-team/results?entity_id=${otherPrincipal}&${query}`);
    else expect(screen.queryByRole("link", { name: "Open linked test run" })).not.toBeInTheDocument();
  });

  it.each(["open", "reload"])("%s selects the exact Red Team history run through the scoped client", async mode => {
    const location = `/red-team/results?entity_id=${otherPrincipal}&organization_id=${organization}&workspace_id=${workspace}&environment_id=${environment}`;
    window.history.replaceState({}, "", mode === "open" ? "/red-team/results" : location);
    const requests: Request[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; requests.push(request);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["red-team.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (["/api/v1/tests", "/api/v1/test-runs"].includes(path)) return json({ items: [] });
      if (["/api/v1/agents", "/api/v1/tools"].includes(path)) return json({ items: [], page_info: { next_cursor: null, has_more: false } });
      if (path === `/api/v1/test-runs/${otherPrincipal}`) return new Response(JSON.stringify({ id: otherPrincipal, version: 1, definition_id: principal, definition_version: 1, status: "queued", attempt: 0, cancel_requested: false, queued_at: "2026-09-17T00:00:00Z", attempts: [] }), { headers: { "Content-Type": "application/json", ETag: '"1"' } });
      throw new Error(`Unexpected history request ${path}`);
    });
    render(<ZaspProductionApp />);
    if (mode === "open") {
      await screen.findByText("No Red Team tests in this scope.");
      window.history.replaceState({}, "", location);
      await act(async () => window.dispatchEvent(new PopStateEvent("popstate")));
    }
    expect(await screen.findByRole("dialog", { name: "Red team run" })).toHaveTextContent(otherPrincipal);
    const detail = requests.find(request => new URL(request.url).pathname === `/api/v1/test-runs/${otherPrincipal}`);
    expect(detail?.headers.get("X-Zasp-Expected-Scope")).toBe(`${organization}/${workspace}/${environment}`);
    expect(requests.every(request => request.method === "GET")).toBe(true);
  });

  it.each(["foreign", "invalid"])("rejects %s Red Team history links before detail reads", async kind => {
    window.history.replaceState({}, "", `/red-team/results?entity_id=${kind === "invalid" ? "invalid" : otherPrincipal}&organization_id=${kind === "foreign" ? otherPrincipal : organization}&workspace_id=${workspace}&environment_id=${environment}`);
    const reads: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["red-team.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      throw new Error(`Unexpected history request ${path}`);
    });
    render(<ZaspProductionApp />);
    expect(await screen.findByRole("alert")).toHaveTextContent(kind === "foreign" ? "different organization" : "link is invalid");
    expect(reads.some(path => path.startsWith("/api/v1/test-runs") || path === "/api/v1/session/scope")).toBe(false);
  });

  afterEach(() => { vi.unstubAllGlobals(); window.history.replaceState({}, "", "/"); });
  const findingID = "pid_20000001-0000-4000-8000-000000000001";
  const pathID = "pid_30000001-0000-4000-8000-000000000001";
  const scopeQuery = "organization_id=pid_10000001-0000-4000-8000-000000000001&workspace_id=pid_10000002-0000-4000-8000-000000000002&environment_id=pid_10000003-0000-4000-8000-000000000003";
  const finding = { id: findingID, source: "posture", rule: "unapproved_tool", title: "Linked live finding", severity: "high", status: "open", agent_id: principal, path_id: pathID, evidence_ids: [principal], risk_factors: [], version: 1, created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:01Z" };
  const attackPath = { id: pathID, entry_id: principal, sink_id: otherPrincipal, node_ids: [principal, otherPrincipal], state: "verified", evidence_ids: [principal], blocked_edge: -1, version: 1, created_at: "2026-09-16T00:00:00Z", updated_at: "2026-09-16T00:00:01Z" };

  it.each(["finding", "attack_path"] as const)("opens a related run from %s using bootstrapped capability and exact scope", async kind => {
    const entityID = kind === "finding" ? findingID : pathID;
    const route = kind === "finding" ? "/violations" : "/exposure/attack-paths";
    window.history.replaceState({}, "", `${route}?entity_id=${entityID}&${scopeQuery}`);
    const reads: Request[] = [];
    const run = { id: otherPrincipal, agent_id: principal, state: "queued", evidence_ids: [findingID], definition_version: 1, version: 1 };
    vi.stubGlobal("fetch", async (request: Request) => {
      const pathname = new URL(request.url).pathname; reads.push(request);
      if (pathname === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["findings.read", "attack-paths.read", "security-agents.read"] });
      if (pathname === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (pathname === `/api/v1/findings/${findingID}`) return new Response(JSON.stringify(finding), { headers: { "Content-Type": "application/json", ETag: '"1"' } });
      if (pathname === `/api/v1/attack-paths/${pathID}`) return json(attackPath);
      if (pathname === `/api/v1/attack-paths/${pathID}/break-options`) return json({ items: [] });
      if (pathname === `/api/v1/security-agent-activity/${kind}/${entityID}/runs`) return new Response(JSON.stringify({ items: [run], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (pathname.startsWith(`/api/v1/security-agent-runs/${otherPrincipal}/activity/`)) {
        const targetKind = pathname.split("/").at(-1);
        return new Response(JSON.stringify({ items: targetKind === kind ? [{ kind, id: entityID }] : [], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      }
      if (pathname === `/api/v1/security-agent-runs/${otherPrincipal}`) return new Response(JSON.stringify({ run, evidence_ids: run.evidence_ids, plan: null, authorization: "not_planned", approvals: [], execution: [], verification: "not_started" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      throw new Error(`Unexpected request ${pathname}`);
    });
    const view = render(<ZaspProductionApp />);
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${otherPrincipal}` }));
    expect(await screen.findByRole("dialog", { name: `Run ${otherPrincipal}` })).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`/protect/security-agents?entity_id=${otherPrincipal}&${scopeQuery}`);
    const relationReads = reads.filter(request => new URL(request.url).pathname.includes("/security-agent-activity/"));
    expect(relationReads).toHaveLength(1);
    expect(relationReads[0].headers.get("X-Zasp-Expected-Scope")).toBe(`${organization}/${workspace}/${environment}`);
    expect(reads.some(request => ["/api/v1/findings", "/api/v1/attack-paths", "/api/v1/security-agent-runs"].includes(new URL(request.url).pathname))).toBe(false);
    await userEvent.click(await screen.findByRole("button", { name: `Open ${kind === "finding" ? "finding" : "attack path"} ${entityID}` }));
    expect(await screen.findByRole("dialog", { name: kind === "finding" ? finding.title : "Attack path detail" })).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`${route}?entity_id=${entityID}&${scopeQuery}`);
    view.unmount();
  });

  it("opens an exact audit record and its persisted run without enumerating either list", async () => {
    const location = `/administration/audit-log?entity_id=${findingID}&${scopeQuery}`;
    window.history.replaceState({}, "", location);
    const reads: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["audit.read", "security-agents.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === `/api/v1/security-agent-audit-events/${findingID}`) return new Response(JSON.stringify({ id: findingID, run_id: pathID, organization_id: organization, workspace_id: workspace, environment_id: environment, actor_reference: "worker-linked-audit", event_kind: "run_queued", correlation_id: principal, occurred_at: "2026-09-16T00:00:00.000001Z" }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
      if (path === `/api/v1/security-agent-runs/${pathID}/activity/audit`) return new Response(JSON.stringify({ items: [{ kind: "audit", id: findingID }], coverage: "complete" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (path === `/api/v1/security-agent-activity/audit/${findingID}/runs`) return new Response(JSON.stringify({ items: [{ id: pathID, agent_id: principal, state: "queued", evidence_ids: [findingID], definition_version: 1, version: 1 }], coverage: "complete" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (path === `/api/v1/security-agent-runs/${pathID}`) return new Response(JSON.stringify({ run: { id: pathID, agent_id: principal, state: "queued", evidence_ids: [findingID], definition_version: 1, version: 1 }, evidence_ids: [findingID], plan: null, authorization: "not_planned", approvals: [], execution: [], verification: "not_started" }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
      throw new Error(`Unexpected list read ${path}`);
    });
    const view = render(<ZaspProductionApp />);
    expect(await screen.findByText("worker-linked-audit")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Open Security Agent run" }));
    expect(await screen.findByRole("dialog", { name: `Run ${pathID}` })).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`/protect/security-agents?entity_id=${pathID}&${scopeQuery}`);
    await userEvent.click(await screen.findByRole("button", { name: `Open audit record ${findingID}` }));
    expect(await screen.findByText("worker-linked-audit")).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(location);
    await act(async () => { window.history.replaceState({}, "", location); window.dispatchEvent(new PopStateEvent("popstate")); });
    expect(await screen.findByText("worker-linked-audit")).toBeVisible();
    expect(reads).not.toContain("/api/v1/audit-events");
    expect(reads).not.toContain("/api/v1/security-agent-runs");
    view.unmount();
  });

  it("opens a linked run and follows its persisted session trigger through registered client routes", async () => {
    window.history.replaceState({}, "", `/protect/security-agents?entity_id=${findingID}&${scopeQuery}`);
    const reads: string[] = [];
    const at = "2026-09-16T00:00:00Z";
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["security-agents.read", "sessions.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === `/api/v1/security-agent-runs/${findingID}`) return new Response(JSON.stringify({ run: { id: findingID, agent_id: principal, state: "queued", evidence_ids: [pathID], definition_version: 1, version: 1 }, evidence_ids: [pathID], plan: null, authorization: "not_planned", approvals: [], execution: [], verification: "not_started", run_context: { trigger: { kind: "runtime_decision", id: pathID, version: 1 }, rationale: null } }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
      if (path === `/api/v1/sessions/${pathID}`) return json({ id: pathID, kind: "runtime", workspace_id: workspace, environment_id: environment, agent_id: principal, principal_id: null, first_event_at: at, last_event_at: at, projected_at: at, event_count: 1, confidence_counts: { exact: 1, strong: 0, probable: 0, unattributed: 0 } });
      if (path === `/api/v1/sessions/${pathID}/events`) return json({ items: [{ id: principal, session_id: pathID, agent_id: principal, class: "runtime", action: "exec", label: "Run-linked runtime evidence", evidence_id: principal, source: "tetragon", confidence: "exact", at, projected_at: at }], page_info: { next_cursor: null, has_more: false } });
      if (path === `/api/v1/security-agent-activity/session/${pathID}/runs`) return new Response(JSON.stringify({ items: [{ id: findingID, agent_id: principal, state: "queued", evidence_ids: [pathID], definition_version: 1, version: 1 }], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      if (path === `/api/v1/security-agent-runs/${findingID}/activity/session`) return new Response(JSON.stringify({ items: [{ kind: "session", id: pathID }], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      throw new Error(`Unexpected list read ${path}`);
    });
    const view = render(<ZaspProductionApp />);
    expect(await screen.findByRole("dialog", { name: `Run ${findingID}` })).toBeVisible();
    await waitFor(() => expect(screen.getByRole("button", { name: "Open trigger record" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Open trigger record" }));
    expect(await screen.findByText("Run-linked runtime evidence")).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`/investigate/sessions?entity_id=${pathID}&${scopeQuery}`);
    await userEvent.click(await screen.findByRole("button", { name: `Open run ${findingID}` }));
    expect(await screen.findByRole("dialog", { name: `Run ${findingID}` })).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`/protect/security-agents?entity_id=${findingID}&${scopeQuery}`);
    await userEvent.click(await screen.findByRole("button", { name: `Open session ${pathID}` }));
    expect(await screen.findByText("Run-linked runtime evidence")).toBeVisible();
    expect(window.location.pathname + window.location.search).toBe(`/investigate/sessions?entity_id=${pathID}&${scopeQuery}`);
    expect(reads).not.toContain("/api/v1/security-agent-runs");
    expect(reads).not.toContain("/api/v1/sessions");
    view.unmount();
  });

  it("loads exact records through the real client and preserves scope when following a finding's path", async () => {
    window.history.replaceState({}, "", `/violations?entity_id=${findingID}&${scopeQuery}`);
    const requested: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const url = new URL(request.url); requested.push(url.pathname);
      if (url.pathname === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["findings.read", "attack-paths.read"] });
      if (url.pathname === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (url.pathname === `/api/v1/findings/${findingID}`) return new Response(JSON.stringify(finding), { headers: { "Content-Type": "application/json", ETag: '"1"' } });
      if (url.pathname === `/api/v1/attack-paths/${pathID}`) return json(attackPath);
      if (url.pathname === `/api/v1/attack-paths/${pathID}/break-options`) return json({ items: [] });
      if (url.pathname === "/api/v1/attack-paths") return json({ items: [], page_info: { has_more: false, next_cursor: null } });
      throw new Error(`Unexpected request ${url.pathname}`);
    });
    const view = render(<ZaspProductionApp />);
    expect(await screen.findByRole("dialog", { name: finding.title })).toHaveTextContent(principal);
    await waitFor(() => expect(screen.getByRole("button", { name: "Open attack path" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Open attack path" }));
    expect(await screen.findByRole("dialog", { name: "Attack path detail" })).toBeVisible();
    await screen.findByText(`${principal} → ${otherPrincipal}`);
    expect(window.location.pathname + window.location.search).toBe(`/exposure/attack-paths?entity_id=${pathID}&${scopeQuery}`);
    expect(requested).not.toContain("/api/v1/findings");
    expect(requested).not.toContain("/api/v1/attack-paths");
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    await userEvent.click(screen.getByRole("button", { name: "All attack paths" }));
    expect(await screen.findByText("No attack paths in this scope.")).toBeVisible();
    expect(window.location.search).toBe("");
    window.history.replaceState({}, "", `/violations?entity_id=${findingID}&${scopeQuery}`);
    await act(async () => window.dispatchEvent(new PopStateEvent("popstate")));
    expect(await screen.findByRole("dialog", { name: finding.title })).toBeVisible();
    view.unmount();
  });

  it.each(["organization_id", "workspace_id", "environment_id"])("refuses foreign %s before mounting any record reader", async key => {
    const query = new URLSearchParams(`entity_id=${findingID}&${scopeQuery}`);
    query.set(key, otherPrincipal);
    window.history.replaceState({}, "", `/violations?${query}`);
    const reads: string[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname; reads.push(path);
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), capabilities: ["findings.read"] });
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      throw new Error(`Unexpected record reader ${path}`);
    });
    const view = render(<ZaspProductionApp />);
    expect(await screen.findByRole("alert")).toHaveTextContent("different organization, workspace or environment");
    expect(reads.some(path => path.startsWith("/api/v1/findings") || path === "/api/v1/session/scope")).toBe(false);
    view.unmount();
  });
});

describe("production audit identity wiring", () => {
  beforeEach(() => window.history.replaceState({}, "", "/administration/audit-log"));
  afterEach(() => vi.unstubAllGlobals());

  it.each(["fresh", "stale", "revoked", "other-principal"])("rebootstraps generic export forbidden and uses the resulting %s authority", async outcome => {
    sessionStorage.clear(); let bootstraps = 0; const posts: Request[] = [];
    let release!: (response: Response) => void; const rebootstrap = new Promise<Response>(resolve => { release = resolve; });
    const enabled = (actor = principal, fresh = true, permitted = true) => ({ ...bootstrap(actor), capabilities: permitted ? ["audit.read", "audit.exports"] : ["audit.read"], fresh_auth_expires_at: fresh ? new Date(Date.now() + 60000).toISOString() : "2000-01-01T00:00:00Z" });
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return ++bootstraps === 1 ? json(enabled()) : rebootstrap;
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === "/api/v1/audit-events") return page("audit.current");
      if (path === "/api/v1/audit-exports") { posts.push(request); return json({ code: "forbidden", message: "Authorization rejected", correlation_id: principal, retryable: false }, 403); }
      throw new Error(`Unexpected request ${path}`);
    });
    const view = render(<ZaspProductionApp />);
    await userEvent.click(await screen.findByRole("button", { name: "Create export" }));
    await waitFor(() => expect(bootstraps).toBe(2));
    expect(screen.queryByRole("button", { name: "Reauthenticate" })).not.toBeInTheDocument();
    await act(async () => release(json(enabled(outcome === "other-principal" ? otherPrincipal : principal, outcome !== "stale", outcome !== "revoked"))));
    if (outcome === "revoked") { expect(await screen.findByText("Audit exports unavailable")).toBeVisible(); expect(screen.getByText("Export is unavailable for this session or installation.")).toBeVisible(); expect(screen.queryByText(/no export mutation is mounted/i)).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: /create export/i })).not.toBeInTheDocument(); }
    else {
      const retry = await screen.findByRole("button", { name: outcome === "other-principal" ? "Create export" : "Retry create export" });
      if (outcome === "stale") { expect(retry).toBeDisabled(); expect(screen.getByRole("button", { name: "Reauthenticate" })).toBeEnabled(); }
      else expect(retry).toBeEnabled();
    }
    expect(posts).toHaveLength(1); expect(await posts[0].json()).toEqual({});
    expect(posts[0].headers.get("X-CSRF-Token")).toBe("c".repeat(32)); view.unmount();
  });

  it("joins an aborted physical read across actual scope remounts and drops obsolete waiting scopes", async () => {
    const stagingWorkspace = "pid_10000022-0000-4000-8000-000000000022";
    const stagingEnvironment = "pid_10000023-0000-4000-8000-000000000023";
    let currentWorkspace = workspace; let currentEnvironment = environment;
    let resolveOld!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { resolveOld = resolve; });
    const auditRequests: Request[] = []; const scopeMutations: unknown[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return json({ ...bootstrap(principal), workspace_id: currentWorkspace, environment_id: currentEnvironment, capabilities: ["audit.read", "scope.switch"] });
      if (path === "/api/v1/session/scopes") return json({ items: [
        { organization_id: organization, workspace_id: workspace, environment_id: environment, label: "Production" },
        { organization_id: organization, workspace_id: stagingWorkspace, environment_id: stagingEnvironment, label: "Staging" },
      ] });
      if (path === "/api/v1/session/scope") {
        expect(request.method).toBe("PUT");
        const body: unknown = await request.json(); scopeMutations.push(body);
        if (scopeMutations.length === 1) { expect(body).toEqual({ workspace_id: stagingWorkspace, environment_id: stagingEnvironment }); currentWorkspace = stagingWorkspace; currentEnvironment = stagingEnvironment; }
        else { expect(body).toEqual({ workspace_id: workspace, environment_id: environment }); currentWorkspace = workspace; currentEnvironment = environment; }
        return new Response(null, { status: 204 });
      }
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === "/api/v1/audit-events") {
        auditRequests.push(request);
        return auditRequests.length === 1 ? page("audit.original") : auditRequests.length === 2 ? old : page("audit.current");
      }
      throw new Error(`Unexpected request ${path}`);
    });
    const view = render(<ZaspProductionApp />);
    try {
      await screen.findByText("audit.original");
      await userEvent.click(screen.getByRole("button", { name: "Next" }));
      await waitFor(() => expect(auditRequests).toHaveLength(2));
      await userEvent.selectOptions(screen.getByRole("combobox", { name: "Authorized scope" }), `${stagingWorkspace}/${stagingEnvironment}`);
      await waitFor(() => expect(screen.getByRole("combobox", { name: "Authorized scope" })).toHaveValue(`${stagingWorkspace}/${stagingEnvironment}`));
      await screen.findByLabelText("Action (exact)");
      expect(auditRequests[1].signal.aborted).toBe(true);
      expect(screen.queryByText("audit.original")).not.toBeInTheDocument();
      expect(auditRequests).toHaveLength(2);
      await userEvent.selectOptions(screen.getByRole("combobox", { name: "Authorized scope" }), `${workspace}/${environment}`);
      await waitFor(() => expect(screen.getByRole("combobox", { name: "Authorized scope" })).toHaveValue(`${workspace}/${environment}`));
      await screen.findByLabelText("Action (exact)");
      expect(auditRequests).toHaveLength(2);
      expect(scopeMutations).toHaveLength(2);
      await act(async () => resolveOld(page("audit.obsolete")));
      expect(await screen.findByText("audit.current")).toBeVisible();
      expect(auditRequests).toHaveLength(3);
      expect(auditRequests[2].headers.get("X-Zasp-Expected-Scope")).toBe(`${organization}/${workspace}/${environment}`);
      expect(Object.fromEntries(new URL(auditRequests[2].url).searchParams)).toEqual({ limit: "50" });
      expect(screen.queryByText("audit.obsolete")).not.toBeInTheDocument();
    } finally { view.unmount(); await act(async () => resolveOld(page("audit.obsolete"))); }
  });

  it("clears the visible audit page when the shared client receives session expiry", async () => {
    let reads = 0;
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return json(bootstrap(principal));
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === "/api/v1/audit-events") return ++reads === 1 ? page("audit.private") : json({ code: "authentication_required", message: "Sign in required", correlation_id: principal, retryable: false }, 401);
      throw new Error(`Unexpected request ${path}`);
    });
    render(<ZaspProductionApp />);
    await screen.findByText("audit.private");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByRole("heading", { name: "Sign in to Zasp" })).toBeVisible();
    expect(screen.queryByText("audit.private")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Next" })).not.toBeInTheDocument();
  });

  it("aborts and restarts from newest when the shared query generation changes", async () => {
    let resolveOld!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { resolveOld = resolve; });
    const requests: Request[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return json(bootstrap(principal));
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path !== "/api/v1/audit-events") throw new Error(`Unexpected request ${path}`);
      requests.push(request);
      return requests.length === 1 ? page("audit.original") : requests.length === 2 ? old : page("audit.current");
    });
    render(<ZaspProductionApp />);
    try {
      await screen.findByText("audit.original");
      await userEvent.click(screen.getByRole("button", { name: "Next" }));
      await waitFor(() => expect(requests).toHaveLength(2));
      await userEvent.click(screen.getByRole("button", { name: "Invalidate test query cache" }));
      expect(requests[1].signal.aborted).toBe(true);
      expect(screen.queryByText("audit.original")).not.toBeInTheDocument();
      await act(async () => resolveOld(page("audit.late")));
      expect(await screen.findByText("audit.current")).toBeVisible();
      expect(new URL(requests[2].url).searchParams.has("cursor")).toBe(false);
      expect(screen.queryByText("audit.late")).not.toBeInTheDocument();
    } finally { await act(async () => resolveOld(page("audit.late"))); }
  });

  it.each([principal, otherPrincipal])("discards old pages and pending cursors after scope invalidation and rebootstrap as %s", async nextPrincipal => {
    let bootstraps = 0; let resolveOld!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { resolveOld = resolve; });
    const auditRequests: Request[] = [];
    vi.stubGlobal("fetch", async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/session/bootstrap") return json(bootstrap(++bootstraps === 1 ? principal : nextPrincipal));
      if (path === "/api/v1/workflow-mutation-receipts") return json({ items: [] });
      if (path === "/api/v1/audit-events") {
        auditRequests.push(request);
        return auditRequests.length === 1 ? page("audit.original") : auditRequests.length === 2 ? old : page("audit.revalidated");
      }
      if (path === "/api/v1/search") return json({ code: "scope_stale", message: "Session scope changed; rebootstrap required", correlation_id: principal, retryable: true }, 409);
      throw new Error(`Unexpected request ${path}`);
    });
    render(<ZaspProductionApp />);
    try {
      await screen.findByText("audit.original");
      expect(auditRequests[0].headers.get("X-Zasp-Expected-Scope")).toBe(`${organization}/${workspace}/${environment}`);
      expect(auditRequests[0].headers.has("X-CSRF-Token")).toBe(false);
      await userEvent.click(screen.getByRole("button", { name: "Next" }));
      await waitFor(() => expect(auditRequests).toHaveLength(2));
      await userEvent.type(screen.getByRole("searchbox", { name: "Search product entities" }), "invalidate");
      await userEvent.click(screen.getByRole("button", { name: "Search" }));
      expect(auditRequests[1].signal.aborted).toBe(true);
      await act(async () => resolveOld(page("audit.late")));
      expect(await screen.findByText("audit.revalidated")).toBeVisible();
      expect(new URL(auditRequests[2].url).searchParams.has("cursor")).toBe(false);
      expect(screen.queryByText("audit.original")).not.toBeInTheDocument();
      await act(async () => resolveOld(page("audit.late")));
      expect(screen.queryByText("audit.late")).not.toBeInTheDocument();
      expect(screen.getByText("Audit exports unavailable")).toBeVisible();
      expect(screen.queryByRole("button", { name: /export|reauthenticate/i })).not.toBeInTheDocument();
    } finally { await act(async () => resolveOld(page("audit.late"))); }
  });
});
