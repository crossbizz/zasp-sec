import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import { createSessionsComplianceAPI, hydrateSessionEvents, SessionsComplianceView, type SessionsComplianceAPI } from "./SessionsComplianceView";

const principal = "pid_10000004-0000-4000-8000-000000000004";
const workspace = "pid_10000002-0000-4000-8000-000000000002";
const environment = "pid_10000003-0000-4000-8000-000000000003";
function api(overrides: Partial<SessionsComplianceAPI> = {}): SessionsComplianceAPI { return {
  listSessions: async () => [{ id: "session-live", agent_id: "product-console", principal_id: principal, workspace_id: workspace, environment_id: environment, state: "active", authenticated_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-20T00:00:00Z", version: 1, events: [{ id: "event-1", session_id: "session-live", class: "tool", label: "Shell requested", evidence_id: "evidence-1", source: "product", confidence: "exact", at: "2026-08-19T00:00:01Z" }] }],
  revokeSession: async () => undefined,
  listControls: async () => [{ id: "access-control", framework: "SOC 2", name: "Security", evidence_ids: ["evidence-1"], fresh_until: "2026-08-20T00:00:00Z" }],
  listEvidence: async () => [{ control: { id: "access-control", framework: "SOC 2", name: "Security", evidence_ids: ["evidence-1"], fresh_until: "2026-08-20T00:00:00Z" }, freshness: "fresh", evidence: [{ id: "evidence-1", asset_id: "asset-1", source: "runtime", at: "2026-08-19T00:00:00Z" }] }],
  getDataControls: async () => ({ environment_id: environment, environment_class: "production", collection_mode: "metadata_only", retention_days: 30, deletion_enabled: true, version: 1 }),
  updateDataControls: async (value) => ({ ...value, version: value.version + 1 }),
  ...overrides,
}; }

describe("Sessions, compliance, and data controls", () => {
  it("bounds event hydration and preserves sessions whose event request fails", async () => {
    const sessions = Array.from({ length: 12 }, (_, index) => ({ ...((awaitableSession()) as Awaited<ReturnType<SessionsComplianceAPI["listSessions"]>>[number]), id: `session-${index}` }));
    let active = 0;
    let peak = 0;
    const hydrated = await hydrateSessionEvents(sessions, async (session) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      if (session.id === "session-5") throw new Error("provider detail");
      return [];
    }, 4);
    expect(peak).toBeLessThanOrEqual(4);
    expect(hydrated).toHaveLength(12);
    expect(hydrated.find((session) => session.id === "session-5")?.eventsUnavailable).toBe(true);
    expect(hydrated.filter((session) => session.eventsUnavailable)).toHaveLength(1);
  });
  it("renders ordered evidence and revokes the exact version", async () => { const revoke = vi.fn(api().revokeSession); render(<SessionsComplianceView surface="sessions" api={api({ revokeSession: revoke })} canMutate />); expect(await screen.findByText(/Shell requested/)).toHaveTextContent("evidence-1"); await userEvent.click(screen.getByRole("button", { name: "Revoke session session-live" })); expect(revoke).toHaveBeenCalledWith("session-live", 1); expect(await screen.findByRole("status")).toHaveTextContent("Session revoked"); });
  it("accepts only the declared 204 session revoke response", async () => {
    const client = { DELETE: vi.fn(async () => ({ response: new Response("{}", { status: 200, headers: { "content-type": "application/json" } }), data: {} })) } as unknown as APIClient;
    await expect(createSessionsComplianceAPI(client).revokeSession("session-live", 1)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it("renders legacy evidence without claiming current freshness or exports", async () => { render(<SessionsComplianceView surface="compliance" api={api()} />); expect(await screen.findByText("SOC 2 · Security")).toBeVisible(); expect(screen.getByText(/asset-1/)).toBeVisible(); expect(screen.getByText("Evidence exports unavailable")).toBeVisible(); expect(screen.getByText("Legacy evidence (current freshness unavailable)")).toBeVisible(); expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument(); });
  it("updates versioned metadata-only production controls", async () => { const update = vi.fn(api().updateDataControls); render(<SessionsComplianceView surface="data-controls" api={api({ updateDataControls: update })} canMutate />); expect(await screen.findByDisplayValue("30")).toBeVisible(); await userEvent.clear(screen.getByLabelText("Retention days")); await userEvent.type(screen.getByLabelText("Retention days"), "60"); await userEvent.click(screen.getByRole("button", { name: "Save data controls" })); expect(update).toHaveBeenCalledWith(expect.objectContaining({ retention_days: 60, version: 1 })); });
});

function awaitableSession() { return { id: "session-live", agent_id: "product-console", principal_id: principal, workspace_id: workspace, environment_id: environment, state: "active" as const, authenticated_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-20T00:00:00Z", version: 1, events: [] }; }

const organization = "pid_10000001-0000-4000-8000-000000000001";
const target = { source_kind: "policy" as const, source_id: "policy-production", source_version: 2 };
const record = { id: "policy-production", asset_id: "policy-production", source: "policy", at: "2026-09-01T12:00:00Z", target, metadata: { verification: "definition_only" } };
const control = { id: "soc2-policy", framework: "soc2_security", name: "Policy definition", evidence_ids: [record.id], fresh_until: "2026-10-01T12:00:00Z", freshness: "stale" };
const boundary = { principalID: principal, organizationID: organization, workspaceID: workspace, environmentID: environment, generation: 1, permitted: true, fresh: true, isCurrent: () => true };
const job = { id: principal, status: "pending", formats: ["json", "csv", "human"], created_at: "2026-09-01T00:00:00Z", expires_at: "2099-09-02T00:00:00Z", failure_code: null, mapping_revision: "product-evidence-v1" };
function complianceClient(handle?: (request: Request) => Promise<Response | undefined>) {
  return createAPIClient({ getCSRFToken: () => "c".repeat(32), getExpectedScope: () => `${organization}/${workspace}/${environment}`, fetch: async request => {
    const custom = await handle?.(request); if (custom) return custom;
    const path = new URL(request.url).pathname;
    if (path.endsWith("/controls")) return response({ items: [control, { ...control, id: "hipaa-config", framework: "HIPAA", name: "Configuration", freshness: "missing", evidence_ids: [] }], page_info: { has_more: false, next_cursor: null } });
    if (path.endsWith("/evidence")) return response({ items: new URL(request.url).searchParams.get("framework") === "hipaa" ? [] : [{ control, freshness: "fresh", evidence: [record] }], page_info: { has_more: false, next_cursor: null } });
    if (path.endsWith("/policy/policy-production")) return response({ record, freshness: "stale", organization_id: organization, workspace_id: workspace, environment_id: environment });
    if (path.endsWith("/exports")) return response(job, 201);
    if (path.endsWith(`/exports/${principal}`)) return response({ ...job, status: "completed" });
    throw new Error("Unexpected compliance request");
  } });
}
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }); }
const legacyControl = { id: "legacy-control", framework: "SOC 2", name: "Legacy seed", evidence_ids: ["legacy-evidence"], fresh_until: "2020-01-02T00:00:00Z" };
const legacyEvidence = { control: legacyControl, freshness: "fresh", evidence: [{ id: "legacy-evidence", asset_id: "legacy-asset", source: "runtime", at: "2020-01-01T00:00:00+00:00" }] };
describe("compliance retained-service compatibility", () => {
  it("keeps populated legacy reads usable through the real adapter and strict cursor/limit query contract", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async request => {
      const url = new URL(request.url); requests.push(url);
      if ([...url.searchParams.keys()].some(key => !["cursor", "limit"].includes(key))) return response({ code: "invalid_request", message: "Invalid request", correlation_id: principal, retryable: false }, 400);
      return response({ items: [url.pathname.endsWith("/controls") ? legacyControl : legacyEvidence], page_info: { has_more: false, next_cursor: null } });
    } });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    expect(await screen.findByText(/legacy-asset/)).toBeVisible();
    expect(screen.getByText("Legacy evidence (current freshness unavailable)")).toBeVisible();
    expect(screen.getByText("Evidence exports unavailable")).toBeVisible();
    expect(screen.queryByText("fresh", { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create evidence export" })).not.toBeInTheDocument();
    expect(requests.map(url => url.pathname)).toEqual(["/api/v1/compliance/controls", "/api/v1/compliance/evidence"]);
    expect(requests.every(url => !url.searchParams.has("framework"))).toBe(true);
  });
  it("treats empty controls as unfiltered legacy without inventing current support", async () => {
    const evidenceQueries: string[] = [];
    const client = complianceClient(async request => { const url = new URL(request.url); if (url.pathname.endsWith("/evidence")) evidenceQueries.push(url.search); return response({ items: [], page_info: { has_more: false, next_cursor: null } }); });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    expect(await screen.findByText("Evidence exports unavailable")).toBeVisible();
    expect(evidenceQueries).toEqual(["?limit=100"]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("rejects mixed current/legacy controls before reading evidence", async () => {
    let evidenceReads = 0;
    const client = complianceClient(async request => { if (new URL(request.url).pathname.endsWith("/evidence")) { evidenceReads++; return undefined; } return response({ items: [control, legacyControl], page_info: { has_more: false, next_cursor: null } }); });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Compliance request failed");
    expect(evidenceReads).toBe(0);
    expect(screen.queryByRole("button", { name: "Create evidence export" })).not.toBeInTheDocument();
  });
  it.each([[401, "authentication_required"], [403, "forbidden"], [409, "scope_stale"], [503, "service_unavailable"]] as const)("never downgrades a controls failure %s into legacy reads", async (status, code) => {
    const paths: string[] = [];
    const client = createAPIClient({ fetch: async request => { paths.push(new URL(request.url).pathname); return response({ code, message: "Request denied", correlation_id: principal, retryable: status === 409 || status === 503 }, status); } });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await screen.findByRole("alert");
    expect(paths).toEqual(["/api/v1/compliance/controls"]);
    expect(screen.queryByText(/Legacy evidence \(/)).not.toBeInTheDocument();
  });
});
describe("current compliance UI", () => {
  it("loads populated HIPAA and SOC2 with independent cursor chains through the mounted client", async () => {
    const seen: string[] = [];
    const hipaa = { ...control, id: "hipaa-policies", framework: "hipaa", name: "HIPAA policy definitions" };
    const client = complianceClient(async request => {
      const url = new URL(request.url);
      if (url.pathname.endsWith("/controls")) return response({ items: [control, hipaa], page_info: { has_more: false, next_cursor: null } });
      if (!url.pathname.endsWith("/evidence")) return undefined;
      const framework = url.searchParams.get("framework") ?? "soc2_security";
      const cursor = url.searchParams.get("cursor");
      seen.push(`${framework}:${cursor ?? "first"}`);
      if (!cursor) return response({ items: [], page_info: { has_more: true, next_cursor: `${framework}-next` } });
      expect(cursor).toBe(`${framework}-next`);
      return response({ items: [{ control: framework === "hipaa" ? hipaa : control, freshness: "fresh", evidence: [record] }], page_info: { has_more: false, next_cursor: null } });
    });
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await waitFor(() => expect(screen.getAllByRole("link", { name: "Open policy policy-production version 2" })).toHaveLength(2));
    expect(seen).toEqual(["soc2_security:first", "soc2_security:soc2_security-next", "hipaa:first", "hipaa:hipaa-next"]);
    await userEvent.selectOptions(screen.getByLabelText("Framework"), "hipaa");
    await userEvent.selectOptions(screen.getByLabelText("Control"), "hipaa-policies");
    expect(screen.getByRole("link", { name: "Open policy policy-production version 2" })).toHaveAttribute("href", expect.stringContaining("source_kind=policy&source_id=policy-production&source_version=2"));
    expect(screen.queryByText("soc2_security · Policy definitions")).not.toBeInTheDocument();
  });
  it.each((["controls", "soc2_security", "hipaa"] as const).flatMap(chain => [["scope", 1, chain], ["principal", 1, chain], ["scope", 2, chain], ["principal", 2, chain]] as const))("cancels obsolete %s list page %s in %s before a continuation starts", async (replacement, pendingPage, chain) => {
    const oldRequests: Request[] = [];
    const releases: Array<(response: Response) => void> = [];
    let replaced = false;
    let obsoleteContinuations = 0;
    const client = complianceClient(async request => {
      const url = new URL(request.url);
      if (url.searchParams.get("cursor") === "obsolete-page-two") obsoleteContinuations++;
      if (replaced) return undefined;
      if ((url.pathname.endsWith("/controls") ? "controls" : url.searchParams.get("framework")) !== chain) return undefined;
      if (pendingPage === 2 && !new URL(request.url).searchParams.has("cursor")) return response({ items: [], page_info: { has_more: true, next_cursor: "first-continuation" } });
      oldRequests.push(request);
      return new Promise(resolve => releases.push(resolve));
    });
    const view = render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await waitFor(() => expect(releases).toHaveLength(1));
    replaced = true;
    const next = { ...boundary, generation: 2, ...(replacement === "scope" ? { workspaceID: principal } : { principalID: environment }) };
    view.rerender(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={next} />);
    await screen.findByRole("link", { name: /Open policy/ });
    await act(async () => {
      releases.forEach((release, i) => release(response({ items: new URL(oldRequests[i].url).pathname.endsWith("/controls") ? [control] : [{ control, freshness: "fresh", evidence: [record] }], page_info: { has_more: true, next_cursor: "obsolete-page-two" } })));
    });
    expect(oldRequests.every(request => request.signal.aborted)).toBe(true);
    expect(oldRequests).toHaveLength(1);
    expect(obsoleteContinuations).toBe(0);
  });
  it.each((["controls", "soc2_security", "hipaa"] as const).flatMap(chain => ([
    ["scope", 401, "authentication_required", "Authentication required", false],
    ["principal", 401, "authentication_required", "Authentication required", false],
    ["scope", 409, "scope_stale", "Session scope changed; rebootstrap required", true],
    ["principal", 409, "scope_stale", "Session scope changed; rebootstrap required", true],
  ] as const).map(values => [...values, chain] as const)))("refuses obsolete %s %s errors before they can invalidate replacement authority (%s/%s/%s/%s)", async (replacement, status, code, message, retryable, chain) => {
    let replaced = false, invalidations = 0;
    const releases: Array<(response: Response) => void> = [];
    const client = createAPIClient({
      onSessionExpired: () => { invalidations++; },
      onScopeStale: () => { invalidations++; },
      fetch: async request => {
        if (replaced) return response({ items: [], page_info: { has_more: false, next_cursor: null } });
        const url = new URL(request.url);
        if ((url.pathname.endsWith("/controls") ? "controls" : url.searchParams.get("framework")) !== chain) return response({ items: url.pathname.endsWith("/controls") ? [control] : [], page_info: { has_more: false, next_cursor: null } });
        return new Promise(resolve => releases.push(resolve));
      },
    });
    const view = render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await waitFor(() => expect(releases).toHaveLength(1));
    replaced = true;
    view.rerender(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={{ ...boundary, generation: 2, ...(replacement === "scope" ? { workspaceID: principal } : { principalID: environment }) }} />);
    await screen.findByText("Evidence exports unavailable");
    await act(async () => { releases.forEach(release => release(response({ code, message, correlation_id: principal, retryable }, status))); });
    expect(invalidations).toBe(0);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("uses aggregate freshness, exposes typed source/time links, and filters frameworks and controls", async () => {
    render(<SessionsComplianceView surface="compliance" client={complianceClient()} complianceBoundary={boundary} />);
    const link = await screen.findByRole("link", { name: "Open policy policy-production version 2" });
    expect(link.getAttribute("href")).toContain("source_kind=policy&source_id=policy-production&source_version=2");
    expect(screen.getByText("2026-09-01T12:00:00Z")).toBeVisible();
    expect(screen.getByText("stale")).toBeVisible(); expect(screen.getByText("missing")).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText("Framework"), "hipaa");
    expect(screen.queryByRole("link", { name: /Open policy/ })).not.toBeInTheDocument();
    expect(screen.getByText("Missing required evidence")).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText("Framework"), "soc2_security");
    await userEvent.selectOptions(screen.getByLabelText("Control"), "soc2-policy");
    expect(screen.queryByText("missing")).not.toBeInTheDocument();
  });
  it("reads exact source versions through the compliance detail endpoint", async () => {
    const reads: string[] = [];
    render(<SessionsComplianceView surface="compliance" client={complianceClient(async request => { reads.push(request.url); return undefined; })} complianceBoundary={boundary} selectedSource={target} />);
    expect(await screen.findByRole("heading", { name: "Evidence source" })).toBeVisible();
    expect(screen.getByText(/definition_only/)).toBeVisible();
    expect(reads.some(url => url.endsWith("/compliance/evidence/policy/policy-production?source_version=2"))).toBe(true);
    expect(reads.some(url => url.includes("security-agent"))).toBe(false);
  });
  it.each([[409, "source_changed", "Evidence source changed", /Source changed/], [404, "not_found", "not_found", /Source unavailable/], [403, "forbidden", "forbidden", /Access denied/]] as const)("keeps deterministic detail denial %s", async (status, code, message, expected) => {
    render(<SessionsComplianceView surface="compliance" client={complianceClient(async request => new URL(request.url).pathname.endsWith("/policy/policy-production") ? response({ code, message, correlation_id: principal, retryable: false }, status) : undefined)} complianceBoundary={boundary} selectedSource={target} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(expected);
  });
  it("creates queued exports with the selected filters, recovers status on reload, and leaves evidence readable on download failure", async () => {
    const requests: Request[] = [];
    const client = complianceClient(async request => {
      requests.push(request.clone() as Request);
      if (new URL(request.url).pathname.endsWith("/download-grants")) return response({ code: "forbidden", message: "expired", correlation_id: principal, retryable: false }, 403);
      return undefined;
    });
    const view = render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await userEvent.selectOptions(await screen.findByLabelText("Framework"), "soc2_security");
    await userEvent.selectOptions(screen.getByLabelText("Control"), "soc2-policy");
    await userEvent.click(screen.getByRole("button", { name: "Create evidence export" }));
    expect(await screen.findByText("Export queued")).toBeVisible();
    const creation = requests.find(request => request.method === "POST" && new URL(request.url).pathname.endsWith("/exports"));
    expect(await creation?.json()).toEqual({ framework: "soc2_security", control_id: "soc2-policy" });
    view.unmount(); render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    expect(await screen.findByText("Export completed")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Download JSON" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Access denied/);
    expect(screen.getByRole("link", { name: /Open policy/ })).toBeVisible();
    expect(JSON.stringify(sessionStorage)).not.toContain("token");
    sessionStorage.clear();
  });
  it.each(["failed", "expired"])("renders %s export without hiding evidence", async state => {
    const client = complianceClient(async request => new URL(request.url).pathname.endsWith("/exports") ? response({ ...job, status: state === "failed" ? "failed" : "completed", failure_code: state === "failed" ? "collection_failed" : null, expires_at: state === "expired" ? "2026-09-02T00:00:00Z" : job.expires_at }, 201) : undefined);
    render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await userEvent.click(await screen.findByRole("button", { name: "Create evidence export" }));
    expect(await screen.findByText(state === "failed" ? /Export failed: collection_failed/ : "Export expired")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open policy/ })).toBeVisible(); sessionStorage.clear();
  });
  it("drops late evidence responses on a changed principal and hides revoked authority immediately", async () => {
    let finish!: (value: Response) => void;
    const client = complianceClient(async request => new URL(request.url).pathname.endsWith("/evidence") ? new Promise(resolve => { finish = resolve; }) : undefined);
    const view = render(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={boundary} />);
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    view.rerender(<SessionsComplianceView surface="compliance" client={client} complianceBoundary={{ ...boundary, principalID: environment, permitted: false }} />);
    await act(async () => finish(response({ items: [{ control, freshness: "fresh", evidence: [record] }], page_info: { has_more: false, next_cursor: null } })));
    expect(screen.queryByText("policy-production")).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/Access denied/);
  });
});
