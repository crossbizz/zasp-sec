import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { AuditEventPage } from "../../../apps/web/api/generated";
import { AdminOperationsView } from "./AdminOperationsView";

const id = "pid_10000001-0000-4000-8000-000000000001";
function event(action = "member.role.update") {
  return { id, workspace_id: id, environment_id: id, actor_id: id, action, target_id: id, outcome: "succeeded", metadata: {}, occurred_at: "2026-09-12T00:00:00.123456Z" };
}
function page(action = "member.role.update", cursor: string | null = null): AuditEventPage {
  return { items: [{ ...event(action), outcome: "succeeded" }], page_info: cursor === null ? { has_more: false, next_cursor: null } : { has_more: true, next_cursor: cursor } };
}
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }); }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }

describe("bounded audit browsing", () => {
  it("clears a retained page immediately when current authorization refuses Next", async () => {
    let requests = 0;
    const client = createAPIClient({ fetch: async () => ++requests === 1 ? json(page("audit.sensitive", "next-denied")) : json({ code: "request_forbidden", message: "Request forbidden", correlation_id: id, retryable: false }, 403) });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("audit.sensitive");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("alert");
    expect(screen.queryByText("audit.sensitive")).not.toBeInTheDocument();
    expect(document.getElementById(`audit-event-${id}`)).toBeNull();
    expect(screen.getByText(/Results are unavailable, not empty/)).toBeVisible();
    expect(screen.getByText("Audit exports unavailable")).toBeVisible();
  });
  it("binds rendered rows to exact public IDs and drops old IDs on replacement and invalidation", async () => {
    const nextID = "pid_20000001-0000-4000-8000-000000000001";
    const api = { page: async (_filters: unknown, cursor: string | undefined): Promise<AuditEventPage> => cursor
      ? { items: [{ ...event("policy.create"), id: nextID, outcome: "succeeded" }], page_info: { has_more: false, next_cursor: null } }
      : page("identity_provider.createSSOConnection", "next") };
    const view = render(<AdminOperationsView surface="audit" auditAPI={api} />);
    await screen.findByText("identity_provider.createSSOConnection");
    expect(document.getElementById(`audit-event-${id}`)).toHaveTextContent(`Actor ${id}`);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("policy.create");
    expect(document.getElementById(`audit-event-${nextID}`)).toHaveTextContent("policy.create");
    expect(document.getElementById(`audit-event-${id}`)).toBeNull();
    view.rerender(<AdminOperationsView surface="audit" auditAPI={api} auditBoundary={{ identityKey: null }} />);
    expect(document.getElementById(`audit-event-${nextID}`)).toBeNull();
  });
  it.each(["session", "scope"])("checks the current %s generation after a non-cooperating API resolves", async kind => {
    const old = deferred<AuditEventPage>(); let generation = 0; const signals: AbortSignal[] = [];
    const api = { page: async (_filters: unknown, _cursor: unknown, _limit: number, signal: AbortSignal) => { signals.push(signal); return signals.length === 1 ? old.promise : page("audit.current"); } };
    const getGeneration = () => generation;
    const boundary = { identityKey: "principal/scope/0", ...(kind === "session" ? { getSessionInvalidationGeneration: getGeneration } : { getScopeStaleGeneration: getGeneration }) };
    const view = render(<AdminOperationsView surface="audit" auditAPI={api} auditBoundary={boundary} />);
    await waitFor(() => expect(signals).toHaveLength(1));
    generation++;
    await act(async () => old.resolve(page("audit.forbidden-late")));
    expect(screen.queryByText("audit.forbidden-late")).not.toBeInTheDocument();
    view.rerender(<AdminOperationsView surface="audit" auditAPI={api} auditBoundary={{ ...boundary, identityKey: null }} />);
    expect(signals[0].aborted).toBe(true);
    expect(screen.getByText("Revalidating audit access…")).toBeVisible();
    expect(signals).toHaveLength(1);
    view.rerender(<AdminOperationsView surface="audit" auditAPI={api} auditBoundary={{ ...boundary, identityKey: "principal/new-scope/1" }} />);
    expect(await screen.findByText("audit.current")).toBeVisible();
  });

  it("aborts an unmounted page read and never paints its late result", async () => {
    const old = deferred<AuditEventPage>(); let signal: AbortSignal | undefined;
    const view = render(<AdminOperationsView surface="audit" auditAPI={{ page: async (_filters, _cursor, _limit, currentSignal) => { signal = currentSignal; return old.promise; } }} />);
    await waitFor(() => expect(signal).toBeDefined());
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => old.resolve(page("audit.unmounted")));
    expect(screen.queryByText("audit.unmounted")).not.toBeInTheDocument();
  });

  it("keeps drafts separate and resends all five normalized filters on every continuation", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async request => {
      requests.push(new URL(request.url)); return json(page("identity_provider.createSSOConnection", `next-${requests.length}`));
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("identity_provider.createSSOConnection");
    await userEvent.click(screen.getByRole("button", { name: "Use this action" }));
    await userEvent.click(screen.getByRole("button", { name: "Use this actor" }));
    expect(screen.getByLabelText("Action (exact)")).toHaveValue("identity_provider.createSSOConnection");
    expect(screen.getByLabelText("Actor ID (exact)")).toHaveValue(id);
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "denied");
    fireEvent.change(screen.getByLabelText("From (UTC, inclusive)"), { target: { value: "2026-09-12T00:00:00.123455Z" } });
    fireEvent.change(screen.getByLabelText("To (UTC, exclusive)"), { target: { value: "2026-09-12T00:00:00.123456Z" } });
    expect(requests).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    const expected = { limit: "50", actor_id: id, action: "identity_provider.createSSOConnection", outcome: "denied", from: "2026-09-12T00:00:00.123455Z", to: "2026-09-12T00:00:00.123456Z" };
    expect(Object.fromEntries(requests[1].searchParams)).toEqual(expected);
    fireEvent.change(screen.getByLabelText("Action (exact)"), { target: { value: "draft.change" } });
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(requests).toHaveLength(3));
    expect(Object.fromEntries(requests[2].searchParams)).toEqual({ ...expected, cursor: "next-2" });
    expect(screen.getByLabelText("Applied audit filters")).toHaveTextContent("identity_provider.createSSOConnection");
    expect(screen.getByLabelText("Applied audit filters")).not.toHaveTextContent("draft.change");
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(requests).toHaveLength(4));
    expect(Object.fromEntries(requests[3].searchParams)).toEqual({ limit: "50" });
    expect(screen.getByLabelText("Action (exact)")).toHaveValue("");
  });

  it("retains only the visible page beyond twenty pages, and First and Refresh restart newest", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async request => {
      const url = new URL(request.url); requests.push(url);
      const n = Number(url.searchParams.get("cursor") ?? 0);
      return json(page(`audit.page-${n}`, n === 22 ? null : String(n + 1)));
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("audit.page-0");
    for (let n = 1; n <= 22; n++) {
      await userEvent.click(screen.getByRole("button", { name: "Next" }));
      expect(await screen.findByText(`audit.page-${n}`)).toBeVisible();
      expect(screen.queryByText(`audit.page-${n - 1}`)).not.toBeInTheDocument();
      expect(screen.getAllByRole("button", { name: "Use this action" })).toHaveLength(1);
    }
    expect(requests).toHaveLength(23);
    expect(screen.getByText("Showing 1 matching audit events")).toBeVisible();
    expect(screen.getByText("No older matching events")).toBeVisible();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "First" }));
    await screen.findByText("audit.page-0");
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(requests).toHaveLength(25));
    expect(requests.slice(-2).every(url => !url.searchParams.has("cursor"))).toBe(true);
    expect(screen.queryByText(/\btotal\b|Page \d+ of/)).not.toBeInTheDocument();
  });

  it("keeps the last good page on Next failure and retries the exact cursor", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async request => {
      requests.push(new URL(request.url));
      if (requests.length === 1) return json(page("audit.first", "exact-next"));
      if (requests.length === 2) return json({ code: "unavailable", message: "Try later", correlation_id: id, retryable: true }, 503);
      return json(page("audit.second"));
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("audit.first");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be loaded");
    expect(screen.getByText("audit.first")).toBeVisible();
    expect(screen.queryByText("No matching audit events")).not.toBeInTheDocument();
    expect(screen.getByText("Audit exports unavailable")).toBeVisible();
    expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry next page" }));
    expect(await screen.findByText("audit.second")).toBeVisible();
    expect(requests[2].search).toBe(requests[1].search);
    expect(requests[2].searchParams.get("cursor")).toBe("exact-next");
    expect(screen.queryByText("audit.first")).not.toBeInTheDocument();
  });

  it("clears old results on Apply, aborts the old read, and ignores a late response", async () => {
    const old = deferred<Response>(); const next = deferred<Response>(); const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => {
      requests.push(request);
      if (requests.length === 1) return json(page("audit.old", "older"));
      return requests.length === 2 ? old.promise : next.promise;
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("audit.old");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.change(screen.getByLabelText("Action (exact)"), { target: { value: "audit.new" } });
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(requests[1].signal.aborted).toBe(true);
    expect(screen.queryByText("audit.old")).not.toBeInTheDocument();
    await act(async () => old.resolve(json(page("audit.late"))));
    expect(screen.queryByText("audit.late")).not.toBeInTheDocument();
    await act(async () => next.resolve(json(page("audit.new"))));
    expect(await screen.findByText("audit.new")).toBeVisible();
  });

  it("shows a genuine empty terminal match separately from a first-page error", async () => {
    let calls = 0;
    const client = createAPIClient({ fetch: async () => ++calls === 1 ? json({ code: "unavailable", message: "Try later", correlation_id: id, retryable: true }, 503) : json({ items: [], page_info: { has_more: false, next_cursor: null } }) });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByRole("alert");
    expect(screen.queryByText("No matching audit events")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry page" }));
    expect(await screen.findByText("No matching audit events")).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it.each([
    ["Actor ID (exact)", "pid_invalid"], ["Action (exact)", "identity_provider.CreateSSOConnection"],
    ["From (UTC, inclusive)", "2026-02-30T00:00:00Z"], ["From (UTC, inclusive)", "2026-09-12T00:00:00.1234567Z"],
    ["To (UTC, exclusive)", "2026-09-12T00:00:00+00:00"],
  ])("refuses invalid %s before replacing applied results", async (label, value) => {
    let calls = 0;
    const client = createAPIClient({ fetch: async () => { calls++; return json(page()); } });
    render(<AdminOperationsView surface="audit" client={client} />);
    await screen.findByText("member.role.update");
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(screen.getByRole("alert")).toBeVisible();
    expect(calls).toBe(1);
    expect(screen.getByText("member.role.update")).toBeVisible();
  });
});
