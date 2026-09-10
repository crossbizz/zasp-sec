import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import type { RuntimeSession, RuntimeSessionEvent, RuntimeSessionEventPage } from "../../../apps/web/api/generated";
import { createRuntimeSessionTimelineAPI, RuntimeSessionTimeline, type RuntimeSessionTimelineAPI } from "./RuntimeSessionTimeline";
import type { RuntimeSessionEvidenceAPI } from "./RuntimeSessionEvidence";

const id = "pid_10000001-0000-4000-8000-000000000001";
const agent = "pid_10000002-0000-4000-8000-000000000002";
const laterID = "pid_10000003-0000-4000-8000-000000000003";
const at = "2026-09-09T10:00:00Z", later = "2026-09-09T10:00:01Z";
const summary: RuntimeSession = { id, kind: "runtime", workspace_id: id, environment_id: id, agent_id: agent, principal_id: null, first_event_at: at, last_event_at: later, projected_at: later, event_count: 2, confidence_counts: { exact: 2, strong: 0, probable: 0, unattributed: 0 } };
const first: RuntimeSessionEvent = { id, session_id: id, agent_id: agent, class: "runtime", action: "exec", label: "First canonical event", evidence_id: id, source: "tetragon", confidence: "exact", at, projected_at: later };
const second: RuntimeSessionEvent = { ...first, id: laterID, label: "Second canonical event", at: later };
const page = (items: readonly RuntimeSessionEvent[], cursor: string | null = null): RuntimeSessionEventPage => ({ items, page_info: cursor ? { next_cursor: cursor, has_more: true } : { next_cursor: null, has_more: false } });
const api = (overrides: Partial<RuntimeSessionTimelineAPI> = {}): RuntimeSessionTimelineAPI => ({ get: async () => summary, events: async () => page([first, second]), ...overrides });

describe("canonical runtime timeline", () => {
  it("opens an exact evidence link through the product API and clears it on client change", async () => {
    const get = vi.fn<RuntimeSessionEvidenceAPI["get"]>(async () => first);
    const view = render(<RuntimeSessionTimeline id={id} api={api()} evidenceAPI={{ get }} />);
    await screen.findByText("First canonical event");
    await userEvent.click(screen.getAllByRole("link", { name: `Open evidence ${id}` })[0]);
    const dialog = screen.getByRole("dialog", { name: "Evidence metadata" });
    expect(await within(dialog).findByText("Raw archive content is not included in this view.")).toBeVisible();
    expect(get.mock.calls[0][0]).toEqual({ investigationID: id, eventID: id, evidenceID: id });
    view.rerender(<RuntimeSessionTimeline id={laterID} api={api({ get: async () => ({ ...summary, id: laterID }), events: async () => page([{ ...second, session_id: laterID }]) })} evidenceAPI={{ get }} />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await screen.findByText("Second canonical event");
  });
  it("uses generated detail and bounded event APIs and verifies target identity", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return new Response(JSON.stringify(new URL(request.url).pathname.endsWith("/events") ? page([first, second]) : summary), { headers: { "content-type": "application/json" } }); } });
    const store = createRuntimeSessionTimelineAPI(client), signal = new AbortController().signal;
    expect(await store.get(id, signal)).toEqual(summary);
    expect(await store.events(id, "cursor_one", signal)).toEqual(page([first, second]));
    expect(new URL(requests[1].url).searchParams.get("limit")).toBe("25");
    expect(new URL(requests[1].url).searchParams.get("cursor")).toBe("cursor_one");
    await expect(store.get(laterID, signal)).rejects.toThrow();
    await expect(store.events(laterID, null, signal)).rejects.toThrow();
  });

  it("renders canonical time order and source/confidence without inferred identity", async () => {
    render(<RuntimeSessionTimeline id={id} api={api()} />);
    await screen.findByText("First canonical event");
    const rows = screen.getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("First canonical event"); expect(rows[1]).toHaveTextContent("Second canonical event");
    expect(rows[0]).toHaveTextContent("tetragon"); expect(rows[0]).toHaveTextContent("Exact");
    expect(screen.getByText(/Principal: Unknown/)).toBeVisible();
    expect(screen.queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument();
  });

  it("loads only the requested event page and resumes from its cursor", async () => {
    const events = vi.fn<RuntimeSessionTimelineAPI["events"]>().mockResolvedValueOnce(page([first], "cursor_one")).mockResolvedValue(page([second]));
    render(<RuntimeSessionTimeline id={id} api={api({ events })} />);
    await screen.findByText("First canonical event");
    expect(events).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Next event page" }));
    await screen.findByText("Second canonical event");
    expect(screen.queryByText("First canonical event")).not.toBeInTheDocument();
    expect(events.mock.calls[1].slice(0, 2)).toEqual([id, "cursor_one"]);
    expect(screen.getByRole("button", { name: "Next event page" })).toBeDisabled();
  });

  it.each(["provider error", "reverse order", "foreign session", "repeated boundary"])("rejects %s without displaying false timeline rows", async fault => {
    const events = vi.fn<RuntimeSessionTimelineAPI["events"]>();
    if (fault === "provider error") events.mockRejectedValue(new Error("secret provider detail"));
    else if (fault === "reverse order") events.mockResolvedValue(page([second, first]));
    else if (fault === "foreign session") events.mockResolvedValue(page([{ ...first, session_id: laterID }]));
    else events.mockResolvedValueOnce(page([first], "cursor_one")).mockResolvedValue(page([first]));
    render(<RuntimeSessionTimeline id={id} api={api({ events })} />);
    if (fault === "repeated boundary") { await screen.findByText("First canonical event"); await userEvent.click(screen.getByRole("button", { name: "Next event page" })); }
    expect(await screen.findByRole("alert")).toHaveTextContent("Runtime timeline could not be loaded");
    expect(screen.queryByText("First canonical event")).not.toBeInTheDocument();
    expect(screen.queryByText(/secret provider detail/)).not.toBeInTheDocument();
  });

  it("cancels and hides a previous investigation when its target changes", async () => {
    let finish!: (value: RuntimeSessionEventPage) => void;
    const events = vi.fn<RuntimeSessionTimelineAPI["events"]>(() => new Promise(resolve => { finish = resolve; }));
    const prior = api({ events });
    const view = render(<RuntimeSessionTimeline id={id} api={prior} />);
    await waitFor(() => expect(events).toHaveBeenCalledTimes(1));
    const next = api({ get: async () => ({ ...summary, id: laterID }), events: async () => page([{ ...second, session_id: laterID }]) });
    view.rerender(<RuntimeSessionTimeline id={laterID} api={next} />);
    await screen.findByText("Second canonical event");
    expect(events.mock.calls[0][2].aborted).toBe(true);
    await act(async () => finish(page([first])));
    expect(screen.queryByText("First canonical event")).not.toBeInTheDocument();
  });
});
