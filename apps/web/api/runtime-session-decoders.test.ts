import { describe, expect, it } from "vitest";
import { decodeRuntimeSession, decodeRuntimeSessionEventPage, decodeRuntimeSessionPage } from "./runtime-session-decoders";

const id = "pid_10000001-0000-4000-8000-000000000001";
const agent = "pid_10000002-0000-4000-8000-000000000002";
const first = "2026-09-09T10:00:00Z";
const last = "2026-09-09T10:00:01Z";
const summary = { id, kind: "runtime", workspace_id: id, environment_id: id, agent_id: agent, principal_id: null, first_event_at: first, last_event_at: last, projected_at: last, event_count: 2, confidence_counts: { exact: 1, strong: 1, probable: 0, unattributed: 0 } };
const event = { id, session_id: id, agent_id: agent, class: "runtime", action: "exec", label: "Process executed", evidence_id: id, source: "tetragon", confidence: "exact", at: first, projected_at: last };
const page = (items: unknown[]) => ({ items, page_info: { next_cursor: null, has_more: false } });
const search = { state: "current", pending_batches: 0, pending_batches_capped: false, quarantined_batches: 0, quarantined_batches_capped: false, last_indexed_at: first, oldest_pending_at: null, checked_at: last, selector_coverage: "observed_only" };

describe("runtime session search checkpoint boundary", () => {
  it("preserves checkpoint status for results and empty matches", () => {
    for (const items of [[], [summary]]) expect(decodeRuntimeSessionPage({ ...page(items), search })).toEqual({ ...page(items), search });
    const backlog = { ...search, state: "catching_up", pending_batches: 1000, pending_batches_capped: true, oldest_pending_at: first };
    expect(decodeRuntimeSessionPage({ ...page([]), search: backlog })).toEqual({ ...page([]), search: backlog });
  });
  it.each([
    null, { ...search, state: "healthy" }, { ...search, pending_batches: 1 },
    { ...search, pending_batches_capped: true }, { ...search, pending_batches_capped: null },
    { ...search, pending_batches: 1001 }, { ...search, pending_batches: -1 },
    { ...search, last_indexed_at: null }, { ...search, last_indexed_at: "2026-09-10T00:00:00Z" },
    { ...search, oldest_pending_at: first }, { ...search, selector_coverage: "complete" },
    { ...search, checked_at: null }, { ...search, secret: "not-allowed" },
  ])("rejects invalid or overstated checkpoint status %j", (status) => {
    expect(() => decodeRuntimeSessionPage({ ...page([]), search: status })).toThrow("schema mismatch");
  });
});

describe("runtime investigation response boundary", () => {
  it("accepts durable summaries, multiple-agent uncertainty and explicit unknown collections", () => {
    expect(decodeRuntimeSession(summary)).toEqual(summary);
    expect(decodeRuntimeSession({ ...summary, agent_id: null }).agent_id).toBeNull();
    const unknown = { ...summary, id: "unattributed", kind: "unattributed", agent_id: null, event_count: 2, confidence_counts: { exact: 0, strong: 0, probable: 1, unattributed: 1 } };
    expect(decodeRuntimeSessionPage(page([unknown])).items[0]).toEqual(unknown);
    expect(decodeRuntimeSessionEventPage(page([{ ...event, session_id: null, agent_id: null, confidence: "probable" }])).items[0].session_id).toBeNull();
  });
  it.each([
    { kind: "console" }, { id: "unattributed" }, { first_event_at: last, last_event_at: first },
    { event_count: 3 }, { event_count: 1.5 }, { event_count: Number.MAX_SAFE_INTEGER + 1 },
    { confidence_counts: { exact: 1, strong: 0, probable: 1, unattributed: 0 } },
    { principal_id: "unknown" }, { events: [] }, { state: "active" }, { projected_at: "yesterday" },
  ])("rejects summary drift %j", (override) => {
    expect(() => decodeRuntimeSession({ ...summary, ...override })).toThrow("schema mismatch");
  });
  it.each([
    { confidence: "exact", session_id: null }, { confidence: "strong", agent_id: null },
    { confidence: "probable" }, { confidence: "unattributed" }, { confidence: "certain" },
    { source: "fixture" }, { class: "credential" }, { class: "network", action: "exec" },
    { session_id: "unattributed" }, { evidence_id: "" }, { provider_secret: "not-allowed" },
  ])("rejects event attribution or schema drift %j", (override) => {
    expect(() => decodeRuntimeSessionEventPage(page([{ ...event, ...override }]))).toThrow("schema mismatch");
  });
  it("rejects reordered, duplicate, mixed-session and invalid cursor pages", () => {
    const later = { ...event, id: agent, at: last };
    expect(decodeRuntimeSessionEventPage(page([event, later])).items).toHaveLength(2);
    for (const items of [[later, event], [event, event], [event, { ...later, session_id: agent }]]) {
      expect(() => decodeRuntimeSessionEventPage(page(items))).toThrow("schema mismatch");
    }
    expect(() => decodeRuntimeSessionPage({ items: [], page_info: { next_cursor: null, has_more: true } })).toThrow("schema mismatch");
    expect(() => decodeRuntimeSessionPage(page([summary, summary]))).toThrow("schema mismatch");
  });
  it("preserves sub-millisecond canonical ordering and rejects normalized invalid dates", () => {
    const earlier = { ...event, id: agent, at: "2026-09-09T10:00:00.000001Z" };
    const later = { ...event, at: "2026-09-09T10:00:00.000002Z" };
    expect(decodeRuntimeSessionEventPage(page([earlier, later])).items).toHaveLength(2);
    expect(() => decodeRuntimeSessionEventPage(page([later, earlier]))).toThrow("schema mismatch");
    expect(() => decodeRuntimeSessionEventPage(page([{ ...event, at: "2026-02-30T10:00:00Z" }]))).toThrow("schema mismatch");
  });
});
