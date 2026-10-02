import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";
import { decodeSecurityAgentActivityRuns, decodeSecurityAgentActivityTargets, listSecurityAgentActivityRuns, listSecurityAgentRunActivity } from "./security-agent-activity";

const id = "pid_78000005-0000-4000-8000-000000000005";
const other = "pid_78000009-0000-4000-8000-000000000009";
const scope = { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" };
const run = { id, agent_id: other, state: "queued", evidence_ids: [other], definition_version: 1, version: 1 };
const target = { kind: "finding", id };

describe("typed Security Agent activity pages", () => {
  it("retains partial coverage and exact typed records", () => {
    expect(decodeSecurityAgentActivityTargets({ items: [target], coverage: "partial" }, "finding", 10)).toEqual({ items: [target], coverage: "partial" });
    expect(decodeSecurityAgentActivityRuns({ items: [run], coverage: "complete" }, "finding", 10).items).toEqual([run]);
  });
  it.each([
    { items: null, coverage: "complete" }, { items: [], coverage: "unknown" }, { items: [], coverage: "complete", next_cursor: null },
    { items: [target, target], coverage: "complete" }, { items: [{ ...target, id: other }, target], coverage: "complete" },
    { items: [{ ...target, kind: "session" }], coverage: "complete" }, { items: [{ ...target, secret: "private" }], coverage: "complete" },
    { items: [], coverage: "complete", next_cursor: "abc" }, { items: [target], coverage: "complete", secret: "private" },
  ])("rejects invalid forward page %#", (value) => { expect(() => decodeSecurityAgentActivityTargets(value, "finding", 10)).toThrow(); });
  it("rejects duplicate runs and unsupported audit coverage", () => {
    expect(() => decodeSecurityAgentActivityRuns({ items: [run, run], coverage: "complete" }, "finding", 10)).toThrow();
    expect(() => decodeSecurityAgentActivityRuns({ items: [], coverage: "partial" }, "audit", 10)).toThrow();
    expect(() => decodeSecurityAgentActivityTargets({ items: [], coverage: "partial" }, "audit", 10)).toThrow();
    expect(() => decodeSecurityAgentActivityRuns({ items: [run, { ...run, id: other }], coverage: "complete" }, "audit", 10)).toThrow();
    expect(() => decodeSecurityAgentActivityRuns({ items: [run], coverage: "complete", next_cursor: "abc" }, "audit", 1)).toThrow();
    expect(() => decodeSecurityAgentActivityRuns({ items: [run, { ...run, id: other }], coverage: "complete" }, "finding", 1)).toThrow();
    expect(() => decodeSecurityAgentActivityTargets({ items: [target, { ...target, id: other }], coverage: "complete" }, "finding", 1)).toThrow();
  });
  it("preserves bounded opaque cursors", () => {
    expect(decodeSecurityAgentActivityTargets({ items: [target], coverage: "complete", next_cursor: "abc" }, "finding", 1).next_cursor).toBe("abc");
    expect(() => decodeSecurityAgentActivityRuns({ items: [run], coverage: "complete", next_cursor: "x".repeat(2049) }, "finding", 1)).toThrow();
  });
  it.each(["forward", "reverse"])("calls the real %s API with pinned scope and cancellation", async (direction) => {
    const controller = new AbortController();
    const fetcher = vi.fn(async (request: Request) => { expect(request.method).toBe("GET"); return new Response(JSON.stringify({ items: direction === "forward" ? [target] : [run], coverage: "partial" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); });
    const client = createAPIClient({ fetch: fetcher, getExpectedScope: () => "different/scope/value" });
    const read = direction === "forward" ? listSecurityAgentRunActivity : listSecurityAgentActivityRuns;
    const page = await read(client, id, "finding", scope, { limit: 10, cursor: "abc", signal: controller.signal });
    expect(page.coverage).toBe("partial");
    const request = fetcher.mock.calls[0]?.[0] as Request | undefined;
    expect(new URL(request!.url).pathname).toBe(direction === "forward" ? `/api/v1/security-agent-runs/${id}/activity/finding` : `/api/v1/security-agent-activity/finding/${id}/runs`);
    expect(new URL(request!.url).searchParams.get("limit")).toBe("10");
    expect(new URL(request!.url).searchParams.get("cursor")).toBe("abc");
    expect(request?.headers.get("X-Zasp-Expected-Scope")).toBe(Object.values(scope).join("/"));
    expect(request?.credentials).toBe("same-origin");
    controller.abort(); expect(request?.signal.aborted).toBe(true);
  });
  it("rejects invalid requests before transport and cacheable responses", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: [], coverage: "complete" }), { headers: { "Content-Type": "application/json" } }));
    const client = createAPIClient({ fetch: fetcher });
    await expect(listSecurityAgentRunActivity(client, `${id}\n`, "finding", scope)).rejects.toMatchObject({ kind: "invalid_configuration" });
    expect(fetcher).not.toHaveBeenCalled();
    await expect(listSecurityAgentActivityRuns(client, id, "finding", scope)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it.each(["finding", "attack_path", "session", "audit"] as const)("reads %s records in both directions", async (kind) => {
    const forward = createAPIClient({ fetch: async () => new Response(JSON.stringify({ items: [{ kind, id }], coverage: "complete" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    const reverse = createAPIClient({ fetch: async () => new Response(JSON.stringify({ items: [run], coverage: "complete" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    expect((await listSecurityAgentRunActivity(forward, other, kind, scope)).items).toEqual([{ kind, id }]);
    expect((await listSecurityAgentActivityRuns(reverse, other, kind, scope)).items).toEqual([run]);
  });
  it.each(["forward", "reverse"])("rejects repeated %s cursor and invalid limit without transport", async (direction) => {
    const read = direction === "forward" ? listSecurityAgentRunActivity : listSecurityAgentActivityRuns;
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: direction === "forward" ? [target] : [run], coverage: "complete", next_cursor: "abc" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }));
    const client = createAPIClient({ fetch: fetcher });
    for (const limit of [0, 101, 1.5, null, "10"] as unknown as number[]) {
      await expect(read(client, id, "finding", scope, { limit })).rejects.toMatchObject({ kind: "invalid_configuration" });
    }
    expect(fetcher).not.toHaveBeenCalled();
    await expect(read(client, id, "finding", scope, { limit: 1, cursor: "abc" })).rejects.toMatchObject({ kind: "invalid_response" });
  });
});
