import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";
import { decodeSecurityAgentAuditEvent, getSecurityAgentAuditEvent } from "./security-agent-audit";

const id = "pid_7b000003-0000-4000-8000-000000000003";
const scope = { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" };
const record = { ...scope, id, run_id: "pid_7b000002-0000-4000-8000-000000000002", actor_reference: "worker-activity-audit", event_kind: "run_queued", correlation_id: "pid_7b000004-0000-4000-8000-000000000004", occurred_at: "2026-09-16T12:00:00.123456Z" };

describe("Security Agent audit contract", () => {
  it("preserves the distinct worker reference and exact fields", () => { expect(decodeSecurityAgentAuditEvent(record)).toEqual(record); });
  it.each([
    ["run_id", "bad"], ["actor_reference", ""], ["actor_reference", "x".repeat(129)], ["actor_reference", "\ud800"], ["event_kind", "line\nbreak"],
    ["occurred_at", "2026-09-16T12:00:00.1234567Z"], ["occurred_at", "2026-09-16T12:00:00+01:00"], ["occurred_at", "2026-02-30T12:00:00Z"], ["occurred_at", "0000-01-01T00:00:00Z"], ["body", "private"], ["id", `${id}\n`], ["run_id", `${record.run_id}\n`], ["occurred_at", `${record.occurred_at}\n`],
  ])("rejects invalid %s", (key, value) => { expect(() => decodeSecurityAgentAuditEvent({ ...record, [key]: value })).toThrow(); });
  it("rejects missing or null values", () => { for (const key of Object.keys(record)) { const value: Record<string, unknown> = { ...record }; delete value[key]; expect(() => decodeSecurityAgentAuditEvent(value)).toThrow(); expect(() => decodeSecurityAgentAuditEvent({ ...record, [key]: null })).toThrow(); } });
  it("loads the exact scoped record through the real client", async () => {
    const fetcher = vi.fn(async (request: Request) => { expect(request.method).toBe("GET"); return new Response(JSON.stringify(record), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }); });
    const client = createAPIClient({ fetch: fetcher, getExpectedScope: () => [scope.organization_id, scope.workspace_id, "pid_7b000099-0000-4000-8000-000000000099"].join("/"), generateCorrelationID: () => record.correlation_id });
    expect(await getSecurityAgentAuditEvent(client, id, scope)).toEqual(record);
    const request = fetcher.mock.calls[0]?.[0] as Request | undefined;
    expect(new URL(request!.url).pathname).toBe(`/api/v1/security-agent-audit-events/${id}`);
    expect(request?.credentials).toBe("same-origin");
    expect(request?.headers.get("X-Zasp-Expected-Scope")).toBe([scope.organization_id, scope.workspace_id, scope.environment_id].join("/"));
  });
  it.each(["id", "organization_id", "workspace_id", "environment_id"])("refuses response with another %s", async (key) => {
    const client = createAPIClient({ fetch: async () => new Response(JSON.stringify({ ...record, [key]: "pid_7b000099-0000-4000-8000-000000000099" }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } }) });
    await expect(getSecurityAgentAuditEvent(client, id, scope)).rejects.toThrow();
  });
  it("refuses cacheable responses", async () => {
    const client = createAPIClient({ fetch: async () => new Response(JSON.stringify(record), { headers: { "Content-Type": "application/json" } }) });
    await expect(getSecurityAgentAuditEvent(client, id, scope)).rejects.toThrow();
  });
  it("rejects a newline-suffixed request ID before transport", async () => {
    const fetcher = vi.fn(async () => new Response("{}"));
    await expect(getSecurityAgentAuditEvent(createAPIClient({ fetch: fetcher }), `${id}\n`, scope)).rejects.toMatchObject({ kind: "invalid_configuration" });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
