import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { createComplianceAPI } from "./compliance-api";
const id = "pid_10000004-0000-4000-8000-000000000004";
const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
describe("compliance action authority", () => {
  it("downloads exact bounded bytes with the one-time grant only in its POST body", async () => {
    const seen: Request[] = [];
    const api = createComplianceAPI(createAPIClient({ getCSRFToken: () => "c".repeat(32), fetch: async request => {
      seen.push(request.clone() as Request);
      if (request.url.endsWith("download-grants")) return new Response(JSON.stringify({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } });
      return new Response('[{"source_id":"policy-production","source_version":2}]', { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Disposition": `attachment; filename="compliance-${id}.json"`, "X-Content-Type-Options": "nosniff" } });
    } }), scope);
    const blob = await api.download(id, "json", new AbortController().signal, () => true);
    expect(await blob.text()).toBe('[{"source_id":"policy-production","source_version":2}]');
    expect(seen.map(r => r.url).join(" ")).not.toContain("a".repeat(64));
    expect(await seen[1].json()).toEqual({ token: "a".repeat(64), format: "json" });
  });
  it("does not redeem a late grant after session authority changes", async () => {
    let current = true, calls = 0;
    const api = createComplianceAPI(createAPIClient({ fetch: async () => {
      calls++; current = false;
      return new Response(JSON.stringify({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } });
    } }), scope);
    await expect(api.download(id, "json", new AbortController().signal, () => current)).rejects.toThrow();
    expect(calls).toBe(1);
  });
});
