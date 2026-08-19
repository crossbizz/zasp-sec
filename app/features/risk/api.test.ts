import { describe, expect, it, vi } from "vitest";

import { createAPIClient, APITransportError } from "../../../apps/web/api/client";
import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import { createWorkflowReceiptReconciler } from "../workflows/api";
import { createProductionRiskAPI } from "./api";

const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const finding = { id: "pid_20000001-0000-4000-8000-000000000001", source: "posture", title: "Public tool access", severity: "high", status: "open", evidence_ids: ["pid_20000002-0000-4000-8000-000000000002"], risk_factors: [], version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" } as const;

const response = (body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json", ...headers } });

describe("production risk API", () => {
  it("uses exact generated requests, expected scope, stable pagination, and strict response decoding", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ getExpectedScope: () => scope, fetch: async (request) => {
      requests.push(request);
      const cursor = new URL(request.url).searchParams.get("cursor");
      return response({ items: cursor ? [] : [finding], page_info: cursor ? { next_cursor: null, has_more: false } : { next_cursor: "YQ", has_more: true } });
    } });
    const api = createProductionRiskAPI(client, "browser");
    expect(await api.listFindings()).toEqual([finding]);
    expect(requests).toHaveLength(2);
    expect(new URL(requests[0]!.url).searchParams.get("limit")).toBe("100");
    expect(new URL(requests[1]!.url).searchParams.get("cursor")).toBe("YQ");
    expect(requests[0]!.headers.get("X-Zasp-Expected-Scope")).toBe(scope);
  });

  it("requires exact ETag, audit, and browser receipt headers while retaining the caller key", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf", fetch: async (request) => {
      requests.push(request);
      return response({ ...finding, status: "under_review", version: 2 }, { ETag: '"2"', "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" });
    } });
    const result = await createProductionRiskAPI(client, "browser").updateFinding(finding.id, "under_review", '"1"', { idempotencyKey: "idem-risk-update-0001" });
    expect(result.value.status).toBe("under_review");
    expect(result.version).toBe('"2"');
    expect(result.receiptID).toMatch(/^pid_/);
    expect(requests[0]!.headers.get("Idempotency-Key")).toBe("idem-risk-update-0001");
    expect(requests[0]!.headers.get("If-Match")).toBe('"1"');
  });

  it("requires PAT mutations to return zero browser receipt", async () => {
    const client = createAPIClient({ getExpectedScope: () => scope, fetch: async () => response({ ...finding, status: "accepted", acceptance_reason: "Approved", version: 2 }, { ETag: '"2"', "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" }) });
    await expect(createProductionRiskAPI(client, "pat").acceptFindingRisk(finding.id, "Approved", '"1"', { idempotencyKey: "idem-risk-accept-0001" })).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it("rejects malformed success and repeated cursors and preserves caller abort", async () => {
    const malformed = createProductionRiskAPI(createAPIClient({ getExpectedScope: () => scope, fetch: async () => response({ items: [{ ...finding, extra: true }], page_info: { next_cursor: null, has_more: false } }) }), "browser");
    await expect(malformed.listFindings()).rejects.toBeInstanceOf(APITransportError);

    const repeated = createProductionRiskAPI(createAPIClient({ getExpectedScope: () => scope, fetch: async () => response({ items: [], page_info: { next_cursor: "YQ", has_more: true } }) }), "browser");
    await expect(repeated.listFindings()).rejects.toThrow("repeated cursor");

    const controller = new AbortController();
    const fetch = vi.fn((request: Request) => new Promise<Response>((_resolve, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true })));
    const pending = createProductionRiskAPI(createAPIClient({ getExpectedScope: () => scope, fetch }), "browser").listAttackPaths(controller.signal);
    controller.abort(new DOMException("obsolete", "AbortError"));
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });

  it("authoritatively refetches an exact-scope finding receipt and rejects version drift", async () => {
    const requests: Request[] = [];
    const versions = ['"2"', '"3"'];
    const client = createAPIClient({ fetch: async (request) => {
      requests.push(request);
      return response({ ...finding, status: "under_review", version: 2 }, { ETag: versions.shift()! });
    } });
    const receipt = {
      id: "pid_30000001-0000-4000-8000-000000000001", operation: "updateFinding",
      idempotency_key: "idem-risk-recovery-0001", intent: { resource_id: finding.id, expected_version: 1, body: { status: "under_review" } },
      result: { ...finding, status: "under_review", version: 2 }, resource_kind: "finding", resource_id: finding.id, resource_version: 2,
      audit_id: "pid_30000002-0000-4000-8000-000000000002", correlation_id: "pid_30000003-0000-4000-8000-000000000003",
      created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-26T00:00:00Z",
    } as WorkflowMutationReceipt;
    const reconcile = createWorkflowReceiptReconciler(client, scope);
    await reconcile(receipt, new AbortController().signal);
    expect(requests[0]!.method).toBe("GET");
    expect(requests[0]!.headers.get("X-Zasp-Expected-Scope")).toBe(scope);
    await expect(reconcile(receipt, new AbortController().signal)).rejects.toThrow("version does not match");
  });
});
