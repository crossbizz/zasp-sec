import { describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { decodeIntegrationWebhookTestStatus } from "../../../apps/web/api/decoders";
import { createIntegrationsAPI, createRetainedWorkflowMutationController } from "./api";

const id = "pid_42000001-0000-4000-8000-000000000001";
const status = { integration_id: id, delivery_id: "pid_41000001-0000-4000-8000-000000000001", audit_id: "pid_42000002-0000-4000-8000-000000000002", delivery_status: "succeeded", signature_status: "signed", attempted_at: "2026-09-08T00:00:00Z", completed_at: "2026-09-08T00:00:01Z", error_code: "" };
const response = (data: unknown = status, headers: Record<string,string> = { "Cache-Control":"no-store", "X-Audit-ID":status.audit_id }) => ({ data, response:new Response(JSON.stringify(data),{status:200,headers}) });

describe("production webhook delivery API", () => {
  it("retains the exact integration, version, empty body, and key after lost responses", async () => {
    const POST = vi.fn().mockRejectedValueOnce(new TypeError("lost")).mockRejectedValueOnce(new TypeError("lost")).mockResolvedValue(response());
    const api = createIntegrationsAPI({ POST } as unknown as APIClient);
    const retained = createRetainedWorkflowMutationController<{id:string; version:string}>();
    await expect(retained.execute({id,version:'"3"'},(intent,attempt) => api.testIntegrationWebhook(intent.id,intent.version,attempt))).rejects.toThrow("lost");
    expect(retained.canRetry()).toBe(true);
    await expect(retained.retry()).resolves.toEqual(status);
    expect(POST).toHaveBeenCalledTimes(3);
    const first = POST.mock.calls[0];
    expect(first[0]).toBe("/api/v1/integrations/{id}/test-delivery");
    expect(first[1]).toEqual({params:{path:{id},header:{"Idempotency-Key":expect.any(String),"If-Match":'"3"'}},body:{}});
    expect(POST.mock.calls[1]).toEqual(first); expect(POST.mock.calls[2]).toEqual(first);
    expect(retained.isUnresolved()).toBe(false);
  });

  it("rejects cached, cross-resource, pending mutation, and audit-mismatched responses", async () => {
    for (const result of [response(status,{}),response({...status,integration_id:status.delivery_id}),response({...status,delivery_status:"pending",signature_status:"unconfirmed",completed_at:null}),response(status,{"Cache-Control":"no-store","X-Audit-ID":status.delivery_id})]) {
      const POST = vi.fn(async () => result);
      await expect(createIntegrationsAPI({POST} as unknown as APIClient).testIntegrationWebhook(id,'"3"')).rejects.toMatchObject({kind:"invalid_response"});
    }
  });

  it("accepts pending reads without claiming a signed delivery and rejects secret leakage", async () => {
    const pending = {...status,delivery_status:"pending",signature_status:"unconfirmed",completed_at:null};
    const GET = vi.fn(async () => response(pending));
    await expect(createIntegrationsAPI({GET} as unknown as APIClient).getIntegrationWebhookStatus(id)).resolves.toEqual(pending);
    expect(GET.mock.calls).toHaveLength(1);
    for (const invalid of [{...pending,signature_status:"signed"},{...pending,completed_at:status.completed_at},{...status,secret_reference:"secret_ref_prod"},{...status,completed_at:"2026-09-07T00:00:00Z"},{...status,delivery_status:"failed"}]) expect(() => decodeIntegrationWebhookTestStatus(invalid,id)).toThrow();
  });
});
