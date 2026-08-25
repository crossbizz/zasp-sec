import { describe, expect, it, vi } from "vitest";

import { createAPIClient, APITransportError } from "../../../apps/web/api/client";
import type { RecoveryBackup, RecoveryManifestLocator, RecoveryRestore } from "../../../apps/web/api/generated";
import { createRecoveryAPI } from "./api";

const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const backupID = "pid_71000001-0000-4000-8000-000000000001";
const restoreID = "pid_71000002-0000-4000-8000-000000000002";
const auditID = "pid_71000005-0000-4000-8000-000000000005";
const receiptID = "pid_71000006-0000-4000-8000-000000000006";
const manifest: RecoveryManifestLocator = {
  reference: `s3://zasp-recovery/organizations/${scope.split("/")[0]}/workspaces/${scope.split("/")[1]}/environments/${scope.split("/")[2]}/artifacts/pid_71000003-0000-4000-8000-000000000003`,
  version_id: "version-recovery-0001", sha256: "a".repeat(64), size_bytes: 512,
  media_type: "application/vnd.zasp.recovery-manifest+json", schema: "recovery_signed_manifest_v1",
  signing_key_id: "11111111-1111-4111-8111-111111111111", signature: "A".repeat(43),
};
const backup: RecoveryBackup = { id: backupID, version: 1, state: "queued", retention_days: 30, attempt: 0, created_at: "2026-08-25T12:00:00Z" };
const restore: RecoveryRestore = { id: restoreID, version: 1, state: "queued", target_environment: "recovery-e2e-01", attempt: 0, manifest, created_at: "2026-08-25T12:00:00Z" };

describe("production recovery API", () => {
  it("starts a browser backup with exact fresh-auth, idempotency, version, and durable evidence authority", async () => {
    let request: Request | undefined;
    const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (value) => {
      request = value;
      return jsonResponse(backup, 202, { ETag: '"1"', "X-Audit-ID": auditID, "X-Mutation-Receipt-ID": receiptID });
    } });
    const input = { backupID, retentionDays: 30, idempotencyKey: "recovery_backup_00000001" } as const;
    expect(await createRecoveryAPI(client, scope).startBackup(input)).toEqual(backup);
    expect(new URL(request!.url).pathname).toBe("/api/v1/recovery/backups");
    expect(request!.method).toBe("POST");
    expect(request!.headers.get("Idempotency-Key")).toBe(input.idempotencyKey);
    expect(request!.headers.get("If-Match")).toBe('"0"');
    expect(request!.headers.get("X-Zasp-Fresh-Auth")).toBe("confirmed");
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-value");
    expect(await request!.json()).toEqual({ backup_id: backupID, retention_days: 30 });
  });

  it("reuses the exact restore identity, manifest, and idempotency key after a lost response", async () => {
    const requests: Request[] = [];
    let call = 0;
    const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (request) => {
      requests.push(request.clone() as Request); call += 1;
      if (call === 1) return jsonResponse({ code: "temporarily_unavailable", message: "Response unavailable", correlation_id: auditID, retryable: true }, 503);
      return jsonResponse(restore, 202, { ETag: '"1"', "X-Audit-ID": auditID, "X-Mutation-Receipt-ID": receiptID });
    } });
    const api = createRecoveryAPI(client, scope);
    const input = { restoreID, targetEnvironment: "recovery-e2e-01", manifest, idempotencyKey: "recovery_restore_0000001" } as const;
    await expect(api.startRestore(input)).rejects.toMatchObject({ status: 503 });
    await expect(api.startRestore(input)).resolves.toEqual(restore);
    expect(requests).toHaveLength(2);
    expect(await requests[0]!.text()).toBe(await requests[1]!.text());
    expect(requests.map((request) => request.headers.get("Idempotency-Key"))).toEqual([input.idempotencyKey, input.idempotencyKey]);
  });

  it("binds detail identity and cancellation while rejecting cacheable or contradictory responses", async () => {
    const controller = new AbortController();
    const pendingFetch = vi.fn((request: Request) => new Promise<Response>((_resolve, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true })));
    const pending = createRecoveryAPI(createAPIClient({ getExpectedScope: () => scope, fetch: pendingFetch }), scope).getRestore(restoreID, controller.signal);
    controller.abort(new DOMException("route changed", "AbortError"));
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });

    const cacheable = createRecoveryAPI(createAPIClient({ getExpectedScope: () => scope, fetch: async () => new Response(JSON.stringify(backup), { status: 200, headers: { "Content-Type": "application/json", ETag: '"1"' } }) }), scope);
    await expect(cacheable.getBackup(backupID)).rejects.toBeInstanceOf(APITransportError);

    const foreign = createRecoveryAPI(createAPIClient({ getExpectedScope: () => scope, fetch: async () => jsonResponse({ ...backup, id: restoreID }, 200, { ETag: '"1"' }) }), scope);
    await expect(foreign.getBackup(backupID)).rejects.toBeInstanceOf(APITransportError);
  });
});

function jsonResponse(body: unknown, status: number, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
}
