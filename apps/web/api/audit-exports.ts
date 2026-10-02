import { APITransportError, requireAPIData, type APIClient } from "./client";
import type { AuditExport, AuditExportRead } from "./generated";
import { decodeAuditExport } from "./audit-export-decoders";
import { verifyAuditExportRead } from "./audit-export-codec";
export interface AuditExportsAPI {
  create(key: string, signal: AbortSignal): Promise<AuditExport>;
  read(id: string, cursor: string | undefined, signal: AbortSignal): Promise<AuditExportRead>;
}
export type AuditExportRequestBoundary = Readonly<{ generation: number; scope: string | null; csrf: string | null; signal: AbortSignal }>;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
function invalid(): never { throw new APITransportError("invalid_response", "Audit export response did not match its request"); }
export function createAuditExportsAPI(client: APIClient, boundary: () => AuditExportRequestBoundary): AuditExportsAPI {
  let active = false;
  async function run<T>(caller: AbortSignal, operation: (scope: string, csrf: string | null, signal: AbortSignal, check: () => void) => Promise<T>): Promise<T> {
    caller.throwIfAborted();
    const captured = boundary();
    if (!captured.scope || captured.scope.split("/").length !== 3 || !captured.scope.split("/").every(part => productID.test(part))) throw new APITransportError("invalid_configuration", "Audit export needs a current session scope");
    if (active) throw new APITransportError("invalid_configuration", "An audit export request is already in progress");
    const signal = AbortSignal.any([caller, captured.signal]);
    const check = () => {
      signal.throwIfAborted();
      const current = boundary();
      if (current.generation !== captured.generation || current.scope !== captured.scope) throw new DOMException("Audit export session or scope changed", "AbortError");
    };
    check(); active = true;
    try { const result = await operation(captured.scope, captured.csrf, signal, check); check(); return result; }
    finally { active = false; }
  }
  return Object.freeze({
    async create(key: string, signal: AbortSignal) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$(?![\s\S])/.test(key)) throw new APITransportError("invalid_configuration", "Invalid retained audit export key");
      return run(signal, async (scope, csrf, requestSignal, check) => {
        const result = await client.POST("/api/v1/audit-exports", { params: { header: { "Idempotency-Key": key, "X-CSRF-Token": csrf ?? "" } }, headers: { "X-Zasp-Expected-Scope": scope }, body: {}, signal: requestSignal });
        check();
        const descriptor = requireAPIData(result, decodeAuditExport);
        if ([descriptor.organization_id, descriptor.workspace_id, descriptor.environment_id].join("/") !== scope) invalid();
        return descriptor;
      });
    },
    async read(id: string, cursor: string | undefined, signal: AbortSignal) {
      if (!productID.test(id) || cursor !== undefined && (cursor.length > 1024 || !/^[A-Za-z0-9_-]+$(?![\s\S])/.test(cursor))) throw new APITransportError("invalid_configuration", "Invalid audit export read input");
      return run(signal, async (scope, _csrf, requestSignal, check) => {
        const result = await client.GET("/api/v1/audit-exports/{id}", { params: { path: { id }, query: cursor === undefined ? {} : { cursor } }, headers: { "X-Zasp-Expected-Scope": scope }, signal: requestSignal });
        check();
        const data = requireAPIData<unknown>(result);
        let read: AuditExportRead;
        try { read = (await verifyAuditExportRead(data)).read; } catch { check(); invalid(); }
        check();
        if (read.export.id !== id || read.export.organization_id !== scope.split("/")[0] || cursor !== undefined && read.contents?.page_info.next_cursor === cursor) invalid();
        return read;
      });
    },
  });
}
