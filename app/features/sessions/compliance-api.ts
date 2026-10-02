import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeComplianceDownloadGrant, decodeComplianceEvidenceDetail, decodeComplianceExport } from "../../../apps/web/api/compliance-decoders";
import type { ComplianceControl, ComplianceDownloadFormat, ComplianceEvidenceTarget, ComplianceExportInput } from "../../../apps/web/api/generated";
import type { ActivityScope } from "../../domain/activity-links";

export type ComplianceReadMode = "current" | "legacy";
// Strictly decoded live controls carry authoritative freshness; retained seed
// controls omit it. Empty data cannot assert current-service support. Do not
// turn mixed responses or authorization/read errors into a compatibility retry.
export function complianceReadMode(controls: readonly ComplianceControl[]): ComplianceReadMode {
  const current = controls.filter(control => control.freshness !== undefined).length;
  if (current !== 0 && current !== controls.length) throw new APITransportError("invalid_response", "Mixed compliance control authority");
  return current > 0 ? "current" : "legacy";
}

export function createComplianceAPI(client: APIClient, scope: ActivityScope) {
  return {
    async detail(target: ComplianceEvidenceTarget, signal: AbortSignal) {
      const detail = requireAPIData(await client.GET("/api/v1/compliance/evidence/{sourceKind}/{id}", { signal, params: { path: { sourceKind: target.source_kind, id: target.source_id }, query: { source_version: target.source_version } } }), value => decodeComplianceEvidenceDetail(value, { organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID }));
      const actual = detail.record.target;
      if (!actual || actual.source_kind !== target.source_kind || actual.source_id !== target.source_id || actual.source_version !== target.source_version) throw new APITransportError("invalid_response", "Evidence identity mismatch");
      return detail;
    },
    async create(input: ComplianceExportInput, key: string, signal: AbortSignal) {
      return requireAPIData(await client.POST("/api/v1/compliance/exports", { signal, params: { header: { "X-CSRF-Token": "", "Idempotency-Key": key } }, body: input }), decodeComplianceExport);
    },
    async status(id: string, signal: AbortSignal) {
      const job = requireAPIData(await client.GET("/api/v1/compliance/exports/{id}", { signal, params: { path: { id } } }), decodeComplianceExport);
      if (job.id !== id) throw new APITransportError("invalid_response", "Export identity mismatch");
      return job;
    },
    async download(id: string, format: ComplianceDownloadFormat, signal: AbortSignal, isCurrent: () => boolean) {
      const grant = requireAPIData(await client.POST("/api/v1/compliance/exports/{id}/download-grants", { signal, params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: { format } }), decodeComplianceDownloadGrant);
      signal.throwIfAborted();
      if (!isCurrent() || grant.format !== format || Date.parse(grant.expires_at) <= Date.now()) throw new APITransportError("invalid_response", "Download authorization expired");
      const result = await client.POST("/api/v1/compliance/exports/{id}/download", { signal, params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: { token: grant.token, format }, parseAs: "blob" });
      const blob = requireAPIData<Blob>(result);
      signal.throwIfAborted();
      if (!isCurrent() || !blob || typeof blob.arrayBuffer !== "function" || !Number.isSafeInteger(blob.size) || blob.size < 1 || blob.size > 4 * 1024 * 1024) throw new APITransportError("invalid_response", "Download unavailable");
      return blob;
    },
  };
}
