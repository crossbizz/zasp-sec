import { APITransportError, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeComplianceDownloadGrant } from "../../../apps/web/api/compliance-decoders";
import { decodeSecurityAgentExportStatus } from "../../../apps/web/api/security-agent-export-decoders";
import type { ComplianceDownloadFormat, SecurityAgentExportStatus } from "../../../apps/web/api/generated";

export function createSecurityAgentExportAPI(client: APIClient, expectedScope?: string, boundaryCurrent: () => boolean = () => true) {
  const headers = expectedScope ? { "X-Zasp-Expected-Scope": expectedScope } : undefined;
  return {
    async status(run: string, step: string, signal: AbortSignal, isCurrent: () => boolean): Promise<SecurityAgentExportStatus> {
      signal.throwIfAborted();
      if (!isCurrent() || !boundaryCurrent()) throw new APITransportError("invalid_response", "Export session or scope changed");
      const status = requireAPIData(await client.GET("/api/v1/security-agent-runs/{id}/steps/{stepId}/export", { signal, headers, params: { path: { id: run, stepId: step } } }), decodeSecurityAgentExportStatus);
      signal.throwIfAborted();
      if (!isCurrent() || !boundaryCurrent()) throw new APITransportError("invalid_response", "Export session or scope changed");
      return status;
    },
    async download(run: string, step: string, format: ComplianceDownloadFormat, signal: AbortSignal, isCurrent: () => boolean): Promise<Blob> {
      const current = () => {
        signal.throwIfAborted();
        if (!isCurrent() || !boundaryCurrent()) throw new APITransportError("invalid_response", "Export session or scope changed");
      };
      current();
      const path = { id: run, stepId: step };
      const grant = requireAPIData(await client.POST("/api/v1/security-agent-runs/{id}/steps/{stepId}/export/download-grants", { signal, headers, params: { path, header: { "X-CSRF-Token": "" } }, body: { format } }), decodeComplianceDownloadGrant);
      current();
      if (grant.format !== format || Date.parse(grant.expires_at) <= Date.now()) throw new APITransportError("invalid_response", "Download authorization expired");
      const result = await client.POST("/api/v1/security-agent-runs/{id}/steps/{stepId}/export/download", { signal, headers, params: { path, header: { "X-CSRF-Token": "" } }, body: { format, token: grant.token }, parseAs: "blob" });
      const blob = requireAPIData<Blob>(result);
      current();
      if (!blob || typeof blob.arrayBuffer !== "function" || !Number.isSafeInteger(blob.size) || blob.size < 1 || blob.size > 4 * 1024 * 1024) throw new APITransportError("invalid_response", "Download unavailable");
      return blob;
    },
  };
}
