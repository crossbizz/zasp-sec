export type AuditExportIdentity = Readonly<{ principalID: string; organizationID: string; workspaceID: string; environmentID: string }>;
export type AuditExportResume = AuditExportIdentity & Readonly<{ key: string; exportID?: string }>;
const identityFields = ["principalID", "organizationID", "workspaceID", "environmentID"] as const;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const productID = (v: string) => v.startsWith("pid_") && uuid.test(v.slice(4));
const path = "/administration/audit-log";

function auditExportLink(record: AuditExportResume) {
  const requestID = record.key.slice("audit_export_".length);
  if (!record.key.startsWith("audit_export_") || !uuid.test(requestID) || !identityFields.every(k => productID(record[k])) || (record.exportID !== undefined && !productID(record.exportID))) throw Error("Invalid audit export reference");
  const query = new URLSearchParams({ export_request: requestID, principal_id: record.principalID, organization_id: record.organizationID, workspace_id: record.workspaceID, environment_id: record.environmentID });
  if (record.exportID) query.set("export_id", record.exportID);
  return `${path}?${query}`;
}

export function parseAuditExportLink(location: string, identity: AuditExportIdentity | null) {
  if (!location.startsWith(`${path}?export_request=`)) return { state: "none" as const };
  const query = new URLSearchParams(location.slice(location.indexOf("?") + 1));
  const record: AuditExportResume = {
    principalID: query.get("principal_id") ?? "", organizationID: query.get("organization_id") ?? "",
    workspaceID: query.get("workspace_id") ?? "", environmentID: query.get("environment_id") ?? "",
    key: `audit_export_${query.get("export_request") ?? ""}`, ...(query.has("export_id") ? { exportID: query.get("export_id")! } : {}),
  };
  try { if (auditExportLink(record) !== location) return { state: "invalid" as const }; } catch { return { state: "invalid" as const }; }
  if (!identity || !identityFields.every(k => record[k] === identity[k])) return { state: "scope_mismatch" as const };
  return { state: "selected" as const, record };
}
export function loadAuditExportResume(identity: AuditExportIdentity): AuditExportResume | null {
  if (typeof window === "undefined") return null;
  const link = parseAuditExportLink(window.location.pathname + window.location.search + window.location.hash, identity);
  return link.state === "selected" ? link.record : null;
}
export function storeAuditExportResume(record: AuditExportResume): void {
  // Reserve the public request ID before POST, so an interrupted response can be
  // reconciled using the same server-side idempotency identity after reload.
  window.history.replaceState(window.history.state, "", auditExportLink(record));
}
export function exportIdentityKey(identity: AuditExportIdentity): string {
  return identityFields.map(key => identity[key]).join("/");
}
