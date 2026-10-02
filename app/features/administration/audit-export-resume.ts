export type AuditExportIdentity = Readonly<{ principalID: string; organizationID: string; workspaceID: string; environmentID: string }>;
export type AuditExportResume = AuditExportIdentity & Readonly<{ key: string; exportID?: string }>;
type ResumeStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;
const storageKey = "zasp.audit-export.resume.v1";
const identityFields = ["principalID", "organizationID", "workspaceID", "environmentID"] as const;
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
function valid(value: unknown): value is AuditExportResume {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).every(key => [...identityFields, "key", "exportID"].includes(key)) &&
    identityFields.every(key => typeof v[key] === "string" && productID.test(v[key])) &&
    typeof v.key === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$(?![\s\S])/.test(v.key) &&
    (v.exportID === undefined || typeof v.exportID === "string" && productID.test(v.exportID));
}
export function loadAuditExportResume(storage: ResumeStorage, identity: AuditExportIdentity): AuditExportResume | null {
  try {
    const raw = storage.getItem(storageKey);
    if (!raw || raw.length > 1024) return null;
    const record: unknown = JSON.parse(raw);
    return valid(record) && identityFields.every(key => record[key] === identity[key]) ? record : null;
  } catch { return null; }
}
export function storeAuditExportResume(storage: ResumeStorage, record: AuditExportResume): void {
  if (!valid(record)) throw new Error("Invalid export resume identity");
  storage.setItem(storageKey, JSON.stringify(record));
}
export function exportIdentityKey(identity: AuditExportIdentity): string {
  return identityFields.map(key => identity[key]).join("/");
}
