import type { ComplianceEvidenceDetail, ComplianceExport, ComplianceDownloadGrant, EvidenceRecord } from "./generated";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
function bad(): never { throw new Error("schema mismatch"); }
function exact(value: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) bad();
  const v = value as Record<string, unknown>;
  if (required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) bad();
  return v;
}
function text(value: unknown, max: number): asserts value is string { if (typeof value !== "string" || !value || new TextEncoder().encode(value).length > max || Array.from(value).some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)) bad(); }
function id(v: unknown) { if (typeof v !== "string" || !productID.test(v)) bad(); }
function one(v: unknown, values: readonly unknown[]) { if (!values.includes(v)) bad(); }
function integer(v: unknown, max = 999999999999999) { if (!Number.isSafeInteger(v) || (v as number) < 1 || (v as number) > max) bad(); }
function date(v: unknown) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(v) || !Number.isFinite(Date.parse(v)) || v.startsWith("0001-")) bad();
  if (new Date(v).toISOString().slice(0, 19) !== v.slice(0, 19)) bad();
}
function legacyDate(v: unknown) {
  // Retained PostgreSQL JSON uses RFC3339 numeric offsets. Validate the local
  // calendar separately from its offset, without normalizing the returned wire.
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(v) || !Number.isFinite(Date.parse(v))) bad();
  date(v.replace(/[+-]\d{2}:\d{2}$/, "Z"));
}
function target(value: unknown) {
  const t = exact(value, ["source_kind", "source_id", "source_version"]); integer(t.source_version); text(t.source_id, 128);
  switch (t.source_kind) {
    case "policy": if (!/^policy-[a-z0-9][a-z0-9-]{0,120}$/.test(t.source_id)) bad(); break;
    case "administration": case "workflow_policy": case "red_team_mutation": if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(t.source_id) || t.source_version !== 1) bad(); break;
    case "red_team_test": case "attack_lab_test": integer(t.source_version, 5); id(t.source_id); break;
    case "finding": case "configuration": id(t.source_id); break;
    default: bad();
  }
  return t;
}
export function decodeComplianceRecord(value: unknown, requireTarget = false): EvidenceRecord {
  const v = exact(value, ["id", "asset_id", "source", "at"], ["target", "metadata"]); text(v.id, 128); text(v.asset_id, 128); text(v.source, 64);
  const current = requireTarget || Object.hasOwn(v, "target") || Object.hasOwn(v, "metadata");
  if (current) date(v.at); else legacyDate(v.at);
  if (current) {
    const t = target(v.target); if (t.source_id !== v.id || v.asset_id !== v.id) bad(); let family: string;
    switch (t.source_kind) {
      case "policy": { family = "policy"; const m = exact(v.metadata, ["verification"]); one(m.verification, ["definition_only"]); break; }
      case "configuration": { family = "configuration"; const m = exact(v.metadata, ["verification", "migration_seeded"]); if (typeof m.migration_seeded !== "boolean" || m.verification !== (m.migration_seeded ? "unverified" : "configured")) bad(); break; }
      case "finding": { family = "finding"; const m = exact(v.metadata, ["status", "severity", "evidence_ids"]); one(m.status, ["open", "under_review", "resolved", "accepted"]); one(m.severity, ["critical", "high", "medium", "low"]); if (!Array.isArray(m.evidence_ids) || m.evidence_ids.length > 64 || new Set(m.evidence_ids).size !== m.evidence_ids.length) bad(); m.evidence_ids.forEach(id); break; }
      case "red_team_test": case "attack_lab_test": { family = "test"; const m = exact(v.metadata, ["status", "definition_id", "definition_version", "receipt_sha256", "receipt_version", "receipt_size"]); id(m.definition_id); integer(m.definition_version, 1000000); integer(m.receipt_size, 67108864); text(m.receipt_version, 512); if (typeof m.receipt_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(m.receipt_sha256)) bad(); one(m.status, t.source_kind === "red_team_test" ? ["pass", "fail", "engine_error"] : ["verified", "not_reproduced", "inconclusive"]); break; }
      default: { family = "audit"; const m = exact(v.metadata, ["action", "status"]); text(m.action, 128); one(m.status, ["succeeded", "rejected", "failed"]); }
    }
    if (v.source !== family) bad();
  }
  return value as EvidenceRecord;
}
export type ComplianceScope = Readonly<{ organization_id: string; workspace_id: string; environment_id: string }>;
export function decodeComplianceEvidenceDetail(value: unknown, scope: ComplianceScope): ComplianceEvidenceDetail {
  const v = exact(value, ["record", "freshness", "organization_id", "workspace_id", "environment_id"]);
  for (const k of ["organization_id", "workspace_id", "environment_id"] as const) { id(v[k]); if (v[k] !== scope[k]) bad(); }
  const record = decodeComplianceRecord(v.record, true); if (record.target?.source_kind === "configuration" && record.id !== scope.environment_id) bad(); one(v.freshness, ["fresh", "stale"]); return value as ComplianceEvidenceDetail;
}
export function decodeComplianceExport(value: unknown): ComplianceExport {
  const v = exact(value, ["id", "status", "formats", "created_at", "expires_at", "failure_code", "mapping_revision"]); id(v.id); one(v.status, ["pending", "completed", "failed"]); date(v.created_at); date(v.expires_at);
  if (Date.parse(v.expires_at as string) <= Date.parse(v.created_at as string) || !Array.isArray(v.formats) || v.formats.length !== 3 || new Set(v.formats).size !== 3) bad(); v.formats.forEach(f => one(f, ["json", "csv", "human"])); one(v.mapping_revision, ["product-evidence-v1"]); one(v.failure_code, [null, "collection_failed", "storage_unresolved", "authorization_revoked", "retrieval_expired"]); if (v.status !== "failed" && v.failure_code !== null) bad(); return value as ComplianceExport;
}
export function decodeComplianceDownloadGrant(value: unknown): ComplianceDownloadGrant {
  const v = exact(value, ["token", "format", "expires_at"]); if (typeof v.token !== "string" || !/^[a-f0-9]{64}$/.test(v.token)) bad(); one(v.format, ["json", "csv", "human"]); date(v.expires_at); return value as ComplianceDownloadGrant;
}
