import type { SecurityAgentExportStatus } from "./generated";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const hash = /^[a-f0-9]{64}$(?![\s\S])/;
function bad(): never { throw new Error("Invalid agent export status"); }
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) bad();
  const v = value as Record<string, unknown>;
  if (keys.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !keys.includes(k))) bad();
  return v;
}
function matches(v: unknown, pattern: RegExp) { if (typeof v !== "string" || !pattern.test(v)) bad(); }
function one(v: unknown, choices: readonly unknown[]) { if (!choices.includes(v)) bad(); }
function date(v: unknown) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$(?![\s\S])/.test(v) || v.startsWith("0001-") || !Number.isFinite(Date.parse(v)) || new Date(v).toISOString().slice(0, 19) !== v.slice(0, 19)) bad();
}
export function decodeSecurityAgentExportStatus(value: unknown): SecurityAgentExportStatus {
  const v = exact(value, ["export_id", "state", "phase", "failure_code", "created_at", "retrieval_expires_at", "mapping_revision", "snapshot_at", "cleanup_state", "selection", "artifact"]);
  matches(v.export_id, productID);
  one(v.state, ["pending", "completed", "failed"]);
  one(v.phase, ["queued", "collecting", "uploading", "terminal"]);
  if ((v.state === "pending") === (v.phase === "terminal")) bad();
  one(v.failure_code, [null, "collection_failed", "storage_unresolved", "authorization_revoked", "retrieval_expired", "integrity_failure", "export_cancelled", "export_parent_stopped"]);
  date(v.created_at); date(v.retrieval_expires_at);
  if (v.snapshot_at !== null) date(v.snapshot_at);
  one(v.mapping_revision, ["security-agent-run-evidence-v1"]);
  one(v.cleanup_state, ["retained", "pending", "deleted"]);
  validateSecurityAgentExportSelections(v.selection);
  if (v.artifact !== null) {
    const artifact = exact(v.artifact, ["sha256", "size"]);
    matches(artifact.sha256, hash);
    if (!Number.isSafeInteger(artifact.size) || (artifact.size as number) < 1 || (artifact.size as number) > 8388608) bad();
  }
  return value as SecurityAgentExportStatus;
}

export function validateSecurityAgentExportSelections(value: unknown): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) bad();
  const seen = new Set<string>();
  for (const item of value) {
    const s = exact(item, ["source_kind", "source_id", "source_version", "association_digest"]);
    one(s.source_kind, ["finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual"]);
    matches(s.source_id, s.source_kind === "manual" ? hash : productID);
    if (!Number.isSafeInteger(s.source_version) || (s.source_version as number) < 1) bad();
    matches(s.association_digest, /^sha256:[a-f0-9]{64}$(?![\s\S])/);
    const key = `${s.source_kind}/${s.source_id}`;
    if (seen.has(key)) bad();
    seen.add(key);
  }
}
