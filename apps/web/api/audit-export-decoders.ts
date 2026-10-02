import type { AuditExport, AuditExportBinding, AuditExportChunk, AuditExportEvent, AuditExportManifest, AuditExportRead } from "./generated";

const encoder = new TextEncoder();
const idPattern = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const digestPattern = /^[0-9a-f]{64}$(?![\s\S])/;
export const AUDIT_EXPORT_ZERO_DIGEST = "0".repeat(64);
const scopeKeys = ["organization_id", "workspace_id", "environment_id"] as const;
const bindingKeys = [...scopeKeys, "export_id", "capture_id"] as const;
const descriptorKeys = ["id", ...scopeKeys, "created_at", "audit_correlation_id", "status", "event_count"];

function bad(): never { throw new Error("Invalid audit export contract"); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) bad();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) bad();
  return value as Record<string, unknown>;
}
function exact(value: unknown, keys: readonly string[]) {
  const v = record(value);
  if (Object.keys(v).length !== keys.length || keys.some(key => !Object.hasOwn(v, key))) bad();
  return v;
}
export function auditExportScalar(value: unknown): asserts value is string {
  if (typeof value !== "string") bad();
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) bad();
    } else if (c >= 0xdc00 && c <= 0xdfff) bad();
  }
}
function text(value: unknown, max: number) {
  auditExportScalar(value);
  if (!value || encoder.encode(value).byteLength > max) bad();
  for (const char of value) if (char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) bad();
}
function id(value: unknown) { if (typeof value !== "string" || !idPattern.test(value)) bad(); }
function digest(value: unknown) { if (typeof value !== "string" || !digestPattern.test(value)) bad(); }
function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) bad();
}
function scope(value: Record<string, unknown>) {
  scopeKeys.forEach(key => id(value[key]));
  if (new Set(scopeKeys.map(key => value[key])).size !== 3) bad();
}
function timestamp(value: unknown) {
  if (typeof value !== "string") bad();
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$(?![\s\S])/.exec(value);
  if (!parts || value === "0001-01-01T00:00:00.000000Z") bad();
  const [y, m, d, h, minute, second] = parts.slice(1, 7).map(Number);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (y < 1 || m < 1 || m > 12 || d < 1 || d > days[m-1] || h > 23 || minute > 59 || second > 59) bad();
}
// This is a size calculation only. Property order cannot change JSON byte count.
// Canonical saved/hashed bytes use the explicit codec, never this serialization.
function bounded(value: unknown, max: number) {
  const json = JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
  if (encoder.encode(json).byteLength > max) bad();
}
function counts(v: Record<string, unknown>) {
  integer(v.event_count); integer(v.chunk_count); integer(v.chunk_bytes);
  if (v.event_count === 0) { if (v.chunk_count !== 0 || v.chunk_bytes !== 0) bad(); }
  else if (v.chunk_count < 1 || v.chunk_count > v.event_count || Math.floor((v.event_count-1)/1000)+1 > v.chunk_count || v.chunk_bytes < v.chunk_count || Math.floor((v.chunk_bytes-1)/1048576)+1 > v.chunk_count) bad();
}
export function decodeAuditExport(value: unknown): AuditExport {
  const v = record(value);
  const extra = v.status === "ready" ? ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"] : v.status === "failed" ? ["failure_code"] : [];
  exact(v, [...descriptorKeys, ...extra]); scope(v); id(v.id); id(v.audit_correlation_id); timestamp(v.created_at);
  if (v.status === "ready") { timestamp(v.captured_at); digest(v.manifest_sha256); counts(v); }
  else {
    if (v.event_count !== null || typeof v.status !== "string" || !["queued", "processing", "failed"].includes(v.status)) bad();
    if (v.status === "failed" && (typeof v.failure_code !== "string" || !["capacity_exceeded", "invalid_source", "execution_failed"].includes(v.failure_code))) bad();
  }
  bounded(v, 8192);
  return value as AuditExport;
}
export function decodeAuditExportBinding(value: unknown): AuditExportBinding {
  const v = exact(value, bindingKeys); bindingKeys.forEach(key => id(v[key]));
  if (new Set(Object.values(v)).size !== 5) bad();
  return value as AuditExportBinding;
}
export function sameAuditExportBinding(a: AuditExportBinding, b: AuditExportBinding): boolean { return bindingKeys.every(key => a[key] === b[key]); }
export function decodeAuditExportEvent(value: unknown): AuditExportEvent {
  const v = exact(value, ["ordinal", "id", ...scopeKeys, "actor_id", "action", "target_id", "outcome", "metadata", "occurred_at"]);
  integer(v.ordinal, 1); id(v.id); id(v.actor_id); scope(v); timestamp(v.occurred_at); text(v.target_id, 128); text(v.action, 127);
  if (!/^(?:[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*|identity_provider\.(?:createSSOConnection|deleteSSOConnection|testSSOConnection|createSCIMConnection|deleteSCIMConnection))$(?![\s\S])/.test(v.action as string)) bad();
  if (typeof v.outcome !== "string" || !["succeeded", "failed", "denied"].includes(v.outcome)) bad();
  const metadata = record(v.metadata);
  if (Object.keys(metadata).length > 32) bad();
  for (const [key, entry] of Object.entries(metadata)) {
    text(key, 64); text(entry, 512);
    // Go uses simple Unicode lowercase; JS expands U+0130 to i + combining dot.
    const lower = key.replace(/\u0130/g, "I").toLowerCase();
    if (/secret|token|password|authorization|credential|api_key/.test(lower) && entry !== "[REDACTED]") bad();
  }
  bounded(v, 131072);
  return value as AuditExportEvent;
}
export function decodeAuditExportChunk(value: unknown): AuditExportChunk {
  const v = exact(value, ["schema", "binding", "ordinal", "first_event", "event_count", "previous_digest", "events"]);
  if (v.schema !== "audit-export-chunk-v1") bad();
  const binding = decodeAuditExportBinding(v.binding);
  integer(v.ordinal, 1); integer(v.first_event, 1); integer(v.event_count, 1, 1000); digest(v.previous_digest);
  if (v.first_event > Number.MAX_SAFE_INTEGER-v.event_count+1 || v.ordinal > v.first_event) bad();
  if (v.ordinal === 1) { if (v.first_event !== 1 || v.previous_digest !== AUDIT_EXPORT_ZERO_DIGEST) bad(); }
  else if (v.previous_digest === AUDIT_EXPORT_ZERO_DIGEST || Math.floor((v.first_event-2)/1000)+1 > v.ordinal-1) bad();
  if (!Array.isArray(v.events) || v.events.length !== v.event_count) bad();
  let previous: AuditExportEvent | undefined;
  const seen = new Set<string>();
  for (let i = 0; i < v.events.length; i++) {
    const e = decodeAuditExportEvent(v.events[i]);
    if (e.organization_id !== binding.organization_id || e.ordinal !== v.first_event+i || seen.has(e.id)) bad();
    if (previous && (previous.occurred_at < e.occurred_at || previous.occurred_at === e.occurred_at && previous.id <= e.id)) bad();
    seen.add(e.id); previous = e;
  }
  bounded(v, 1048576);
  return value as AuditExportChunk;
}
export function decodeAuditExportManifest(value: unknown): AuditExportManifest {
  const v = exact(value, ["schema", "binding", "event_count", "chunk_count", "chunk_bytes", "chain_root"]);
  if (v.schema !== "audit-export-manifest-v1") bad();
  decodeAuditExportBinding(v.binding); counts(v); digest(v.chain_root);
  if ((v.event_count === 0) !== (v.chain_root === AUDIT_EXPORT_ZERO_DIGEST)) bad();
  bounded(v, 2048);
  return value as AuditExportManifest;
}
export function decodeAuditExportRead(value: unknown): AuditExportRead {
  const v = exact(value, ["export", "contents"]);
  const descriptor = decodeAuditExport(v.export);
  if (descriptor.status !== "ready") { if (v.contents !== null) bad(); return value as AuditExportRead; }
  const contents = exact(v.contents, ["manifest", "chunk", "chunk_sha256", "page_info"]);
  const manifest = decodeAuditExportManifest(contents.manifest);
  if (manifest.binding.export_id !== descriptor.id || scopeKeys.some(key => manifest.binding[key] !== descriptor[key]) || manifest.event_count !== descriptor.event_count || manifest.chunk_count !== descriptor.chunk_count || manifest.chunk_bytes !== descriptor.chunk_bytes) bad();
  const page = exact(contents.page_info, ["next_cursor", "has_more"]);
  if (page.has_more === true) { if (typeof page.next_cursor !== "string" || page.next_cursor.length > 1024 || !/^[A-Za-z0-9_-]+$(?![\s\S])/.test(page.next_cursor)) bad(); }
  else if (page.has_more !== false || page.next_cursor !== null) bad();
  if (manifest.event_count === 0) {
    if (contents.chunk !== null || contents.chunk_sha256 !== null || page.has_more) bad();
  } else {
    const chunk = decodeAuditExportChunk(contents.chunk); digest(contents.chunk_sha256);
    const lastEvent = chunk.first_event+chunk.event_count-1;
    if (!sameAuditExportBinding(chunk.binding, manifest.binding) || chunk.ordinal > manifest.chunk_count || lastEvent > manifest.event_count || page.has_more !== (chunk.ordinal < manifest.chunk_count)) bad();
    if (page.has_more ? lastEvent >= manifest.event_count : lastEvent !== manifest.event_count) bad();
    if (!page.has_more && contents.chunk_sha256 !== manifest.chain_root) bad();
  }
  return value as AuditExportRead;
}
