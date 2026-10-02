import type { AuditExportBinding, AuditExportEvent, AuditExportRead } from "./generated";
import { AUDIT_EXPORT_ZERO_DIGEST, auditExportScalar, decodeAuditExportChunk, decodeAuditExportEvent, decodeAuditExportManifest, decodeAuditExportRead } from "./audit-export-decoders";

const utf8 = new TextEncoder();
function reject(): never { throw new Error("Audit export bytes or traversal did not match"); }
function quote(value: string): string {
  auditExportScalar(value);
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
function object(entries: readonly (readonly [string, string])[]): string {
  return `{${entries.map(([key, encoded]) => `${quote(key)}:${encoded}`).join(",")}}`;
}
function binding(value: AuditExportBinding): string {
  return object((["organization_id", "workspace_id", "environment_id", "export_id", "capture_id"] as const).map(key => [key, quote(value[key])]));
}
function utf8Order(a: string, b: string): number {
  const left = utf8.encode(a), right = utf8.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i]-right[i];
  return left.length-right.length;
}
function event(value: AuditExportEvent): string {
  // Emit metadata entries directly: rebuilding an object would reorder integer keys.
  const metadata = object(Object.keys(value.metadata).sort(utf8Order).map(key => [key, quote(value.metadata[key])]));
  return object([
    ["ordinal", String(value.ordinal)], ["id", quote(value.id)], ["organization_id", quote(value.organization_id)],
    ["workspace_id", quote(value.workspace_id)], ["environment_id", quote(value.environment_id)], ["actor_id", quote(value.actor_id)],
    ["action", quote(value.action)], ["target_id", quote(value.target_id)], ["outcome", quote(value.outcome)],
    ["metadata", metadata], ["occurred_at", quote(value.occurred_at)],
  ]);
}
function bytes(value: string, maximum: number): Uint8Array<ArrayBuffer> {
  const result = utf8.encode(value);
  if (result.byteLength > maximum) reject();
  return result;
}
export function encodeAuditExportEvent(value: unknown): Uint8Array<ArrayBuffer> { return bytes(event(decodeAuditExportEvent(value)), 131072); }
export function encodeAuditExportChunk(value: unknown): Uint8Array<ArrayBuffer> {
  const v = decodeAuditExportChunk(value);
  return bytes(object([
    ["schema", quote(v.schema)], ["binding", binding(v.binding)], ["ordinal", String(v.ordinal)],
    ["first_event", String(v.first_event)], ["event_count", String(v.event_count)],
    ["previous_digest", quote(v.previous_digest)], ["events", `[${v.events.map(event).join(",")}]`],
  ]), 1048576);
}
export function encodeAuditExportManifest(value: unknown): Uint8Array<ArrayBuffer> {
  const v = decodeAuditExportManifest(value);
  return bytes(object([
    ["schema", quote(v.schema)], ["binding", binding(v.binding)], ["event_count", String(v.event_count)],
    ["chunk_count", String(v.chunk_count)], ["chunk_bytes", String(v.chunk_bytes)], ["chain_root", quote(v.chain_root)],
  ]), 2048);
}
async function sha256(value: Uint8Array<ArrayBuffer>): Promise<string> {
  const sum = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", value));
  return Array.from(sum, byte => byte.toString(16).padStart(2, "0")).join("");
}
export type VerifiedAuditExportRead = Readonly<{
  read: AuditExportRead;
  manifestBytes: Uint8Array<ArrayBuffer> | null;
  chunkBytes: Uint8Array<ArrayBuffer> | null;
}>;
// Local page verification accepts any authorized cursor position. The sequential
// verifier below adds pinned traversal coverage; readiness alone is never completion.
export async function verifyAuditExportRead(value: unknown): Promise<VerifiedAuditExportRead> {
  const read = decodeAuditExportRead(value);
  if (read.export.status !== "ready" || read.contents === null) return { read, manifestBytes: null, chunkBytes: null };
  const manifestBytes = encodeAuditExportManifest(read.contents.manifest);
  if (await sha256(manifestBytes) !== read.export.manifest_sha256) reject();
  const chunkBytes = read.contents.chunk === null ? null : encodeAuditExportChunk(read.contents.chunk);
  if (chunkBytes !== null && await sha256(chunkBytes) !== read.contents.chunk_sha256) reject();
  return { read, manifestBytes, chunkBytes };
}
export type AuditExportProgress = Readonly<{
  manifestSHA256: string;
  eventCount: number;
  chunkCount: number;
  chunkBytes: number;
  previousDigest: string;
  nextCursor: string | null;
  lastEventTime: string | null;
  lastEventID: string | null;
  complete: boolean;
}>;
export type VerifiedAuditExportPage = VerifiedAuditExportRead & { readonly progress: AuditExportProgress };

// Caller commits this small state only after successfully closing the chunk file.
// A failed write retries from the previous state; no pages/cursor history accumulates.
export async function verifyAuditExportPage(value: unknown, previous?: AuditExportProgress): Promise<VerifiedAuditExportPage> {
  const verified = await verifyAuditExportRead(value);
  const { read, chunkBytes } = verified;
  if (read.export.status !== "ready" || read.contents === null) reject();
  const { manifest, chunk, page_info: page } = read.contents;
  if (previous && (previous.complete || previous.manifestSHA256 !== read.export.manifest_sha256 || previous.nextCursor === null || page.next_cursor === previous.nextCursor)) reject();
  const eventCount = (previous?.eventCount ?? 0)+(chunk?.event_count ?? 0);
  const chunkCount = (previous?.chunkCount ?? 0)+(chunk === null ? 0 : 1);
  const byteCount = (previous?.chunkBytes ?? 0)+(chunkBytes?.byteLength ?? 0);
  if (![eventCount, chunkCount, byteCount].every(Number.isSafeInteger)) reject();
  if (chunk !== null) {
    if (chunk.ordinal !== chunkCount || chunk.first_event !== (previous?.eventCount ?? 0)+1 || chunk.previous_digest !== (previous?.previousDigest ?? AUDIT_EXPORT_ZERO_DIGEST)) reject();
    const first = chunk.events[0];
    if (previous?.lastEventTime && (previous.lastEventTime < first.occurred_at || previous.lastEventTime === first.occurred_at && previous.lastEventID! <= first.id)) reject();
  } else if (previous) reject();
  if (eventCount > manifest.event_count || chunkCount > manifest.chunk_count || byteCount > manifest.chunk_bytes) reject();
  const previousDigest = read.contents.chunk_sha256 ?? AUDIT_EXPORT_ZERO_DIGEST;
  const complete = !page.has_more;
  if (complete && (eventCount !== manifest.event_count || chunkCount !== manifest.chunk_count || byteCount !== manifest.chunk_bytes || previousDigest !== manifest.chain_root)) reject();
  const last = chunk?.events[chunk.events.length-1];
  return { ...verified, progress: Object.freeze({ manifestSHA256: read.export.manifest_sha256, eventCount, chunkCount, chunkBytes: byteCount, previousDigest,
    nextCursor: page.next_cursor, lastEventTime: last?.occurred_at ?? null, lastEventID: last?.id ?? null, complete }) };
}
