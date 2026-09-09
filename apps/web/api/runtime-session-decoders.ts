import type { RuntimeSession, RuntimeSessionEvent, RuntimeSessionEventPage, RuntimeSessionPage } from "./generated";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONFIDENCE = ["exact", "strong", "probable", "unattributed"];
const ACTIONS: Record<string, readonly string[]> = { tool: ["invoke"], runtime: ["exec", "exit"], file: ["read", "write"], network: ["connect", "accept"] };

export function decodeRuntimeSession(value: unknown): RuntimeSession {
  const record = exact(value, ["id", "kind", "workspace_id", "environment_id", "agent_id", "principal_id", "first_event_at", "last_event_at", "projected_at", "event_count", "confidence_counts"]);
  id(record.workspace_id); id(record.environment_id); nullableID(record.agent_id); nullableID(record.principal_id);
  const unknown = record.id === "unattributed";
  if (!unknown) id(record.id);
  if (record.kind !== (unknown ? "unattributed" : "runtime")) bad();
  if (instant(record.first_event_at) > instant(record.last_event_at)) bad();
  instant(record.projected_at);
  count(record.event_count, 1);
  const counts = exact(record.confidence_counts, CONFIDENCE);
  for (const value of Object.values(counts)) count(value, 0);
  const total = CONFIDENCE.reduce((sum, key) => sum + BigInt(counts[key] as number), BigInt(0));
  if (total !== BigInt(record.event_count as number)) bad();
  if (unknown) {
    if (record.agent_id !== null || record.principal_id !== null || counts.exact !== 0 || counts.strong !== 0) bad();
  } else if (counts.probable !== 0 || counts.unattributed !== 0) bad();
  return value as RuntimeSession;
}

export function decodeRuntimeSessionEvent(value: unknown): RuntimeSessionEvent {
  const record = exact(value, ["id", "session_id", "agent_id", "class", "action", "label", "evidence_id", "source", "confidence", "at", "projected_at"]);
  id(record.id); id(record.evidence_id); nullableID(record.session_id); nullableID(record.agent_id);
  text(record.label, 256);
  if ([...record.label as string].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) bad();
  if (typeof record.class !== "string" || !Object.hasOwn(ACTIONS, record.class) || typeof record.action !== "string" || !ACTIONS[record.class].includes(record.action)) bad();
  if (record.source !== "otlp" && record.source !== "tetragon") bad();
  if (typeof record.confidence !== "string" || !CONFIDENCE.includes(record.confidence)) bad();
  const attributed = record.confidence === "exact" || record.confidence === "strong";
  if (attributed ? record.session_id === null || record.agent_id === null : record.session_id !== null || record.agent_id !== null) bad();
  instant(record.at); instant(record.projected_at);
  return value as RuntimeSessionEvent;
}

export function decodeRuntimeSessionPage(value: unknown): RuntimeSessionPage {
  const items = page(value).map(decodeRuntimeSession);
  for (let index = 1; index < items.length; index += 1) if (items[index - 1].id >= items[index].id) bad();
  return value as RuntimeSessionPage;
}

export function decodeRuntimeSessionEventPage(value: unknown): RuntimeSessionEventPage {
  const items = page(value).map(decodeRuntimeSessionEvent);
  const seen = new Set<string>();
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (seen.has(item.id) || item.session_id !== items[0].session_id) bad();
    seen.add(item.id);
    if (index > 0) {
      const prior = items[index - 1], earlier = instant(prior.at), current = instant(item.at);
      if (earlier > current || earlier === current && prior.id >= item.id) bad();
    }
  }
  return value as RuntimeSessionEventPage;
}

function page(value: unknown): unknown[] {
  const record = exact(value, ["items", "page_info"]);
  if (!Array.isArray(record.items) || record.items.length > 100) bad();
  const info = exact(record.page_info, ["next_cursor", "has_more"]);
  if (info.has_more === true) {
    text(info.next_cursor, 512);
    if (typeof info.next_cursor !== "string" || !/^[A-Za-z0-9_-]{2,512}$/.test(info.next_cursor) || record.items.length === 0) bad();
  } else if (info.has_more !== false || info.next_cursor !== null) bad();
  return record.items;
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) bad();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) bad();
  return record;
}
function id(value: unknown) { if (typeof value !== "string" || !PRODUCT_ID.test(value)) bad(); }
function nullableID(value: unknown) { if (value !== null) id(value); }
function text(value: unknown, maximum: number) { if (typeof value !== "string" || value.length < 1 || value.length > maximum) bad(); }
function count(value: unknown, minimum: number) { if (!Number.isSafeInteger(value) || (value as number) < minimum) bad(); }
function instant(value: unknown): bigint {
  if (typeof value !== "string") bad();
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) bad();
  const [, year, month, day, hour, minute, second, fraction, offset] = match;
  if (+year < 1 || +month < 1 || +month > 12 || +day < 1 || +day > new Date(Date.UTC(+year, +month, 0)).getUTCDate() || +hour > 23 || +minute > 59 || +second > 59) bad();
  const milliseconds = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${offset}`);
  if (!Number.isFinite(milliseconds)) bad();
  return BigInt(milliseconds) * BigInt(1_000_000) + BigInt((fraction ?? "").padEnd(9, "0"));
}
function bad(): never { throw new Error("schema mismatch"); }
