import { APITransportError, requireAPIData, type APIClient } from "./client";
import { decodeAuditEventPage } from "./administration-decoders";
import type { AuditEventPage } from "./generated";

export type AuditFilters = Readonly<{
  actor_id?: string;
  action?: string;
  outcome?: "succeeded" | "denied" | "failed";
  from?: string;
  to?: string;
}>;

export interface AuditLogAPI {
  page(filters: AuditFilters, cursor: string | undefined, limit: number, signal: AbortSignal): Promise<AuditEventPage>;
}

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const action = /^(?:[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*|identity_provider\.(?:createSSOConnection|deleteSSOConnection|testSSOConnection|createSCIMConnection|deleteSCIMConnection))$(?![\s\S])/;

// Compare fixed-width UTC strings, never millisecond-rounded Date values.
function utc(value: string): string {
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$(?![\s\S])/.exec(value);
  if (!parts) throw new Error("Enter UTC timestamps ending Z with seconds and at most six fractional digits.");
  const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) {
    throw new Error("Enter a valid UTC calendar date and time.");
  }
  return `${value.slice(0, 19)}.${(parts[7] ?? "").padEnd(6, "0")}Z`;
}

export function normalizeAuditFilters(filters: AuditFilters): AuditFilters {
  const normalized: { actor_id?: string; action?: string; outcome?: AuditFilters["outcome"]; from?: string; to?: string } = {};
  if (filters.actor_id !== undefined) {
    if (!productID.test(filters.actor_id)) throw new Error("Enter an exact canonical actor Product ID.");
    normalized.actor_id = filters.actor_id;
  }
  if (filters.action !== undefined) {
    if (filters.action.length > 127 || !action.test(filters.action)) throw new Error("Enter an exact audit action, preserving its case.");
    normalized.action = filters.action;
  }
  if (filters.outcome !== undefined) {
    if (!["succeeded", "denied", "failed"].includes(filters.outcome)) throw new Error("Choose a listed outcome.");
    normalized.outcome = filters.outcome;
  }
  if (filters.from !== undefined) normalized.from = utc(filters.from);
  if (filters.to !== undefined) normalized.to = utc(filters.to);
  if (normalized.from && normalized.to && normalized.from >= normalized.to) throw new Error("From must be earlier than To; To is exclusive.");
  return normalized;
}

// Scope/session/route remounts keep the same API client. Share only its audit
// read coordinator, never pages or results; unrelated clients remain independent.
// Weak ownership lets a discarded client and its coordinator be collected.
const auditReaders = new WeakMap<APIClient, AuditLogAPI>();

export function createAuditLogAPI(client: APIClient): AuditLogAPI {
  const existing = auditReaders.get(client);
  if (existing) return existing;
  // One transport read and one replaceable waiting request per client. Caller
  // cancellation releases its promise immediately; physical settlement is still
  // joined before another read starts, even if a transport ignores its signal.
  type WaitingRead = { run(): Promise<void>; cancel(reason: unknown): void };
  let active = false;
  let waiting: WaitingRead | null = null;
  const drain = () => {
    if (active || !waiting) return;
    const next = waiting;
    waiting = null;
    active = true;
    void next.run().finally(() => { active = false; drain(); });
  };
  const api: AuditLogAPI = {
    async page(filters, cursor, limit, signal) {
      signal.throwIfAborted();
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("Audit page limit must be between 1 and 100.");
      const query = { ...normalizeAuditFilters(filters), limit, ...(cursor !== undefined ? { cursor } : {}) };
      return new Promise<AuditEventPage>((resolve, reject) => {
        const abort = () => read.cancel(signal.reason);
        const read: WaitingRead = {
          cancel(reason) {
            if (waiting === read) waiting = null;
            signal.removeEventListener("abort", abort);
            reject(reason);
          },
          async run() {
            try {
              signal.throwIfAborted();
              const page = requireAPIData(await client.GET("/api/v1/audit-events", { params: { query }, signal }), decodeAuditEventPage);
              signal.throwIfAborted();
              if (page.items.length > limit || (page.page_info.has_more && (page.items.length === 0 || page.page_info.next_cursor === cursor))) {
                throw new APITransportError("invalid_response", "Audit page did not advance within its bounds");
              }
              resolve(page);
            } catch (error) { reject(error); }
            finally { signal.removeEventListener("abort", abort); }
          },
        };
        waiting?.cancel(new DOMException("A newer audit read replaced this waiting request", "AbortError"));
        waiting = read;
        signal.addEventListener("abort", abort, { once: true });
        drain();
      });
    },
  };
  auditReaders.set(client, api);
  return api;
}
