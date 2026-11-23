import { APITransportError, requireAPIData, type APIClient } from "./client";

export const frameworkNames = {
  owasp_agentic_top10: "OWASP Top 10 for Agentic Applications",
  owasp_llm_top10: "OWASP Top 10 for LLM Applications",
  mitre_atlas: "MITRE ATLAS",
  mitre_attack_enterprise: "MITRE Enterprise ATT&CK",
} as const;

export const evidenceNames = {
  posture_finding: "Posture finding",
  static_scan: "Static scan",
  observed_event: "Observed event",
  tested_control: "Tested control",
  verified_prevention: "Verified prevention",
} as const;

export type CatalogFramework = keyof typeof frameworkNames;
export type EvidenceKind = keyof typeof evidenceNames;
export type EditionKey = { framework: CatalogFramework; edition: string };
export type CoverageSelector = EditionKey & { upstream_id?: string; evidence_kind?: EvidenceKind };
export type SourceSelector = { source_kind: SourceKind; source_id: string };
export type SourceKind = "finding" | "addon_version" | "runtime_action" | "ticket_test";
const controlKinds = ["risk", "technique", "subtechnique", "mitigation"] as const;
const applicability = ["applicable", "unassessed", "out_of_scope"] as const;
const sources = ["finding", "addon_version", "runtime_action", "ticket_test"] as const;
const frameworkKeys = Object.keys(frameworkNames) as CatalogFramework[];
const evidenceKinds = Object.keys(evidenceNames) as EvidenceKind[];
const pid = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function invalid(): never {
  throw new APITransportError("invalid_response", "The framework evidence response could not be verified.");
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

function text(value: unknown, max = 2048): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max || Array.from(value).some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)) invalid();
  return value;
}

function member<T extends string>(value: unknown, values: readonly T[]): T {
  const matched = values.find(item => value === item);
  if (matched === undefined) invalid();
  return matched;
}

function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}

function rows<T>(value: unknown, max: number, decode: (row: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > max) invalid();
  return value.map(decode);
}

function digest(value: unknown): string {
  const parsed = text(value, 71);
  if (!/^(?:sha256:)?[a-f0-9]{64}$/.test(parsed)) invalid();
  return parsed;
}

function date(value: unknown): string {
  const parsed = text(value, 48);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(parsed) || !Number.isFinite(Date.parse(parsed))) invalid();
  return parsed;
}

function catalogID(value: unknown): string {
  const id = text(value, 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(id)) invalid();
  return id;
}

function publicID(value: unknown): string {
  const id = text(value, 40);
  if (!pid.test(id)) invalid();
  return id;
}

function nextAfter(value: unknown): string | null {
  return value === null ? null : text(value, 2048);
}

function sourceURL(value: unknown): string {
  const url = new URL(text(value));
  if (url.protocol !== "https:" || url.username || url.password) invalid();
  return url.href;
}

function editionKey(value: Record<string, unknown>): EditionKey {
  return { framework: member(value.framework, frameworkKeys), edition: catalogID(value.edition) };
}

function equalEdition(a: EditionKey, b: EditionKey) {
  if (a.framework !== b.framework || a.edition !== b.edition) invalid();
}

export function decodeEditions(value: unknown) {
  const items = rows(record(value).items, 100, entry => {
    const row = record(entry);
    return { ...editionKey(row), total_controls: count(row.total_controls), source_digest: digest(row.source_digest) };
  });
  if (new Set(items.map(item => item.framework + "/" + item.edition)).size !== items.length) invalid();
  return items;
}

function control(value: unknown, selector: CoverageSelector) {
  const item = record(value);
  equalEdition(editionKey(item), selector);
  const id = catalogID(item.upstream_id);
  if (selector.upstream_id && id !== selector.upstream_id) invalid();
  return {
    upstream_id: id,
    title: text(item.title),
    kind: member(item.kind, controlKinds),
    parent_id: item.parent_id === undefined ? undefined : catalogID(item.parent_id),
    owner: text(item.owner),
    applicability: member(item.applicability, applicability),
    scope: text(item.scope),
    rationale: text(item.rationale, 4096),
    source_url: sourceURL(item.source_url),
    digest_basis: member(item.digest_basis, ["upstream_bytes", "reviewed_index"] as const),
    source_digest: digest(item.source_digest),
    license: text(item.license),
    attribution: text(item.attribution),
    status: member(item.status, ["active", "retired"] as const),
  };
}

export function decodeCoverage(value: unknown, selector: CoverageSelector) {
  const page = record(value);
  equalEdition(editionKey(page), selector);
  const collected = date(page.collected_at);
  const total = count(page.total_controls), matched = count(page.matched_controls);
  if (matched > total) invalid();
  const items = rows(page.items, 200, item => {
    const row = record(item);
    const evidence_counts: Partial<Record<EvidenceKind, number>> = {};
    for (const [kind, n] of Object.entries(record(row.evidence_counts))) evidence_counts[member(kind, evidenceKinds)] = count(n);
    return { control: control(row.control, selector), evidence_counts, last_verified_at: row.last_verified_at === null ? null : date(row.last_verified_at) };
  });
  if (items.some(row => row.last_verified_at && Date.parse(row.last_verified_at) > Date.parse(collected)) || items.length > matched || new Set(items.map(item => item.control.upstream_id)).size !== items.length) invalid();
  const rawSummary = record(page.summary);
  const summary = {
    applicable_controls: count(rawSummary.applicable_controls), verified_applicable_controls: count(rawSummary.verified_applicable_controls),
    out_of_scope_controls: count(rawSummary.out_of_scope_controls), unassessed_controls: count(rawSummary.unassessed_controls),
    risks: count(rawSummary.risks), techniques: count(rawSummary.techniques), subtechniques: count(rawSummary.subtechniques), mitigations: count(rawSummary.mitigations),
  };
  if (summary.applicable_controls + summary.unassessed_controls + summary.out_of_scope_controls !== total ||
      summary.risks + summary.techniques + summary.subtechniques + summary.mitigations !== total ||
      summary.verified_applicable_controls > summary.applicable_controls) invalid();
  return { items, total, matched, summary, collected_at: collected, source_digest: digest(page.source_digest), next_after: nextAfter(page.next_after) };
}

export type EvidenceSelector = (CoverageSelector & { upstream_id: string }) | SourceSelector;

export function decodeCoverageEvidence(value: unknown, selector: EvidenceSelector) {
  const page = record(value);
  const items = rows(page.items, 200, item => {
    const row = record(item);
    const key = editionKey(row);
    const upstream_id = catalogID(row.upstream_id);
    const evidence_kind = member(row.evidence_kind, evidenceKinds);
    const source_kind = member(row.source_kind, sources), source_id = publicID(row.source_id);
    if ("source_kind" in selector) {
      if (source_kind !== selector.source_kind || source_id !== selector.source_id) invalid();
    } else {
      equalEdition(key, selector);
      if (upstream_id !== selector.upstream_id || selector.evidence_kind && evidence_kind !== selector.evidence_kind) invalid();
    }
    if (row.manifest_digest !== undefined && source_kind !== "addon_version") invalid();
    return {
      ...key, upstream_id, source_kind, source_id,
      manifest_digest: row.manifest_digest === undefined ? undefined : digest(row.manifest_digest),
      rule: text(row.rule, 256), rule_version: text(row.rule_version, 128),
      evidence_kind, occurred_at: date(row.occurred_at),
      session_id: row.session_id === undefined ? undefined : publicID(row.session_id),
    };
  });
  return { items, next_after: nextAfter(page.next_after) };
}

export type CatalogEdition = ReturnType<typeof decodeEditions>[number];
export type CoverageRow = ReturnType<typeof decodeCoverage>["items"][number];
export type CoverageEvidence = ReturnType<typeof decodeCoverageEvidence>["items"][number];

export function frameworkCoverageAPI(client: APIClient) {
  return {
    async editions(signal: AbortSignal) {
      return requireAPIData(await client.GET("/api/v1/compliance/editions", { signal }), decodeEditions);
    },
    async coverage(selector: CoverageSelector, after: string | undefined, signal: AbortSignal) {
      const query = { ...selector, after, limit: 25 };
      return requireAPIData(await client.GET("/api/v1/compliance/coverage", { params: { query }, signal }), value => decodeCoverage(value, selector));
    },
    async evidence(selector: EvidenceSelector, after: string | undefined, signal: AbortSignal) {
      const query = { ...selector, after, limit: 25 };
      return requireAPIData(await client.GET("/api/v1/compliance/coverage/evidence", { params: { query }, signal }), value => decodeCoverageEvidence(value, selector));
    },
  };
}
