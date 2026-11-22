import { APITransportError, requireAPIData, type APIClient } from "./client";
import type {
  EndpointDevice,
  EndpointDetail,
  EndpointFleetPage,
  EndpointRegistration,
  EndpointInstallationDetail,
  EndpointPartitionSummary,
  EndpointObservationDetail,
} from "./generated";

const idPattern = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function invalid(): never {
  throw new APITransportError("invalid_response", "Invalid fleet response");
}
function obj(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid();
  return value as Record<string, unknown>;
}
function n(value: unknown, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) return invalid();
  return value;
}
function optionalCount(value: unknown) {
  return value === null ? null : n(value);
}
export function decodeDevice(data: unknown, expected?: string): EndpointDevice {
  const r = obj(data);
  if (
    typeof r.id !== "string" ||
    !idPattern.test(r.id) ||
    (expected !== undefined && r.id !== expected) ||
    typeof r.cohort !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(r.cohort) ||
    (r.state !== "pending" && r.state !== "active" && r.state !== "retired") ||
    (r.connection !== "never_seen" &&
      r.connection !== "online" &&
      r.connection !== "stale" &&
      r.connection !== "retired") ||
    typeof r.acknowledged !== "boolean" ||
    (r.last_seen !== null && (typeof r.last_seen !== "string" || !Number.isFinite(Date.parse(r.last_seen))))
  )
    return invalid();
  return {
    id: r.id,
    cohort: r.cohort,
    state: r.state,
    version: n(r.version, 1),
    credential_generation: n(r.credential_generation, 1),
    connection: r.connection,
    last_seen: r.last_seen,
    policy_revision: n(r.policy_revision),
    reported_policy_revision: n(r.reported_policy_revision),
    acknowledged: r.acknowledged,
    queued_receipts: optionalCount(r.queued_receipts),
    dropped_receipts: optionalCount(r.dropped_receipts),
  };
}
export function decodeFleet(data: unknown, cursor?: string): EndpointFleetPage {
  const r = obj(data),
    c = obj(r.counts);
  if (
    !Array.isArray(r.items) ||
    r.items.length > 50 ||
    (r.next_after_id !== null &&
      (typeof r.next_after_id !== "string" || !idPattern.test(r.next_after_id) || r.next_after_id === cursor))
  )
    return invalid();
  const items = r.items.map((v) => decodeDevice(v));
  if (
    new Set(items.map((row) => row.id)).size !== items.length ||
    (r.next_after_id && items.at(-1)?.id !== r.next_after_id)
  )
    return invalid();
  return {
    items,
    next_after_id: r.next_after_id,
    counts: {
      expected: n(c.expected),
      enrolled: n(c.enrolled),
      online: n(c.online),
      acknowledged: n(c.acknowledged),
    },
  };
}
const digestPattern = /^[0-9a-f]{64}$/;
function digest(value: unknown): string {
  return typeof value === "string" && digestPattern.test(value) ? value : invalid();
}
function boundedRows<T>(value: unknown, total: number, max: number, decode: (row: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length !== Math.min(total, max)) return invalid();
  return value.map(decode);
}
function decodeInstallation(row: unknown): EndpointInstallationDetail {
  const r = obj(row);
  if (
    r.manifest_digest !== undefined &&
    (typeof r.manifest_digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(r.manifest_digest))
  )
    return invalid();
  return {
    installation_id: digest(r.installation_id),
    ...(typeof r.manifest_digest === "string" && { manifest_digest: r.manifest_digest }),
  };
}
function decodePartition(row: unknown): EndpointPartitionSummary {
  const r = obj(row),
    generation = n(r.generation, 1),
    completeGeneration = r.last_complete_generation === null ? null : n(r.last_complete_generation, 1),
    count = n(r.observed_count),
    confirmed = optionalCount(r.confirmed_count);
  if (
    typeof r.complete !== "boolean" ||
    (completeGeneration === null) !== (confirmed === null) ||
    (completeGeneration !== null && completeGeneration > generation) ||
    (r.complete && (generation !== completeGeneration || count !== confirmed))
  )
    return invalid();
  return {
    partition_id: digest(r.partition_id),
    generation,
    complete: r.complete,
    observed_count: count,
    observed_installations: boundedRows(r.observed_installations, count, 12, decodeInstallation),
    last_complete_generation: completeGeneration,
    confirmed_count: confirmed,
    confirmed_installations: boundedRows(r.confirmed_installations, confirmed ?? 0, 12, decodeInstallation),
  };
}
export const endpointAdapterLabels = {
  unknown: "Unknown",
  macos_claude_ticket: "macOS · Claude Code ticket hook",
  linux_claude_ticket_test: "Linux · ticket hook test adapter",
  windows_inventory: "Windows · inventory only",
  macos_claude_pretool_v2: "macOS · Claude Code pre-tool hook",
  macos_codex_pretool_v2: "macOS · Codex pre-tool hook",
  windows_claude_pretool_v2: "Windows · Claude Code pre-tool hook",
  linux_claude_pretool_v2_test: "Linux · Claude Code pre-tool test adapter",
} as const;
const receiptCode = /^[a-z][a-z0-9._-]{0,63}$/;
function decodeObservation(row: unknown): EndpointObservationDetail {
  const r = obj(row);
  if (
    (r.adapter !== undefined && (typeof r.adapter !== "string" || !Object.hasOwn(endpointAdapterLabels,r.adapter))) ||
    (r.reason_code !== undefined && (typeof r.reason_code !== "string" || !receiptCode.test(r.reason_code))) ||
    (r.rule_id !== undefined && (typeof r.rule_id !== "string" || r.rule_id !== "" && !receiptCode.test(r.rule_id))) ||
    (r.tool_class !== undefined && r.tool_class !== "mcp" && r.tool_class !== "file" && r.tool_class !== "shell" && r.tool_class !== "web" && r.tool_class !== "other") ||
    typeof r.observed_at !== "string" ||
    !Number.isFinite(Date.parse(r.observed_at)) ||
    (r.mode !== "" && r.mode !== "monitor" && r.mode !== "enforce") ||
    (r.verdict !== "unavailable" && r.verdict !== "continue" && r.verdict !== "deny") ||
    (r.target_class !== "unknown" &&
      r.target_class !== "allowed_destination" &&
      r.target_class !== "outside_allowed_destination") ||
    typeof r.would_block !== "boolean" ||
    r.skill_usage !== "unknown" ||
    r.target_effect !== "unknown" ||
    (r.graph_state === undefined) !== (r.graph_evidence_id === undefined) ||
    (r.graph_state !== undefined && r.graph_state !== "projected" && r.graph_state !== "pending") ||
    (r.graph_evidence_id !== undefined &&
      (typeof r.graph_evidence_id !== "string" || !idPattern.test(r.graph_evidence_id)))
  )
    return invalid();
  return {
    ...(typeof r.adapter === "string" && { adapter:r.adapter }),
    ...(typeof r.reason_code === "string" && { reason_code:r.reason_code }),
    ...(typeof r.rule_id === "string" && { rule_id:r.rule_id }),
    ...(r.tool_class !== undefined && { tool_class:r.tool_class }),
    action_id: digest(r.action_id),
    session_ref: digest(r.session_ref),
    credential_generation: n(r.credential_generation, 1),
    observed_at: r.observed_at,
    policy_revision: n(r.policy_revision),
    mode: r.mode,
    verdict: r.verdict,
    would_block: r.would_block,
    target_class: r.target_class,
    skill_usage: r.skill_usage,
    target_effect: r.target_effect,
    ...(r.graph_state !== undefined &&
      typeof r.graph_evidence_id === "string" && {
        graph_state: r.graph_state,
        graph_evidence_id: r.graph_evidence_id,
      }),
  };
}
export function decodeDetail(data: unknown, id: string): EndpointDetail {
  const r = obj(data),
    partitions = n(r.inventory_partitions),
    observations = n(r.observation_count);
  if (
    typeof r.reported_adapter !== "string" || !Object.hasOwn(endpointAdapterLabels,r.reported_adapter)
  )
    return invalid();
  return {
    ...decodeDevice(data, id),
    inventory_partitions: partitions,
    observation_count: observations,
    reported_adapter: r.reported_adapter as keyof typeof endpointAdapterLabels,
    partition_summaries: boundedRows(r.partition_summaries, partitions, 8, decodePartition),
    recent_observations: boundedRows(r.recent_observations, observations, 20, decodeObservation),
  };
}
export function createFleetAPI(client: APIClient) {
  return {
    async list(cursor?: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.GET("/api/v1/devices", { params: { query: { after_id: cursor, limit: 50 } }, signal }),
        (v) => decodeFleet(v, cursor),
      );
    },
    async get(id: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.GET("/api/v1/devices/{id}", { params: { path: { id } }, signal }),
        (v) => decodeDetail(v, id),
      );
    },
    async register(input: EndpointRegistration, key: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.POST("/api/v1/device-enrollments", {
          params: { header: { "X-CSRF-Token": "", "Idempotency-Key": key } },
          body: input,
          signal,
        }),
        (v) => decodeDevice(v),
      );
    },
    async retire(row: EndpointDevice, key: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.POST("/api/v1/devices/{id}/retire", {
          params: {
            path: { id: row.id },
            header: { "X-CSRF-Token": "", "Idempotency-Key": key, "If-Match": `"${row.version}"` },
          },
          signal,
        }),
        (v) => {
          const result = decodeDevice(v, row.id);
          if (result.state !== "retired") return invalid();
          return result;
        },
      );
    },
  };
}
export type EndpointFleetAPI = ReturnType<typeof createFleetAPI>;
