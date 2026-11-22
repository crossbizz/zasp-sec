import { decodeAddonInstallationPage } from "./addon-installations";
import { APITransportError, requireAPIData, type APIClient } from "./client";

export const addonID =
  /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const rules = [
  "dependency.unpinned",
  "instruction.hidden_text",
  "mcp.remote_endpoint",
  "mcp.unpinned_launcher",
  "script.network_access",
  "script.shell_execution",
];
export type ReviewDecision = "approved" | "rejected" | "revoked";
export type AddonVersion = Readonly<{
  id: string;
  manifest_digest: string;
  origin: "local" | "ci" | "private_worker";
  provenance: "reported";
  ruleset: "zasp-static.v1";
  findings: readonly { rule_id: string; count: number }[];
  review_state: ReviewDecision | "pending";
  revision: number;
}>;
function invalid(): never {
  throw new APITransportError(
    "invalid_response",
    "Invalid add-on registry response",
  );
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return invalid();
  return value as Record<string, unknown>;
}
export function decodeAddonVersion(
  value: unknown,
  expectedID?: string,
): AddonVersion {
  const row = record(value);
  if (
    typeof row.id !== "string" ||
    !addonID.test(row.id) ||
    (expectedID !== undefined && row.id !== expectedID) ||
    typeof row.manifest_digest !== "string" ||
    !digest.test(row.manifest_digest) ||
    row.provenance !== "reported" ||
    (row.origin !== "local" && row.origin !== "ci" && row.origin !== "private_worker") ||
    row.ruleset !== "zasp-static.v1" ||
    (row.review_state !== "pending" &&
      row.review_state !== "approved" &&
      row.review_state !== "rejected" &&
      row.review_state !== "revoked") ||
    typeof row.revision !== "number" ||
    !Number.isSafeInteger(row.revision) ||
    row.revision < 0 ||
    !Array.isArray(row.findings) ||
    row.findings.length > rules.length
  )
    return invalid();
  const seen = new Set<string>();
  const findings = row.findings.map((item) => {
    const f = record(item);
    if (
      typeof f.rule_id !== "string" ||
      !rules.includes(f.rule_id) ||
      seen.has(f.rule_id) ||
      typeof f.count !== "number" ||
      !Number.isSafeInteger(f.count) ||
      f.count < 1
    )
      return invalid();
    seen.add(f.rule_id);
    return { rule_id: f.rule_id, count: f.count };
  });
  return {
    id: row.id,
    manifest_digest: row.manifest_digest,
    origin: row.origin,
    provenance: row.provenance,
    ruleset: row.ruleset,
    findings,
    review_state: row.review_state,
    revision: row.revision,
  };
}
export type AddonReviewAPI = ReturnType<typeof createAddonReviewAPI>;
export function createAddonReviewAPI(client: APIClient) {
  return {
    async list(cursor: string | undefined, signal?: AbortSignal) {
      const limit = 25;
      return requireAPIData(
        await client.GET("/api/v1/addon-versions", {
          params: { query: { cursor, limit } },
          signal,
        }),
        (value) => {
          const page = record(value);
          if (
            !Array.isArray(page.items) ||
            page.items.length > limit ||
            (page.next_cursor !== null &&
              (typeof page.next_cursor !== "string" ||
                !addonID.test(page.next_cursor) ||
                page.next_cursor === cursor))
          )
            return invalid();
          const items = page.items.map((item) => decodeAddonVersion(item));
          if (
            new Set(items.map((item) => item.id)).size !== items.length ||
            (page.next_cursor && items.at(-1)?.id !== page.next_cursor)
          )
            return invalid();
          return { items, next_cursor: page.next_cursor };
        },
      );
    },
    async get(id: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.GET("/api/v1/addon-versions/{id}", {
          params: { path: { id } },
          signal,
        }),
        (value) => decodeAddonVersion(value, id),
      );
    },
    async installations(id: string, cursor?: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.GET("/api/v1/addon-versions/{id}/installations", {
          params: {
            path: { id },
            query: { limit: 25, ...(cursor ? { cursor } : {}) },
          },
          signal,
        }),
        (raw) => decodeAddonInstallationPage(raw, cursor),
      );
    },
    async ciOrigin(id: string, signal?: AbortSignal) {
      return requireAPIData(
        await client.GET("/api/v1/addon-versions/{id}/ci-origin", {
          params: { path: { id } },
          signal,
        }),
        (value) => {
          const origin = record(value);
          if (
            origin.status === "unknown" &&
            [
              origin.match,
              origin.repository,
              origin.commit,
              origin.scan_id,
            ].every((v) => v === null)
          )
            return null;
          if (
            origin.status !== "verified" ||
            (origin.match !== "direct" && origin.match !== "same_manifest") ||
            typeof origin.repository !== "string" ||
            !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(origin.repository) ||
            typeof origin.commit !== "string" ||
            !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(origin.commit) ||
            typeof origin.scan_id !== "string" ||
            !addonID.test(origin.scan_id)
          )
            return invalid();
          return {
            match: origin.match,
            repository: origin.repository,
            commit: origin.commit,
            scanID: origin.scan_id,
          };
        },
      );
    },
    async review(
      version: AddonVersion,
      state: ReviewDecision,
      key: string,
      signal?: AbortSignal,
    ) {
      const result = await client.POST(
        "/api/v1/addon-versions/{id}/review-decisions",
        {
          params: {
            path: { id: version.id },
            header: {
              "Idempotency-Key": key,
              "If-Match": `"${version.revision}"`,
              "X-CSRF-Token": "",
            },
          },
          body: { state },
          signal,
        },
      );
      return requireAPIData(result, (value) => {
        const row = decodeAddonVersion(value, version.id);
        if (
          row.review_state !== state ||
          row.manifest_digest !== version.manifest_digest ||
          row.revision !== version.revision + 1
        )
          return invalid();
        return row;
      });
    },
  };
}
