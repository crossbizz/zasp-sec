import { describe, expect, it } from "vitest";
import { decodeAPITokenCredential, decodeDataControls, decodeOrganization, decodeSessionPage, decodeSystemComponentPage } from "./administration-decoders";

const id = "pid_10000001-0000-4000-8000-000000000001";
describe("administration response decoders", () => {
  it("accepts exact durable shapes and rejects unknown success fields", () => {
    expect(decodeOrganization({ id, name: "Zasp", domain: "zasp.example", version: 1 })).toMatchObject({ version: 1 });
    expect(() => decodeOrganization({ id, name: "Zasp", domain: "zasp.example", version: 1, injected: true })).toThrow("schema mismatch");
    expect(decodeDataControls({ environment_id: id, environment_class: "production", collection_mode: "metadata_only", retention_days: 30, deletion_enabled: true, version: 1 })).toMatchObject({ retention_days: 30 });
  });
  it("requires an exact one-time token credential", () => {
    const token = { id, name: "Automation", principal_id: id, workspace_id: id, environment_id: id, permissions: ["view"], created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-20T00:00:00Z", last_used_at: null, revoked_at: null, version: 1, raw_token: `zasp_pat_${"A".repeat(43)}`, audit_correlation_id: id };
    expect(decodeAPITokenCredential(token).raw_token).toBe(token.raw_token);
    expect(() => decodeAPITokenCredential({ ...token, raw_token: "stored-secret" })).toThrow("schema mismatch");
  });
  it("accepts PostgreSQL RFC 3339 offsets without accepting informal dates", () => {
    const token = { id, name: "Automation", principal_id: id, workspace_id: id, environment_id: id, permissions: ["view"], created_at: "2026-08-19T00:00:00+00:00", expires_at: "2026-08-20T01:02:03.456-07:00", last_used_at: null, revoked_at: null, version: 1, raw_token: `zasp_pat_${"A".repeat(43)}`, audit_correlation_id: id };
    expect(decodeAPITokenCredential(token).created_at).toBe(token.created_at);
    expect(() => decodeAPITokenCredential({ ...token, created_at: "August 19, 2026" })).toThrow("schema mismatch");
  });
  it("bounds session pages and component inventories", () => {
    expect(decodeSessionPage({ items: [], page_info: { next_cursor: null, has_more: false } }).items).toEqual([]);
    expect(() => decodeSessionPage({ items: [], page_info: { next_cursor: "forged", has_more: false } })).toThrow("schema mismatch");
    expect(decodeSystemComponentPage({ items: [{ id: "postgresql", required: true, state: "healthy", fresh_at: "2026-08-19T00:00:00Z" }] }).items).toHaveLength(1);
    expect(() => decodeSystemComponentPage({ items: [{ id: "fabricated", required: true, state: "ready", fresh_at: "2026-08-19T00:00:00Z" }] })).toThrow("schema mismatch");
  });
});
