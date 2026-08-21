import { describe, expect, it } from "vitest";
import { decodeAPITokenRevealGrant, decodeAPITokenRevealedCredential, decodeComplianceEvidencePage, decodeConnectionDeletion, decodeConnectionTest, decodeDataControls, decodeOrganization, decodeSCIMConnectionCredential, decodeSCIMConnectionPage, decodeSessionPage, decodeSSOConnectionMutation, decodeSSOConnectionPage, decodeSystemComponentPage } from "./administration-decoders";

const id = "pid_10000001-0000-4000-8000-000000000001";
describe("administration response decoders", () => {
  it("accepts exact durable shapes and rejects unknown success fields", () => {
    expect(decodeOrganization({ id, name: "Zasp", domain: "zasp.example", version: 1 })).toMatchObject({ version: 1 });
    expect(() => decodeOrganization({ id, name: "Zasp", domain: "zasp.example", version: 1, injected: true })).toThrow("schema mismatch");
    expect(decodeDataControls({ environment_id: id, environment_class: "production", collection_mode: "metadata_only", retention_days: 30, deletion_enabled: true, version: 1 })).toMatchObject({ retention_days: 30 });
  });
  it("separates exact durable reveal metadata from the bounded revealed credential", () => {
    const token = { id, name: "Automation", principal_id: id, workspace_id: id, environment_id: id, permissions: ["view"], created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-20T00:00:00Z", last_used_at: null, revoked_at: null, version: 1, audit_correlation_id: id };
    const grant = { grant_id: id, expires_at: "2026-08-19T00:05:00Z", token };
    expect(decodeAPITokenRevealGrant(grant).grant_id).toBe(id);
    expect(() => decodeAPITokenRevealGrant({ ...grant, raw_token: `zasp_pat_${"A".repeat(43)}` })).toThrow("schema mismatch");
    const revealed = { grant_id: id, token_id: id, expires_at: grant.expires_at, raw_token: `zasp_pat_${"A".repeat(43)}` };
    expect(decodeAPITokenRevealedCredential(revealed).raw_token).toBe(revealed.raw_token);
    expect(() => decodeAPITokenRevealedCredential({ ...revealed, raw_token: "stored-secret" })).toThrow("schema mismatch");
  });
  it("accepts PostgreSQL RFC 3339 offsets without accepting informal dates", () => {
    const token = { id, name: "Automation", principal_id: id, workspace_id: id, environment_id: id, permissions: ["view"], created_at: "2026-08-19T00:00:00+00:00", expires_at: "2026-08-20T01:02:03.456-07:00", last_used_at: null, revoked_at: null, version: 1, audit_correlation_id: id };
    const grant = { grant_id: id, expires_at: "2026-08-19T00:05:00+00:00", token };
    expect(decodeAPITokenRevealGrant(grant).token.created_at).toBe(token.created_at);
    expect(() => decodeAPITokenRevealGrant({ ...grant, token: { ...token, created_at: "August 19, 2026" } })).toThrow("schema mismatch");
  });
  it("bounds session pages and component inventories", () => {
    expect(decodeSessionPage({ items: [], page_info: { next_cursor: null, has_more: false } }).items).toEqual([]);
    expect(() => decodeSessionPage({ items: [], page_info: { next_cursor: "forged", has_more: false } })).toThrow("schema mismatch");
    expect(decodeSystemComponentPage({ items: [{ id: "postgresql", required: true, state: "healthy", fresh_at: "2026-08-19T00:00:00Z" }] }).items).toHaveLength(1);
    expect(() => decodeSystemComponentPage({ items: [{ id: "fabricated", required: true, state: "ready", fresh_at: "2026-08-19T00:00:00Z" }] })).toThrow("schema mismatch");
  });
  it("requires exactly one evidence record in every paged compliance item", () => {
    const evidence = { id: "evidence-1", asset_id: "asset-1", source: "runtime", at: "2026-08-19T00:00:00Z" };
    const item = { control: { id: "control-1", framework: "SOC 2", name: "Access control", evidence_ids: ["evidence-1"], fresh_until: "2026-08-20T00:00:00Z" }, freshness: "fresh", evidence: [evidence] };
    const page = (items: unknown[]) => ({ items, page_info: { next_cursor: null, has_more: false } });
    expect(decodeComplianceEvidencePage(page([item])).items[0]?.evidence).toEqual([evidence]);
    expect(() => decodeComplianceEvidencePage(page([{ ...item, evidence: [] }]))).toThrow("schema mismatch");
    expect(() => decodeComplianceEvidencePage(page([{ ...item, evidence: [evidence, { ...evidence, id: "evidence-2" }] }]))).toThrow("schema mismatch");
  });
  it("strictly decodes tenant SSO and SCIM administration without leaking list credentials", () => {
    const pageInfo = { next_cursor: null, has_more: false };
    const sso = { id: "saml-connection-live-a", status: "active", display_name: "Corporate SAML", protocol: "saml", identity_provider: "okta" };
    const scim = { id: "scim-connection-live-a", status: "pending", display_name: "Corporate SCIM", identity_provider: "okta", base_url: "https://scim.stytch.com/v2/live-a" };
    expect(decodeSSOConnectionPage({ items: [sso], page_info: pageInfo }).items[0]).toEqual(sso);
    expect(decodeSCIMConnectionPage({ items: [scim], page_info: pageInfo }).items[0]).toEqual(scim);
    expect(decodeSSOConnectionMutation({ ...sso, audit_correlation_id: id }).audit_correlation_id).toBe(id);
    const credential = { ...scim, status: "active", bearer_token: "scim_bearer_token_recoverable", audit_correlation_id: id };
    expect(decodeSCIMConnectionCredential(credential).bearer_token).toBe(credential.bearer_token);
    expect(decodeConnectionDeletion({ id: sso.id, audit_correlation_id: id }).id).toBe(sso.id);
    expect(decodeConnectionTest({ healthy: true, audit_correlation_id: id }).healthy).toBe(true);
    expect(() => decodeSCIMConnectionPage({ items: [{ ...scim, bearer_token: credential.bearer_token }], page_info: pageInfo })).toThrow("schema mismatch");
    expect(() => decodeSSOConnectionPage({ items: [{ ...sso, status: "connected" }], page_info: pageInfo })).toThrow("schema mismatch");
    expect(() => decodeSCIMConnectionCredential({ ...credential, bearer_token: "provider-secret" })).toThrow("schema mismatch");
  });
});
