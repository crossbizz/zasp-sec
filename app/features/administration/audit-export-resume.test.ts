import { beforeEach, expect, it } from "vitest";
import { loadAuditExportResume, storeAuditExportResume, type AuditExportIdentity } from "./audit-export-resume";
const id = "pid_10000001-0000-4000-8000-000000000001";
const identity: AuditExportIdentity = { principalID: id, organizationID: id, workspaceID: id, environmentID: id };
beforeEach(() => sessionStorage.clear());
it("restores only a bounded exact-identity key/job record in a new reader", () => {
  storeAuditExportResume(sessionStorage, { ...identity, key: "audit_export_0123456789", exportID: id });
  expect(loadAuditExportResume(sessionStorage, { ...identity })).toEqual({ ...identity, key: "audit_export_0123456789", exportID: id });
  expect(sessionStorage.length).toBe(1);
  expect(sessionStorage.getItem(sessionStorage.key(0)!)).not.toMatch(/csrf|cursor|contents|cookie/);
});
it.each(["principalID", "organizationID", "workspaceID", "environmentID"] as const)("never restores a different %s", field => {
  storeAuditExportResume(sessionStorage, { ...identity, key: "audit_export_0123456789" });
  expect(loadAuditExportResume(sessionStorage, { ...identity, [field]: "pid_10000002-0000-4000-8000-000000000002" })).toBeNull();
});
it("rejects oversized, malformed and extra-field storage without replay", () => {
  storeAuditExportResume(sessionStorage, { ...identity, key: "audit_export_0123456789" });
  const storageKey = sessionStorage.key(0)!;
  for (const value of ["x".repeat(2049), "{", JSON.stringify({ ...identity, key: "audit_export_0123456789", cursor: "secret" }), JSON.stringify({ ...identity, key: "short" })]) {
    sessionStorage.setItem(storageKey, value);
    expect(loadAuditExportResume(sessionStorage, identity)).toBeNull();
  }
});
it("fails closed for unavailable persistence before a new POST can be attempted", () => {
  const unavailable = { getItem: () => { throw new Error("disabled"); }, setItem: () => { throw new Error("disabled"); }, removeItem: () => {} };
  expect(loadAuditExportResume(unavailable, identity)).toBeNull();
  expect(() => storeAuditExportResume(unavailable, { ...identity, key: "audit_export_0123456789" })).toThrow();
});
