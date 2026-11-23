import { beforeEach, expect, it, vi } from "vitest";
import { loadAuditExportResume, parseAuditExportLink, storeAuditExportResume, type AuditExportIdentity } from "./audit-export-resume";
const id = "pid_10000001-0000-4000-8000-000000000001";
const identity: AuditExportIdentity = { principalID: id, organizationID: id, workspaceID: id, environmentID: id };
const key = "audit_export_10000002-0000-4000-8000-000000000002";
beforeEach(() => window.history.replaceState({}, "", "/administration/audit-log"));
it("resumes an opaque audit request and status from the exact scoped link", () => {
  const record = { ...identity, key, exportID: id };
  storeAuditExportResume(record);
  expect(loadAuditExportResume(identity)).toEqual(record);
  expect(window.location.href).not.toMatch(/token|grant|cursor|audit_export_|secret/);
  expect(window.location.search).toContain("export_request=10000002");
});
it.each(["principalID", "organizationID", "workspaceID", "environmentID"] as const)("rejects a changed %s", field => {
  storeAuditExportResume({ ...identity, key });
  expect(loadAuditExportResume({ ...identity, [field]: "pid_10000002-0000-4000-8000-000000000002" })).toBeNull();
});
it("rejects malformed or expanded selectors without replay", () => {
  storeAuditExportResume({ ...identity, key });
  const link = window.location.pathname + window.location.search;
  for (const target of [link + "&cursor=extra", link + "&export_id=bad", link + "#grant", link.replace("export_request=1", "export_request=Z")]) expect(parseAuditExportLink(target, identity)).toEqual({ state: "invalid" });
});
it("fails before sending if the request cannot be bookmarked", () => {
  const save = vi.spyOn(window.history, "replaceState").mockImplementation(() => { throw Error("unavailable"); });
  try { expect(() => storeAuditExportResume({ ...identity, key })).toThrow(); } finally { save.mockRestore(); }
});
