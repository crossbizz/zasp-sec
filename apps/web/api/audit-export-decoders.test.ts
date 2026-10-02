import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeAuditExport, decodeAuditExportEvent, decodeAuditExportRead } from "./audit-export-decoders";

const read = () => JSON.parse(readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8"));
const near = () => JSON.parse(readFileSync("apps/web/api/testdata/audit-export-near-bound.json", "utf8"));

describe("strict audit export wire decoding", () => {
  it.each(["queued", "processing", "failed"])("rejects array-coerced %s status through descriptor and read decoding", status => {
    const descriptor = { ...read().export, status: [status], event_count: null };
    for (const field of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[field];
    expect(() => decodeAuditExport(descriptor)).toThrow("Invalid audit export contract");
    expect(() => decodeAuditExportRead({ export: descriptor, contents: null })).toThrow("Invalid audit export contract");
  });
  it.each(["capacity_exceeded", "invalid_source", "execution_failed"])("requires a string %s failure code through descriptor and read decoding", failure_code => {
    const descriptor = { ...read().export, status: "failed", event_count: null, failure_code };
    for (const field of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[field];
    expect(decodeAuditExport(descriptor)).toEqual(descriptor);
    expect(decodeAuditExportRead({ export: descriptor, contents: null })).toEqual({ export: descriptor, contents: null });
    for (const invalid of [[failure_code], [[failure_code]], null, true, 0, {}, "unknown"]) {
      const changed = { ...descriptor, failure_code: invalid };
      expect(() => decodeAuditExport(changed)).toThrow("Invalid audit export contract");
      expect(() => decodeAuditExportRead({ export: changed, contents: null })).toThrow("Invalid audit export contract");
    }
  });
  it.each(["succeeded", "failed", "denied"])("requires a string %s event outcome through event and read decoding", outcome => {
    const value = read();
    value.contents.chunk.events[0].outcome = outcome;
    expect(decodeAuditExportEvent(value.contents.chunk.events[0]).outcome).toBe(outcome);
    expect(decodeAuditExportRead(value)).toEqual(value);
    for (const invalid of [[outcome], [[outcome]], null, true, 0, {}, "unknown"]) {
      value.contents.chunk.events[0].outcome = invalid;
      expect(() => decodeAuditExportEvent(value.contents.chunk.events[0])).toThrow("Invalid audit export contract");
      expect(() => decodeAuditExportRead(value)).toThrow("Invalid audit export contract");
    }
  });
  it("accepts actual Go ready and near-bound envelopes plus exact pending/failed states", () => {
    expect(decodeAuditExportRead(read())).toEqual(read());
    expect(decodeAuditExportRead(near())).toEqual(near());
    const d = read().export;
    for (const field of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete d[field];
    for (const status of ["queued", "processing", "failed"]) {
      const descriptor = { ...d, status, event_count: null, ...(status === "failed" ? { failure_code: "capacity_exceeded" } : {}) };
      expect(decodeAuditExport(descriptor)).toEqual(descriptor);
      expect(decodeAuditExportRead({ export: descriptor, contents: null })).toEqual({ export: descriptor, contents: null });
    }
  });
  it("rejects omitted, unknown, cross-bound and state-inconsistent fields", () => {
    const mutations: ((v: ReturnType<typeof read>) => void)[] = [
      v => { delete v.export.event_count; }, v => { v.export.object_url = "https://provider.invalid"; },
      v => { v.export.status = "processing"; }, v => { v.contents = null; },
      v => { v.contents.manifest.binding.export_id = v.contents.manifest.binding.capture_id; },
      v => { v.contents.chunk.binding.capture_id = v.export.id; },
      v => { v.contents.chunk.events[0].organization_id = v.contents.chunk.events[0].workspace_id; },
      v => { v.contents.manifest.event_count++; }, v => { v.contents.chunk.first_event = 2; },
      v => { v.contents.chunk.events[0].ordinal = 2; }, v => { v.contents.chunk.events[0].private = true; },
      v => { v.contents.page_info.has_more = true; }, v => { v.contents.chunk_sha256 = null; },
      v => { v.contents.chunk.previous_digest = "a".repeat(64); },
    ];
    for (const mutate of mutations) { const v = read(); mutate(v); expect(() => decodeAuditExportRead(v)).toThrow(); }
  });
  it("rejects unsafe counts, invalid calendar dates, non-scalars, controls and byte-overlong text", () => {
    for (const count of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      const v = read(); v.export.chunk_bytes = count; expect(() => decodeAuditExportRead(v)).toThrow();
    }
    for (const stamp of ["2026-02-29T00:00:00.000000Z", "0001-01-01T00:00:00.000000Z", "0000-01-01T00:00:00.000000Z", "2026-09-12T08:09:10.123Z", "2026-09-12T08:09:60.123456Z"]) {
      const v = read(); v.contents.chunk.events[0].occurred_at = stamp; expect(() => decodeAuditExportRead(v)).toThrow();
    }
    for (const value of ["\ud800", "\udfff", "ok\n", "\u0000", "\u007f", "é".repeat(257)]) {
      const v = read(); v.contents.chunk.events[0].metadata.message = value; expect(() => decodeAuditExportRead(v)).toThrow();
    }
    const secret = read(); secret.contents.chunk.events[0].metadata.TOKEN = "secret";
    expect(() => decodeAuditExportRead(secret)).toThrow();
    const dotted = read(); dotted.contents.chunk.events[0].metadata["CREDENTİAL"] = "secret";
    expect(() => decodeAuditExportRead(dotted)).toThrow();
  });
});
