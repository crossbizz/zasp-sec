import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { encodeAuditExportChunk, encodeAuditExportEvent, encodeAuditExportManifest, verifyAuditExportPage, verifyAuditExportRead } from "./audit-export-codec";
const raw = (name: string) => readFileSync(`apps/web/api/testdata/audit-export-${name}.json`, "utf8");
const parsed = (name: string) => JSON.parse(raw(name));
beforeEach(() => vi.stubGlobal("crypto", webcrypto));

describe("Go canonical audit export bytes", () => {
  it.each(["queued", "processing", "failed"])("rejects coerced %s descriptors before the no-content verification return", async status => {
    const descriptor = { ...parsed("read").export, status, event_count: null, ...(status === "failed" ? { failure_code: "capacity_exceeded" } : {}) };
    for (const field of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[field];
    const read = { export: descriptor, contents: null };
    await expect(verifyAuditExportRead(read)).resolves.toEqual({ read, manifestBytes: null, chunkBytes: null });
    if (status === "failed") descriptor.failure_code = ["capacity_exceeded"];
    else descriptor.status = [status];
    await expect(verifyAuditExportRead(read)).rejects.toThrow("Invalid audit export contract");
  });
  it("verifies two real Go pages in order and an empty terminal manifest", async () => {
    const first = await verifyAuditExportPage(parsed("page-one"));
    expect(first.progress.complete).toBe(false);
    const second = await verifyAuditExportPage(parsed("page-two"), first.progress);
    expect(second.progress).toMatchObject({ complete: true, eventCount: 2, chunkCount: 2, nextCursor: null });
    await expect(verifyAuditExportPage(parsed("page-two"))).rejects.toThrow();
    await expect(verifyAuditExportPage(parsed("page-one"), first.progress)).rejects.toThrow();
    await expect(verifyAuditExportPage(parsed("page-two"), { ...first.progress, chunkBytes: first.progress.chunkBytes-1 })).rejects.toThrow();
    await expect(verifyAuditExportPage(parsed("page-two"), { ...first.progress, previousDigest: "b".repeat(64) })).rejects.toThrow();
    await expect(verifyAuditExportPage(parsed("read"), first.progress)).rejects.toThrow();
    expect((await verifyAuditExportPage(parsed("empty"))).progress).toMatchObject({ complete: true, eventCount: 0, chunkCount: 0, chunkBytes: 0, previousDigest: "0".repeat(64) });
  });
  it("matches real Go event/chunk/manifest bytes including UTF8 key order and Go escapes", () => {
    for (const [name, encode] of [["event", encodeAuditExportEvent], ["chunk", encodeAuditExportChunk], ["manifest", encodeAuditExportManifest]] as const) {
      expect(new TextDecoder().decode(encode(parsed(name)))).toBe(raw(name));
    }
    expect(raw("event").indexOf('"10"')).toBeLessThan(raw("event").indexOf('"2"'));
    expect(raw("event").indexOf('"\ue000"')).toBeLessThan(raw("event").indexOf('"😀"'));
  });
  it("hashes the bytes to the pinned Go digest and produces only bounded progress", async () => {
    const page = await verifyAuditExportPage(parsed("read"));
    if (page.chunkBytes === null || page.manifestBytes === null) throw new Error("Ready Go vector omitted verified bytes");
    expect(new TextDecoder().decode(page.chunkBytes)).toBe(raw("chunk"));
    expect(new TextDecoder().decode(page.manifestBytes)).toBe(raw("manifest"));
    expect(page.progress).toMatchObject({ eventCount: 1, chunkCount: 1, chunkBytes: 1060, previousDigest: "52493e93a2fae272ec64df64fdd97bcfb1a669681f9e01241212fc25120b8016", complete: true });
    expect(Object.values(page.progress).some(Array.isArray)).toBe(false);
  });
  it("rejects same-length corruption, changed manifest, repeated ordinal/cursor and incomplete coverage", async () => {
    const changed = parsed("read"); changed.contents.chunk.events[0].metadata["10"] = "TEN";
    await expect(verifyAuditExportPage(changed)).rejects.toThrow();
    const manifest = parsed("read"); manifest.contents.manifest.chain_root = "a".repeat(64);
    await expect(verifyAuditExportPage(manifest)).rejects.toThrow();
    const first = await verifyAuditExportPage(parsed("near-bound"));
    await expect(verifyAuditExportPage(parsed("near-bound"), first.progress)).rejects.toThrow();
    const wrong = { ...first.progress, previousDigest: "b".repeat(64) };
    await expect(verifyAuditExportPage(parsed("read"), wrong)).rejects.toThrow();
  });
  it("accepts a legal one-MiB chunk in the actual Go public envelope", async () => {
    const page = await verifyAuditExportPage(parsed("near-bound"));
    expect(page.chunkBytes?.byteLength).toBe(1048576);
    expect(page.progress.complete).toBe(false);
    expect(page.progress.eventCount).toBe(1000);
  });
});
