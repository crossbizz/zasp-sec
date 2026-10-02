import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { beforeEach, expect, it, vi } from "vitest";
import { APITransportError } from "../../../apps/web/api/client";
import type { AuditExportRead } from "../../../apps/web/api/generated";
import { saveAuditExport, type ExportDirectory, type ExportWriter } from "./audit-export-save";
const page = (name: string): AuditExportRead => JSON.parse(readFileSync(`apps/web/api/testdata/audit-export-${name}.json`, "utf8"));
beforeEach(() => vi.stubGlobal("crypto", webcrypto));
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }
function fixture(hook: (name: string, step: string) => Promise<void> = async () => {}) {
  const files = new Map<string, Uint8Array>(); const sequence: string[] = []; const existing = new Set<string>();
  const destination: ExportDirectory = {
    async getDirectoryHandle() { throw new DOMException("missing", "NotFoundError"); },
    async *keys() { yield* existing; },
    async getFileHandle(name, options) {
      if (!options?.create) { if (!existing.has(name)) throw new DOMException("missing", "NotFoundError"); }
      else { existing.add(name); sequence.push(`open:${name}`); }
      return { async createWritable(): Promise<ExportWriter> { let pending: Uint8Array | undefined; return {
        async write(bytes) { await hook(name, "write"); pending = bytes; sequence.push(`write:${name}`); },
        async close() { await hook(name, "close"); if (pending) files.set(name, pending); sequence.push(`close:${name}`); },
        async abort() { sequence.push(`abort:${name}`); },
      }; } };
    },
  };
  const parent: ExportDirectory = { ...destination, async getDirectoryHandle(name, options) { sequence.push(`${options?.create ? "create" : "probe"}:${name}`); if (!options?.create) throw new DOMException("missing", "NotFoundError"); return destination; } };
  const signal = new AbortController();
  const progress: number[] = []; const cursors: (string | undefined)[] = [];
  const options = { parent, exportID: page("read").export.id, signal: signal.signal, isCurrent: () => true,
    read: async (_id: string, cursor: string | undefined) => { cursors.push(cursor); return page(cursor ? "page-two" : "page-one"); },
    onProgress: (value: { chunkCount: number }) => { progress.push(value.chunkCount); }, onFinalizing: () => {}, };
  return { options, files, sequence, existing, destination, parent, signal, progress, cursors };
}
it("writes exact Go chunks sequentially and manifest last, then reports saved", async () => {
  const f = fixture(); const result = await saveAuditExport(f.options);
  expect(result.status).toBe("saved"); expect(f.cursors).toEqual([undefined, "next_2"]); expect(f.progress).toEqual([1, 2]);
  expect([...f.files.keys()]).toEqual(["chunk-000001.json", "chunk-000002.json", "manifest.json"]);
  expect(new TextDecoder().decode(f.files.get("chunk-000001.json"))).toBe(readFileSync("apps/web/api/testdata/audit-export-chunk.json", "utf8"));
  expect(f.sequence.indexOf("close:chunk-000001.json")).toBeLessThan(f.sequence.indexOf("open:chunk-000002.json"));
  expect(f.sequence.at(-1)).toBe("close:manifest.json");
});
it("saves the legal empty manifest without fabricating a chunk", async () => {
  const f = fixture(); const result = await saveAuditExport({ ...f.options, read: async () => page("empty") });
  expect(result.status).toBe("saved"); expect([...f.files.keys()]).toEqual(["manifest.json"]); expect(f.progress).toEqual([0]);
});
it.each(["corrupt", "repeat", "wrong-chain", "network"])("refuses %s and never publishes a final manifest", async mode => {
  const f = fixture(); let reads = 0;
  const result = await saveAuditExport({ ...f.options, read: async () => {
    if (++reads === 1) return page("page-one");
    if (mode === "network") throw new Error("network lost");
    if (mode === "repeat") return page("page-one");
    const next = JSON.parse(JSON.stringify(page("page-two")));
    if (mode === "corrupt") next.contents.chunk.events[0].metadata["10"] = "TEN";
    else next.contents.chunk.previous_digest = "a".repeat(64);
    return next;
  } });
  expect(result.status).toBe("incomplete"); expect(f.files.has("manifest.json")).toBe(false); expect(f.progress).toEqual([1]);
});
it("refuses an existing random child, an occupied new child and a known chunk", async () => {
  const collision = fixture(); collision.parent.getDirectoryHandle = async () => collision.destination;
  expect((await saveAuditExport(collision.options)).status).toBe("incomplete"); expect(collision.files.size).toBe(0);
  const occupied = fixture(); occupied.existing.add("user-data.txt");
  expect((await saveAuditExport(occupied.options)).status).toBe("incomplete"); expect(occupied.files.size).toBe(0);
  const chunk = fixture(); chunk.options.read = async () => { chunk.existing.add("chunk-000001.json"); return page("page-one"); };
  expect((await saveAuditExport(chunk.options)).status).toBe("incomplete"); expect(chunk.files.size).toBe(0);
});
it("refuses a manifest collision without touching that file", async () => {
  const f = fixture(); const result = await saveAuditExport({ ...f.options, onFinalizing: () => { f.existing.add("manifest.json"); } });
  expect(result.status).toBe("unconfirmed"); expect(f.sequence).not.toContain("open:manifest.json");
});
it("does not adopt progress before close and joins cancellation during a chunk write", async () => {
  const held = deferred(); const entered = deferred();
  const f = fixture(async (name, step) => { if (name === "chunk-000001.json" && step === "write") { entered.resolve(); await held.promise; } });
  let settled = false; const pending = saveAuditExport(f.options).then(r => { settled = true; return r; });
  await entered.promise; expect(f.progress).toEqual([]); f.signal.abort(); await Promise.resolve(); expect(settled).toBe(false);
  held.resolve(); expect((await pending).status).toBe("incomplete"); expect(f.sequence).toContain("abort:chunk-000001.json"); expect(f.files.has("manifest.json")).toBe(false);
});
it.each(["write", "close"])("joins cancellation and changed authority during final %s and reports the successful close", async step => {
  const held = deferred(); const entered = deferred(); let current = true;
  const f = fixture(async (name, at) => { if (name === "manifest.json" && at === step) { entered.resolve(); await held.promise; } });
  const pending = saveAuditExport({ ...f.options, isCurrent: () => current });
  await entered.promise; current = false; f.signal.abort(); held.resolve();
  expect((await pending).status).toBe("saved"); expect(f.files.has("manifest.json")).toBe(true);
});
it.each(["chunk-000001.json", "manifest.json"])("never reports saved when %s close rejects", async file => {
  const f = fixture(async (name, step) => { if (name === file && step === "close") throw new Error("disk rejected"); });
  expect((await saveAuditExport(f.options)).status).toBe(file === "manifest.json" ? "unconfirmed" : "incomplete");
  expect(f.files.has("manifest.json")).toBe(false);
});
it("checks authority after the final chunk closes and before finalization", async () => {
  let current = true; const f = fixture(async (name, step) => { if (name === "chunk-000002.json" && step === "close") current = false; });
  expect((await saveAuditExport({ ...f.options, isCurrent: () => current })).status).toBe("incomplete"); expect(f.files.has("manifest.json")).toBe(false);
});
it("pauses a timed-out read, retries its exact cursor and never rewrites a committed chunk", async () => {
  const f = fixture(); const retry = deferred(); const waiting = deferred(); let reads = 0;
  const cursors: (string | undefined)[] = [];
  const pending = saveAuditExport({ ...f.options, read: async (_id, cursor) => { cursors.push(cursor); if (++reads === 2) throw new APITransportError("timeout", "timeout"); return page(cursor ? "page-two" : "page-one"); },
    ...{ waitForReadRetry: async () => { waiting.resolve(); await retry.promise; } } });
  await Promise.race([waiting.promise, pending]);
  expect(f.progress).toEqual([1]); expect(f.files.has("manifest.json")).toBe(false);
  retry.resolve(); expect((await pending).status).toBe("saved");
  expect(cursors).toEqual([undefined, "next_2", "next_2"]);
  expect(f.sequence.filter(item => item === "open:chunk-000001.json")).toHaveLength(1);
});
it("checks cancellation after a read-retry pause before any further request", async () => {
  const f = fixture(); let calls = 0;
  const result = await saveAuditExport({ ...f.options, read: async () => { calls++; throw new APITransportError("timeout", "timeout"); }, waitForReadRetry: async () => { f.signal.abort(); } });
  expect(result.status).toBe("incomplete"); expect(calls).toBe(1); expect(f.files.size).toBe(0);
});
