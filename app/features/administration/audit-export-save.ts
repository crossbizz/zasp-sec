import type { AuditExportsAPI } from "../../../apps/web/api/audit-exports";
import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import { verifyAuditExportPage, type AuditExportProgress } from "../../../apps/web/api/audit-export-codec";

// Structural subset of File System Access, also usable by bounded test writers.
export interface ExportWriter {
  write(bytes: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}
export interface ExportDirectory {
  getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<ExportDirectory>;
  getFileHandle(name: string, options?: { create?: boolean }): Promise<{ createWritable(): Promise<ExportWriter> }>;
  keys(): AsyncIterableIterator<string>;
}
export type AuditExportSaveResult = Readonly<{ status: "saved" | "incomplete" | "unconfirmed"; error?: unknown }>;
export function directoryPicker(): (() => Promise<ExportDirectory>) | null {
  if (typeof window === "undefined" || !window.isSecureContext) return null;
  const browser = window as Window & { showDirectoryPicker?: (options: { mode: "readwrite" }) => Promise<ExportDirectory> };
  return browser.showDirectoryPicker ? () => browser.showDirectoryPicker!({ mode: "readwrite" }) : null;
}
async function refuseExisting(directory: ExportDirectory, name: string, kind: "directory" | "file") {
  try {
    if (kind === "directory") await directory.getDirectoryHandle(name);
    else await directory.getFileHandle(name);
  } catch (error) {
    if (error instanceof DOMException && error.name === "NotFoundError") return;
    throw error;
  }
  throw new Error("Destination already exists; nothing will be overwritten");
}
export async function saveAuditExport(options: {
  parent: ExportDirectory; exportID: string; read: AuditExportsAPI["read"]; signal: AbortSignal;
  isCurrent(): boolean; onProgress(progress: AuditExportProgress): void; onFinalizing(): void;
  waitForReadRetry?(error: unknown): Promise<void>;
}): Promise<AuditExportSaveResult> {
  let finalizing = false;
  const check = () => { options.signal.throwIfAborted(); if (!options.isCurrent()) throw new DOMException("Export authority changed", "AbortError"); };
  async function write(directory: ExportDirectory, name: string, bytes: Uint8Array<ArrayBuffer>) {
    if (!finalizing) check();
    await refuseExisting(directory, name, "file");
    if (!finalizing) check();
    const file = await directory.getFileHandle(name, { create: true });
    if (!finalizing) check();
    const writer = await file.createWritable();
    try {
      if (!finalizing) check();
      await writer.write(bytes);
      if (!finalizing) check();
      await writer.close();
    } catch (error) {
      // Join every owned operation. Never delete user files or claim rollback.
      try { await writer.abort(); } catch { /* Original failure remains the save outcome. */ }
      throw error;
    }
  }
  try {
    check();
    const name = `audit-export-${options.exportID}-${crypto.randomUUID()}`;
    await refuseExisting(options.parent, name, "directory"); check();
    const directory = await options.parent.getDirectoryHandle(name, { create: true }); check();
    // Probe/create is not atomic exclusive creation against another local actor.
    for await (const entry of directory.keys()) { throw new Error(`Destination is not empty (${entry ? "entry present" : "unknown entry"})`); }
    let progress: AuditExportProgress | undefined;
    for (;;) {
      check();
      const read = await (async () => {
        for (;;) {
          check();
          try { return await options.read(options.exportID, progress?.nextCursor ?? undefined, options.signal); }
          catch (error) {
            check();
            if (!options.waitForReadRetry || !(error instanceof APIProductError && error.status === 503 || error instanceof APITransportError && error.kind === "timeout" || error instanceof TypeError)) throw error;
            await options.waitForReadRetry(error);
          }
        }
      })(); check();
      const page = await verifyAuditExportPage(read, progress); check();
      if (read.export.id !== options.exportID) throw new Error("Export identity mismatch");
      if (page.chunkBytes) await write(directory, `chunk-${String(page.progress.chunkCount).padStart(6, "0")}.json`, page.chunkBytes);
      check();
      progress = page.progress;
      options.onProgress(progress);
      if (progress.complete) {
        check();
        if (!page.manifestBytes) throw new Error("Missing verified manifest");
        // From here onward, cancellation cannot erase the actual close outcome.
        finalizing = true; options.onFinalizing();
        await write(directory, "manifest.json", page.manifestBytes);
        return { status: "saved" };
      }
    }
  } catch (error) { return { status: finalizing ? "unconfirmed" : "incomplete", error }; }
}
