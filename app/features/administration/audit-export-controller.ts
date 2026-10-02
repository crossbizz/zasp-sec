import type { AuditExportsAPI } from "../../../apps/web/api/audit-exports";
import type { AuditExport } from "../../../apps/web/api/generated";
import { APIProductError } from "../../../apps/web/api/client";
import type { AuditExportProgress } from "../../../apps/web/api/audit-export-codec";
import { loadAuditExportResume, storeAuditExportResume, type AuditExportIdentity, type AuditExportResume } from "./audit-export-resume";
import { saveAuditExport, type ExportDirectory } from "./audit-export-save";

export type AuditExportAuthority = AuditExportIdentity & Readonly<{ generation: number; permitted: boolean; fresh: boolean; isCurrent?: () => boolean }>;
type Phase = "idle" | "creating" | "ambiguous" | "queued" | "processing" | "ready" | "failed" | "checking" | "paused" | "saving" | "read-retry" | "finalizing" | "saved" | "incomplete" | "unconfirmed" | "revalidating" | "error";
export type AuditExportState = Readonly<{ phase: Phase; descriptor: AuditExport | null; resume: AuditExportResume | null; progress: AuditExportProgress | null; message: string | null; busy: boolean }>;
// Remounts join the physical operation, even if a transport ignores abort.
const lanes = new WeakMap<AuditExportsAPI, Promise<void>>();
let finalNotice = "";
const noticeListeners = new Set<() => void>();
export const exportSaveNotice = { snapshot: () => finalNotice, subscribe: (listener: () => void) => { noticeListeners.add(listener); return () => { noticeListeners.delete(listener); }; } };
function publishFinalNotice(message: string) { finalNotice = message; noticeListeners.forEach(listener => listener()); }
export class AuditExportController {
  private state: AuditExportState;
  private listeners = new Set<() => void>();
  private active: AbortController | null = null;
  private owned: Promise<void> = Promise.resolve();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private disposed = false;
  private pollUntil = 0;
  private delay = 2000;
  private readRetry: (() => void) | null = null;
  private fresh: boolean;
  constructor(private readonly options: { api: AuditExportsAPI; authority: AuditExportAuthority; storage: Pick<Storage, "getItem" | "setItem" | "removeItem">; retrySession(): Promise<void> }) {
    const resume = loadAuditExportResume(options.storage, options.authority);
    this.fresh = options.authority.fresh;
    this.state = { phase: "idle", descriptor: null, resume, progress: null, message: null, busy: false };
  }
  snapshot = () => this.state;
  setFresh = (fresh: boolean) => { this.fresh = fresh; };
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  attach = () => {
    // React may replay setup/cleanup in development. A revived owner still
    // joins its prior aborted physical operation through the same API lane.
    if (this.disposed) {
      this.disposed = false;
      this.patch({ resume: loadAuditExportResume(this.options.storage, this.options.authority) });
    }
  };
  private patch(update: Partial<AuditExportState>) {
    if (this.disposed) return;
    this.state = { ...this.state, ...update }; this.listeners.forEach(listener => listener());
  }
  private current = () => !this.disposed && this.options.authority.permitted && (this.options.authority.isCurrent?.() ?? true);
  private clearTimer() { clearTimeout(this.timer); this.timer = undefined; }
  private run(operation: (signal: AbortSignal) => Promise<void>): Promise<void> {
    if (this.active || !this.current()) return Promise.resolve();
    this.clearTimer();
    const abort = new AbortController(); this.active = abort;
    const previous = lanes.get(this.options.api);
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
    lanes.set(this.options.api, gate);
    this.patch({ busy: true });
    this.owned = (async () => {
      try {
        if (previous) await previous;
        abort.signal.throwIfAborted(); if (!this.current()) return;
        await operation(abort.signal);
      } catch (error) {
        if (!abort.signal.aborted && this.current()) await this.failure(error);
      } finally {
        this.active = null; release(); if (lanes.get(this.options.api) === gate) lanes.delete(this.options.api);
        this.patch({ busy: false });
        if (!abort.signal.aborted) this.schedule();
      }
    })();
    return this.owned;
  }
  private async failure(error: unknown) {
    if (error instanceof APIProductError && error.status === 403) {
      this.patch({ phase: "revalidating", descriptor: null, progress: null, message: "Checking current authorization..." });
      // retry() returns void. The remounted/current session decides permission
      // and freshness; a captured pre-bootstrap identity never makes that call.
      await this.options.retrySession();
      this.patch({ phase: this.state.resume?.exportID ? "error" : "ambiguous", message: "Authorization was rejected. Check current access before retrying." }); return;
    }
    if (error instanceof APIProductError && error.status === 401) {
      this.patch({ phase: "error", descriptor: null, progress: null, message: "Sign in to continue." }); return;
    }
    const message = error instanceof APIProductError && error.status === 404 ? "Export is not available to this session." : "Export request could not be completed. Retry the retained operation.";
    this.patch({ phase: this.state.resume?.exportID ? "error" : "ambiguous", message: error instanceof APIProductError ? `${message} Correlation: ${error.correlationID}` : message });
  }
  private accept(descriptor: AuditExport) {
    this.patch({ descriptor, phase: descriptor.status, message: null });
    if (this.state.resume) {
      const resume = { ...this.state.resume, exportID: descriptor.id };
      // The pending key was durable before POST. Even a failed ID update can
      // still recover the original exact operation after reload.
      this.patch({ resume });
      try { storeAuditExportResume(this.options.storage, resume); }
      catch { this.patch({ message: "Job received. Resume storage could not be updated; keep this tab open." }); }
    }
  }
  create = (newJob = false): Promise<void> => {
    if (!this.fresh || !this.current() || this.active) return Promise.resolve();
    return this.run(async signal => {
      // The previous owner may have held this lane past freshness expiry.
      // Check before replacing the retained key or sending its exact replay.
      if (!this.fresh) return;
      let resume = newJob ? null : this.state.resume;
      if (resume?.exportID) return;
      if (!resume) {
        const a = this.options.authority;
        resume = { principalID: a.principalID, organizationID: a.organizationID, workspaceID: a.workspaceID, environmentID: a.environmentID, key: `audit_export_${crypto.randomUUID()}` };
        storeAuditExportResume(this.options.storage, resume);
        this.patch({ resume });
      }
      this.patch({ phase: "creating", descriptor: null, progress: null, message: null });
      this.pollUntil = Date.now() + 120000; this.delay = 2000;
      const descriptor = await this.options.api.create(resume.key, signal);
      signal.throwIfAborted(); if (this.current()) this.accept(descriptor);
    });
  };
  check = (automatic = false): Promise<void> => {
    if (!this.state.resume?.exportID) return Promise.resolve();
    const id = this.state.resume.exportID;
    return this.run(async signal => {
      if (!automatic) { this.pollUntil = Date.now() + 120000; this.delay = 2000; }
      this.patch({ phase: "checking", message: null });
      const read = await this.options.api.read(id, undefined, signal);
      signal.throwIfAborted(); if (this.current()) this.accept(read.export);
    });
  };
  private schedule() {
    if (!this.current() || !["queued", "processing"].includes(this.state.phase)) return;
    const remaining = this.pollUntil - Date.now();
    if (remaining <= 0) { this.patch({ phase: "paused", message: "Automatic checks paused. The server job keeps running." }); return; }
    this.timer = setTimeout(() => {
      if (Date.now() >= this.pollUntil || typeof document !== "undefined" && document.visibilityState === "hidden") this.patch({ phase: "paused", message: "Automatic checks paused. Check status when ready." });
      else void this.check(true);
    }, Math.min(this.delay, remaining));
    this.delay = Math.min(this.delay * 2, 10000);
  }
  save = (parent: Promise<ExportDirectory>): Promise<void> => {
    if (this.active || this.state.descriptor?.status !== "ready" || !this.current()) { void parent.catch(() => {}); return Promise.resolve(); }
    const id = this.state.descriptor.id;
    return this.run(async signal => {
      this.patch({ phase: "saving", progress: null, message: null });
      let directory: ExportDirectory;
      try { directory = await parent; } catch { this.patch({ phase: "ready", message: "No destination selected. No export was saved." }); return; }
      const result = await saveAuditExport({ parent: directory, exportID: id, read: this.options.api.read, signal, isCurrent: this.current,
        onProgress: progress => this.patch({ progress }), onFinalizing: () => this.patch({ phase: "finalizing" }),
        waitForReadRetry: () => new Promise<void>((resolve, reject) => {
          this.patch({ phase: "read-retry", message: "Page read interrupted. Retry continues at the next unwritten chunk." });
          const abort = () => { this.readRetry = null; reject(signal.reason); };
          this.readRetry = () => { signal.removeEventListener("abort", abort); this.readRetry = null; this.patch({ phase: "saving", message: null }); resolve(); };
          if (signal.aborted) abort(); else signal.addEventListener("abort", abort, { once: true });
        }),
      });
      const message = result.status === "saved" ? "Export bundle saved. All chunks and the final manifest closed successfully." : result.status === "unconfirmed" ? "Export completion could not be confirmed. Check the destination; the manifest might exist." : "Save incomplete. Partial files may remain. Another save uses a new directory.";
      if (result.status !== "incomplete") publishFinalNotice(message);
      this.patch({ phase: result.status, message });
      if (result.status === "incomplete" && result.error instanceof APIProductError && [401, 403].includes(result.error.status)) await this.failure(result.error);
    });
  };
  retryRead = () => this.readRetry?.();
  stop = async () => {
    this.clearTimer(); this.active?.abort();
    await this.owned;
    if (!["saved", "unconfirmed"].includes(this.state.phase)) this.patch({ phase: "incomplete", message: "Stopped. The server job keeps running; partial local files may remain." });
  };
  dispose = async () => {
    this.disposed = true; this.clearTimer(); this.active?.abort();
    this.state = { phase: "idle", descriptor: null, resume: null, progress: null, message: null, busy: false };
    await this.owned;
  };
}
