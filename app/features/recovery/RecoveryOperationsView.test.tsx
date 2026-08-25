import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { RecoveryBackup, RecoveryManifestLocator, RecoveryRestore } from "../../../apps/web/api/generated";
import { RecoveryOperationsView } from "./RecoveryOperationsView";
import type { RecoveryAPI } from "./api";

const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const backupID = "pid_71000001-0000-4000-8000-000000000001";
const restoreID = "pid_71000002-0000-4000-8000-000000000002";
const manifest: RecoveryManifestLocator = {
  reference: `s3://zasp-recovery/organizations/${scope.split("/")[0]}/workspaces/${scope.split("/")[1]}/environments/${scope.split("/")[2]}/artifacts/pid_71000003-0000-4000-8000-000000000003`,
  version_id: "version-recovery-0001", sha256: "a".repeat(64), size_bytes: 512,
  media_type: "application/vnd.zasp.recovery-manifest+json", schema: "recovery_signed_manifest_v1",
  signing_key_id: "11111111-1111-4111-8111-111111111111", signature: "A".repeat(43),
};
const queuedBackup: RecoveryBackup = { id: backupID, version: 1, state: "queued", retention_days: 30, attempt: 0, created_at: "2026-08-25T12:00:00Z" };
const succeededBackup: RecoveryBackup = { ...queuedBackup, version: 3, state: "succeeded", attempt: 1, manifest, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:02Z" };
const queuedRestore: RecoveryRestore = { id: restoreID, version: 1, state: "queued", target_environment: "recovery-e2e-01", attempt: 0, manifest, created_at: "2026-08-25T12:00:03Z" };
const counts = { assets: 12, findings: 3, policies: 2 } as const;
const evidence = { reference: manifest.reference.replace(backupID, "pid_71000004-0000-4000-8000-000000000004"), version_id: "version-evidence-0001", sha256: "b".repeat(64), size_bytes: 256, media_type: "application/json", schema: "recovery_validation_v1" } as const;
const succeededRestore: RecoveryRestore = { ...queuedRestore, version: 5, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:04Z", completed_at: "2026-08-25T12:00:08Z", observed_counts: counts, validation_evidence: { state: "validated", expected_counts: counts, observed_counts: counts, evidence }, cleanup_evidence: { state: "deleted", evidence } };

describe("tenant recovery operations", () => {
  it("requires confirmation and retains the exact backup attempt for an idempotent retry", async () => {
    const user = userEvent.setup(); const storage = memoryStorage();
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValue(true);
    const startBackup = vi.fn<RecoveryAPI["startBackup"]>().mockRejectedValueOnce(new TypeError("response lost")).mockResolvedValue(queuedBackup);
    render(<RecoveryOperationsView api={api({ startBackup })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={60_000} />);
    await user.click(screen.getByRole("button", { name: "Start signed backup" }));
    expect(startBackup).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start signed backup" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("may have committed");
    await user.click(screen.getByRole("button", { name: "Retry retained backup" }));
    expect(startBackup).toHaveBeenCalledTimes(2);
    expect(startBackup.mock.calls[1]![0]).toEqual(startBackup.mock.calls[0]![0]);
    expect(await screen.findByText("Backup queued")).toBeVisible();
    const retained = storage.getItem(`zasp:recovery:v1:${scope}`) ?? "";
    expect(retained).toContain(backupID);
    expect(retained).not.toMatch(/s3:|signature|version_id|signing_key|arn:|token/i);
    confirm.mockRestore();
  });

  it("recovers public operation IDs after reload, bounds polling, and cancels an in-flight read on navigation", async () => {
    const storage = memoryStorage({ [`zasp:recovery:v1:${scope}`]: JSON.stringify({ version: 1, backup: { id: backupID, retention_days: 30, idempotency_key: "recovery_backup_00000001" }, restore: null }) });
    let signal: AbortSignal | undefined;
    const getBackup = vi.fn<RecoveryAPI["getBackup"]>((_id, currentSignal) => { signal = currentSignal; return new Promise(() => undefined); });
    const view = render(<RecoveryOperationsView api={api({ getBackup })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={5} maximumPolls={2} />);
    await waitFor(() => expect(getBackup).toHaveBeenCalledOnce());
    view.unmount();
    expect(signal?.aborted).toBe(true);

    const boundedGet = vi.fn<RecoveryAPI["getBackup"]>(async () => queuedBackup);
    render(<RecoveryOperationsView api={api({ getBackup: boundedGet })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={5} maximumPolls={2} />);
    expect(await screen.findByText("Backup queued")).toBeVisible();
    expect(await screen.findByRole("alert")).toHaveTextContent("Automatic status checks paused");
    expect(boundedGet).toHaveBeenCalledTimes(3);
  });

  it("preserves the authoritative backup and exact restore retry when one reload lookup is unavailable", async () => {
    const storage = memoryStorage({ [`zasp:recovery:v1:${scope}`]: JSON.stringify({ version: 1, backup: { id: backupID, retention_days: 30, idempotency_key: "recovery_backup_00000001" }, restore: { id: restoreID, target_environment: "recovery-e2e-01", idempotency_key: "recovery_restore_0000001" } }) });
    render(<RecoveryOperationsView api={api({ getBackup: async () => succeededBackup, getRestore: async () => { throw new TypeError("temporary status failure"); } })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={60_000} />);
    expect(await screen.findByText("Backup succeeded")).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("could not be verified");
    expect(screen.getByRole("button", { name: "Retry retained restore" })).toBeVisible();
  });

  it("starts an isolated restore from the authoritative backup and renders only public status evidence", async () => {
    const user = userEvent.setup(); const storage = memoryStorage(); vi.spyOn(window, "confirm").mockReturnValue(true);
    const startBackup = vi.fn<RecoveryAPI["startBackup"]>(async () => succeededBackup);
    const startRestore = vi.fn<RecoveryAPI["startRestore"]>(async () => succeededRestore);
    render(<RecoveryOperationsView api={api({ startBackup, startRestore })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={60_000} />);
    await user.click(screen.getByRole("button", { name: "Start signed backup" }));
    expect(await screen.findByText("Backup succeeded")).toBeVisible();
    await user.clear(screen.getByLabelText("Recovery target")); await user.type(screen.getByLabelText("Recovery target"), "recovery-e2e-01");
    await user.click(screen.getByRole("button", { name: "Start restore rehearsal" }));
    expect(startRestore).toHaveBeenCalledWith(expect.objectContaining({ targetEnvironment: "recovery-e2e-01", manifest }), expect.any(AbortSignal));
    expect(await screen.findByText("Restore succeeded")).toBeVisible();
    expect(screen.getByText("12 assets")).toBeVisible(); expect(screen.getByText("3 findings")).toBeVisible(); expect(screen.getByText("2 policies")).toBeVisible();
    expect(screen.getByText("Temporary resources deleted")).toBeVisible();
    expect(document.body.textContent).not.toMatch(/s3:|version-recovery|signing_key|signature|arn:|token|provider/i);
  });

  it("rejects a production restore target before retaining or sending an operation", async () => {
    const user = userEvent.setup(); const storage = memoryStorage(); vi.spyOn(window, "confirm").mockReturnValue(true);
    const startRestore = vi.fn<RecoveryAPI["startRestore"]>();
    render(<RecoveryOperationsView api={api({ startBackup: async () => succeededBackup, startRestore })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={60_000} />);
    await user.click(screen.getByRole("button", { name: "Start signed backup" }));
    await user.clear(await screen.findByLabelText("Recovery target")); await user.type(screen.getByLabelText("Recovery target"), "production");
    expect(screen.getByRole("button", { name: "Start restore rehearsal" })).toBeDisabled();
    expect(startRestore).not.toHaveBeenCalled();
    expect(storage.getItem(`zasp:recovery:v1:${scope}`)).not.toContain("target_environment");
  });

  it("shows cleanup failure remediation without exposing internal evidence", async () => {
    const storage = memoryStorage({ [`zasp:recovery:v1:${scope}`]: JSON.stringify({ version: 1, backup: { id: backupID, retention_days: 30, idempotency_key: "recovery_backup_00000001" }, restore: { id: restoreID, target_environment: "recovery-e2e-01", idempotency_key: "recovery_restore_0000001" } }) });
    const failed: RecoveryRestore = { ...queuedRestore, state: "failed_cleanup", attempt: 2, version: 4, started_at: "2026-08-25T12:00:04Z", completed_at: "2026-08-25T12:00:08Z", error_code: "cleanup_failed", cleanup_evidence: { state: "failed", evidence } };
    render(<RecoveryOperationsView api={api({ getBackup: async () => succeededBackup, getRestore: async () => failed })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} pollIntervalMs={60_000} />);
    expect(await screen.findByText("Restore cleanup failed")).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("Temporary recovery resources require manual cleanup");
    expect(document.body.textContent).not.toMatch(/s3:|version-evidence|signing_key|signature|cleanup_failed/i);
  });

  it("renders a safe empty state and sends stale authentication to reauthentication", async () => {
    const user = userEvent.setup(); const reauthenticate = vi.fn(); const startBackup = vi.fn<RecoveryAPI["startBackup"]>();
    render(<RecoveryOperationsView api={api({ startBackup })} expectedScope={scope} storage={memoryStorage()} canWrite fresh={false} onReauthenticate={reauthenticate} />);
    expect(screen.getByText("No recovery operation in this scope")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Reauthenticate to start backup" }));
    expect(reauthenticate).toHaveBeenCalledOnce(); expect(startBackup).not.toHaveBeenCalled();
  });

  it("rejects an out-of-bounds retention before confirmation, storage, or API I/O", async () => {
    const user = userEvent.setup(); const storage = memoryStorage(); const startBackup = vi.fn<RecoveryAPI["startBackup"]>(); const confirm = vi.spyOn(window, "confirm");
    render(<RecoveryOperationsView api={api({ startBackup })} expectedScope={scope} storage={storage} canWrite fresh onReauthenticate={() => undefined} />);
    confirm.mockClear();
    await user.clear(screen.getByLabelText("Retention days")); await user.type(screen.getByLabelText("Retention days"), "91");
    expect(screen.getByRole("button", { name: "Start signed backup" })).toBeDisabled();
    expect(confirm).not.toHaveBeenCalled(); expect(startBackup).not.toHaveBeenCalled(); expect(storage.length).toBe(0);
  });
});

function api(overrides: Partial<RecoveryAPI> = {}): RecoveryAPI { return {
  startBackup: async () => queuedBackup, getBackup: async () => queuedBackup,
  startRestore: async () => queuedRestore, getRestore: async () => queuedRestore,
  ...overrides,
}; }

function memoryStorage(initial: Record<string, string> = {}): Storage {
  const values = new Map(Object.entries(initial));
  return { get length() { return values.size; }, clear: () => values.clear(), getItem: (key) => values.get(key) ?? null, key: (index) => [...values.keys()][index] ?? null, removeItem: (key) => { values.delete(key); }, setItem: (key, value) => { values.set(key, value); } };
}
