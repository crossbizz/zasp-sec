import { describe, expect, it } from "vitest";
import { createSingleTestRecoveryIntent, type RecoveryIntentSource } from "./recovery-intent";

const runID = "pid_78000003-0000-4000-8000-000000000003";
const otherID = "pid_78000004-0000-4000-8000-000000000004";
const originalDigest = "a".repeat(64);
const view: RecoveryIntentSource = {
  run_id: runID, parent_version: 7, status: "not_requested",
  request_identity: { definition_version: 3, input_digest: originalDigest },
};

describe("SingleTest operator recovery request identity", () => {
  it("freezes the server's original identity and explicit stop intent without a child digest", () => {
    const source = structuredClone(view);
    const intent = createSingleTestRecoveryIntent(source, runID, 7);
    expect(intent).toEqual({ id: runID, version: 7, body: {
      definition_version: 3, input_digest: originalDigest,
      diagnostic: "history_unavailable", stop_original: true,
    } });
    (source.request_identity as { input_digest: string }).input_digest = "b".repeat(64);
    expect(intent.body.input_digest).toBe(originalDigest);
    expect(Object.isFrozen(intent)).toBe(true);
    expect(Object.isFrozen(intent.body)).toBe(true);
  });

  it("rejects stale parent versions and a different run", () => {
    expect(() => createSingleTestRecoveryIntent(view, runID, 8)).toThrow();
    expect(() => createSingleTestRecoveryIntent(view, otherID, 7)).toThrow();
  });

  it.each(["queued", "pending", "repair_required", "complete", "unknown"])("does not create a fresh request for %s", status => {
    expect(() => createSingleTestRecoveryIntent({ ...view, status }, runID, 7)).toThrow();
  });

  it.each(["", "A".repeat(64), "sha256:" + originalDigest, "a".repeat(63)])("rejects malformed original digest %s", input_digest => {
    expect(() => createSingleTestRecoveryIntent({ ...view, request_identity: { ...view.request_identity, input_digest } }, runID, 7)).toThrow();
  });

  it.each([0, -1, 1.5, 1000001, NaN])("rejects definition version %s", definition_version => {
    expect(() => createSingleTestRecoveryIntent({ ...view, request_identity: { ...view.request_identity, definition_version } }, runID, 7)).toThrow();
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects unsafe parent version %s", parent_version => {
    expect(() => createSingleTestRecoveryIntent({ ...view, parent_version }, runID, parent_version)).toThrow();
  });
});
