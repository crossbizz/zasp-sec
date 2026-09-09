import { describe, expect, it } from "vitest";
import { decodeTestAttempt } from "./decoders";

const scope = "organizations/pid_91000001-0000-4000-8000-000000000001/workspaces/pid_91000002-0000-4000-8000-000000000002/environments/pid_91000003-0000-4000-8000-000000000003/artifacts/";
const input = { reference: "s3://zasp-evidence/" + scope + "pid_91000004-0000-4000-8000-000000000004", version_id: "immutable-version-1", sha256: "b".repeat(64), size_bytes: 512 };
const attempt = { attempt: 1, verdict: "pass", objective: "Evaluate prompt injection", behavior: "Target refused", evidence: ["prompt_injection: protected"], evidence_reference: "s3://zasp-evidence/" + scope + "pid_91000005-0000-4000-8000-000000000005", completed_at: "2026-09-09T02:00:00Z" };
describe("immutable Red Team input receipt", () => {
  it("retains an exact receipt while accepting legacy attempts without one", () => {
    expect(decodeTestAttempt(attempt)).toEqual(attempt);
    expect(decodeTestAttempt({ ...attempt, input_artifact: input })).toEqual({ ...attempt, input_artifact: input });
  });
  it.each([
    null, {}, { ...input, secret: "fixture" }, { ...input, version_id: "" },
    { ...input, version_id: "mutable\nvalue" }, { ...input, sha256: "0".repeat(64) },
    { ...input, sha256: "A".repeat(64) }, { ...input, size_bytes: 0 }, { ...input, size_bytes: 65537 },
    { ...input, reference: input.reference + "?token=fixture" }, { ...input, reference: input.reference.replace("s3://", "https://") },
    { ...input, reference: attempt.evidence_reference }, { ...input, reference: input.reference.replace("pid_91000001", "pid_99000001") },
  ])("rejects malformed or cross-scope receipts %#", (input_artifact) => {
    expect(() => decodeTestAttempt({ ...attempt, input_artifact })).toThrow();
  });
});
