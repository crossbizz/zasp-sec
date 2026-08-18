import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-17a through M8-23b recovery readiness batch", () => {
  it("adds bounded preflight, recovery, and upgrade command models", () => {
    const source = read("cmd/agentsecctl/release.go");
    for (const symbol of [
      "EvaluatePreflight", "BuildBackupManifest", "DecodeRecoveryManifest",
      "RunRestoreRehearsal", "EvaluateUpgrade", "RunUpgradeFixture",
    ]) expect(source).toContain(`func ${symbol}`);
    for (const boundary of ["iam_irsa", "s3_kms_secrets", "sqs", "opensearch", "eks_fargate", "neon", "stytch", "sensor"]) expect(source).toContain(`"${boundary}"`);
  });

  it("keeps manifests reference-only and restore/upgrade operations injected", () => {
    const source = read("cmd/agentsecctl/release.go");
    for (const value of ["NeonRecoveryPoint", "GraphExportReference", "EvidenceReferences", "RestoreRuntime", "UpgradeRuntime"]) expect(source).toContain(value);
    for (const forbidden of ["AccessKey", "SecretKey", "Password", "PrivateKey"]) expect(source).not.toContain(forbidden);
  });

  it("advances exactly the selected 25 tasks without claiming completion", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const selected = ["M8-17a", "M8-17b", "M8-17c", "M8-17d", "M8-17e", "M8-17", "M8-18", "M8-19", "M8-20a", "M8-20b", "M8-20c", "M8-20", "M8-21a", "M8-21b", "M8-21c", "M8-21d", "M8-21e", "M8-21", "M8-22a", "M8-22b", "M8-22c", "M8-22d", "M8-22", "M8-23a", "M8-23b"];
    for (const id of selected) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 193 |", "`0/193/532/3`", "| M8 | 141 | 0 | 141 | 0 | 0 |"]) expect(tracker).toContain(value);
  });
});
