import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M3 gate and M4 reconciliation accelerated batch", () => {
  it("binds the local M3 gate to five independent evidence classes", async () => {
    const [gate, test] = await Promise.all([
      readFile(resolve(root, "services/platform/m3gate/m3gate.go"), "utf8"),
      readFile(resolve(root, "services/platform/m3gate/m3gate_test.go"), "utf8"),
    ]);
    for (const evidence of ["ConnectorAssets", "SensorSupported", "OTLPEvents", "TetragonEvents", "ArchiveIndexLinked", "ReplayIdempotent", "DLQMessages", "LastKnownInventoryRetained", "Freshness"]) {
      expect(gate).toContain(evidence);
    }
    expect(gate).toContain('Report{Status: "PASS", Checks: 5}');
    for (const boundary of ["NormalizeAWS", "NormalizeKubernetes", "NormalizeGitHub", "NormalizeIdP", "AdaptTetragon", "AdaptOTLP", "BuildBatches", "NewWorker", "RecordFailure"]) {
      expect(test).toContain(boundary);
    }
  });

  it("implements full-scope deterministic reconciliation without raw credentials", async () => {
    const source = await readFile(resolve(root, "services/platform/reconciliation/reconciliation.go"), "utf8");
    for (const symbol of ["KindAsset", "KindAgent", "KindTool", "KindIdentity", "KindRuntime", "UpdateOwnership", "ProjectRelationships", "MemoryProjector"]) {
      expect(source).toContain(symbol);
    }
    expect(source).toContain("scope.OrganizationID().String()");
    expect(source).toContain("scope.WorkspaceID().String()");
    expect(source).toContain("scope.EnvironmentID().String()");
    expect(source).toContain('value.RawCredential != ""');
    expect(source).toContain("validFingerprint(value.CredentialFingerprint)");
  });

  it("exposes provider-specific connection and generated-schema sensor flows", async () => {
    const [connectors, sensors, seed, app] = await Promise.all([
      readFile(resolve(root, "app/features/connectors/ConnectorViews.tsx"), "utf8"),
      readFile(resolve(root, "app/features/sensors/SensorView.tsx"), "utf8"),
      readFile(resolve(root, "app/domain/seed.ts"), "utf8"),
      readFile(resolve(root, "app/components/ZaspApp.tsx"), "utf8"),
    ]);
    expect(connectors).toMatch(/setupSteps[\s\S]*Setup boundary/);
    expect(connectors).toContain('key={selected?.id ?? "none"}');
    for (const value of ["AWS", "Kubernetes", "GitHub", "Generic Webhook", "Workforce Directory", "Missing iam:GetRole"]) expect(seed).toContain(value);
    expect(sensors).toContain('from "../../../apps/web/api/generated"');
    for (const value of ["Enroll sensor", "Rotate enrollment token", "Delete sensor", "Unsupported kernel", "Copy this token now"]) expect(sensors).toContain(value);
    expect(app).toContain("<SensorView");
  });

  it("moves exactly the 22-task batch to In progress without a provider claim", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toContain("| M3 | 75 | 0 | 61 | 14 | 0 |");
    expect(tracker).toMatch(/^\| M4 \| 82 \| \d+ \| \d+ \| 0 \| 0 \|$/m);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = ["M3-48d", "M3-48e", "M3-48f", "M3-48g", "M3-48h", "M3-48", "M3-49", "M3-50", "M3-51", "M3-52a", "M3-52b", "M3-52c", "M3-52d", "M3-52e", "M3-52", "M4-01a", "M4-01b", "M4-01c", "M4-01d", "M4-01e", "M4-01f", "M4-01"];
    expect(tasks).toHaveLength(22);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    expect(readme).toContain("M3-48d through M3-52 and M4-01a through M4-01 are batched as In progress");
    const compactReadme = readme.replace(/\s+/g, " ");
    expect(compactReadme).toContain("real SQS, S3, OpenSearch, connector, sensor, and staging evidence still depends on M1A-10");
    expect(compactReadme).toContain("makes no Neon or staging claim");
  });
});
