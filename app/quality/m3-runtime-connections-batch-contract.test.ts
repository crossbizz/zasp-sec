import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M3 runtime ingestion and connection surfaces batch", () => {
  it("pins one bounded Tetragon wrapper and exactly three policy classes", async () => {
    const [chart, values, policies] = await Promise.all([
      readFile(resolve(root, "deploy/staging/tetragon/Chart.yaml"), "utf8"),
      readFile(resolve(root, "deploy/staging/tetragon/values.yaml"), "utf8"),
      readFile(resolve(root, "deploy/staging/tetragon/templates/policies.yaml"), "utf8"),
    ]);
    expect(chart).toContain("version: 1.7.0");
    expect(values).toContain("quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527");
    expect(values).toContain("quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82");
    expect(policies.match(/kind: TracingPolicy/g)).toHaveLength(3);
    expect(policies).toMatch(/sys_execve[\s\S]*security_file_permission[\s\S]*tcp_connect/);
    expect(policies).not.toMatch(/capabilities|credentials|packet_capture/i);
  });

  it("keeps runtime ingest bounded, scoped, durable-before-ack, and ambiguity-safe", async () => {
    const [runtime, handler] = await Promise.all([
      readFile(resolve(root, "services/platform/runtimeevent/runtimeevent.go"), "utf8"),
      readFile(resolve(root, "services/platform/runtimeevent/http.go"), "utf8"),
    ]);
    for (const symbol of ["AdaptTetragon", "AdaptOTLP", "EvaluateSensorHealth", "FilterRecord", "BuildBatches", "NewWorker", "Correlate", "SortedIndexDocuments"]) {
      expect(runtime).toContain(`func ${symbol}`);
    }
    expect(runtime).toMatch(/safeArchive[\s\S]*safeIndex[\s\S]*safeCorrelation[\s\S]*safeAcknowledge/);
    expect(runtime).toContain("EvidenceConfidenceProbable");
    expect(handler).toMatch(/Authenticate\(scope[\s\S]*io\.ReadAll/);
    expect(handler).toContain("maximumIngestBytes = 1024 * 1024");
  });

  it("renders product connection catalog, freshness, detail, history, and gated actions", async () => {
    const [view, seed] = await Promise.all([
      readFile(resolve(root, "app/features/connectors/ConnectorViews.tsx"), "utf8"),
      readFile(resolve(root, "app/domain/seed.ts"), "utf8"),
    ]);
    for (const value of ["Connected integrations", "Collected data", "Sync history", "Review access", "Sync now", "Delete connection"]) expect(view).toContain(value);
    expect(view).not.toMatch(/Cartography|Prowler|Nango|Tetragon|OpenTelemetry/);
    expect(seed).toMatch(/freshness: "healthy"/);
    expect(seed).toMatch(/freshness: "stale"/);
    expect(seed).toMatch(/status: "failed"/);
  });

  it("records the second 22-task batch as In progress without claiming provider completion", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toContain("| Pending | 495 |");
    expect(tracker).toContain("| In progress | 46 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M3 | 75 | 15 | 46 | 14 | 0 |");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = ["M3-35", "M3-36", "M3-37", "M3-38", "M3-39", "M3-40", "M3-41", "M3-42", "M3-43a", "M3-43b", "M3-43c", "M3-43d", "M3-43", "M3-44", "M3-45", "M3-46", "M3-47", "M3-48a", "M3-48b", "M3-48c1", "M3-48c2", "M3-48c3"];
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    expect(readme).toContain("M3-35 through M3-48c3 are also batched as In progress");
    expect(readme.replace(/\s+/g, " ")).toContain("the local worker tests do not substitute for that provider gate");
  });
});
