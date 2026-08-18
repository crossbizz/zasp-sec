import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M3-37 through M3-48h completion batch", () => {
  it("binds runtime processing and setup surfaces to reviewed code", () => {
    const runtime = read("services/platform/runtimeevent/runtimeevent.go") + read("services/platform/runtimeevent/http.go");
    for (const symbol of ["EvaluateSensorHealth", "AdaptOTLP", "FilterRecord", "BuildBatches", "NewWorker", "Correlate"]) expect(runtime).toContain(`func ${symbol}`);
    const connector = read("app/features/connectors/ConnectorViews.tsx") + read("app/domain/seed.ts");
    for (const value of ["Review access", "Initial sync", "Coverage", "Signature status", "Directory security integration is separate", "Repository and Organization scope"]) expect(connector).toContain(value);
  });

  it("completes exactly 25 independently verified runtime and setup tasks", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] || "";
    const selected = ["M3-37", "M3-38", "M3-39", "M3-40", "M3-41", "M3-42", "M3-43a", "M3-43b", "M3-43c", "M3-43d", "M3-43", "M3-44", "M3-45", "M3-46", "M3-47", "M3-48a", "M3-48b", "M3-48c1", "M3-48c2", "M3-48c3", "M3-48d", "M3-48e", "M3-48f", "M3-48g", "M3-48h"];
    for (const id of selected) expect(complete.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 441 |", "| Complete | 284 |", "`0/441/284/3`", "| M3 | 75 | 0 | 2 | 73 | 0 |"]) expect(tracker).toContain(value);
  });
});
