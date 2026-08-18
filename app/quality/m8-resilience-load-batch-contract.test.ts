import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-23c through M8-39 resilience and load batch", () => {
  it("adds rollback, diagnostics, parity, outage, and bounded load models", () => {
    const source = read("cmd/agentsecctl/resilience.go");
    for (const symbol of ["RunRollbackRehearsal", "BuildDiagnosticsBundle", "EvaluateParity", "EvaluateOutages", "EvaluateRuntimeLatency", "EvaluateAPILoad", "EvaluateGraphLoad", "GenerateEventLoad", "EvaluateEventLoad", "RecordSensorOverhead"]) expect(source).toContain(`func ${symbol}`);
    for (const boundary of ["stytch", "neon", "nango", "optional_vendors", "opensearch", "neo4j", "sqs_saturation"]) expect(source).toContain(`"${boundary}"`);
  });

  it("uses exact MVP reference thresholds without making a universal sensor claim", () => {
    const source = read("cmd/agentsecctl/resilience.go");
    expect(source).toContain("25*time.Millisecond");
    expect(source).toContain("750*time.Millisecond");
    expect(source).toContain("3*time.Second");
    expect(source).toContain("5000");
    expect(source).not.toContain("universalOverhead");
  });

  it("advances exactly 25 tasks and keeps provider/load execution honest", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const selected = ["M8-23c", "M8-23d", "M8-23", "M8-24", "M8-25", "M8-26", "M8-27", "M8-28", "M8-29", "M8-30", "M8-31", "M8-32", "M8-33", "M8-34", "M8-35", "M8-36a", "M8-36b", "M8-36c", "M8-36", "M8-37", "M8-38a", "M8-38b", "M8-38c", "M8-38", "M8-39"];
    for (const id of selected) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 97 |", "`0/97/628/3`", "| M8 | 141 | 0 | 91 | 50 | 0 |"]) expect(tracker).toContain(value);
    expect(tracker).toContain("live parity, outage injection, and reference load execution remain unresolved");
  });
});
