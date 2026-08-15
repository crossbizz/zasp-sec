import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const collectorImage =
  "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

describe("OTLP ingest proof contract", () => {
  it("binds the source-plan dependency, deliverable, and verification boundary", async () => {
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const section = plan.match(/\*\*M0-13 - OTLP proof\*\*[\s\S]*?\*\*M0-14a/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("Depends on: `M0-12`");
    expect(section).toContain("real local OTel Collector");
    expect(section).toContain("Trace IDs and required agent attributes reach the ingest adapter");
    expect(section).toContain("Timebox: <=15 minutes");
  });

  it("records an exact-pinned ingest-only design with bounded semantic identity", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-13-otlp-proof-design.md"),
      "utf8",
    );

    expect(design).toContain(collectorImage);
    expect(design).toContain("OTLP/HTTP receiver");
    expect(design).toContain("product-owned ingest adapter");
    expect(design).toContain("organization.id");
    expect(design).toContain("agent.id");
    expect(design).toContain("session.id");
    expect(design).toContain("task.id");
    expect(design).toContain("tool.id");
    expect(design).toContain("sandbox.id");
    expect(design).toContain("remote OTLP export is disabled");
    expect(design).toContain("raw prompt text");
    expect(design).toContain("arbitrary tool arguments");
  });

  it("locks an executable TDD and exact-owned lifecycle plan", async () => {
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-14-m0-13-otlp-proof-implementation-plan.md"),
      "utf8",
    );

    expect(plan).toContain("Tests-first RED");
    expect(plan).toContain("strict OTLP JSON parser");
    expect(plan).toContain("exact full container ID");
    expect(plan).toContain("loopback-only random port");
    expect(plan).toContain("prefix-wide zero-resource audit");
    expect(plan).toContain("independent cleanup");
    expect(plan).toContain("two consecutive live runs");
    expect(plan).toContain("independent review");
  });

  it("starts exactly M0-13 without changing blocked provider boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const section = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const rows = markdownRows(section).slice(2);

    expect(tracker).toContain("| Pending | 715 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 11 |");
    expect(tracker).toContain("| Blocked | 1 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 14 \| 1 \| 11 \| 1 \|/);
    expect(rows).toEqual([
      ["M0-13", "August 14, 2026", expect.stringContaining("OTLP")],
    ]);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("keeps R-12 Not run until both ingest and later export proofs complete", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const rows = markdownRows(riskRegister).filter(([id]) => id === "R-12");

    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveLength(6);
    expect(rows[0]?.[5]).toBe("Not run — M0-13/M0-22");
  });
});
