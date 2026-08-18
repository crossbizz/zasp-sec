import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type PackageManifest = { scripts?: Record<string, string> };

const repositoryRoot = resolve(import.meta.dirname, "../..");
const collectorImage =
  "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5";
const r12Evidence =
  "PASS — M0-13/M0-22 — .superpowers/sdd/2026-08-14-m0-13-otlp-proof-implementation-plan/task-6-report.md; proof head c91047923bcbf9e567e640ade8c308c03a0100bc; .superpowers/sdd/2026-08-15-m0-22-otlp-export-proof-implementation-plan/task-4-report.md; proof head 425accdf9293e7652c6cedd5e49e772799a431fa";

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function assertM013Complete(tracker: string) {
  const inProgress = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
  const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
  const inProgressRows = markdownRows(inProgress).slice(2);
  const allCompleteRows = markdownRows(complete).slice(2);
  const completeRows = allCompleteRows.filter(([task]) => task === "M0-13");

  expect(inProgressRows.map(([task]) => task)).toEqual([]);
  expect([...inProgressRows, ...allCompleteRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(completeRows).toHaveLength(1);
  expect(completeRows[0]?.[1]).toBe("August 14, 2026");
  expect(completeRows[0]?.[2]).toContain("exact-pinned local OTLP ingest proof");
  expect(completeRows[0]?.[2]).toContain("zero-finding independent review");
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

  it("completes exactly M0-13 without changing blocked provider boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    expect(tracker).toContain("| Pending | 658 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 67 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    assertM013Complete(tracker);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("rejects duplicate M0-13 completion and concurrent in-progress rows", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const row = tracker.split("\n").find((line) => line.startsWith("| M0-13 |"));
    expect(row).toBeDefined();
    const duplicate = tracker.replace(`${row}\n`, `${row}\n${row}\n`);
    const concurrent = tracker.replace(
      "## Complete\n",
      "| M0-15 | August 15, 2026 | Decoy concurrent work. |\n\n## Complete\n",
    );
    expect(() => assertM013Complete(duplicate)).toThrow();
    expect(() => assertM013Complete(concurrent)).toThrow();
  });

  it("advances R-12 only from the combined ingest and export evidence", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const rows = markdownRows(riskRegister).filter(([id]) => id === "R-12");

    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveLength(6);
    expect(rows[0]?.[5]).toBe(r12Evidence);
  });

  it("exposes exact hermetic and disposable live root commands", async () => {
    const manifest = JSON.parse(
      await readFile(resolve(repositoryRoot, "package.json"), "utf8"),
    ) as PackageManifest;

    expect(manifest.scripts?.["proof:otlp:test"]).toBe(
      "node --test proofs/otlp-ingest/*.test.mjs",
    );
    expect(manifest.scripts?.["proof:otlp:run"]).toBe(
      "node proofs/otlp-ingest/run.mjs",
    );
    expect(manifest.scripts?.["proof:otlp:test"]).not.toMatch(/docker|env-file|credential|proxy/i);
    expect(manifest.scripts?.["proof:otlp:run"]).not.toMatch(/env-file|credential|proxy/i);
  });

  it("documents the fixed local-only ingest boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## OTLP ingest proof[\s\S]*?## Tetragon signal proof/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain(collectorImage);
    expect(section).toContain(
      "OTLP ingest proof passed: traces=1 spans=1 identity=true cleanup=true.",
    );
    expect(section).toContain("Node.js `22.23.1` and npm `10.9.8`");
    expect(section).toContain("loopback-only");
    expect(section).toContain("remote OTLP export is disabled");
    expect(section).toContain("raw prompts, tool arguments, credentials, or customer payloads");
    expect(section).toContain("R-12 PASS");
    expect(section).toContain("M0-13 is Complete");
    expect(section).toContain("npm run proof:otlp:test");
    expect(section).toContain("npm run proof:otlp:run");
  });
});
