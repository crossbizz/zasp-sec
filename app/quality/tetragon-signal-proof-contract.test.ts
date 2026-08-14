import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = process.cwd();
const tetragonImage = "quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527";
const operatorImage = "quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82";
const nodeImage = "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95";
const expectedR07Row = [
  "R-07",
  "**Tetragon runtime signal quality.** Tetragon is runtime observation, not semantic truth, and must show usable workload identity and sensor health.",
  "One supported Linux/Kubernetes test workload yields process, file, and outbound-network events sharing workload identity; the sensor reports capability and drop state.",
  "Any required event class or shared workload identity is absent, or capability/drop state is unavailable.",
  "Runtime-sensor owner: do not claim required runtime coverage; narrow supported environments or select an alternate signal before M3.",
  "Not run — M0-12",
];

function parseMarkdownRows(markdown: string) {
  return markdown
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function assertM012InProgress(tracker: string) {
  const section = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0];
  const rows = parseMarkdownRows(section ?? "");
  const [header, separator, ...dataRows] = rows;

  expect(section).toBeDefined();
  expect(header).toEqual(["Task", "Started", "Current work"]);
  expect(separator).toHaveLength(3);
  expect(separator?.every((cell) => /^:?-{3,}:?$/.test(cell))).toBe(true);
  expect(dataRows).toHaveLength(1);
  expect(dataRows[0]).toHaveLength(3);
  expect(dataRows[0]?.[0]).toBe("M0-12");
  expect(dataRows[0]?.[1]).toBe("August 14, 2026");
  expect(dataRows[0]?.[2]).toContain("Tetragon");
  expect(dataRows[0]?.[2]).toContain("process, file, and outbound TCP");
  expect(dataRows[0]?.[2]).toContain("R-07 remains Not run");
}

function assertR07NotRun(riskRegister: string) {
  const rows = parseMarkdownRows(riskRegister).filter(([id]) => id === "R-07");

  expect(rows).toHaveLength(1);
  expect(rows[0]).toEqual(expectedR07Row);
}

describe("Tetragon signal proof contract", () => {
  it("locks the source requirement and exact observation-only runtime design", async () => {
    const [design, sourcePlan, riskRegister] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-14-m0-12-tetragon-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8"),
    ]);

    expect(sourcePlan).toContain("**M0-12 - Tetragon proof**");
    expect(sourcePlan).toContain("Capture process, file and outbound-network events for one supported Linux/Kubernetes test workload.");
    expect(sourcePlan).toContain("Events share workload identity and sensor reports capability/drop state.");
    expect(design).toContain(tetragonImage);
    expect(design).toContain(operatorImage);
    expect(design).toContain(nodeImage);
    expect(design).toMatch(/does not make Tetragon a semantic source of\s+truth/);
    expect(design).toContain("enable enforcement");
    assertR07NotRun(riskRegister);
  });

  it("starts exactly M0-12 without weakening completed or blocked boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );

    expect(tracker).toContain("| Pending | 716 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 10 |");
    expect(tracker).toContain("| Blocked | 1 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 15 \| 1 \| 10 \| 1 \|/);
    assertM012InProgress(tracker);
    expect(tracker).toMatch(/## Complete[\s\S]*?\| M0-11 \| August 14, 2026 \|/);
    expect(tracker).toMatch(/## Blocked[\s\S]*?\| M0-09 \| August 13, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("rejects duplicate or concurrent In progress rows despite valid aggregate text", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const m012Row = tracker.split("\n").find((line) => line.startsWith("| M0-12 |"));

    expect(m012Row).toBeDefined();
    const duplicate = tracker.replace(`${m012Row}\n`, `${m012Row}\n${m012Row}\n`);
    const concurrent = tracker.replace(`${m012Row}\n`, `${m012Row}\n| M0-13 | August 14, 2026 | Decoy concurrent work. |\n`);
    expect(duplicate).toContain("| In progress | 1 |");
    expect(concurrent).toContain("| In progress | 1 |");
    expect(() => assertM012InProgress(duplicate)).toThrow();
    expect(() => assertM012InProgress(concurrent)).toThrow();
  });

  it("documents the approved start boundary without claiming live evidence", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Tetragon signal proof[\s\S]*?## Real AWS cross-account IAM proof/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("M0-12 is In progress");
    expect(section).toContain(tetragonImage);
    expect(section).toContain(operatorImage);
    expect(section).toContain(nodeImage);
    expect(section).toMatch(/process, file,\s+and outbound TCP/);
    expect(section).toContain("same Kubernetes workload identity");
    expect(section).toContain("capability and drop state");
    expect(section).toContain("observation-only");
    expect(section).toContain("does not prove internet egress");
    expect(section).toMatch(/R-07 remains\s+Not run/);
    expect(section).toContain("M0-09 and PROV-01 remain Blocked");
  });

  it("binds R-07 to one exact six-cell Not run row", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const row = riskRegister.split("\n").find((line) => line.startsWith("| R-07 |"));

    expect(row).toBeDefined();
    assertR07NotRun(riskRegister);
    const changed = (row ?? "").replace("| Not run — M0-12 |", "| PASS — decoy |") + "\n| Not run — M0-12 |";
    expect(() => assertR07NotRun(riskRegister.replace(row ?? "", changed))).toThrow();
  });
});
