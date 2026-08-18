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
  "PASS — M0-12",
];

function parseMarkdownRows(markdown: string) {
  return markdown
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function assertM012Complete(tracker: string) {
  const inProgressSection = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0];
  const inProgressRows = parseMarkdownRows(inProgressSection ?? "");
  const completeSection = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0];
  const completeRows = parseMarkdownRows(completeSection ?? "").slice(2);
  const m012Rows = completeRows.filter(([task]) => task === "M0-12");

  const activeRows = inProgressRows.slice(2);
  expect(activeRows).toHaveLength(24);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(m012Rows).toHaveLength(1);
  expect(m012Rows[0]).toHaveLength(3);
  expect(m012Rows[0]?.[1]).toBe("August 14, 2026");
  expect(m012Rows[0]?.[2]).toContain("process, file, and outbound TCP");
  expect(m012Rows[0]?.[2]).toContain("shared Kubernetes workload identity");
  expect(m012Rows[0]?.[2]).toContain("zero-finding independent review");
}

function assertR07Pass(riskRegister: string) {
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
    assertR07Pass(riskRegister);
  });

  it("completes exactly M0-12 without weakening completed or blocked boundaries", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );

    expect(tracker).toContain("| Pending | 517 |");
    expect(tracker).toContain("| In progress | 24 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
    assertM012Complete(tracker);
    expect(tracker).toMatch(/## Complete[\s\S]*?\| M0-11 \| August 14, 2026 \|/);
    expect(tracker).toMatch(/## Blocked[\s\S]*?\| M0-09 \| August 13, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
  });

  it("rejects duplicate Complete or concurrent In progress rows despite valid aggregate text", async () => {
    const tracker = await readFile(
      resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"),
      "utf8",
    );
    const m012Row = tracker.split("\n").find((line) => line.startsWith("| M0-12 |"));

    expect(m012Row).toBeDefined();
    const duplicate = tracker.replace(`${m012Row}\n`, `${m012Row}\n${m012Row}\n`);
    const concurrent = tracker.replace(
      "## Complete\n",
      "| M0-15 | August 15, 2026 | Decoy concurrent work. |\n\n## Complete\n",
    );
    expect(duplicate).toContain("| In progress | 24 |");
    expect(concurrent).toContain("| In progress | 24 |");
    expect(() => assertM012Complete(duplicate)).toThrow();
    expect(() => assertM012Complete(concurrent)).toThrow();
  });

  it("documents the completed proof boundary and retained live evidence", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Tetragon signal proof[\s\S]*?## Real AWS cross-account IAM proof/)?.[0];

    expect(section).toBeDefined();
    expect(section).toContain("M0-12 is Complete");
    expect(section).toContain(tetragonImage);
    expect(section).toContain(operatorImage);
    expect(section).toContain(nodeImage);
    expect(section).toMatch(/process, file,\s+and outbound TCP/);
    expect(section).toContain("same Kubernetes workload identity");
    expect(section).toContain("capability and drop state");
    expect(section).toContain("observation-only");
    expect(section).toContain("does not prove internet egress");
    expect(section).toMatch(/R-07 is\s+PASS/);
    expect(section).toContain("two consecutive final-code live runs");
    expect(section).toContain("zero-finding independent review");
    expect(section).toContain("M0-09 and PROV-01 remain Blocked");
  });

  it("exposes exact hermetic and live root commands with fixed runtime boundaries", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, string> };
    const section = readme.match(/## Tetragon signal proof[\s\S]*?## Real AWS cross-account IAM proof/)?.[0];

    expect(packageJson.scripts?.["proof:tetragon:test"]).toBe(
      "node --test proofs/tetragon-signal/*.test.mjs",
    );
    expect(packageJson.scripts?.["proof:tetragon:run"]).toBe(
      "node proofs/tetragon-signal/run.mjs",
    );
    expect(section).toContain("npm run proof:tetragon:test");
    expect(section).toContain("npm run proof:tetragon:run");
    expect(section).toContain("Node.js 22.23.1");
    expect(section).toContain("Docker");
    expect(section).toContain("kind 0.32.0");
    expect(section).toContain("Helm 3");
    expect(section).toContain("kubectl");
    expect(section).toContain("Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.");
    expect(section).toContain("does not load `.env`");
    expect(section).toContain("ambient kubeconfig");
    expect(section).toContain("proxy variables");
    expect(section).toContain("exact-owned cleanup");
  });

  it("binds R-07 to one exact six-cell PASS row", async () => {
    const riskRegister = await readFile(
      resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"),
      "utf8",
    );
    const row = riskRegister.split("\n").find((line) => line.startsWith("| R-07 |"));

    expect(row).toBeDefined();
    assertR07Pass(riskRegister);
    const changed = (row ?? "").replace("| PASS — M0-12 |", "| PASS — decoy |") + "\n| PASS — M0-12 |";
    expect(() => assertR07Pass(riskRegister.replace(row ?? "", changed))).toThrow();
  });
});
